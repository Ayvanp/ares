"""
API REST de ARES.

Para ejecutar:
    python api.py

Documentación interactiva en: http://localhost:8000/docs

Autenticación (Etapa 0): la API ya NO es abierta. Toda petición (salvo la raíz
y /salud) exige un token en la cabecera `Authorization: Bearer <token>` o
`X-API-Key: <token>`. Para el arranque inicial se acepta el valor de la variable
de entorno `ARES_API_TOKEN` como token admin; con él se crean tokens con nombre.
Los escaneos activos solo arrancan bajo un engagement vigente y contra un
objetivo dentro de su alcance autorizado (compuerta dura), y todo intento queda
en la tabla de auditoría.
"""

import os
import tempfile

from fastapi import (
    FastAPI, UploadFile, File, Query, HTTPException, Header, Depends, Request,
)
from fastapi.responses import FileResponse

from parsers.nmap import parsear_nmap
from parsers.whatweb import parsear_whatweb
from parsers.gobuster import parsear_gobuster
from parsers.nuclei import parsear_nuclei
from parsers.dirb import parsear_dirb
from base_datos.conexion import BaseDatos
from base_datos.operaciones import (
    guardar_resultado, guardar_resultado_combinado,
    obtener_todos_los_escaneos, obtener_resumen,
    obtener_correlaciones, obtener_resumen_correlacion,
    comparar_escaneos,
)
from base_datos import gestion
from base_datos.tablas import (
    TablaEscaneo, TablaTarea, TablaActivo, TablaServicio,
    TablaTecnologia, TablaEndpoint, TablaHallazgo, TablaEvidencia,
    hora_actual,
)
from orquestador import orquestar, PERFILES, herramienta_disponible
from cola import ColaEscaneos
from autenticacion import (
    identidad_de_token, extraer_token, crear_token, listar_tokens, revocar_token,
)

URL_BD = os.environ.get("ARES_DATABASE_URL", "sqlite:///ares.db")
bd = BaseDatos(URL_BD)
bd.crear_tablas()

# Cola de escaneos (pool de hilos en el mismo proceso). Número de trabajadores
# configurable; por defecto 1 (FIFO serializado), robusto sobre SQLite.
cola = ColaEscaneos(bd, runner=orquestar,
                    trabajadores=int(os.environ.get("ARES_TRABAJADORES", "1")))

PARSERS = {"nmap": parsear_nmap, "whatweb": parsear_whatweb,
           "gobuster": parsear_gobuster, "nuclei": parsear_nuclei,
           "dirb": parsear_dirb}

RUTAS_ABIERTAS = {"/", "/salud", "/docs", "/redoc", "/openapi.json"}


# ── Autenticación ──

async def autenticar(request: Request,
                     authorization: str = Header(default=None),
                     x_api_key: str = Header(default=None, alias="X-API-Key")):
    """Dependencia global: valida el token salvo en las rutas abiertas."""
    if request.url.path in RUTAS_ABIERTAS:
        return None
    identidad = identidad_de_token(bd, extraer_token(authorization, x_api_key))
    if not identidad:
        raise HTTPException(status_code=401,
                            detail="Token inválido o ausente. Usa Authorization: Bearer <token>.")
    request.state.identidad = identidad
    return identidad


def identidad_actual(request: Request):
    return getattr(request.state, "identidad", None) or {"nombre": "desconocido", "es_admin": False}


def requiere_admin(request: Request):
    ident = getattr(request.state, "identidad", None)
    if not ident or not ident.get("es_admin"):
        raise HTTPException(status_code=403, detail="Esta operación requiere un token admin")
    return ident


app = FastAPI(title="ARES API",
              description="Sistema automatizado de evaluación de seguridad",
              version="1.1.0",
              dependencies=[Depends(autenticar)])


@app.get("/")
def inicio():
    return {"nombre": "ARES", "version": "1.1.0",
            "herramientas": list(PARSERS.keys()),
            "autenticacion": "requerida (Bearer token / X-API-Key)"}


@app.get("/salud")
def salud():
    return {"estado": "ok", "escaneos_en_cola": cola.pendientes()}


# ── Tokens (admin) ──

@app.post("/tokens")
def crear_token_api(nombre: str = Query(description="Nombre descriptivo del token"),
                    admin: bool = Query(default=False),
                    _=Depends(requiere_admin)):
    datos = crear_token(bd, nombre, es_admin=admin)
    return {"mensaje": "Token creado. Guárdalo ahora: no se vuelve a mostrar.",
            **datos}


@app.get("/tokens")
def listar_tokens_api(_=Depends(requiere_admin)):
    return {"tokens": listar_tokens(bd)}


@app.delete("/tokens/{token_id}")
def revocar_token_api(token_id: str, _=Depends(requiere_admin)):
    if not revocar_token(bd, token_id):
        raise HTTPException(status_code=404, detail="Token no encontrado")
    return {"mensaje": "Token revocado", "id": token_id}


# ── Clientes y engagements (admin) ──

@app.post("/clientes")
def crear_cliente_api(nombre: str = Query(), notas: str = Query(default=None),
                      _=Depends(requiere_admin)):
    return gestion.crear_cliente(bd, nombre, notas)


@app.get("/clientes")
def listar_clientes_api():
    return {"clientes": gestion.listar_clientes(bd)}


@app.post("/engagements")
def crear_engagement_api(cliente_id: str = Query(), nombre: str = Query(),
                         ventana_inicio: str = Query(default=None),
                         ventana_fin: str = Query(default=None),
                         _=Depends(requiere_admin)):
    try:
        return gestion.crear_engagement(bd, cliente_id, nombre, ventana_inicio, ventana_fin)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/engagements")
def listar_engagements_api():
    return {"engagements": gestion.listar_engagements(bd)}


@app.get("/engagements/{engagement_id}")
def detalle_engagement_api(engagement_id: str):
    eng = gestion.obtener_engagement(bd, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement no encontrado")
    return eng


@app.post("/engagements/{engagement_id}/alcance")
def agregar_alcance_api(engagement_id: str,
                        tipo: str = Query(description="ip, cidr, hostname o dominio"),
                        valor: str = Query(),
                        _=Depends(requiere_admin)):
    try:
        return gestion.agregar_alcance(bd, engagement_id, tipo, valor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/engagements/{engagement_id}/activar")
def activar_engagement_api(engagement_id: str,
                           nda_firmado: bool = Query(),
                           roe_firmado: bool = Query(),
                           _=Depends(requiere_admin)):
    try:
        return gestion.activar_engagement(bd, engagement_id, nda_firmado, roe_firmado)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/engagements/{engagement_id}/cerrar")
def cerrar_engagement_api(engagement_id: str, _=Depends(requiere_admin)):
    r = gestion.cerrar_engagement(bd, engagement_id)
    if not r:
        raise HTTPException(status_code=404, detail="Engagement no encontrado")
    return r


@app.get("/engagements/{engagement_id}/auditoria")
def auditoria_engagement_api(engagement_id: str):
    return {"engagement_id": engagement_id,
            "auditoria": gestion.listar_auditoria(bd, engagement_id=engagement_id)}


@app.get("/auditoria")
def auditoria_api(_=Depends(requiere_admin)):
    return {"auditoria": gestion.listar_auditoria(bd)}


# ── Escaneos ──

@app.get("/escaneos")
def listar_escaneos():
    escaneos = obtener_todos_los_escaneos(bd)
    return {"total": len(escaneos), "escaneos": [
        {"id": e.id, "objetivo": e.objetivo, "perfil": e.perfil,
         "estado": e.estado, "engagement_id": e.engagement_id,
         "creado_en": str(e.creado_en) if e.creado_en else None}
        for e in escaneos]}


@app.get("/escaneos/{escaneo_id}")
def detalle_escaneo(escaneo_id: str):
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    if not escaneo:
        sesion.close(); raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    tareas = sesion.query(TablaTarea).filter_by(escaneo_id=escaneo_id).all()
    activos = sesion.query(TablaActivo).filter_by(escaneo_id=escaneo_id).all()
    lista_activos = []
    for activo in activos:
        servicios = sesion.query(TablaServicio).filter_by(activo_id=activo.id).all()
        tecnologias = sesion.query(TablaTecnologia).filter_by(activo_id=activo.id).all()
        endpoints = sesion.query(TablaEndpoint).filter_by(activo_id=activo.id).all()
        hallazgos = sesion.query(TablaHallazgo).filter_by(activo_id=activo.id).all()
        lista_hallazgos = []
        for h in hallazgos:
            evidencias = sesion.query(TablaEvidencia).filter_by(hallazgo_id=h.id).all()
            lista_hallazgos.append({
                "id": h.id, "titulo": h.titulo, "severidad": h.severidad,
                "descripcion": h.descripcion, "id_plantilla": h.id_plantilla,
                "url": h.url, "hash_dedup": h.hash_dedup,
                "evidencias": [{"encontrado_en": e.encontrado_en, "comando_curl": e.comando_curl}
                               for e in evidencias],
            })
        lista_activos.append({
            "id": activo.id, "ip": activo.ip, "hostname": activo.hostname,
            "estado": activo.estado,
            "sistema_operativo": {"nombre": activo.so_nombre, "familia": activo.so_familia,
                                  "precision": activo.so_precision} if activo.so_nombre else None,
            "servicios": [{"puerto": s.puerto, "protocolo": s.protocolo,
                           "estado": s.estado, "producto": s.producto, "version": s.version}
                          for s in servicios],
            "tecnologias": [{"nombre": t.nombre, "version": t.version, "categoria": t.categoria}
                            for t in tecnologias],
            "endpoints": [{"ruta": e.ruta, "codigo_estado": e.codigo_estado} for e in endpoints],
            "hallazgos": lista_hallazgos,
        })
    sesion.close()
    return {"id": escaneo.id, "objetivo": escaneo.objetivo, "perfil": escaneo.perfil,
            "estado": escaneo.estado, "engagement_id": escaneo.engagement_id,
            "creado_en": str(escaneo.creado_en) if escaneo.creado_en else None,
            "tareas": [{"herramienta": t.nombre_herramienta, "estado": t.estado} for t in tareas],
            "activos": lista_activos}


@app.get("/escaneos/{escaneo_id}/resumen")
def resumen_escaneo(escaneo_id: str):
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    sesion.close()
    if not escaneo: raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    resumen = obtener_resumen(bd, escaneo_id)
    resumen["id"] = escaneo_id; resumen["objetivo"] = escaneo.objetivo
    return resumen


@app.get("/escaneos/{escaneo_id}/estado")
def estado_escaneo(escaneo_id: str):
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    if not escaneo:
        sesion.close(); raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    tareas = sesion.query(TablaTarea).filter_by(escaneo_id=escaneo_id).all()
    sesion.close()
    resumen = obtener_resumen(bd, escaneo_id) if escaneo.estado == "completed" else None
    return {"escaneo_id": escaneo_id, "target": escaneo.objetivo, "perfil": escaneo.perfil,
            "estado": escaneo.estado,
            "creado": str(escaneo.creado_en) if escaneo.creado_en else None,
            "completado": str(escaneo.completado_en) if escaneo.completado_en else None,
            "tareas": [{"herramienta": t.nombre_herramienta, "estado": t.estado,
                        "comando": t.comando, "razon": t.razon,
                        "iniciado": str(t.iniciado_en) if t.iniciado_en else None,
                        "terminado": str(t.terminado_en) if t.terminado_en else None}
                       for t in tareas],
            "resumen": resumen}


# ── Evidencia y comparación ──

@app.get("/escaneos/{escaneo_id}/evidencias")
def listar_evidencias(escaneo_id: str):
    """Lista los archivos de salida cruda que dejó el escaneo."""
    carpeta = os.path.join("evidencias", escaneo_id)
    if not os.path.isdir(carpeta):
        return {"escaneo_id": escaneo_id, "evidencias": []}
    archivos = []
    for nombre in sorted(os.listdir(carpeta)):
        ruta = os.path.join(carpeta, nombre)
        if os.path.isfile(ruta):
            archivos.append({"archivo": nombre,
                             "tamano": os.path.getsize(ruta), "ruta": ruta})
    return {"escaneo_id": escaneo_id, "carpeta": carpeta, "evidencias": archivos}


@app.get("/escaneos/{escaneo_id}/comparar/{base_id}")
def comparar(escaneo_id: str, base_id: str):
    """Compara este escaneo (nuevo) contra otro anterior (base)."""
    dif = comparar_escaneos(bd, base_id, escaneo_id)
    if not dif:
        raise HTTPException(status_code=404, detail="Escaneo(s) no encontrado(s)")
    return dif


# ── Orquestador ──

@app.get("/perfiles")
def listar_perfiles():
    return {"perfiles": {n: c["descripcion"] for n, c in PERFILES.items()}}


@app.post("/escaneos/iniciar")
def iniciar_escaneo(
    request: Request,
    engagement_id: str = Query(description="Engagement autorizado bajo el que se escanea"),
    target: str = Query(description="IP o host a escanear (debe estar en el alcance)"),
    perfil: str = Query(default="completo"),
):
    """
    Compuerta dura: solo arranca si el engagement está vigente y el objetivo
    está dentro de su alcance. Todo intento (permitido o denegado) se audita.
    """
    actor = identidad_actual(request)["nombre"]
    if perfil not in PERFILES:
        raise HTTPException(status_code=400, detail="Perfil inválido: " + ", ".join(PERFILES.keys()))

    evaluacion = gestion.evaluar_autorizacion(bd, engagement_id, target)
    if not evaluacion["existe"]:
        gestion.registrar_auditoria(bd, actor, "escaneo.iniciar", objetivo=target,
            engagement_id=engagement_id, resultado="denegado", detalle="Engagement inexistente")
        raise HTTPException(status_code=404, detail="Engagement no encontrado")
    if not evaluacion["ok"]:
        gestion.registrar_auditoria(bd, actor, "escaneo.iniciar", objetivo=target,
            engagement_id=engagement_id, resultado="denegado", detalle=evaluacion["motivo"])
        raise HTTPException(status_code=403, detail="Fuera de alcance: " + evaluacion["motivo"])

    sesion = bd.nueva_sesion()
    try:
        escaneo = TablaEscaneo(objetivo=target, perfil=perfil, estado="pending",
            engagement_id=engagement_id, creado_en=hora_actual())
        sesion.add(escaneo); sesion.flush()
        sesion.add(TablaTarea(escaneo_id=escaneo.id, nombre_herramienta="nmap", estado="pending"))
        sesion.commit()
        escaneo_id = escaneo.id
    finally:
        sesion.close()

    gestion.registrar_auditoria(bd, actor, "escaneo.iniciar", objetivo=target,
        engagement_id=engagement_id, escaneo_id=escaneo_id, resultado="permitido",
        detalle="Perfil " + perfil)
    cola.encolar(escaneo_id, target, perfil)
    return {"escaneo_id": escaneo_id, "target": target, "perfil": perfil,
            "engagement_id": engagement_id, "estado": "queued",
            "mensaje": "Escaneo en cola. Usa GET /escaneos/" + escaneo_id + "/estado"}


@app.get("/herramientas/estado")
def estado_herramientas():
    herramientas = ["nmap", "whatweb", "gobuster", "dirb", "nuclei"]
    estado = {h: "instalada" if herramienta_disponible(h) else "no instalada" for h in herramientas}
    return {"herramientas": estado, "puede_orquestar": estado.get("nmap") == "instalada"}


# ── Parseo manual ──

@app.post("/parsear")
async def parsear_archivo(
    herramienta: str = Query(description="nmap, whatweb, gobuster, nuclei"),
    objetivo: str = Query(default="unknown"),
    archivo: UploadFile = File(),
):
    herramienta = herramienta.lower()
    if herramienta not in PARSERS:
        raise HTTPException(status_code=400, detail="Herramienta inválida")
    contenido = await archivo.read()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + archivo.filename)
    tmp.write(contenido); tmp.close()
    try:
        resultado = PARSERS[herramienta](tmp.name)
        escaneo = guardar_resultado(bd, resultado, objetivo=objetivo)
        return {"mensaje": "Parseado correctamente", "escaneo_id": escaneo.id,
                "herramienta": herramienta, "resumen": obtener_resumen(bd, escaneo.id)}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al parsear: " + str(e))
    finally:
        os.unlink(tmp.name)


@app.post("/parsear/multiples")
async def parsear_multiples(
    objetivo: str = Query(),
    archivos_nmap: UploadFile = File(default=None),
    archivos_whatweb: UploadFile = File(default=None),
    archivos_gobuster: UploadFile = File(default=None),
    archivos_nuclei: UploadFile = File(default=None),
):
    archivos_map = {"nmap": archivos_nmap, "whatweb": archivos_whatweb,
                    "gobuster": archivos_gobuster, "nuclei": archivos_nuclei}
    resultados = []; herramientas_usadas = []; tmps = []
    try:
        for herramienta, archivo in archivos_map.items():
            if archivo is None: continue
            contenido = await archivo.read()
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + archivo.filename)
            tmp.write(contenido); tmp.close(); tmps.append(tmp.name)
            resultados.append(PARSERS[herramienta](tmp.name))
            herramientas_usadas.append(herramienta)
        if not resultados:
            raise HTTPException(status_code=400, detail="No se subió ningún archivo")
        escaneo = guardar_resultado_combinado(bd, resultados, objetivo=objetivo)
        return {"mensaje": "Consolidado correctamente", "escaneo_id": escaneo.id,
                "herramientas": herramientas_usadas, "resumen": obtener_resumen(bd, escaneo.id)}
    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error: " + str(e))
    finally:
        for t in tmps:
            if os.path.exists(t): os.unlink(t)


# ── Hallazgos ──

@app.get("/hallazgos")
def listar_hallazgos(severidad: str = Query(default=None)):
    sesion = bd.nueva_sesion()
    q = sesion.query(TablaHallazgo)
    if severidad: q = q.filter_by(severidad=severidad)
    hallazgos = q.all()
    lista = []
    for h in hallazgos:
        activo = sesion.query(TablaActivo).filter_by(id=h.activo_id).first()
        lista.append({"id": h.id, "titulo": h.titulo, "severidad": h.severidad,
                      "ip_host": activo.ip if activo else None,
                      "url": h.url, "herramienta": h.herramienta,
                      "id_plantilla": h.id_plantilla, "hash_dedup": h.hash_dedup})
    sesion.close()
    return {"total": len(lista), "hallazgos": lista}


# ── Correlación ──

@app.get("/escaneos/{escaneo_id}/correlacion")
def ver_correlacion(escaneo_id: str):
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    sesion.close()
    if not escaneo: raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    correlaciones = obtener_correlaciones(bd, escaneo_id)
    resumen = obtener_resumen_correlacion(bd, escaneo_id)
    return {"escaneo_id": escaneo_id, "objetivo": escaneo.objetivo,
            "resumen": resumen, "correlaciones": correlaciones}


@app.get("/escaneos/{escaneo_id}/correlacion/resumen")
def resumen_correlacion(escaneo_id: str):
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    sesion.close()
    if not escaneo: raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    resumen = obtener_resumen_correlacion(bd, escaneo_id)
    resumen["escaneo_id"] = escaneo_id
    return resumen


# ── Reportes ──

@app.post("/escaneos/{escaneo_id}/reporte/html")
def generar_reporte_html(escaneo_id: str):
    """Genera y descarga el reporte HTML completo del escaneo."""
    from reportes.generador import generar_reporte_html as _generar
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    sesion.close()
    if not escaneo: raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    try:
        ruta = _generar(bd, escaneo_id)
        return FileResponse(ruta, media_type="text/html",
            filename="reporte_" + escaneo_id[:8] + ".html")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error generando reporte: " + str(e))


@app.post("/escaneos/{escaneo_id}/reporte/csv")
def generar_reporte_csv(escaneo_id: str):
    """Genera y descarga el CSV de hallazgos del escaneo."""
    from reportes.generador import generar_reporte_csv as _generar
    sesion = bd.nueva_sesion()
    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    sesion.close()
    if not escaneo: raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    try:
        ruta = _generar(bd, escaneo_id)
        return FileResponse(ruta, media_type="text/csv",
            filename="hallazgos_" + escaneo_id[:8] + ".csv")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error generando CSV: " + str(e))


if __name__ == "__main__":
    import uvicorn
    print("Iniciando ARES API...")
    print("Documentación en: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
