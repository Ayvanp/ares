"""
API REST de ARES.

Para ejecutar:
    python api.py

Documentación interactiva en: http://localhost:8000/docs
"""

import json
import os
import tempfile
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Query, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from parsers.nmap import parsear_nmap
from parsers.whatweb import parsear_whatweb
from parsers.gobuster import parsear_gobuster
from parsers.nuclei import parsear_nuclei
from parsers.dirb import parsear_dirb
from base_datos.conexion import BaseDatos
from base_datos.operaciones import (
    guardar_resultado, guardar_resultado_combinado,
    obtener_todos_los_escaneos, obtener_activos_de_escaneo,
    obtener_hallazgos_por_severidad, obtener_resumen,
    buscar_duplicados, obtener_correlaciones,
    obtener_resumen_correlacion, guardar_correlacion,
    guardar_resultados_en_escaneo,
    comparar_escaneos, escaneo_anterior_mismo_objetivo,
)
from base_datos.tablas import (
    TablaEscaneo, TablaTarea, TablaActivo, TablaServicio,
    TablaTecnologia, TablaEndpoint, TablaHallazgo, TablaEvidencia,
    generar_id, hora_actual,
)
from orquestador import orquestar, PERFILES, herramienta_disponible

app = FastAPI(title="ARES API", description="Sistema automatizado de evaluación de seguridad", version="1.0.0")

URL_BD = os.environ.get("ARES_DATABASE_URL", "sqlite:///ares.db")
bd = BaseDatos(URL_BD)
bd.crear_tablas()

PARSERS = {"nmap": parsear_nmap, "whatweb": parsear_whatweb,
           "gobuster": parsear_gobuster, "nuclei": parsear_nuclei,
           "dirb": parsear_dirb}


@app.get("/")
def inicio():
    return {"nombre": "ARES", "version": "1.0.0",
            "herramientas": list(PARSERS.keys())}


# ── Escaneos ──

@app.get("/escaneos")
def listar_escaneos():
    escaneos = obtener_todos_los_escaneos(bd)
    return {"total": len(escaneos), "escaneos": [
        {"id": e.id, "objetivo": e.objetivo, "perfil": e.perfil,
         "estado": e.estado, "creado_en": str(e.creado_en) if e.creado_en else None}
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
            "estado": escaneo.estado, "creado_en": str(escaneo.creado_en) if escaneo.creado_en else None,
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
    target: str = Query(description="IP o rango a escanear"),
    perfil: str = Query(default="completo"),
    background_tasks: BackgroundTasks = None,
):
    if perfil not in PERFILES:
        raise HTTPException(status_code=400, detail="Perfil inválido: " + ", ".join(PERFILES.keys()))
    sesion = bd.nueva_sesion()
    try:
        escaneo = TablaEscaneo(objetivo=target, perfil=perfil,
            estado="pending", creado_en=hora_actual())
        sesion.add(escaneo); sesion.flush()
        sesion.add(TablaTarea(escaneo_id=escaneo.id, nombre_herramienta="nmap", estado="pending"))
        sesion.commit()
        escaneo_id = escaneo.id
    finally:
        sesion.close()
    background_tasks.add_task(orquestar, target=target, perfil_nombre=perfil,
        bd=bd, escaneo_id=escaneo_id)
    return {"escaneo_id": escaneo_id, "target": target, "perfil": perfil,
            "estado": "pending", "mensaje": "Escaneo iniciado. Usa GET /escaneos/" + escaneo_id + "/estado"}


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
