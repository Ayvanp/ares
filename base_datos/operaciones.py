"""
Operaciones con la base de datos.
Incluye deduplicación por hash: no guarda el mismo hallazgo dos veces en el mismo escaneo.
"""

import json
from datetime import datetime, timezone

from base_datos.tablas import (
    TablaEscaneo, TablaTarea, TablaActivo, TablaServicio,
    TablaTecnologia, TablaEndpoint, TablaHallazgo, TablaEvidencia,
    TablaCorrelacion, TablaVinculo, hora_actual,
)


def guardar_resultado(bd, resultado_canonico, objetivo=None, perfil=None):
    meta = resultado_canonico.metadatos
    sesion = bd.nueva_sesion()
    try:
        escaneo = TablaEscaneo(
            objetivo=objetivo or meta.objetivo or "unknown", perfil=perfil,
            estado="completed", creado_en=meta.fecha_inicio,
            completado_en=meta.fecha_fin or hora_actual(),
        )
        sesion.add(escaneo)
        sesion.flush()
        tarea = TablaTarea(escaneo_id=escaneo.id, nombre_herramienta=meta.herramienta,
            estado="completed", comando=meta.comando,
            iniciado_en=meta.fecha_inicio, terminado_en=meta.fecha_fin)
        sesion.add(tarea)
        for host in resultado_canonico.hosts:
            _guardar_host_completo(sesion, escaneo.id, host, meta.herramienta)
        sesion.commit()
        return escaneo
    except Exception:
        sesion.rollback(); raise
    finally:
        sesion.close()


def guardar_resultado_combinado(bd, resultados, objetivo, perfil=None):
    sesion = bd.nueva_sesion()
    try:
        escaneo = TablaEscaneo(objetivo=objetivo, perfil=perfil,
            estado="completed", creado_en=hora_actual())
        sesion.add(escaneo)
        sesion.flush()
        for resultado in resultados:
            meta = resultado.metadatos
            tarea = TablaTarea(escaneo_id=escaneo.id, nombre_herramienta=meta.herramienta,
                estado="completed", comando=meta.comando)
            sesion.add(tarea)
        activos_guardados = {}
        for resultado in resultados:
            herramienta = resultado.metadatos.herramienta
            for host in resultado.hosts:
                ip = host.ip
                if ip not in activos_guardados:
                    activo = _crear_activo(sesion, escaneo.id, host)
                    activos_guardados[ip] = activo
                else:
                    activo = activos_guardados[ip]
                    if host.sistema_operativo:
                        p_nueva = host.sistema_operativo.precision or 0
                        p_actual = activo.so_precision or 0
                        if p_nueva > p_actual:
                            activo.so_nombre = host.sistema_operativo.nombre
                            activo.so_familia = host.sistema_operativo.familia
                            activo.so_precision = host.sistema_operativo.precision
                for s in host.servicios: _guardar_servicio(sesion, activo.id, s)
                for t in host.tecnologias: _guardar_tecnologia(sesion, activo.id, t)
                for e in host.endpoints: _guardar_endpoint(sesion, activo.id, e)
                for h in host.hallazgos: _guardar_hallazgo(sesion, escaneo.id, activo.id, h, herramienta)
        sesion.commit()
        _guardar_correlacion_automatica(bd, escaneo.id, activos_guardados, resultados)
        return escaneo
    except Exception:
        sesion.rollback(); raise
    finally:
        sesion.close()


def guardar_resultados_en_escaneo(bd, escaneo_id, resultados):
    """Guarda resultados bajo un escaneo ya existente (usado por el orquestador)."""
    sesion = bd.nueva_sesion()
    try:
        activos_guardados = {}
        for resultado in resultados:
            herramienta = resultado.metadatos.herramienta
            # Las tareas (con tiempo, comando y razón) las administra el
            # orquestador vía actualizar_estado; aquí solo guardamos los activos.
            for host in resultado.hosts:
                ip = host.ip
                if ip not in activos_guardados:
                    activo = _crear_activo(sesion, escaneo_id, host)
                    activos_guardados[ip] = activo
                else:
                    activo = activos_guardados[ip]
                    if host.sistema_operativo:
                        p_nueva = host.sistema_operativo.precision or 0
                        p_actual = activo.so_precision or 0
                        if p_nueva > p_actual:
                            activo.so_nombre = host.sistema_operativo.nombre
                            activo.so_familia = host.sistema_operativo.familia
                            activo.so_precision = host.sistema_operativo.precision
                for s in host.servicios: _guardar_servicio(sesion, activo.id, s)
                for t in host.tecnologias: _guardar_tecnologia(sesion, activo.id, t)
                for e in host.endpoints: _guardar_endpoint(sesion, activo.id, e)
                for h in host.hallazgos: _guardar_hallazgo(sesion, escaneo_id, activo.id, h, herramienta)
        sesion.commit()
        return activos_guardados
    except Exception:
        sesion.rollback(); raise
    finally:
        sesion.close()


# ── Funciones internas de guardado ──

def _guardar_host_completo(sesion, escaneo_id, host, herramienta):
    activo = _crear_activo(sesion, escaneo_id, host)
    for s in host.servicios: _guardar_servicio(sesion, activo.id, s)
    for t in host.tecnologias: _guardar_tecnologia(sesion, activo.id, t)
    for e in host.endpoints: _guardar_endpoint(sesion, activo.id, e)
    for h in host.hallazgos: _guardar_hallazgo(sesion, escaneo_id, activo.id, h, herramienta)


def _crear_activo(sesion, escaneo_id, host):
    hostname = ",".join(host.hostnames) if host.hostnames else None
    activo = TablaActivo(escaneo_id=escaneo_id, ip=host.ip, hostname=hostname,
        mac=host.mac, mac_fabricante=host.mac_fabricante, estado=host.estado)
    if host.sistema_operativo:
        activo.so_nombre = host.sistema_operativo.nombre
        activo.so_familia = host.sistema_operativo.familia
        activo.so_precision = host.sistema_operativo.precision
        activo.so_cpe = host.sistema_operativo.cpe
    sesion.add(activo); sesion.flush()
    return activo


def _guardar_servicio(sesion, activo_id, servicio):
    cpe = ",".join(servicio.cpe) if servicio.cpe else None
    sesion.add(TablaServicio(activo_id=activo_id, puerto=servicio.puerto,
        protocolo=servicio.protocolo, estado=servicio.estado,
        nombre_servicio=servicio.nombre_servicio, producto=servicio.producto,
        version=servicio.version, cpe=cpe))


def _guardar_tecnologia(sesion, activo_id, tec):
    sesion.add(TablaTecnologia(activo_id=activo_id, nombre=tec.nombre,
        version=tec.version, categoria=tec.categoria))


def _guardar_endpoint(sesion, activo_id, ep):
    # dirb y Gobuster pueden encontrar la misma ruta; no la guardamos dos veces.
    existente = sesion.query(TablaEndpoint).filter_by(
        activo_id=activo_id, ruta=ep.ruta, codigo_estado=ep.codigo_estado).first()
    if existente:
        # Si el nuevo trae el destino de la redirección y el viejo no, lo completamos.
        if ep.redirige_a and not existente.redirige_a:
            existente.redirige_a = ep.redirige_a
        return
    sesion.add(TablaEndpoint(activo_id=activo_id, url=ep.url, ruta=ep.ruta,
        codigo_estado=ep.codigo_estado, tamano=ep.tamano, redirige_a=ep.redirige_a))


def _guardar_hallazgo(sesion, escaneo_id, activo_id, hallazgo, herramienta):
    # ── FIX DEDUPLICACIÓN: no insertar si el mismo hash ya existe en este escaneo ──
    if hallazgo.grupo_dedup:
        existente = sesion.query(TablaHallazgo).filter_by(
            escaneo_id=escaneo_id, hash_dedup=hallazgo.grupo_dedup).first()
        if existente:
            return

    registro = TablaHallazgo(
        escaneo_id=escaneo_id, activo_id=activo_id,
        titulo=hallazgo.titulo, severidad=hallazgo.severidad,
        descripcion=hallazgo.descripcion, id_plantilla=hallazgo.id_plantilla,
        url=hallazgo.url,
        etiquetas=json.dumps(hallazgo.etiquetas) if hallazgo.etiquetas else None,
        referencias=json.dumps(hallazgo.referencias) if hallazgo.referencias else None,
        hash_dedup=hallazgo.grupo_dedup, herramienta=herramienta,
    )
    sesion.add(registro); sesion.flush()
    if hallazgo.evidencia:
        ev = hallazgo.evidencia
        sesion.add(TablaEvidencia(
            hallazgo_id=registro.id, encontrado_en=ev.encontrado_en,
            comando_curl=ev.comando_curl,
            resultados_extraidos=json.dumps(ev.resultados_extraidos) if ev.resultados_extraidos else None,
        ))


# ── Correlación ──

def _guardar_correlacion_automatica(bd, escaneo_id, activos_guardados, resultados):
    from correlacion import correlacionar
    reporte = correlacionar(resultados)
    sesion = bd.nueva_sesion()
    try:
        for host_corr in reporte["hosts"]:
            activo = activos_guardados.get(host_corr["ip"])
            if not activo: continue
            for c in host_corr["correlaciones"]:
                corr = TablaCorrelacion(
                    escaneo_id=escaneo_id, activo_id=activo.id,
                    hallazgo_titulo=c["hallazgo"], hallazgo_severidad=c["severidad"],
                    hallazgo_id_plantilla=c.get("id_plantilla"),
                    confianza=c["confianza"], razon=c["razon"],
                )
                sesion.add(corr); sesion.flush()
                for v in c["vinculos"]:
                    sesion.add(TablaVinculo(correlacion_id=corr.id,
                        tipo=v["tipo"], descripcion=v["descripcion"]))
        sesion.commit()
    except Exception:
        sesion.rollback()
    finally:
        sesion.close()


def guardar_correlacion(bd, escaneo_id, resultados):
    sesion = bd.nueva_sesion()
    activos = sesion.query(TablaActivo).filter_by(escaneo_id=escaneo_id).all()
    sesion.close()
    activos_guardados = {a.ip: a for a in activos}
    # Borrar correlaciones anteriores
    sesion = bd.nueva_sesion()
    try:
        for c in sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id).all():
            sesion.delete(c)
        sesion.commit()
    finally:
        sesion.close()
    _guardar_correlacion_automatica(bd, escaneo_id, activos_guardados, resultados)


# ── Consultas ──

def obtener_todos_los_escaneos(bd):
    sesion = bd.nueva_sesion()
    resultado = sesion.query(TablaEscaneo).order_by(TablaEscaneo.creado_en.desc()).all()
    sesion.close(); return resultado


def obtener_hallazgos_por_severidad(bd, severidad):
    sesion = bd.nueva_sesion()
    resultado = sesion.query(TablaHallazgo).filter_by(severidad=severidad).all()
    sesion.close(); return resultado


def obtener_activos_de_escaneo(bd, escaneo_id):
    sesion = bd.nueva_sesion()
    resultado = sesion.query(TablaActivo).filter_by(escaneo_id=escaneo_id).all()
    sesion.close(); return resultado


def buscar_duplicados(bd, hash_dedup):
    sesion = bd.nueva_sesion()
    resultado = sesion.query(TablaHallazgo).filter_by(hash_dedup=hash_dedup).all()
    sesion.close(); return resultado


def escaneo_anterior_mismo_objetivo(bd, escaneo_id):
    """Devuelve el escaneo completado inmediatamente anterior del mismo objetivo."""
    sesion = bd.nueva_sesion()
    try:
        actual = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
        if not actual:
            return None
        previo = (sesion.query(TablaEscaneo)
                  .filter(TablaEscaneo.objetivo == actual.objetivo,
                          TablaEscaneo.creado_en < actual.creado_en)
                  .order_by(TablaEscaneo.creado_en.desc()).first())
        return previo.id if previo else None
    finally:
        sesion.close()


def comparar_escaneos(bd, id_base, id_nuevo):
    """
    Compara dos escaneos del mismo objetivo: qué puertos y hallazgos
    aparecieron o desaparecieron entre uno y otro.
    """
    sesion = bd.nueva_sesion()
    try:
        def _datos(eid):
            esc = sesion.query(TablaEscaneo).filter_by(id=eid).first()
            if not esc:
                return None
            activos = sesion.query(TablaActivo).filter_by(escaneo_id=eid).all()
            puertos = set()
            for a in activos:
                for s in sesion.query(TablaServicio).filter_by(activo_id=a.id).all():
                    if s.estado == "open":
                        puertos.add(str(s.puerto) + "/" + (s.protocolo or "tcp"))
            hallazgos = set(h.titulo for h in
                            sesion.query(TablaHallazgo).filter_by(escaneo_id=eid).all())
            return {"objetivo": esc.objetivo,
                    "creado": str(esc.creado_en)[:19] if esc.creado_en else "",
                    "puertos": puertos, "hallazgos": hallazgos}

        base = _datos(id_base)
        nuevo = _datos(id_nuevo)
        if not base or not nuevo:
            return None
        return {
            "base": {"id": id_base, "objetivo": base["objetivo"], "creado": base["creado"]},
            "nuevo": {"id": id_nuevo, "objetivo": nuevo["objetivo"], "creado": nuevo["creado"]},
            "puertos_nuevos": sorted(nuevo["puertos"] - base["puertos"]),
            "puertos_cerrados": sorted(base["puertos"] - nuevo["puertos"]),
            "hallazgos_nuevos": sorted(nuevo["hallazgos"] - base["hallazgos"]),
            "hallazgos_resueltos": sorted(base["hallazgos"] - nuevo["hallazgos"]),
        }
    finally:
        sesion.close()


def obtener_correlaciones(bd, escaneo_id):
    sesion = bd.nueva_sesion()
    correlaciones = sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id).all()
    resultado = []
    for c in correlaciones:
        activo = sesion.query(TablaActivo).filter_by(id=c.activo_id).first()
        vinculos = sesion.query(TablaVinculo).filter_by(correlacion_id=c.id).all()
        resultado.append({
            "id": c.id, "ip": activo.ip if activo else "?",
            "hallazgo": c.hallazgo_titulo, "severidad": c.hallazgo_severidad,
            "id_plantilla": c.hallazgo_id_plantilla, "confianza": c.confianza,
            "razon": c.razon,
            "vinculos": [{"tipo": v.tipo, "descripcion": v.descripcion} for v in vinculos],
        })
    sesion.close(); return resultado


def obtener_resumen_correlacion(bd, escaneo_id):
    sesion = bd.nueva_sesion()
    total = sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id).count()
    alta = sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id, confianza="alta").count()
    media = sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id, confianza="media").count()
    baja = sesion.query(TablaCorrelacion).filter_by(escaneo_id=escaneo_id, confianza="baja").count()
    con_vinculos = (sesion.query(TablaCorrelacion)
        .filter(TablaCorrelacion.escaneo_id == escaneo_id)
        .join(TablaVinculo, TablaVinculo.correlacion_id == TablaCorrelacion.id)
        .distinct().count())
    sesion.close()
    return {"total_correlaciones": total, "con_vinculos": con_vinculos,
            "sin_vinculos": total - con_vinculos,
            "confianza_alta": alta, "confianza_media": media, "confianza_baja": baja}


def obtener_resumen(bd, escaneo_id):
    sesion = bd.nueva_sesion()
    total_activos = sesion.query(TablaActivo).filter_by(escaneo_id=escaneo_id).count()
    total_servicios = (sesion.query(TablaServicio).join(TablaActivo)
        .filter(TablaActivo.escaneo_id == escaneo_id).count())
    total_tecnologias = (sesion.query(TablaTecnologia).join(TablaActivo)
        .filter(TablaActivo.escaneo_id == escaneo_id).count())
    total_endpoints = (sesion.query(TablaEndpoint).join(TablaActivo)
        .filter(TablaActivo.escaneo_id == escaneo_id).count())
    total_hallazgos = sesion.query(TablaHallazgo).filter_by(escaneo_id=escaneo_id).count()
    por_severidad = {}
    for sev in ["critical","high","medium","low","info"]:
        c = sesion.query(TablaHallazgo).filter_by(escaneo_id=escaneo_id, severidad=sev).count()
        if c > 0: por_severidad[sev] = c
    sesion.close()
    return {"activos": total_activos, "servicios": total_servicios,
            "tecnologias": total_tecnologias, "endpoints": total_endpoints,
            "hallazgos": total_hallazgos, "por_severidad": por_severidad}
