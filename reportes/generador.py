"""
Generador de reportes de ARES.

Genera reportes en dos formatos:
  - HTML: reporte completo y visual para entregar al cliente
  - CSV: datos estructurados para análisis posterior

Uso:
    from reportes.generador import generar_reporte_html, generar_reporte_csv

    ruta = generar_reporte_html(bd, escaneo_id, "reporte.html")
    ruta = generar_reporte_csv(bd, escaneo_id, "hallazgos.csv")
"""

import csv
import json
import os
from datetime import datetime, timezone

from base_datos.tablas import (
    TablaEscaneo, TablaTarea, TablaActivo, TablaServicio,
    TablaTecnologia, TablaEndpoint, TablaHallazgo, TablaEvidencia,
    TablaCorrelacion, TablaVinculo,
)


# ──────────────────────────────────────────
# Generador HTML
# ──────────────────────────────────────────

def generar_reporte_html(bd, escaneo_id, ruta_salida=None):
    """
    Genera un reporte HTML completo del escaneo.

    Incluye: resumen ejecutivo, cronología de ejecución, hallazgos por
    severidad, detalle por host (servicios, tecnologías, endpoints),
    correlaciones y evidencias.

    Retorna la ruta del archivo generado.
    """
    datos = _recopilar_datos(bd, escaneo_id)
    if not datos:
        raise ValueError("Escaneo no encontrado: " + escaneo_id)

    html = _construir_html(datos)

    if ruta_salida is None:
        os.makedirs("reportes/salida", exist_ok=True)
        ruta_salida = os.path.join("reportes", "salida",
            "reporte_" + escaneo_id[:8] + ".html")

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(html)

    return ruta_salida


def generar_reporte_csv(bd, escaneo_id, ruta_salida=None):
    """
    Genera un CSV con todos los hallazgos del escaneo.

    Columnas: IP, Herramienta, Severidad, Título, CVSS, CVE, URL, Descripción, Remediación
    """
    datos = _recopilar_datos(bd, escaneo_id)
    if not datos:
        raise ValueError("Escaneo no encontrado: " + escaneo_id)

    if ruta_salida is None:
        os.makedirs("reportes/salida", exist_ok=True)
        ruta_salida = os.path.join("reportes", "salida",
            "hallazgos_" + escaneo_id[:8] + ".csv")

    with open(ruta_salida, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Herramienta", "Severidad", "Título",
                         "CVSS", "CVE", "Plantilla", "URL",
                         "Descripción", "Remediación", "Encontrado en"])
        for host in datos["hosts"]:
            for h in host["hallazgos"]:
                writer.writerow([
                    host["ip"],
                    h.get("herramienta", ""),
                    h.get("severidad", "").upper(),
                    h.get("titulo", ""),
                    h.get("cvss", ""),
                    h.get("cve", ""),
                    h.get("id_plantilla", ""),
                    h.get("url", ""),
                    h.get("descripcion", ""),
                    h.get("remediacion", ""),
                    h.get("encontrado_en", ""),
                ])

    return ruta_salida


# ──────────────────────────────────────────
# Recopilar datos de la BD
# ──────────────────────────────────────────

def _hhmmss(dt):
    """Devuelve HH:MM:SS de un datetime, o '' si no hay."""
    return str(dt)[11:19] if dt else ""


def _duracion_seg(ini, fin):
    """Segundos entre dos datetimes, o None si falta alguno."""
    if not ini or not fin:
        return None
    return int((fin - ini).total_seconds())


def _recopilar_datos(bd, escaneo_id):
    """Obtiene todos los datos del escaneo para el reporte."""
    sesion = bd.nueva_sesion()

    escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
    if not escaneo:
        sesion.close()
        return None

    tareas = sesion.query(TablaTarea).filter_by(escaneo_id=escaneo_id).all()
    activos = sesion.query(TablaActivo).filter_by(escaneo_id=escaneo_id).all()

    # Conteos por severidad
    por_severidad = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = sesion.query(TablaHallazgo).filter_by(
            escaneo_id=escaneo_id, severidad=sev).count()
        if c > 0:
            por_severidad[sev] = c

    # Datos por host
    hosts_datos = []
    for activo in activos:
        servicios = sesion.query(TablaServicio).filter_by(activo_id=activo.id).all()
        tecnologias = sesion.query(TablaTecnologia).filter_by(activo_id=activo.id).all()
        endpoints = sesion.query(TablaEndpoint).filter_by(activo_id=activo.id).all()
        hallazgos_db = sesion.query(TablaHallazgo).filter_by(activo_id=activo.id).order_by(
            TablaHallazgo.severidad).all()

        hallazgos = []
        for h in hallazgos_db:
            evidencias = sesion.query(TablaEvidencia).filter_by(hallazgo_id=h.id).all()
            encontrado_en = evidencias[0].encontrado_en if evidencias else ""
            hallazgos.append({
                "id": h.id, "titulo": h.titulo, "severidad": h.severidad,
                "descripcion": h.descripcion or "",
                "id_plantilla": h.id_plantilla or "",
                "url": h.url or "", "herramienta": h.herramienta or "",
                "hash_dedup": h.hash_dedup or "",
                "cvss": "", "cve": "",
                "remediacion": "",
                "encontrado_en": encontrado_en or h.url or "",
                "referencias": json.loads(h.referencias) if h.referencias else [],
                "etiquetas": json.loads(h.etiquetas) if h.etiquetas else [],
                "evidencias": [{"encontrado_en": e.encontrado_en,
                                "comando_curl": e.comando_curl} for e in evidencias],
            })

        # Correlaciones de este activo
        correlaciones_db = sesion.query(TablaCorrelacion).filter_by(
            activo_id=activo.id).all()
        correlaciones = []
        for c in correlaciones_db:
            vinculos = sesion.query(TablaVinculo).filter_by(
                correlacion_id=c.id).all()
            correlaciones.append({
                "hallazgo": c.hallazgo_titulo,
                "severidad": c.hallazgo_severidad,
                "confianza": c.confianza,
                "razon": c.razon,
                "vinculos": [{"tipo": v.tipo, "descripcion": v.descripcion}
                             for v in vinculos],
            })

        hosts_datos.append({
            "ip": activo.ip,
            "hostname": activo.hostname or "",
            "estado": activo.estado,
            "mac": activo.mac or "",
            "mac_fabricante": activo.mac_fabricante or "",
            "so_nombre": activo.so_nombre or "",
            "so_familia": activo.so_familia or "",
            "so_precision": activo.so_precision or 0,
            "servicios": [{"puerto": s.puerto, "protocolo": s.protocolo,
                           "estado": s.estado, "nombre": s.nombre_servicio or "",
                           "producto": s.producto or "",
                           "version": s.version or ""}
                          for s in servicios],
            "tecnologias": [{"nombre": t.nombre, "version": t.version or "",
                             "categoria": t.categoria or ""}
                            for t in tecnologias],
            "endpoints": sorted([{"ruta": e.ruta or "", "url": e.url or "",
                        "codigo": e.codigo_estado,
                        "redirige": e.redirige_a or ""}
                       for e in endpoints],
                      key=lambda x: x["codigo"] or 0),
            "hallazgos": hallazgos,
            "correlaciones": correlaciones,
        })

    # ── Cronología de ejecución ──
    # TablaTarea guarda para cada paso el estado, hora de inicio/fin y (a nivel
    # de herramienta) el comando. Antes se descartaba; ahora lo mostramos.
    pasos = []
    comandos = []
    comandos_vistos = set()
    for t in tareas:
        if t.iniciado_en:  # solo pasos con marca de tiempo real
            pasos.append({
                "paso": t.nombre_herramienta,
                "estado": t.estado,
                "inicio": _hhmmss(t.iniciado_en),
                "fin": _hhmmss(t.terminado_en),
                "duracion": _duracion_seg(t.iniciado_en, t.terminado_en),
                "razon": t.razon or "",
                "_orden": t.iniciado_en,
            })
        if t.comando and t.comando not in comandos_vistos:
            comandos_vistos.add(t.comando)
            comandos.append({"herramienta": t.nombre_herramienta.split("_")[0],
                             "comando": t.comando})
    pasos.sort(key=lambda p: p["_orden"])
    for p in pasos:
        p.pop("_orden", None)

    sesion.close()

    # Archivos de evidencia cruda que dejó el escaneo (incluye orquestacion.log)
    evidencias_dir = os.path.join("evidencias", escaneo_id)
    evidencias = []
    if os.path.isdir(evidencias_dir):
        for nombre in sorted(os.listdir(evidencias_dir)):
            ruta = os.path.join(evidencias_dir, nombre)
            if os.path.isfile(ruta):
                evidencias.append({"archivo": nombre, "tamano": os.path.getsize(ruta)})

    # Calcular duración total
    duracion = ""
    if escaneo.creado_en and escaneo.completado_en:
        delta = escaneo.completado_en - escaneo.creado_en
        minutos = int(delta.total_seconds() // 60)
        segundos = int(delta.total_seconds() % 60)
        duracion = str(minutos) + "m " + str(segundos) + "s"

    return {
        "id": escaneo.id,
        "objetivo": escaneo.objetivo,
        "perfil": escaneo.perfil or "",
        "estado": escaneo.estado,
        "creado_en": str(escaneo.creado_en)[:19] if escaneo.creado_en else "",
        "completado_en": str(escaneo.completado_en)[:19] if escaneo.completado_en else "",
        "duracion": duracion,
        "pasos": pasos,
        "comandos": comandos,
        "evidencias": evidencias,
        "total_activos": len(activos),
        "total_hallazgos": sum(len(h["hallazgos"]) for h in hosts_datos),
        "por_severidad": por_severidad,
        "hosts": hosts_datos,
        "generado_en": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ──────────────────────────────────────────
# Construcción del HTML
# ──────────────────────────────────────────

# Paleta de severidad — tonos apagados, de documento (no colores saturados).
COLORES_SEV = {
    "critical": "#9d2933",
    "high":     "#a85a1e",
    "medium":   "#8a6d12",
    "low":      "#4a6d2f",
    "info":     "#5b6570",
}

NOMBRE_SEV = {
    "critical": "Crítica", "high": "Alta", "medium": "Media",
    "low": "Baja", "info": "Informativa",
}


def _construir_html(d):
    """Construye el HTML completo del reporte."""

    # Score de riesgo simple → nivel legible
    score = (
        d["por_severidad"].get("critical", 0) * 10 +
        d["por_severidad"].get("high", 0) * 7 +
        d["por_severidad"].get("medium", 0) * 4 +
        d["por_severidad"].get("low", 0) * 1
    )
    if score >= 30:
        nivel_riesgo, color_riesgo = "Crítico", "#9d2933"
    elif score >= 15:
        nivel_riesgo, color_riesgo = "Alto", "#a85a1e"
    elif score >= 5:
        nivel_riesgo, color_riesgo = "Medio", "#8a6d12"
    else:
        nivel_riesgo, color_riesgo = "Bajo", "#4a6d2f"

    seccion_resumen = _html_encabezado(d, nivel_riesgo, color_riesgo)
    seccion_estadisticas = _html_resumen_ejecutivo(d)
    seccion_cronologia = _html_cronologia(d)
    seccion_hosts = "".join(_html_host(h, i + 1) for i, h in enumerate(d["hosts"]))
    seccion_evidencia = _html_evidencia(d)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe de evaluación — {d['objetivo']}</title>
  <style>
    :root {{
      --paper:#ffffff; --ground:#f4f3ef; --ink:#1c1e21; --muted:#585c61;
      --faint:#8a8e93; --line:#e4e2dc; --line-strong:#cbc8c0;
      --accent:#294f5c; --accent-soft:#e8eff0;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--ground); color: var(--ink);
      font-size: 15px; line-height: 1.62; -webkit-font-smoothing: antialiased;
    }}
    .page {{ max-width: 840px; margin: 0 auto; padding: 40px 30px 80px; }}
    .sheet {{ background: var(--paper); border: 1px solid var(--line);
              padding: 48px 52px 40px; }}

    h1, h2, h3 {{ font-family: Georgia, "Iowan Old Style", "Palatino Linotype",
                  "Times New Roman", serif; font-weight: 600; line-height: 1.2; }}
    code, .mono {{ font-family: "SFMono-Regular", ui-monospace, "Cascadia Mono",
                   Consolas, "Liberation Mono", monospace; }}
    a {{ color: var(--accent); }}

    /* Encabezado */
    .doc-head {{ border-bottom: 2px solid var(--ink); padding-bottom: 22px; margin-bottom: 4px; }}
    .doc-kicker {{ font-size: 12px; letter-spacing: .18em; text-transform: uppercase;
                   color: var(--accent); font-weight: 600; margin-bottom: 10px; }}
    .doc-head h1 {{ font-size: 30px; letter-spacing: -.01em; }}
    .doc-head .target {{ font-family: "SFMono-Regular", ui-monospace, Consolas, monospace;
                         font-size: 16px; color: var(--muted); margin-top: 6px; }}

    /* Ficha de metadatos */
    .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr);
                  border: 1px solid var(--line); margin: 26px 0 6px; }}
    .meta-grid .cell {{ padding: 11px 16px; border-bottom: 1px solid var(--line); }}
    .meta-grid .cell:nth-child(odd) {{ border-right: 1px solid var(--line); }}
    .meta-grid .cell:nth-last-child(-n+2) {{ border-bottom: none; }}
    .meta-grid .k {{ font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
                     color: var(--faint); margin-bottom: 2px; }}
    .meta-grid .v {{ font-size: 14px; font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; }}
    .riesgo-linea {{ display: flex; align-items: center; gap: 10px; margin-top: 20px;
                     font-size: 14px; }}
    .riesgo-sq {{ width: 13px; height: 13px; display: inline-block; }}
    .riesgo-linea strong {{ font-weight: 600; }}

    /* Secciones numeradas */
    section {{ margin-top: 44px; }}
    section > h2 {{ font-size: 20px; padding-bottom: 8px; border-bottom: 1px solid var(--line-strong);
                    margin-bottom: 18px; display: flex; align-items: baseline; gap: 12px; }}
    section > h2 .n {{ font-family: "SFMono-Regular", ui-monospace, Consolas, monospace;
                       font-size: 14px; color: var(--accent); font-weight: 700; }}
    h3 {{ font-size: 15.5px; margin: 22px 0 9px; color: var(--ink); }}

    /* Tira de conteos */
    .conteos {{ display: flex; flex-wrap: wrap; border: 1px solid var(--line); }}
    .conteos .c {{ flex: 1; min-width: 110px; padding: 16px 18px;
                   border-right: 1px solid var(--line); }}
    .conteos .c:last-child {{ border-right: none; }}
    .conteos .num {{ font-family: Georgia, serif; font-size: 27px; font-weight: 600;
                     font-variant-numeric: tabular-nums; }}
    .conteos .lab {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}

    /* Etiquetas de severidad */
    .sev-row {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
    .sev-tag {{ display: inline-flex; align-items: center; gap: 7px; font-size: 13px;
                padding: 5px 12px 5px 10px; border: 1px solid var(--line-strong);
                background: var(--paper); }}
    .sev-tag .dot {{ width: 9px; height: 9px; display: inline-block; }}
    .sev-tag b {{ font-weight: 600; }}
    .sev-inline {{ font-size: 11.5px; font-weight: 600; letter-spacing: .04em;
                   text-transform: uppercase; padding: 1px 7px; border: 1px solid currentColor; }}

    /* Tablas */
    table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; margin-top: 4px; }}
    th {{ text-align: left; padding: 9px 12px; font-size: 11.5px; letter-spacing: .05em;
          text-transform: uppercase; color: var(--muted); font-weight: 600;
          border-bottom: 1.5px solid var(--line-strong); }}
    td {{ padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    tbody tr:last-child td {{ border-bottom: none; }}
    td.mono, th.mono {{ font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; font-size: 12.5px; }}
    .tnum {{ font-variant-numeric: tabular-nums; white-space: nowrap; }}
    .estado-ok {{ color: #4a6d2f; }} .estado-skip {{ color: var(--faint); }}
    .estado-fail {{ color: #9d2933; }}
    .motivo {{ font-size: 12.5px; color: var(--muted); }}

    /* Lista de comandos */
    .cmd-list {{ margin-top: 14px; border: 1px solid var(--line); }}
    .cmd-list .cmd {{ padding: 10px 14px; border-bottom: 1px solid var(--line);
                      display: flex; gap: 14px; align-items: baseline; }}
    .cmd-list .cmd:last-child {{ border-bottom: none; }}
    .cmd-list .who {{ font-size: 11px; letter-spacing: .05em; text-transform: uppercase;
                      color: var(--accent); font-weight: 600; min-width: 74px; }}
    .cmd-list code {{ font-size: 12.5px; color: var(--ink); word-break: break-all; }}

    /* Host */
    .host {{ border: 1px solid var(--line-strong); margin-bottom: 22px; }}
    .host-head {{ padding: 14px 18px; border-bottom: 1px solid var(--line);
                  background: var(--accent-soft); }}
    .host-head .ip {{ font-family: "SFMono-Regular", ui-monospace, Consolas, monospace;
                      font-size: 17px; font-weight: 600; }}
    .host-head .os {{ font-size: 13px; color: var(--muted); margin-top: 1px; }}
    .host-body {{ padding: 8px 18px 18px; }}

    /* Hallazgo */
    .hallazgo {{ border: 1px solid var(--line); border-left: 3px solid var(--faint);
                 padding: 12px 15px; margin-bottom: 10px; }}
    .hallazgo .htit {{ font-weight: 600; font-size: 14px; }}
    .hallazgo .hmeta {{ font-size: 12px; color: var(--muted); margin-top: 3px;
                        font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; }}
    .hallazgo .hdesc {{ font-size: 13px; color: var(--muted); margin-top: 6px; }}
    .hallazgo .hloc {{ font-size: 12px; color: var(--faint); margin-top: 5px;
                       font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; }}
    .evidencia {{ background: #f7f6f3; border: 1px solid var(--line); padding: 9px 11px;
                  font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; font-size: 11.5px;
                  margin-top: 8px; white-space: pre-wrap; word-break: break-all;
                  max-height: 160px; overflow-y: auto; }}
    .hrem {{ font-size: 12.5px; color: #3a5f4a; border-left: 3px solid #4a6d2f;
             padding: 5px 10px; margin-top: 7px; background: #f3f7f2; }}

    /* Tecnologías / tags */
    .tag {{ display: inline-block; border: 1px solid var(--line-strong); color: var(--muted);
            padding: 2px 9px; font-size: 12px; margin: 2px 3px 2px 0; }}
    .tag em {{ color: var(--faint); font-style: normal; }}
    .cod {{ font-family: "SFMono-Regular", ui-monospace, Consolas, monospace; font-weight: 600; }}
    .cod-2 {{ color: #4a6d2f; }} .cod-3 {{ color: #8a6d12; }} .cod-4, .cod-5 {{ color: #9d2933; }}

    /* Correlación */
    .corr {{ border: 1px solid var(--line); border-left: 3px solid var(--accent);
             padding: 10px 14px; margin-bottom: 8px; }}
    .corr .ct {{ display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }}
    .corr .conf {{ font-size: 11px; font-weight: 600; letter-spacing: .04em;
                   text-transform: uppercase; padding: 1px 8px; border: 1px solid var(--line-strong);
                   color: var(--muted); }}
    .corr .razon {{ font-size: 12px; color: var(--muted); margin: 5px 0; }}
    .vinc {{ font-size: 12.5px; color: var(--muted); }}
    .vinc::before {{ content: "→"; color: var(--accent); font-weight: 700; margin-right: 6px; }}

    .empty {{ font-size: 13px; color: var(--faint); font-style: italic; padding: 4px 0; }}

    .foot {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
             font-size: 12px; color: var(--faint); display: flex; justify-content: space-between;
             flex-wrap: wrap; gap: 8px; }}

    @media print {{
      body {{ background: white; }}
      .page {{ padding: 0; }}
      .sheet {{ border: none; padding: 0; }}
      .evidencia {{ max-height: none; }}
      section {{ page-break-inside: avoid; }}
    }}
    @media (max-width: 620px) {{
      .sheet {{ padding: 28px 20px; }}
      .meta-grid {{ grid-template-columns: 1fr; }}
      .meta-grid .cell:nth-child(odd) {{ border-right: none; }}
    }}
  </style>
</head>
<body>
<div class="page">
  <div class="sheet">

    {seccion_resumen}
    {seccion_estadisticas}
    {seccion_cronologia}

    <section>
      <h2><span class="n">03</span> Detalle por host</h2>
      {seccion_hosts}
    </section>

    {seccion_evidencia}

    <div class="foot">
      <span>ARES · Sistema automatizado de evaluación de seguridad</span>
      <span>Generado {d['generado_en']}</span>
    </div>

  </div>
</div>
</body>
</html>"""


def _html_encabezado(d, nivel_riesgo, color_riesgo):
    return f"""
    <div class="doc-head">
      <div class="doc-kicker">Informe de evaluación de seguridad</div>
      <h1>Resultados del reconocimiento</h1>
      <div class="target">{d['objetivo']}</div>
    </div>
    <div class="meta-grid">
      <div class="cell"><div class="k">Objetivo</div><div class="v">{d['objetivo']}</div></div>
      <div class="cell"><div class="k">Perfil</div><div class="v">{d['perfil'] or '—'}</div></div>
      <div class="cell"><div class="k">Inicio</div><div class="v">{d['creado_en'] or '—'}</div></div>
      <div class="cell"><div class="k">Fin</div><div class="v">{d['completado_en'] or '—'}</div></div>
      <div class="cell"><div class="k">Duración</div><div class="v">{d['duracion'] or '—'}</div></div>
      <div class="cell"><div class="k">Estado</div><div class="v">{d['estado']}</div></div>
    </div>
    <div class="riesgo-linea">
      <span class="riesgo-sq" style="background:{color_riesgo}"></span>
      Nivel de riesgo agregado: <strong>{nivel_riesgo}</strong>
    </div>
    <div style="font-size:11px;color:var(--faint);margin-top:14px;font-family:monospace">ID {d['id']}</div>"""


def _html_resumen_ejecutivo(d):
    conteos = [
        ("Hosts", d["total_activos"]),
        ("Servicios", sum(len(h["servicios"]) for h in d["hosts"])),
        ("Tecnologías", sum(len(h["tecnologias"]) for h in d["hosts"])),
        ("Endpoints", sum(len(h["endpoints"]) for h in d["hosts"])),
        ("Hallazgos", d["total_hallazgos"]),
    ]
    celdas = "".join(
        f'<div class="c"><div class="num">{v}</div><div class="lab">{k}</div></div>'
        for k, v in conteos
    )

    sev_html = ""
    if d["por_severidad"]:
        tags = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = d["por_severidad"].get(sev, 0)
            if c > 0:
                color = COLORES_SEV.get(sev, "#5b6570")
                tags += (f'<span class="sev-tag"><span class="dot" style="background:{color}"></span>'
                         f'<b>{NOMBRE_SEV.get(sev, sev.title())}</b> · {c}</span>')
        sev_html = f'<h3>Hallazgos por severidad</h3><div class="sev-row">{tags}</div>'
    else:
        sev_html = '<p class="empty">No se registraron hallazgos con severidad asignada.</p>'

    return f"""
    <section>
      <h2><span class="n">01</span> Resumen ejecutivo</h2>
      <div class="conteos">{celdas}</div>
      {sev_html}
    </section>"""


def _html_cronologia(d):
    """Cronología de ejecución: qué corrió, cuándo, por qué y con qué comando."""
    filas = ""
    for p in d["pasos"]:
        estado = p["estado"]
        clase = ("estado-ok" if estado == "completed" else
                 "estado-fail" if estado == "failed" else "estado-skip")
        dur = (str(p["duracion"]) + " s") if p["duracion"] is not None else "—"
        filas += f"""<tr>
          <td class="mono">{p['paso']}</td>
          <td class="tnum">{p['inicio'] or '—'}</td>
          <td class="tnum">{p['fin'] or '—'}</td>
          <td class="tnum">{dur}</td>
          <td class="{clase}">{estado}</td>
          <td class="motivo">{p.get('razon') or '—'}</td>
        </tr>"""

    tabla = f"""
      <table>
        <thead><tr><th>Paso</th><th>Inicio</th><th>Fin</th><th>Duración</th><th>Estado</th><th>Motivo</th></tr></thead>
        <tbody>{filas}</tbody>
      </table>""" if filas else '<p class="empty">Sin pasos con marca de tiempo registrada.</p>'

    cmds = ""
    if d["comandos"]:
        items = "".join(
            f'<div class="cmd"><span class="who">{c["herramienta"]}</span>'
            f'<code>{c["comando"]}</code></div>'
            for c in d["comandos"]
        )
        cmds = f'<h3>Comandos ejecutados</h3><div class="cmd-list">{items}</div>'

    return f"""
    <section>
      <h2><span class="n">02</span> Cronología de ejecución</h2>
      {tabla}
      {cmds}
    </section>"""


def _html_evidencia(d):
    """Lista los archivos de salida cruda (incluye el log de orquestación)."""
    evs = d.get("evidencias", [])
    if not evs:
        cuerpo = '<p class="empty">No se conservaron archivos de evidencia.</p>'
    else:
        filas = "".join(
            f'<tr><td class="mono">{e["archivo"]}</td>'
            f'<td class="tnum">{e["tamano"]/1024:.1f} KB</td></tr>'
            for e in evs
        )
        cuerpo = f"""
      <p style="font-size:13.5px;color:var(--muted)">Salida cruda de cada herramienta,
      conservada para auditoría y re-análisis. El archivo
      <span class="mono">orquestacion.log</span> registra el flujo completo del escaneo.</p>
      <table>
        <thead><tr><th>Archivo</th><th>Tamaño</th></tr></thead>
        <tbody>{filas}</tbody>
      </table>"""
    return f"""
    <section>
      <h2><span class="n">04</span> Evidencia recopilada</h2>
      {cuerpo}
    </section>"""


def _html_host(h, indice):
    so_info = h["so_nombre"]
    if h["so_precision"]:
        so_info += f" ({h['so_precision']}% precisión)"

    # Servicios
    servicios_html = ""
    if h["servicios"]:
        filas = ""
        for s in h["servicios"]:
            producto_version = (s["producto"] + " " + s["version"]).strip() or "—"
            clase_estado = "estado-ok" if s["estado"] == "open" else "estado-skip"
            filas += f"""<tr>
              <td class="mono">{s['puerto']}/{s['protocolo']}</td>
              <td class="{clase_estado}">{s['estado']}</td>
              <td>{s['nombre'] or '—'}</td>
              <td>{producto_version}</td>
            </tr>"""
        servicios_html = f"""
        <h3>Servicios ({len(h['servicios'])})</h3>
        <table>
          <thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Producto / Versión</th></tr></thead>
          <tbody>{filas}</tbody>
        </table>"""

    # Tecnologías
    techs_html = ""
    if h["tecnologias"]:
        tags = "".join(
            f'<span class="tag">{t["nombre"]} {t["version"]}'
            + (f' <em>({t["categoria"]})</em>' if t["categoria"] else "")
            + "</span>"
            for t in h["tecnologias"]
        )
        techs_html = f"<h3>Tecnologías ({len(h['tecnologias'])})</h3><div>{tags}</div>"

    # Endpoints
    endpoints_html = ""
    if h["endpoints"]:
        filas = ""
        for e in h["endpoints"][:50]:
            codigo = e["codigo"] or ""
            clase = f"cod cod-{str(codigo)[0]}" if str(codigo)[:1].isdigit() else "cod"
            redir = f' <span style="color:var(--faint)">→ {e["redirige"]}</span>' if e["redirige"] else ""
            filas += f"""<tr>
              <td class="{clase}">{codigo or '—'}</td>
              <td class="mono">{e['ruta']}{redir}</td>
            </tr>"""
        extra = (f"<p style='color:var(--faint);font-size:12px;margin-top:6px'>… y "
                 f"{len(h['endpoints'])-50} más</p>") if len(h["endpoints"]) > 50 else ""
        endpoints_html = f"""
        <h3>Endpoints descubiertos ({len(h['endpoints'])})</h3>
        <table>
          <thead><tr><th>Código</th><th>Ruta</th></tr></thead>
          <tbody>{filas}</tbody>
        </table>{extra}"""
    else:
        endpoints_html = '<h3>Endpoints descubiertos</h3><p class="empty">No se descubrieron endpoints (la web respondió solo con redirecciones o no hubo servicio web navegable por IP).</p>'

    # Hallazgos
    hallazgos_html = ""
    if h["hallazgos"]:
        items = ""
        for hall in h["hallazgos"]:
            sev = hall["severidad"]
            color = COLORES_SEV.get(sev, "#5b6570")
            tags_html = "".join(f'<span class="tag">{t}</span>' for t in hall["etiquetas"][:5])

            cves_html = ""
            for ref in hall["referencias"]:
                if "nvd.nist.gov" in ref:
                    cve_id = ref.split("/")[-1]
                    cves_html += f'<a href="{ref}" target="_blank">{cve_id}</a> '

            evidencia_html = ""
            for ev in hall["evidencias"]:
                if ev.get("comando_curl"):
                    evidencia_html += f'<div class="evidencia">{ev["comando_curl"]}</div>'
                    break

            remediacion_html = ""
            if hall.get("remediacion"):
                remediacion_html = f'<div class="hrem">Remediación: {hall["remediacion"]}</div>'

            meta = f'<span class="sev-inline" style="color:{color}">{NOMBRE_SEV.get(sev, sev.upper())}</span>'
            if hall.get("cvss"):
                meta += f' &nbsp; CVSS {hall["cvss"]}'
            if cves_html:
                meta += f' &nbsp; {cves_html}'
            if hall.get("id_plantilla"):
                meta += f' &nbsp; {hall["id_plantilla"]}'

            items += f"""
            <div class="hallazgo" style="border-left-color:{color}">
              <div class="htit">{hall['titulo']}</div>
              <div class="hmeta">{meta}</div>
              {f'<div class="hdesc">{hall["descripcion"]}</div>' if hall.get("descripcion") else ""}
              {f'<div class="hloc">{hall["encontrado_en"]}</div>' if hall.get("encontrado_en") else ""}
              {f'<div style="margin-top:6px">{tags_html}</div>' if tags_html else ""}
              {evidencia_html}
              {remediacion_html}
            </div>"""
        hallazgos_html = f"<h3>Hallazgos ({len(h['hallazgos'])})</h3>{items}"

    # Correlaciones
    corr_html = ""
    if h["correlaciones"]:
        items = ""
        for c in h["correlaciones"]:
            if not c["vinculos"]:
                continue
            sev = c["severidad"]
            color = COLORES_SEV.get(sev, "#5b6570")
            vinculos = "".join(f'<div class="vinc">{v["descripcion"]}</div>' for v in c["vinculos"])
            items += f"""
            <div class="corr">
              <div class="ct">
                <span class="sev-inline" style="color:{color}">{NOMBRE_SEV.get(sev, sev.upper())}</span>
                <strong>{c['hallazgo']}</strong>
                <span class="conf">confianza {c['confianza']}</span>
              </div>
              <div class="razon">{c['razon']}</div>
              {vinculos}
            </div>"""
        if items:
            corr_html = f"<h3>Correlaciones</h3>{items}"

    return f"""
    <div class="host">
      <div class="host-head">
        <div class="ip">{h['ip']}</div>
        {f'<div class="os">{so_info}</div>' if so_info else ""}
        {f'<div class="os">{h["hostname"]}</div>' if h["hostname"] else ""}
      </div>
      <div class="host-body">
        {servicios_html}
        {techs_html}
        {endpoints_html}
        {hallazgos_html}
        {corr_html}
      </div>
    </div>"""
