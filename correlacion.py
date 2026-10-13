def correlacionar(resultados):
    hosts_por_ip = {}
    for resultado in resultados:
        herramienta = resultado.metadatos.herramienta
        for host in resultado.hosts:
            ip = host.ip
            if ip not in hosts_por_ip:
                hosts_por_ip[ip] = {"ip":ip,"hostnames":[],"servicios":[],"tecnologias":[],
                    "endpoints":[],"hallazgos":[],"herramientas":[],"sistema_operativo":None}
            d = hosts_por_ip[ip]
            for hn in host.hostnames:
                if hn not in d["hostnames"]: d["hostnames"].append(hn)
            d["servicios"].extend(host.servicios)
            d["tecnologias"].extend(host.tecnologias)
            d["endpoints"].extend(host.endpoints)
            d["hallazgos"].extend(host.hallazgos)
            if host.sistema_operativo: d["sistema_operativo"] = host.sistema_operativo
            if herramienta not in d["herramientas"]: d["herramientas"].append(herramienta)
    hosts_correlacionados = [_correlacionar_host(ip, datos) for ip, datos in hosts_por_ip.items()]
    return {"hosts": hosts_correlacionados, "estadisticas": _calcular_estadisticas(hosts_correlacionados)}

def _correlacionar_host(ip, datos):
    correlaciones = []
    vistos = set()
    for hallazgo in datos["hallazgos"]:
        # Un mismo hallazgo puede llegar por dos corridas distintas (p. ej.
        # nuclei con tags "ssh" y "openssh" reporta ambos "openssh-detect").
        # Los hallazgos en BD se deduplican por hash, así que deduplicamos
        # aquí también para no generar correlaciones repetidas.
        clave = (hallazgo.id_plantilla, hallazgo.puerto, hallazgo.url)
        if clave in vistos:
            continue
        vistos.add(clave)
        vinculos = []
        razones = []
        v = _regla_servicio(hallazgo, datos["servicios"])
        if v: vinculos.append(v); razones.append(v["razon"])
        v = _regla_tecnologia(hallazgo, datos["tecnologias"])
        if v: vinculos.append(v); razones.append(v["razon"])
        v = _regla_endpoint(hallazgo, datos["endpoints"])
        if v: vinculos.append(v); razones.append(v["razon"])
        confianza = _calcular_confianza(hallazgo, vinculos)
        correlaciones.append({
            "hallazgo": hallazgo.titulo, "severidad": hallazgo.severidad,
            "id_plantilla": hallazgo.id_plantilla, "cvss_score": hallazgo.cvss_score,
            "confianza": confianza, "vinculos": vinculos,
            "razon": " | ".join(razones) if razones else "Hallazgo sin contexto adicional",
            "remediacion": hallazgo.remediacion,
        })
    software_cruzado = _regla_software_cruzado(datos["servicios"], datos["tecnologias"])
    so = datos["sistema_operativo"].nombre if datos["sistema_operativo"] else None
    return {"ip":ip,"hostnames":datos["hostnames"],"herramientas":datos["herramientas"],
            "sistema_operativo":so,"total_servicios":len(datos["servicios"]),
            "total_tecnologias":len(datos["tecnologias"]),"total_endpoints":len(datos["endpoints"]),
            "total_hallazgos":len(datos["hallazgos"]),"correlaciones":correlaciones,
            "software_multi_herramienta":software_cruzado}

def _regla_servicio(hallazgo, servicios):
    if not hallazgo.puerto: return None
    for s in servicios:
        if s.puerto == hallazgo.puerto:
            prod = s.producto or s.nombre_servicio or "servicio"
            ver = s.version or ""
            desc = (prod + " " + ver).strip()
            return {"tipo":"servicio",
                "descripcion": f"Puerto {s.puerto}/{s.protocolo} → {desc}",
                "razon": f"Hallazgo en :{hallazgo.puerto} corresponde a {desc}"}
    return None

def _regla_tecnologia(hallazgo, tecnologias):
    texto = ((hallazgo.titulo or "") + " " + (hallazgo.id_plantilla or "") + " " + " ".join(hallazgo.etiquetas)).lower()
    for t in tecnologias:
        if t.nombre.lower() in texto:
            ver = t.version or "versión desconocida"
            return {"tipo":"tecnologia",
                "descripcion": f"{t.nombre} {t.version or ''}",
                "razon": f"Hallazgo relacionado con {t.nombre} {ver}"}
    return None

def _regla_endpoint(hallazgo, endpoints):
    if not hallazgo.url: return None
    url_h = hallazgo.url.lower()
    for e in endpoints:
        if not e.ruta or len(e.ruta) < 2 or e.ruta == "/": continue
        if e.ruta.lower() in url_h:
            return {"tipo":"endpoint",
                "descripcion": f"Ruta {e.ruta} (HTTP {e.codigo_estado})",
                "razon": f"Hallazgo en {e.ruta} confirmado por Gobuster"}
    return None

def _regla_software_cruzado(servicios, tecnologias):
    resultados = []; ya = []
    for s in servicios:
        if not s.producto: continue
        prod = s.producto.lower()
        for t in tecnologias:
            n = t.nombre.lower()
            if (n in prod or prod in n) and t.nombre not in ya:
                ya.append(t.nombre)
                resultados.append({"software":t.nombre,"detectado_por":["nmap","whatweb"],
                    "detalle_nmap":f"{s.producto} {s.version or ''}",
                    "detalle_whatweb":f"{t.nombre} {t.version or ''}",
                    "confianza":"alta","razon":"Confirmado por Nmap y WhatWeb"})
    return resultados

def _calcular_confianza(hallazgo, vinculos):
    tiene_svc = any(v["tipo"] == "servicio" for v in vinculos)
    if tiene_svc and len(vinculos) >= 2: return "alta"
    if len(vinculos) >= 1: return "media"
    if hallazgo.cvss_score: return "media"
    return "baja"

def _calcular_estadisticas(hosts):
    total = len(hosts); total_c = 0; con_ctx = 0; sin_ctx = 0; sw = 0
    a = m = b = 0
    for host in hosts:
        for c in host["correlaciones"]:
            total_c += 1
            if c["vinculos"]: con_ctx += 1
            else: sin_ctx += 1
            if c["confianza"] == "alta": a += 1
            elif c["confianza"] == "media": m += 1
            else: b += 1
        sw += len(host["software_multi_herramienta"])
    return {"total_hosts":total,"total_correlaciones":total_c,
            "hallazgos_con_contexto":con_ctx,"hallazgos_sin_contexto":sin_ctx,
            "software_confirmado_multi_herramienta":sw,
            "confianza_alta":a,"confianza_media":m,"confianza_baja":b}
