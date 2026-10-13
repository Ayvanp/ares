"""
Parser de Nuclei con deduplicación integrada.
Salta líneas corruptas y deduplica por template+host+matched-at.
"""
import hashlib, json
from datetime import datetime, timezone
from urllib.parse import urlparse
from modelos import ResultadoCanonico, MetadatosEscaneo, Host, Hallazgo, Evidencia

MAPEO_SEVERIDAD = {"critical":"critical","high":"high","medium":"medium","low":"low","info":"info","unknown":"unknown"}

def parsear_nuclei(ruta_archivo):
    try:
        with open(ruta_archivo,"r",encoding="utf-8") as f:
            contenido = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró: " + str(ruta_archivo))
    lineas = [l.strip() for l in contenido.splitlines() if l.strip()]
    if not lineas: return _vacio()
    entradas = []
    for linea in lineas:
        try: entradas.append(json.loads(linea))
        except: continue
    if not entradas: raise ValueError("Ninguna línea es JSON válido")
    # Deduplicar dentro del mismo archivo
    entradas_unicas = []
    hashes_vistos = set()
    for e in entradas:
        clave = str(e.get("template-id","")) + "|" + e.get("host","") + "|" + e.get("matched-at","")
        if clave not in hashes_vistos:
            hashes_vistos.add(clave)
            entradas_unicas.append(e)
    entradas = entradas_unicas
    hosts_por_ip = {}
    for entrada in entradas:
        ip = _obtener_ip(entrada)
        if ip not in hosts_por_ip: hosts_por_ip[ip] = Host(ip=ip, estado="up")
        h = _crear_hallazgo(entrada)
        if h: hosts_por_ip[ip].hallazgos.append(h)
    objetivos = {e.get("host","") for e in entradas if e.get("host")}
    comando = "nuclei -target " + " ".join(sorted(objetivos)) if objetivos else "nuclei"
    fecha = datetime.now(tz=timezone.utc)
    if entradas:
        f = _parsear_fecha(entradas[0].get("timestamp"))
        if f: fecha = f
    metadatos = MetadatosEscaneo(herramienta="nuclei", comando=comando,
        fecha_inicio=fecha, tipo_escaneo="vulnerability_scan")
    return ResultadoCanonico(metadatos=metadatos, hosts=list(hosts_por_ip.values()))

def _vacio():
    return ResultadoCanonico(metadatos=MetadatosEscaneo(herramienta="nuclei",
        comando="nuclei", fecha_inicio=datetime.now(tz=timezone.utc),
        tipo_escaneo="vulnerability_scan"), hosts=[])

def _parsear_fecha(texto):
    if not texto: return None
    try: return datetime.fromisoformat(texto.replace("Z","+00:00"))
    except: return None

def _obtener_ip(entrada):
    ip = entrada.get("ip")
    if ip: return ip
    h = entrada.get("host","")
    if "://" in h:
        p = urlparse(h)
        return p.hostname or "0.0.0.0"
    if ":" in h:
        partes = h.rsplit(":",1)
        if partes[1].isdigit(): return partes[0]
    return h or "0.0.0.0"

def _obtener_puerto(entrada):
    p = entrada.get("port")
    if p:
        try: return int(p)
        except: pass
    h = entrada.get("host","")
    if ":" in h and "://" not in h:
        partes = h.rsplit(":",1)
        if partes[1].isdigit(): return int(partes[1])
    m = entrada.get("matched-at","")
    if "://" in m:
        from urllib.parse import urlparse
        p2 = urlparse(m)
        if p2.port: return p2.port
    return None

def _crear_hallazgo(entrada):
    info = entrada.get("info",{})
    id_plantilla = entrada.get("template-id")
    titulo = info.get("name")
    if not titulo: return None
    severidad = MAPEO_SEVERIDAD.get(info.get("severity","unknown").lower(),"unknown")
    tipo = entrada.get("type")
    refs = info.get("reference") or []
    if isinstance(refs, str): refs = [refs]
    clasificacion = info.get("classification",{})
    cve_ids = clasificacion.get("cve-id") or []
    if isinstance(cve_ids, str): cve_ids = [cve_ids]
    cwe_ids = clasificacion.get("cwe-id") or []
    if isinstance(cwe_ids, str): cwe_ids = [cwe_ids]
    cvss_score = clasificacion.get("cvss-score")
    cvss_vector = clasificacion.get("cvss-metrics")
    for cve in cve_ids:
        url_nvd = "https://nvd.nist.gov/vuln/detail/" + cve
        if url_nvd not in refs: refs.append(url_nvd)
    etiquetas = info.get("tags") or []
    if isinstance(etiquetas, str): etiquetas = [e.strip() for e in etiquetas.split(",")]
    ip_resuelta = entrada.get("ip")
    puerto = _obtener_puerto(entrada)
    interaccion = None
    di = entrada.get("interaction")
    if di:
        if isinstance(di, dict): interaccion = di.get("protocol","") + ": " + di.get("raw-request","")
        else: interaccion = str(di)
    evidencia = Evidencia(
        encontrado_en=entrada.get("matched-at"),
        resultados_extraidos=entrada.get("extracted-results") or [],
        comando_curl=entrada.get("curl-command"),
        peticion=entrada.get("request"),
        respuesta=entrada.get("response"),
        interaccion=interaccion,
    )
    fecha = _parsear_fecha(entrada.get("timestamp"))
    texto_dedup = str(id_plantilla) + "|" + entrada.get("host","") + "|" + entrada.get("matched-at","")
    hash_dedup = hashlib.sha256(texto_dedup.encode()).hexdigest()[:16]
    return Hallazgo(
        id_hallazgo="nuclei-" + str(id_plantilla) + "-" + hash_dedup[:8],
        titulo=titulo, severidad=severidad, descripcion=info.get("description"),
        id_plantilla=id_plantilla, nombre_matcher=entrada.get("matcher-name"),
        url=entrada.get("matched-at"), referencias=refs, etiquetas=etiquetas,
        evidencia=evidencia, primera_vez=fecha, ultima_vez=fecha,
        grupo_dedup=hash_dedup, tipo=tipo, puerto=puerto, ip_resuelta=ip_resuelta,
        cvss_score=cvss_score, cvss_vector=cvss_vector, cve_ids=cve_ids,
        cwe_ids=cwe_ids, remediacion=info.get("remediation"),
    )
