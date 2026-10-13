import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from modelos import ResultadoCanonico, MetadatosEscaneo, Host, Servicio, InfoSO, ResultadoScript

def parsear_nmap(ruta_archivo):
    try:
        arbol = ET.parse(ruta_archivo)
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró: " + str(ruta_archivo))
    except ET.ParseError:
        raise ValueError("XML inválido: " + str(ruta_archivo))
    raiz = arbol.getroot()
    if raiz.tag != "nmaprun":
        raise ValueError("No es XML de nmap: " + raiz.tag)
    metadatos = _extraer_metadatos(raiz)
    hosts = [_parsear_host(h) for h in raiz.findall("host")]
    return ResultadoCanonico(metadatos=metadatos, hosts=hosts)

def _extraer_metadatos(raiz):
    comando = raiz.get("args", "")
    version = raiz.get("version")
    fecha_inicio = None
    ts = raiz.get("start")
    if ts:
        fecha_inicio = datetime.fromtimestamp(int(ts), tz=timezone.utc)
    fecha_fin = None
    tag_fin = raiz.find(".//runstats/finished")
    if tag_fin is not None and tag_fin.get("time"):
        fecha_fin = datetime.fromtimestamp(int(tag_fin.get("time")), tz=timezone.utc)
    tipo = None
    si = raiz.find("scaninfo")
    if si is not None:
        tipo = si.get("type")
    objetivo = _extraer_objetivo(comando)
    return MetadatosEscaneo(herramienta="nmap", comando=comando,
        fecha_inicio=fecha_inicio, version_herramienta=version,
        fecha_fin=fecha_fin, tipo_escaneo=tipo, objetivo=objetivo)

def _parsear_host(eh):
    ip = _obtener_ip(eh)
    hostnames = _obtener_hostnames(eh)
    mac = mac_fab = None
    for d in eh.findall("address"):
        if d.get("addrtype") == "mac":
            mac = d.get("addr"); mac_fab = d.get("vendor")
    estado = "unknown"
    ts = eh.find("status")
    if ts is not None:
        r = ts.get("state", "unknown").lower()
        estado = "up" if r == "up" else ("down" if r == "down" else r)
    so = _parsear_so(eh)
    servicios = _parsear_servicios(eh)
    scripts_host = []
    ths = eh.find("hostscript")
    if ths is not None:
        for sc in ths.findall("script"):
            if sc.get("id"):
                scripts_host.append(ResultadoScript(sc.get("id"), sc.get("output","").strip()))
    return Host(ip=ip, hostnames=hostnames, estado=estado, mac=mac,
        mac_fabricante=mac_fab, sistema_operativo=so,
        servicios=servicios, scripts_host=scripts_host)

def _obtener_ip(eh):
    v4 = v6 = None
    for d in eh.findall("address"):
        if d.get("addrtype") == "ipv4": v4 = d.get("addr")
        elif d.get("addrtype") == "ipv6": v6 = d.get("addr")
    return v4 or v6 or "0.0.0.0"

def _obtener_hostnames(eh):
    hs = []
    thns = eh.find("hostnames")
    if thns is not None:
        for hn in thns.findall("hostname"):
            n = hn.get("name")
            if n and n not in hs: hs.append(n)
    return hs

def _parsear_so(eh):
    tos = eh.find("os")
    if tos is None: return None
    mejor = None; mejor_p = 0
    for om in tos.findall("osmatch"):
        p = int(om.get("accuracy","0"))
        if p > mejor_p: mejor_p = p; mejor = om
    if mejor is None: return None
    nombre = mejor.get("name","Unknown")
    familia = cpe = None
    oc = mejor.find("osclass")
    if oc is not None:
        familia = oc.get("osfamily")
        tc = oc.find("cpe")
        if tc is not None: cpe = tc.text
    from modelos import InfoSO
    return InfoSO(nombre=nombre, familia=familia, precision=mejor_p, cpe=cpe)

def _parsear_servicios(eh):
    svcs = []
    tp = eh.find("ports")
    if tp is None: return svcs
    for p in tp.findall("port"):
        try: puerto = int(p.get("portid",0))
        except: continue
        proto = p.get("protocol","tcp").lower()
        estado = "unknown"
        ts = p.find("state")
        if ts is not None:
            m = {"open":"open","closed":"closed","filtered":"filtered","open|filtered":"open_filtered"}
            estado = m.get(ts.get("state","unknown").lower(), ts.get("state","unknown").lower())
        nombre_s = producto = version = info_extra = banner = None
        lista_cpe = []
        tsvc = p.find("service")
        if tsvc is not None:
            nombre_s = tsvc.get("name")
            producto = tsvc.get("product")
            version = tsvc.get("version")
            info_extra = tsvc.get("extrainfo")
            if tsvc.get("tunnel") == "ssl" and nombre_s == "http": nombre_s = "https"
            for tc in tsvc.findall("cpe"):
                if tc.text: lista_cpe.append(tc.text)
        scripts = []
        for sc in p.findall("script"):
            if sc.get("id"):
                scripts.append(ResultadoScript(sc.get("id"), sc.get("output","").strip()))
        svcs.append(Servicio(puerto=puerto, protocolo=proto, estado=estado,
            nombre_servicio=nombre_s, producto=producto, version=version,
            info_extra=info_extra, cpe=lista_cpe, banner=banner, scripts=scripts))
    return svcs

def _extraer_objetivo(args):
    if not args: return None
    flags = {"-p","-oN","-oX","-oG","-oA","-iL","-iR","--exclude","--excludefile",
             "--script","--script-args","-e","-g","-S","-D","--spoof-mac","-T",
             "--top-ports","--min-rate","--max-rate"}
    partes = args.split(); targets = []; saltar = False
    for i,p in enumerate(partes):
        if saltar: saltar=False; continue
        if p.startswith("-"):
            if "=" in p: continue
            if p in flags: saltar=True
            continue
        if i==0 and p.lower()=="nmap": continue
        targets.append(p)
    return " ".join(targets) if targets else None
