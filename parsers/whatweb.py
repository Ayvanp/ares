import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from modelos import ResultadoCanonico, MetadatosEscaneo, Host, Tecnologia

CATEGORIAS = {"Apache":"Web Server","Nginx":"Web Server","Microsoft-IIS":"Web Server",
    "HTTPServer":"Web Server","WordPress":"CMS","Joomla":"CMS","Drupal":"CMS",
    "PHP":"Language","jQuery":"JavaScript Library","Bootstrap":"CSS Framework",
    "SSL-Certificate":"Security","Cloudflare":"CDN"}
IGNORAR = {"IP","Country","Title","Meta-Generator","UncommonHeaders","Cookies",
    "PasswordField","HTML5","X-Powered-By","RedirectLocation","Email","Frame",
    "Script","X-UA-Compatible"}

def parsear_whatweb(ruta_archivo):
    try:
        with open(ruta_archivo,"r",encoding="utf-8") as f:
            contenido = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró: " + str(ruta_archivo))
    try:
        datos = json.loads(contenido)
    except json.JSONDecodeError as e:
        raise ValueError("JSON inválido: " + str(e))
    if not isinstance(datos, list):
        raise ValueError("Se esperaba un array JSON")
    hosts_por_ip = {}
    for entrada in datos:
        target = entrada.get("target","")
        plugins = entrada.get("plugins",{})
        ip = _obtener_ip(entrada, target)
        if ip not in hosts_por_ip:
            hosts_por_ip[ip] = Host(ip=ip, hostnames=_obtener_hostnames(target,ip), estado="up")
        host = hosts_por_ip[ip]
        for nombre_plugin, datos_plugin in plugins.items():
            if nombre_plugin in IGNORAR: continue
            tec = _crear_tecnologia(nombre_plugin, datos_plugin)
            if tec is None: continue
            ya = False
            for te in host.tecnologias:
                if te.nombre == tec.nombre:
                    if tec.version and not te.version: te.version = tec.version
                    ya = True; break
            if not ya: host.tecnologias.append(tec)
    targets = [e.get("target","") for e in datos if e.get("target")]
    comando = "whatweb " + " ".join(targets)
    metadatos = MetadatosEscaneo(herramienta="whatweb", comando=comando,
        fecha_inicio=datetime.now(tz=timezone.utc), tipo_escaneo="web_fingerprint")
    return ResultadoCanonico(metadatos=metadatos, hosts=list(hosts_por_ip.values()))

def _obtener_ip(entrada, target):
    ip_plugin = entrada.get("plugins",{}).get("IP",{}).get("string",[])
    if ip_plugin: return ip_plugin[0]
    p = urlparse(target)
    return p.hostname or "0.0.0.0"

def _obtener_hostnames(target, ip):
    p = urlparse(target)
    h = p.hostname or ""
    return [h] if h and h != ip else []

def _crear_tecnologia(nombre, datos_plugin):
    if not isinstance(datos_plugin, dict): return None
    versiones = datos_plugin.get("version",[])
    version = versiones[0] if versiones else None
    categoria = CATEGORIAS.get(nombre,"Other")
    return Tecnologia(nombre=nombre, version=version, categoria=categoria)
