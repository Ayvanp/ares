"""
Parser de Gobuster para ARES.

Gobuster tiene varios modos y formatos. Este parser cubre:

Modos:
  - dir:   fuerza bruta de directorios/archivos
  - dns:   enumeración de subdominios
  - vhost: descubrimiento de virtual hosts

Formatos:
  - JSONL viejo (versiones < 3.6): una línea JSON por resultado
  - JSON nuevo (versiones 3.6+): objeto con "results" y "config"

Edge cases manejados:
  - Wildcard detection: servidor retorna 200 para cualquier URL
  - Salida parcial: scan interrumpido a mitad
  - Líneas corruptas: se saltan sin fallar
  - Archivo vacío: retorna resultado vacío limpio
  - Exit code ≠ 0 aun cuando hay resultados válidos
  - Duplicados en la salida (raro pero posible)
  - SSL/TLS: URLs https sin verificación
  - Resultados con redirect (código 301/302 con Location)
"""

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from modelos import ResultadoCanonico, MetadatosEscaneo, Host, Endpoint


# Formato de texto de gobuster (default en versiones 3.7+, que ya no
# tienen salida JSON). Con -e imprime la URL completa. Ejemplos:
#   http://10.129.96.69/ip (Status: 200) [Size: 17460]
#   http://10.129.96.69/data (Status: 302) [Size: 208] [--> http://10.129.96.69/]
PATRON_GOBUSTER_TXT = re.compile(
    r'^(\S+)\s+\(Status:\s*(\d+)\)'
    r'(?:\s*\[Size:\s*(\d+)\])?'
    r'(?:\s*\[-->\s*([^\]]+)\])?'
)


def parsear_gobuster(ruta_archivo):
    """
    Parsea la salida de Gobuster y retorna un ResultadoCanonico.

    Detecta automáticamente el modo y el formato.
    Si el archivo tiene errores parciales, parsea lo que pueda.
    """
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="replace") as f:
            contenido = f.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró: " + str(ruta_archivo))

    if not contenido:
        return _vacio()

    # Detectar si hay wildcards (gobuster los reporta en stderr/stdout)
    # Ejemplo: "WARN: Wildcard response found: http://... => 200"
    tiene_wildcard = _detectar_wildcard(contenido)

    entradas, config = _leer_entradas(contenido)

    if not entradas:
        return _vacio(wildcard=tiene_wildcard)

    modo = _detectar_modo(entradas)

    if modo == "dns":
        hosts = _procesar_dns(entradas)
    elif modo == "vhost":
        hosts = _procesar_vhost(entradas)
    else:
        hosts = _procesar_dir(entradas)

    comando = _construir_comando(entradas, modo, config)

    metadatos = MetadatosEscaneo(
        herramienta="gobuster",
        comando=comando,
        fecha_inicio=datetime.now(tz=timezone.utc),
        tipo_escaneo=modo,
    )

    resultado = ResultadoCanonico(metadatos=metadatos, hosts=hosts)

    # Si había wildcard, lo registramos en los metadatos para que
    # el orquestador sepa que los resultados pueden ser falsos positivos
    if tiene_wildcard:
        resultado.metadatos.tipo_escaneo = modo + "_wildcard"

    return resultado


# ── Detección de wildcard ──

def _detectar_wildcard(contenido):
    """
    Detecta si gobuster encontró un wildcard response.

    Un wildcard significa que el servidor devuelve 200 para cualquier
    URL, lo que hace que todos los endpoints sean falsos positivos.

    Gobuster lo reporta como:
        WARN: Wildcard response found: http://... => 200
    """
    indicadores = [
        "wildcard response found",
        "wildcard",
        "[-] Wildcard",
    ]
    contenido_lower = contenido.lower()
    return any(ind.lower() in contenido_lower for ind in indicadores)


# ── Lectura del formato ──

def _leer_entradas(contenido):
    """
    Lee el contenido y retorna (lista_de_entradas, config).

    Intenta en orden:
    1. JSON único con "results" (formato nuevo 3.6+)
    2. Lista JSON directa
    3. JSONL línea por línea (formato viejo)
    En todos los casos salta líneas corruptas.
    """
    # Intentar como JSON único
    try:
        datos = json.loads(contenido)
        if isinstance(datos, dict) and "results" in datos:
            # Formato nuevo: {"results": [...], "config": {...}}
            resultados = datos.get("results") or []
            return resultados, datos.get("config", {})
        if isinstance(datos, list):
            return datos, {}
    except json.JSONDecodeError:
        pass

    # JSONL o texto plano: parsear línea por línea, saltando corruptas.
    # Primero intenta JSON; si no lo es, intenta el formato de texto de
    # gobuster (versiones 3.7+ ya no exportan JSON, solo texto).
    entradas = []
    for linea in contenido.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        # Saltar líneas que claramente no son resultados (advertencias, banners)
        if linea.startswith(("WARN:", "ERROR:", "[-]", "[+]", "===", "---")):
            continue
        try:
            entradas.append(json.loads(linea))
            continue
        except json.JSONDecodeError:
            pass
        entrada_txt = _parsear_linea_texto(linea)
        if entrada_txt:
            entradas.append(entrada_txt)

    return entradas, {}


def _parsear_linea_texto(linea):
    """
    Convierte una línea de texto de gobuster al mismo dict que produce
    el formato JSON, para que el resto del parser no note la diferencia.
    Solo procesa líneas con URL completa (gobuster -e); sin URL no se
    puede saber a qué host pertenece el resultado.
    """
    m = PATRON_GOBUSTER_TXT.match(linea)
    if not m:
        return None
    objetivo = m.group(1)
    if "://" not in objetivo:
        return None
    partes = urlparse(objetivo)
    return {
        "url": objetivo,
        "path": partes.path or "/",
        "status": int(m.group(2)),
        "size": int(m.group(3)) if m.group(3) else None,
        "redirectlocation": m.group(4),
    }


# ── Detección de modo ──

def _detectar_modo(entradas):
    """
    Detecta el modo según los campos presentes.
    - dns:   tiene "subdomain" o "Subdomain"
    - vhost: tiene "vhost" o "Vhost"
    - dir:   tiene "path" y "status" (caso por defecto)
    """
    if not entradas:
        return "dir"
    primera = entradas[0]
    if "subdomain" in primera or "Subdomain" in primera:
        return "dns"
    if "vhost" in primera or "Vhost" in primera:
        return "vhost"
    return "dir"


# ── Procesamiento por modo ──

def _procesar_dir(entradas):
    """Procesa resultados del modo dir."""
    hosts_por_ip = {}
    urls_vistas = set()

    for e in entradas:
        url = e.get("url", "")
        if not url:
            continue

        partes = urlparse(url)
        ip = partes.hostname or "0.0.0.0"

        # Deduplicar URLs
        if url in urls_vistas:
            continue
        urls_vistas.add(url)

        if ip not in hosts_por_ip:
            hosts_por_ip[ip] = Host(ip=ip, estado="up")

        # Extraer redirect si hay
        redirige_a = e.get("redirectlocation") or e.get("redirect") or None

        hosts_por_ip[ip].endpoints.append(Endpoint(
            url=url,
            ruta=e.get("path") or partes.path or "/",
            codigo_estado=e.get("status"),
            tamano=e.get("size"),
            redirige_a=redirige_a,
            tipo="dir",
        ))

    return list(hosts_por_ip.values())


def _procesar_dns(entradas):
    """Procesa resultados del modo dns."""
    hosts = []
    subdominios_vistos = set()

    for e in entradas:
        sub = e.get("subdomain") or e.get("Subdomain")
        if not sub or sub in subdominios_vistos:
            continue
        subdominios_vistos.add(sub)

        ip = e.get("ip") or e.get("Ip")
        if isinstance(ip, list):
            ip = ip[0] if ip else None

        host = Host(ip=ip or "0.0.0.0", hostnames=[sub], estado="up")
        host.endpoints.append(Endpoint(
            url=sub, tipo="dns",
            subdominio=sub,
            ip=ip if not isinstance(ip, list) else (ip[0] if ip else None),
        ))
        hosts.append(host)

    return hosts


def _procesar_vhost(entradas):
    """Procesa resultados del modo vhost."""
    hosts = {}
    for e in entradas:
        vhost = e.get("vhost") or e.get("Vhost") or e.get("hostname")
        if not vhost:
            continue
        if vhost not in hosts:
            hosts[vhost] = Host(ip=vhost, hostnames=[vhost], estado="up")
        hosts[vhost].endpoints.append(Endpoint(
            url=vhost, codigo_estado=e.get("status"),
            tamano=e.get("size"), tipo="vhost", subdominio=vhost,
        ))

    return list(hosts.values())


# ── Auxiliares ──

def _construir_comando(entradas, modo, config):
    """Reconstruye el comando aproximado de gobuster."""
    if config:
        url = config.get("url") or config.get("URL")
        if url:
            return "gobuster " + modo + " -u " + str(url)

    objetivos = set()
    for e in entradas:
        url = e.get("url", "")
        p = urlparse(url)
        if p.scheme and p.hostname:
            objetivos.add(p.scheme + "://" + p.hostname)
    if objetivos:
        return "gobuster " + modo + " -u " + " ".join(sorted(objetivos))
    return "gobuster " + modo


def _vacio(wildcard=False):
    """Retorna un resultado sin hosts."""
    tipo = "dir_wildcard" if wildcard else "dir"
    metadatos = MetadatosEscaneo(
        herramienta="gobuster",
        comando="gobuster dir",
        fecha_inicio=datetime.now(tz=timezone.utc),
        tipo_escaneo=tipo,
    )
    return ResultadoCanonico(metadatos=metadatos, hosts=[])
