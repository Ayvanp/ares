"""
Parser de dirb para ARES.

dirb genera salida en texto plano (no JSON) con este formato:

    + http://192.168.1.1/admin (CODE:200|SIZE:1234)
    + http://192.168.1.1/login.php (CODE:200|SIZE:456)
    ==> DIRECTORY: http://192.168.1.1/wp-admin/

Cada línea que empieza con '+' es un archivo encontrado.
Cada línea que empieza con '==>' es un directorio encontrado.

Casos que maneja:
  - Archivos con código y tamaño
  - Directorios encontrados recursivamente
  - Líneas de encabezado y separadores (ignoradas)
  - Archivos vacíos o sin resultados
  - Salida interrumpida a mitad del escaneo
  - URLs con y sin ruta base
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from modelos import ResultadoCanonico, MetadatosEscaneo, Host, Endpoint


# Patrones de las líneas de dirb
PATRON_ARCHIVO = re.compile(
    r'^\+\s+(https?://[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)'
)
PATRON_DIRECTORIO = re.compile(
    r'^==>\s+DIRECTORY:\s+(https?://[^\s]+)'
)
PATRON_URL_BASE = re.compile(
    r'^URL_BASE:\s+(https?://[^\s]+)'
)


def parsear_dirb(ruta_archivo):
    """
    Parsea un archivo de salida de dirb y retorna un ResultadoCanonico.

    dirb se invoca así:
        dirb http://target -o salida.txt

    El archivo de salida es texto plano con el formato que describe
    este módulo.
    """
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="replace") as f:
            contenido = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró: " + str(ruta_archivo))

    if not contenido.strip():
        return _resultado_vacio()

    lineas = contenido.splitlines()

    # Extraer URL base del encabezado para saber el target
    url_base = None
    for linea in lineas[:20]:  # solo buscar en las primeras líneas
        m = PATRON_URL_BASE.match(linea.strip())
        if m:
            url_base = m.group(1).rstrip("/")
            break

    # Parsear endpoints
    endpoints = []
    urls_vistas = set()

    for linea in lineas:
        linea = linea.strip()

        # Archivo encontrado: + URL (CODE:XXX|SIZE:YYYY)
        m = PATRON_ARCHIVO.match(linea)
        if m:
            url = m.group(1)
            codigo = int(m.group(2))
            tamano = int(m.group(3))

            if url not in urls_vistas:
                urls_vistas.add(url)
                ruta = _extraer_ruta(url)
                endpoints.append(Endpoint(
                    url=url,
                    ruta=ruta,
                    codigo_estado=codigo,
                    tamano=tamano,
                    tipo="dir",
                    ip=_extraer_ip(url),
                ))
            continue

        # Directorio encontrado: ==> DIRECTORY: URL/
        m = PATRON_DIRECTORIO.match(linea)
        if m:
            url = m.group(1).rstrip("/")
            if url not in urls_vistas:
                urls_vistas.add(url)
                ruta = _extraer_ruta(url)
                endpoints.append(Endpoint(
                    url=url + "/",
                    ruta=ruta + "/",
                    codigo_estado=301,  # dirb marca como directorio → implica redirect
                    tipo="dir",
                    ip=_extraer_ip(url),
                ))

    # Agrupar por host
    hosts_por_ip = {}
    for ep in endpoints:
        ip = ep.ip or "0.0.0.0"
        if ip not in hosts_por_ip:
            hosts_por_ip[ip] = Host(ip=ip, estado="up")
        hosts_por_ip[ip].endpoints.append(ep)

    # Si no hay resultados válidos pero el archivo existe, retornar vacío limpio
    if not hosts_por_ip:
        return _resultado_vacio(url_base)

    comando = "dirb " + (url_base or "target") + " -o output.txt"
    metadatos = MetadatosEscaneo(
        herramienta="dirb",
        comando=comando,
        fecha_inicio=datetime.now(tz=timezone.utc),
        tipo_escaneo="dir",
        objetivo=url_base,
    )

    return ResultadoCanonico(
        metadatos=metadatos,
        hosts=list(hosts_por_ip.values()),
    )


def _extraer_ruta(url):
    """Extrae la ruta de una URL. Ej: http://1.2.3.4/admin → /admin"""
    partes = urlparse(url)
    return partes.path or "/"


def _extraer_ip(url):
    """Extrae el hostname/IP de una URL."""
    partes = urlparse(url)
    return partes.hostname or "0.0.0.0"


def _resultado_vacio(url_base=None):
    """Retorna un resultado sin hosts."""
    metadatos = MetadatosEscaneo(
        herramienta="dirb",
        comando="dirb " + (url_base or "target"),
        fecha_inicio=datetime.now(tz=timezone.utc),
        tipo_escaneo="dir",
    )
    return ResultadoCanonico(metadatos=metadatos, hosts=[])
