"""
Descubrimiento y registro de vHosts para ARES.

Muchas máquinas (sobre todo en HTB) esconden el sitio real detrás de un
nombre de dominio que aparece en el certificado TLS o en un redirect, y
que hay que agregar a /etc/hosts para poder navegarlo. Este módulo:

  1. Extrae esos nombres de la salida de Nmap (scripts ssl-cert, http-title…).
  2. Los registra en /etc/hosts de forma idempotente y reversible.
  3. Permite limpiar después las entradas que agregó.

El registro en /etc/hosts necesita permisos de root. Si no los hay, las
funciones devuelven un mensaje claro con el comando a ejecutar a mano.
"""

import re
import socket

# Marca para reconocer (y luego limpiar) las líneas que agrega ARES.
MARCA = "# ARES"

# El hostname aparece en: commonName=host, DNS:host (SAN) y redirect a http(s)://host/
_PATRON_CN = re.compile(r"commonName=([A-Za-z0-9.\-*]+)")
_PATRON_DNS = re.compile(r"DNS:([A-Za-z0-9.\-*]+)")
_PATRON_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)")

# Dominios que no son objetivos (ruido típico de banners/scripts).
_IGNORAR = {"nmap.org", "example.com", "example.org", "localhost"}


def descubrir_hostnames(resultado_nmap):
    """
    Devuelve el conjunto de hostnames que Nmap dejó ver en sus scripts
    (certificado TLS, http-title con redirect, etc.).
    """
    nombres = set()

    def procesar(salida):
        if not salida:
            return
        for patron in (_PATRON_CN, _PATRON_DNS, _PATRON_URL):
            for m in patron.findall(salida):
                nombres.add(m)

    for host in resultado_nmap.hosts:
        # Nmap puede conservar el nombre como PTR/hostname en ejecuciones
        # posteriores, cuando ARES ya lo agregó a /etc/hosts. En ese caso el
        # servidor responde directamente y el script HTTP ya no ve el redirect.
        for nombre in host.hostnames:
            nombres.add(nombre)
        for sc in host.scripts_host:
            procesar(sc.salida)
        for s in host.servicios:
            for sc in s.scripts:
                procesar(sc.salida)

    limpios = set()
    for n in nombres:
        n = n.strip().lower().lstrip("*.").rstrip(".")
        if "." not in n:            # tiene que parecer un dominio
            continue
        if n in _IGNORAR:
            continue
        if _es_ip(n):               # descartar IPs
            continue
        limpios.add(n)
    return limpios


def _es_ip(texto):
    partes = texto.split(".")
    return len(partes) == 4 and all(p.isdigit() for p in partes)


def hostname_resuelve(hostname):
    """True si el hostname ya se puede resolver (está en /etc/hosts o DNS)."""
    try:
        socket.gethostbyname(hostname)
        return True
    except OSError:
        return False


def agregar_a_etc_hosts(ip, hostnames, ruta="/etc/hosts"):
    """
    Agrega '<ip> <hostname>  # ARES' a /etc/hosts para los que falten.
    Es idempotente (no duplica) y reversible (limpiar_etc_hosts).

    Devuelve (agregados, mensaje). Si no hay permisos, agregados queda
    vacío y el mensaje incluye el comando para hacerlo a mano.
    """
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        return [], "No había hostnames para agregar"

    try:
        with open(ruta, "r", encoding="utf-8") as f:
            contenido = f.read()
    except OSError as e:
        return [], "No se pudo leer " + ruta + ": " + str(e)

    tokens = set(contenido.split())
    faltantes = [h for h in hostnames if h not in tokens]
    if not faltantes:
        return [], "Los hostnames ya estaban en " + ruta

    nuevas = "".join(ip + "\t" + h + "  " + MARCA + "\n" for h in faltantes)
    prefijo = "" if (not contenido or contenido.endswith("\n")) else "\n"
    try:
        with open(ruta, "a", encoding="utf-8") as f:
            f.write(prefijo + nuevas)
        return faltantes, "Agregado(s) a " + ruta + ": " + ", ".join(faltantes)
    except PermissionError:
        linea = " ".join("'" + ip + " " + h + "'" for h in faltantes)
        cmd = "printf '%s\\n' " + linea + " | sudo tee -a " + ruta
        return [], ("Sin permiso para escribir " + ruta +
                    ". Agregalo a mano con:\n  " + cmd)


def limpiar_etc_hosts(ruta="/etc/hosts"):
    """Quita de /etc/hosts las líneas que había agregado ARES (con la marca)."""
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            lineas = f.readlines()
    except OSError as e:
        return 0, "No se pudo leer " + ruta + ": " + str(e)

    quedan = [l for l in lineas if MARCA not in l]
    quitadas = len(lineas) - len(quedan)
    if quitadas == 0:
        return 0, "No había entradas de ARES en " + ruta

    try:
        with open(ruta, "w", encoding="utf-8") as f:
            f.writelines(quedan)
        return quitadas, "Quitada(s) " + str(quitadas) + " entrada(s) de " + ruta
    except PermissionError:
        return 0, "Sin permiso para escribir " + ruta
