"""
Orquestador de ARES.

Ejecuta las herramientas de seguridad en orden reactivo y guarda
los outputs crudos en una carpeta de evidencias permanente.

Reglas de disparo basadas en nombre_servicio y producto que reporta
Nmap — NO en números de puerto fijos.
"""

import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from vhosts import descubrir_hostnames, agregar_a_etc_hosts, hostname_resuelve

# ── Perfiles ──

PERFILES = {
    "reconocimiento": {
        "descripcion": "Solo Nmap, sin herramientas web ni Nuclei",
        "nmap_flags": "-sV -T3",
        "activar_web": False, "activar_nuclei": False,
        "timeout_por_herramienta": 120,
    },
    "rapido": {
        "descripcion": "Nmap + web, sin Nuclei",
        "nmap_flags": "-sV -T4 --top-ports 100",
        "activar_web": True, "activar_nuclei": False,
        "timeout_por_herramienta": 180,
    },
    "completo": {
        "descripcion": "Todas las herramientas con reglas reactivas",
        "nmap_flags": "-sV -sC -O -T4",
        "activar_web": True, "activar_nuclei": True,
        # Gobuster primario usa una wordlist grande (medium ~220k); con este
        # tope alcanza a COMPLETARLA (reproducibilidad) en vez de cortarse.
        "timeout_por_herramienta": 600,
    },
}

# Nombre de servicio → tags de Nuclei
SERVICIO_NUCLEI = {
    "ssh":"ssh", "ftp":"ftp", "sftp":"ftp", "telnet":"telnet",
    "smtp":"smtp", "smtps":"smtp", "pop3":"pop3", "imap":"imap",
    "microsoft-ds":"smb", "netbios-ssn":"smb", "smb":"smb",
    "mysql":"mysql", "postgresql":"postgresql", "ms-sql-s":"mssql",
    "mongodb":"mongodb", "redis":"redis", "memcache":"memcache",
    "elasticsearch":"elasticsearch", "vnc":"vnc",
    "ms-wbt-server":"rdp", "rdp":"rdp", "snmp":"snmp",
    "ldap":"ldap", "nfs":"nfs", "rsync":"rsync",
    "docker":"docker", "kubernetes":"kubernetes",
    "kafka":"kafka", "rabbitmq":"rabbitmq", "influxdb":"influxdb",
}

# Producto → tags de Nuclei
PRODUCTO_NUCLEI = {
    "apache":"apache", "nginx":"nginx", "iis":"iis", "jetty":"jetty",
    "tomcat":"tomcat", "jboss":"jboss", "weblogic":"weblogic",
    "openssh":"openssh", "vsftpd":"ftp", "proftpd":"ftp",
    "postfix":"smtp", "sendmail":"smtp", "exim":"smtp",
    "influxdb":"influxdb", "grafana":"grafana", "prometheus":"prometheus",
    "consul":"consul", "vault":"vault", "minio":"minio",
}


# ── Reglas de disparo ──

def evaluar_primera_ronda(host, perfil_config):
    """
    Evalúa qué herramientas lanzar según los servicios de Nmap.
    Usa nombre_servicio y producto, no números de puerto.
    """
    tareas = []
    combinaciones = set()

    def nueva_tarea(tarea):
        # Clave de dedup: para Nuclei usamos herramienta+tags+puerto para evitar
        # que el mismo servicio dispare dos veces con los mismos tags
        clave_dedup = tarea.pop("_clave", None)
        clave = clave_dedup or (tarea["herramienta"] + "_" + tarea["sufijo"])
        if clave not in combinaciones:
            combinaciones.add(clave)
            tareas.append(tarea)

    for servicio in host.servicios:
        if servicio.estado != "open":
            continue
        nombre = (servicio.nombre_servicio or "").lower().strip()
        producto = (servicio.producto or "").lower().strip()
        puerto = servicio.puerto
        sp = str(puerto)

        # ── HTTP detectado por nombre_servicio ──
        es_http = "http" in nombre or nombre in ["https","http-alt","http-proxy"]
        es_proxy_no_nav = "proxy" in producto and "golang" in producto

        if es_http and not es_proxy_no_nav and perfil_config["activar_web"]:
            esquema = "https" if ("https" in nombre or puerto == 443) else "http"
            url = esquema + "://" + host.ip + ((":" + sp) if puerto not in [80, 443] else "")
            nueva_tarea({**_tarea_whatweb(host.ip, url, f"HTTP en :{puerto}", "ww_"+sp)})
            # Gobuster (paralelo) es el escáner web PRIMARIO, con wordlist grande.
            nueva_tarea({**_tarea_gobuster(host.ip, url, f"HTTP en :{puerto}",
                sufijo="gb_"+sp, wordlist="mediana", ssl_inseguro=(esquema == "https"))})
            # dirb (lento, un solo hilo) solo se usa como respaldo en la tercera
            # ronda, y solo si Gobuster no encontró ninguna ruta.
            if perfil_config["activar_nuclei"]:
                nueva_tarea({**_tarea_nuclei(host.ip, url, "http,exposure,misconfig",
                    f"HTTP en :{puerto}", "http_"+sp),
                    "_clave": "nuclei_http_tags_" + sp})

        # ── Nuclei por nombre_servicio ──
        if perfil_config["activar_nuclei"] and nombre in SERVICIO_NUCLEI:
            tags = SERVICIO_NUCLEI[nombre]
            nueva_tarea({**_tarea_nuclei(host.ip, host.ip+":"+sp, tags,
                f"Nmap identificó {nombre} en :{puerto}", nombre+"_"+sp),
                "_clave": "nuclei_" + tags + "_" + sp})

        # ── Nuclei por producto ──
        if perfil_config["activar_nuclei"] and producto:
            for clave_prod, tags in PRODUCTO_NUCLEI.items():
                if clave_prod in producto:
                    # Misma clave que la regla por servicio: si ambos apuntan a
                    # los mismos tags en el mismo puerto, se ejecuta una sola vez.
                    nueva_tarea({**_tarea_nuclei(host.ip, host.ip+":"+sp, tags,
                        f"Nmap detectó {servicio.producto} en :{puerto}", clave_prod+"_"+sp),
                        "_clave": "nuclei_" + tags + "_" + sp})

    return tareas


def evaluar_segunda_ronda(host, perfil_config):
    """Segunda ronda: basada en tecnologías que detectó WhatWeb."""
    tareas = []
    if not perfil_config["activar_nuclei"]: return tareas
    ya = set()
    url_base = "http://" + host.ip
    TECH_NUCLEI = {
        "wordpress":"wordpress", "joomla":"joomla", "drupal":"drupal",
        "microsoft-iis":"iis", "nginx":"nginx", "apache":"apache",
        "grafana":"grafana", "jenkins":"jenkins", "gitlab":"gitlab",
        "phpmyadmin":"phpmyadmin", "tomcat":"tomcat",
    }
    for tec in host.tecnologias:
        n = tec.nombre.lower()
        if n in ya: continue
        if n in TECH_NUCLEI:
            tags = TECH_NUCLEI[n]
            tareas.append(_tarea_nuclei(host.ip, url_base, tags,
                f"{tec.nombre} {tec.version or ''} detectado por WhatWeb",
                "tech_" + n))
            ya.add(n)
    return tareas


# Paths que indican un CMS o panel específico
_PATHS_CMS = {
    "wp-admin": "wordpress", "wp-login": "wordpress",
    "wp-content": "wordpress", "wp-includes": "wordpress",
    "administrator": "joomla", "components": "joomla",
    "modules": "joomla",
    "user/login": "drupal", "sites/default": "drupal",
    "phpmyadmin": "phpmyadmin",
    "admin": None, "login": None, "dashboard": None,
    "manager": "tomcat", "host-manager": "tomcat",
}


def evaluar_tercera_ronda(host_gobuster, url, puerto, perfil_config):
    """
    Tercera ronda: mira lo que encontró Gobuster (el escáner web primario) y
    decide si hace falta una pasada de dirb como respaldo.

    dirb es lento (un solo hilo), así que solo se usa en el caso raro en que
    Gobuster no encontró ninguna ruta: es un segundo intento con otra
    herramienta y técnica (dirb es recursivo) antes de darse por vencido.
    """
    tareas = []
    sp = str(puerto)
    total = len(host_gobuster.endpoints) if host_gobuster else 0

    if total == 0:
        ip = url.split("://")[-1].split(":")[0].split("/")[0]
        tareas.append({
            **_tarea_dirb(ip, url,
                razon=f"Gobuster no encontró rutas en :{puerto} → dirb como respaldo",
                sufijo="db_fb_"+sp)
        })

    return tareas


def es_redireccion_uniforme_gobuster(mensaje):
    """Identifica el rechazo de Gobuster a un redirect para rutas inexistentes."""
    mensaje = (mensaje or "").lower()
    return ("non existing urls" in mensaje and
            any("=> " + codigo in mensaje for codigo in ("301", "302", "303", "307", "308")))


def omitir_dirb_sobre_ip(url, redirecciones_gobuster, hostnames_nmap):
    """Evita repetir por IP una búsqueda que debe hacerse contra el vHost."""
    return url in redirecciones_gobuster and bool(hostnames_nmap)


# ── Función principal ──

def orquestar(target, perfil_nombre, bd, escaneo_id, fn_progreso=None):
    """
    Ejecuta el flujo completo de orquestación.
    Guarda los outputs crudos en evidencias/{escaneo_id}/
    """
    from parsers.nmap import parsear_nmap
    from parsers.whatweb import parsear_whatweb
    from parsers.gobuster import parsear_gobuster
    from parsers.nuclei import parsear_nuclei
    from base_datos.operaciones import guardar_resultados_en_escaneo, guardar_correlacion
    from base_datos.tablas import TablaEscaneo, TablaTarea, hora_actual

    perfil_config = PERFILES.get(perfil_nombre, PERFILES["completo"])
    directorio_tmp = tempfile.mkdtemp(prefix="ares_")

    # Carpeta de evidencias permanente
    carpeta_evidencias = os.path.join("evidencias", escaneo_id)
    os.makedirs(carpeta_evidencias, exist_ok=True)

    # Log persistente del escaneo: además del progreso en vivo, cada línea
    # se guarda en evidencias/<id>/orquestacion.log para poder auditarlo después.
    archivo_log = os.path.join(carpeta_evidencias, "orquestacion.log")

    def log(msg):
        if fn_progreso: fn_progreso(msg)
        try:
            marca = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
            with open(archivo_log, "a", encoding="utf-8") as f:
                f.write("[" + marca + "] " + msg + "\n")
        except OSError:
            pass

    def actualizar_estado(estado, herramienta=None, tarea_estado=None,
                          comando=None, razon=None):
        sesion = bd.nueva_sesion()
        try:
            escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
            if escaneo:
                escaneo.estado = estado
                if estado == "completed": escaneo.completado_en = hora_actual()
            if herramienta and tarea_estado:
                tarea = sesion.query(TablaTarea).filter_by(
                    escaneo_id=escaneo_id, nombre_herramienta=herramienta).first()
                if not tarea:
                    tarea = TablaTarea(escaneo_id=escaneo_id,
                        nombre_herramienta=herramienta, estado=tarea_estado)
                    sesion.add(tarea)
                else:
                    tarea.estado = tarea_estado
                # Guardar comando y razón sin pisarlos con None si ya los tenía
                if comando: tarea.comando = comando
                if razon: tarea.razon = razon
                if tarea_estado == "completed": tarea.terminado_en = hora_actual()
                elif tarea_estado == "running": tarea.iniciado_en = hora_actual()
            sesion.commit()
        finally:
            sesion.close()

    try:
        log("Iniciando orquestación de " + target)
        actualizar_estado("running")
        todos_resultados = []

        # ── Etapa 1: Nmap ──
        log("[Nmap] Escaneando " + target)
        archivo_nmap = os.path.join(directorio_tmp, "nmap.xml")
        comando_nmap = ["nmap"] + perfil_config["nmap_flags"].split() + ["-oX", archivo_nmap, target]
        actualizar_estado("running", "nmap", "running",
            comando=" ".join(comando_nmap),
            razon="Escaneo base de puertos, versiones y sistema operativo")
        exito, mensaje = ejecutar_comando(comando_nmap, timeout=perfil_config["timeout_por_herramienta"])
        if not exito:
            log("[Nmap] Error: " + mensaje)
            actualizar_estado("running", "nmap", "failed")
            actualizar_estado("failed"); return
        _copiar_evidencia(archivo_nmap, carpeta_evidencias, "nmap_scan.xml")
        log("[Nmap] Completado")
        actualizar_estado("running", "nmap", "completed")
        resultado_nmap = parsear_nmap(archivo_nmap)
        todos_resultados.append(resultado_nmap)

        # ── Etapa 2: Primera ronda de reglas ──
        tareas_pendientes = []
        ips_vistas = set()
        for host in resultado_nmap.hosts:
            if host.ip in ips_vistas: continue
            ips_vistas.add(host.ip)
            for tarea in evaluar_primera_ronda(host, perfil_config):
                tarea["ip"] = host.ip
                tareas_pendientes.append(tarea)
        log("Primera ronda: " + str(len(tareas_pendientes)) + " tareas")

        # ── Etapa 3: Ejecutar primera ronda ──
        resultados_web = []
        gobuster_redirecciones = set()
        for tarea in tareas_pendientes:
            herramienta = tarea["herramienta"]
            ip = tarea["ip"]
            sufijo = tarea.get("sufijo", "")
            log("[" + herramienta + "] " + tarea["razon"])
            nombre_archivo = herramienta + "_" + ip.replace(".","-") + "_" + sufijo + _extension(herramienta)
            archivo_salida = os.path.join(directorio_tmp, nombre_archivo)
            comando = _construir_comando(tarea["comando_template"], archivo_salida)
            actualizar_estado("running", herramienta + "_" + sufijo, "running",
                comando=" ".join(comando), razon=tarea["razon"])
            exito, mensaje = ejecutar_comando(comando, timeout=perfil_config["timeout_por_herramienta"])
            if not exito:
                # Aunque falle o se corte por timeout, la herramienta puede
                # haber dejado resultados parciales en el archivo. Los rescatamos.
                if not _hay_salida_parcial(archivo_salida):
                    if herramienta == "gobuster" and es_redireccion_uniforme_gobuster(mensaje):
                        gobuster_redirecciones.add(tarea["comando_template"][3])
                    log("[" + herramienta + "] Omitido: " + mensaje)
                    actualizar_estado("running", herramienta + "_" + sufijo, "skipped"); continue
                log("[" + herramienta + "] Parcial (" + mensaje + "), rescatando resultados")
            else:
                log("[" + herramienta + "] Completado")
            _copiar_evidencia(archivo_salida, carpeta_evidencias, nombre_archivo)
            actualizar_estado("running", herramienta + "_" + sufijo, "completed")
            resultado = _parsear_archivo(herramienta, archivo_salida)
            if resultado:
                todos_resultados.append(resultado)
                resultados_web.append(resultado)

        # ── Etapa 4: Segunda ronda (WhatWeb) + respaldo (Gobuster→dirb) ──
        tareas_segunda = []
        hostnames_nmap = descubrir_hostnames(resultado_nmap)

        # Segunda ronda: tecnologías detectadas por WhatWeb → Nuclei
        for resultado in resultados_web:
            if resultado.metadatos.herramienta != "whatweb":
                continue
            for host in resultado.hosts:
                for tarea in evaluar_segunda_ronda(host, perfil_config):
                    tarea["ip"] = host.ip
                    tareas_segunda.append(tarea)

        # Tercera ronda: resultados de Gobuster (primario) → decidir si hace
        # falta una pasada de dirb como respaldo.
        if perfil_config["activar_web"]:
            from urllib.parse import urlparse as _up
            urls_http_vistas = set()
            for tarea_orig in tareas_pendientes:
                if tarea_orig["herramienta"] != "gobuster":
                    continue
                url = tarea_orig["comando_template"][3]  # gobuster -u <url>
                if url in urls_http_vistas:
                    continue
                urls_http_vistas.add(url)

                partes = _up(url)
                puerto = partes.port or (443 if partes.scheme == "https" else 80)

                # Un servidor que redirige incluso las rutas inexistentes hacia
                # un vHost hace fallar Gobuster. Dirb sobre esa misma IP no
                # aporta información: se prioriza el barrido contra el nombre.
                if omitir_dirb_sobre_ip(url, gobuster_redirecciones, hostnames_nmap):
                    log("[dirb] Omitido sobre IP con redirección uniforme; "
                        "se analizará el vHost descubierto")
                    continue

                # ¿Cuántas rutas encontró Gobuster para esta URL?
                host_gb = None
                for res in resultados_web:
                    if res.metadatos.herramienta != "gobuster":
                        continue
                    for h in res.hosts:
                        if any(ep.url and ep.url.startswith(url) for ep in h.endpoints):
                            host_gb = h
                            break
                    if host_gb:
                        break

                for t in evaluar_tercera_ronda(host_gb, url, puerto, perfil_config):
                    t["ip"] = tarea_orig["ip"]
                    tareas_segunda.append(t)

        # ── Pivote a vHost (HTB y similares) ──
        # Muchas máquinas esconden el sitio real detrás de un nombre que
        # aparece en el certificado TLS o en un redirect. Lo descubrimos,
        # lo registramos en /etc/hosts y re-escaneamos contra ese nombre.
        if perfil_config["activar_web"]:
            hostnames = hostnames_nmap
            if hostnames:
                log("vHosts descubiertos: " + ", ".join(sorted(hostnames)))
                # Registrarlos como hostname del activo (para el reporte)
                for host in resultado_nmap.hosts:
                    for hn in hostnames:
                        if hn not in host.hostnames:
                            host.hostnames.append(hn)
                # Intentar agregarlos a /etc/hosts (necesita root)
                ip_obj = resultado_nmap.hosts[0].ip if resultado_nmap.hosts else target
                _agregados, msg_hosts = agregar_a_etc_hosts(ip_obj, sorted(hostnames))
                log("[/etc/hosts] " + msg_hosts)
                # Re-escanear contra cada hostname que ya resuelva
                for hn in sorted(hostnames):
                    if not hostname_resuelve(hn):
                        log("[vHost] " + hn + " no resuelve todavía, se omite el re-escaneo")
                        continue
                    for host in resultado_nmap.hosts:
                        for esquema, puerto in _servicios_web(host):
                            sp = str(puerto)
                            base = esquema + "://" + hn + ("" if puerto in (80, 443) else ":" + sp)
                            etq = hn.replace(".", "_") + "_" + sp
                            razon = "vHost " + hn + " en :" + sp
                            tareas_segunda.append({
                                **_tarea_whatweb(hn, base, razon, "ww_vh_" + etq), "ip": host.ip})
                            tareas_segunda.append({
                                **_tarea_gobuster(ip=hn, url=base, razon=razon,
                                    sufijo="gb_vh_" + etq, wordlist="comun",
                                    ssl_inseguro=(esquema == "https")), "ip": host.ip})

        if tareas_segunda:
            log("Segunda/tercera ronda: " + str(len(tareas_segunda)) + " tareas adicionales")

        # ── Etapa 5: Ejecutar segunda y tercera ronda ──
        for tarea in tareas_segunda:
            herramienta = tarea["herramienta"]
            sufijo = tarea.get("sufijo", "r2")
            ip = tarea["ip"]
            log("[" + herramienta + "] " + tarea["razon"])
            nombre_archivo = herramienta + "_" + ip.replace(".","-") + "_" + sufijo + _extension(herramienta)
            archivo_salida = os.path.join(directorio_tmp, nombre_archivo)
            comando = _construir_comando(tarea["comando_template"], archivo_salida)
            actualizar_estado("running", herramienta + "_" + sufijo, "running",
                comando=" ".join(comando), razon=tarea["razon"])
            exito, _ = ejecutar_comando(comando, timeout=perfil_config["timeout_por_herramienta"])
            # Rescatar salida parcial si la herramienta se cortó por timeout
            if not exito and not _hay_salida_parcial(archivo_salida):
                actualizar_estado("running", herramienta + "_" + sufijo, "skipped"); continue
            actualizar_estado("running", herramienta + "_" + sufijo, "completed")
            _copiar_evidencia(archivo_salida, carpeta_evidencias, nombre_archivo)
            resultado = _parsear_archivo(herramienta, archivo_salida)
            if resultado: todos_resultados.append(resultado)

        # ── Etapa 6: Guardar y correlacionar ──
        log("Guardando " + str(len(todos_resultados)) + " resultados en BD")
        if todos_resultados:
            guardar_resultados_en_escaneo(bd, escaneo_id, todos_resultados)
            try:
                guardar_correlacion(bd, escaneo_id, todos_resultados)
            except Exception as e:
                log("Advertencia: correlación no completada — " + str(e))

        log("Orquestación completada. Evidencias en: " + carpeta_evidencias)
        actualizar_estado("completed")

    except Exception as error:
        log("Error: " + str(error))
        actualizar_estado("failed")
        raise
    finally:
        shutil.rmtree(directorio_tmp, ignore_errors=True)


# ── Ejecutor ──

def ejecutar_comando(comando, timeout=300):
    try:
        resultado = subprocess.run(comando, timeout=timeout,
            capture_output=True, text=True)
        if resultado.returncode != 0:
            return False, resultado.stderr.strip() or "código " + str(resultado.returncode)
        return True, "ok"
    except FileNotFoundError:
        return False, (comando[0] if comando else "herramienta") + " no está instalado"
    except subprocess.TimeoutExpired:
        return False, "timeout después de " + str(timeout) + "s"
    except Exception as e:
        return False, str(e)


def herramienta_disponible(nombre):
    # which comprueba que el binario esté en el PATH. Más fiable que
    # "--version": algunas herramientas (p. ej. dirb) no soportan ese flag.
    return shutil.which(nombre) is not None


def _servicios_web(host):
    """Lista de (esquema, puerto) de los servicios web abiertos del host."""
    web = []
    for s in host.servicios:
        if s.estado != "open":
            continue
        nombre = (s.nombre_servicio or "").lower()
        if "http" in nombre or nombre in ("https", "http-alt", "http-proxy"):
            esquema = "https" if ("https" in nombre or s.puerto == 443) else "http"
            web.append((esquema, s.puerto))
    return web


def _hay_salida_parcial(archivo):
    """
    True si el archivo existe y tiene contenido. Sirve para rescatar
    resultados cuando una herramienta se corta por timeout: dirb y
    gobuster escriben su salida (-o) de forma incremental, así que un
    escaneo interrumpido igual deja lo que alcanzó a encontrar.
    """
    try:
        return os.path.exists(archivo) and os.path.getsize(archivo) > 0
    except OSError:
        return False


# ── Constructores de tareas ──

# Wordlists ACOTADAS a propósito: la fuerza bruta web tiene que COMPLETAR
# dentro del tiempo límite del perfil. Si se corta a mitad por timeout, cada
# corrida encuentra rutas distintas y se pierde la reproducibilidad —que es
# un objetivo central de ARES—. Las listas gigantes (200k+) quedaron afuera.
_WORDLISTS = {
    "corta": [   # ~1k · para dirb, que es de un solo hilo y necesita algo chico
        "/usr/share/dirb/wordlists/small.txt",
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "comun": [   # ~4.6k · gobuster con -t 40 la completa en segundos
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "mediana": [ # ~220k · wordlist primaria de Gobuster (paralelo). Con el
        # timeout ampliado del perfil completo, gobuster la termina.
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/dirb/wordlists/big.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "grande": [  # ~20k · gobuster con -t 40 la completa en ~40s
        "/usr/share/dirb/wordlists/big.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "wordpress": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "joomla": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
}


def _encontrar_wordlist(tipo="comun"):
    """Busca la mejor wordlist disponible para el tipo solicitado."""
    candidatas = _WORDLISTS.get(tipo, _WORDLISTS["comun"])
    for ruta in candidatas:
        if os.path.exists(ruta):
            return ruta
    # Si no encontró ninguna, retornar la primera aunque no exista
    # (gobuster fallará con mensaje claro)
    return candidatas[0]


def _tarea_whatweb(ip, url, razon, sufijo="http"):
    return {
        "herramienta": "whatweb",
        "sufijo": sufijo,
        "razon": razon,
        "comando_template": ["whatweb", url, "--log-json", "{salida}", "--no-errors"],
    }


def _tarea_dirb(ip, url, razon, sufijo="dirb"):
    """
    Tarea de dirb — escáner web primario.

    dirb es recursivo: si encuentra /wp-admin/, también escanea adentro.
    Es de un solo hilo, así que usa una wordlist corta para completar dentro
    del tiempo límite; Gobuster (paralelo) hace la pasada más amplia después.
    La salida es texto plano que maneja parser/dirb.py
    """
    wordlist = _encontrar_wordlist("corta")
    return {
        "herramienta": "dirb",
        "sufijo": sufijo,
        "razon": razon,
        # -o guarda la salida, -r deshabilita recursión profunda para evitar loops
        # -S modo silencioso (solo resultados)
        # -N ignora código de estado específico (e.g. 302 loops)
        "comando_template": [
            "dirb", url, wordlist,
            "-o", "{salida}",
            "-S",   # silencioso: solo muestra resultados
            "-r",   # no recursivo dentro de subdirectorios (evita loops)
        ],
    }


def _tarea_gobuster(ip, url, razon, sufijo="dir",
                    wordlist="comun", ssl_inseguro=False):
    """
    Tarea de gobuster — escáner web secundario/profundo.

    Se lanza después de dirb para complementar o cuando dirb falla.
    Parámetros contextuales permiten adaptar la búsqueda a lo encontrado.

    wordlist: "comun", "mediana", "grande", "wordpress", "joomla"
    ssl_inseguro: True cuando el cert TLS no es válido
    """
    ruta_wordlist = _encontrar_wordlist(wordlist)

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", ruta_wordlist,
        "--no-progress",
        "-o", "{salida}",
        "-q",
        # -t sube los hilos (por defecto 10). 80 acelera bastante en HTB sin
        # arriesgar demasiadas conexiones reseteadas (que harían perder rutas).
        "-t", "80",
        # -e imprime la URL completa. Gobuster 3.7+ ya no exporta JSON,
        # así que necesitamos la URL en el texto para que el parser sepa
        # a qué host pertenece cada resultado.
        "-e",
        # Ignorar códigos que generan ruido
        "-b", "404,500,503",
        # Timeout por request (evita bloqueos en servidores lentos)
        "--timeout", "15s",
    ]

    if ssl_inseguro:
        cmd.append("-k")  # ignorar errores de certificado TLS

    return {
        "herramienta": "gobuster",
        "sufijo": sufijo,
        "razon": razon,
        "comando_template": cmd,
    }


def _tarea_nuclei(ip, objetivo, tags, razon, sufijo="nuclei"):
    return {
        "herramienta": "nuclei",
        "sufijo": sufijo,
        "razon": razon,
        "comando_template": [
            "nuclei", "-target", objetivo,
            "-tags", tags,
            "-jsonl", "-o", "{salida}",
            "-silent",
        ],
    }


def _construir_comando(template, archivo_salida):
    return [p.replace("{salida}", archivo_salida) for p in template]


def _extension(herramienta):
    extensiones = {
        "nmap": ".xml",
        "whatweb": ".json",
        "gobuster": ".jsonl",
        "dirb": ".txt",
        "nuclei": ".jsonl",
    }
    return extensiones.get(herramienta, ".txt")


def _parsear_archivo(herramienta, ruta_archivo):
    from parsers.nmap import parsear_nmap
    from parsers.whatweb import parsear_whatweb
    from parsers.gobuster import parsear_gobuster
    from parsers.nuclei import parsear_nuclei
    from parsers.dirb import parsear_dirb

    parsers = {
        "nmap": parsear_nmap, "whatweb": parsear_whatweb,
        "gobuster": parsear_gobuster, "nuclei": parsear_nuclei,
        "dirb": parsear_dirb,
    }
    if herramienta not in parsers or not os.path.exists(ruta_archivo):
        return None
    try:
        return parsers[herramienta](ruta_archivo)
    except Exception:
        return None


def _copiar_evidencia(origen, carpeta_destino, nombre_archivo):
    """Copia un output crudo a la carpeta de evidencias permanente."""
    if not os.path.exists(origen):
        return
    destino = os.path.join(carpeta_destino, nombre_archivo)
    try:
        shutil.copy2(origen, destino)
    except Exception:
        pass
