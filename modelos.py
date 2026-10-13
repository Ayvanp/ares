"""
Modelo canónico de ARES.

Formato común al que se convierten los resultados de todas las herramientas.
"""

import json
from datetime import datetime, timezone
from uuid import uuid4


class ResultadoScript:
    def __init__(self, script_id, salida=""):
        self.script_id = script_id
        self.salida = salida

    def a_diccionario(self):
        return {"script_id": self.script_id, "salida": self.salida}


class InfoSO:
    def __init__(self, nombre, familia=None, precision=None, cpe=None):
        self.nombre = nombre
        self.familia = familia
        self.precision = precision
        self.cpe = cpe

    def a_diccionario(self):
        return {"nombre": self.nombre, "familia": self.familia,
                "precision": self.precision, "cpe": self.cpe}


class Servicio:
    def __init__(self, puerto, protocolo="tcp", estado="open",
                 nombre_servicio=None, producto=None, version=None,
                 info_extra=None, cpe=None, banner=None, scripts=None):
        self.puerto = puerto
        self.protocolo = protocolo
        self.estado = estado
        self.nombre_servicio = nombre_servicio
        self.producto = producto
        self.version = version
        self.info_extra = info_extra
        self.cpe = cpe if cpe else []
        self.banner = banner
        self.scripts = scripts if scripts else []

    def a_diccionario(self):
        return {
            "puerto": self.puerto, "protocolo": self.protocolo,
            "estado": self.estado, "nombre_servicio": self.nombre_servicio,
            "producto": self.producto, "version": self.version,
            "info_extra": self.info_extra, "cpe": self.cpe,
            "banner": self.banner,
            "scripts": [s.a_diccionario() for s in self.scripts],
        }


class Tecnologia:
    def __init__(self, nombre, version=None, categoria="Other"):
        self.nombre = nombre
        self.version = version
        self.categoria = categoria

    def a_diccionario(self):
        return {"nombre": self.nombre, "version": self.version,
                "categoria": self.categoria}


class Endpoint:
    def __init__(self, url=None, ruta=None, codigo_estado=None,
                 tamano=None, redirige_a=None, tipo="dir",
                 subdominio=None, ip=None):
        self.url = url
        self.ruta = ruta
        self.codigo_estado = codigo_estado
        self.tamano = tamano
        self.redirige_a = redirige_a
        self.tipo = tipo
        self.subdominio = subdominio
        self.ip = ip

    def a_diccionario(self):
        return {
            "url": self.url, "ruta": self.ruta,
            "codigo_estado": self.codigo_estado, "tamano": self.tamano,
            "redirige_a": self.redirige_a, "tipo": self.tipo,
            "subdominio": self.subdominio, "ip": self.ip,
        }


class Evidencia:
    def __init__(self, encontrado_en=None, resultados_extraidos=None,
                 comando_curl=None, peticion=None, respuesta=None,
                 interaccion=None):
        self.encontrado_en = encontrado_en
        self.resultados_extraidos = resultados_extraidos if resultados_extraidos else []
        self.comando_curl = comando_curl
        self.peticion = peticion
        self.respuesta = respuesta
        self.interaccion = interaccion

    def a_diccionario(self):
        return {
            "encontrado_en": self.encontrado_en,
            "resultados_extraidos": self.resultados_extraidos,
            "comando_curl": self.comando_curl,
            "peticion": self.peticion,
            "respuesta": self.respuesta,
            "interaccion": self.interaccion,
        }


class Hallazgo:
    def __init__(self, id_hallazgo, titulo, severidad="unknown",
                 descripcion=None, id_plantilla=None, nombre_matcher=None,
                 url=None, referencias=None, etiquetas=None,
                 evidencia=None, primera_vez=None, ultima_vez=None,
                 grupo_dedup=None, tipo=None, puerto=None,
                 ip_resuelta=None, cvss_score=None, cvss_vector=None,
                 cve_ids=None, cwe_ids=None, remediacion=None):
        self.id_hallazgo = id_hallazgo
        self.titulo = titulo
        self.severidad = severidad
        self.descripcion = descripcion
        self.id_plantilla = id_plantilla
        self.nombre_matcher = nombre_matcher
        self.url = url
        self.referencias = referencias if referencias else []
        self.etiquetas = etiquetas if etiquetas else []
        self.evidencia = evidencia
        self.primera_vez = primera_vez
        self.ultima_vez = ultima_vez
        self.grupo_dedup = grupo_dedup
        self.tipo = tipo
        self.puerto = puerto
        self.ip_resuelta = ip_resuelta
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.cve_ids = cve_ids if cve_ids else []
        self.cwe_ids = cwe_ids if cwe_ids else []
        self.remediacion = remediacion

    def a_diccionario(self):
        return {
            "id_hallazgo": self.id_hallazgo, "titulo": self.titulo,
            "severidad": self.severidad, "descripcion": self.descripcion,
            "id_plantilla": self.id_plantilla, "nombre_matcher": self.nombre_matcher,
            "url": self.url, "referencias": self.referencias,
            "etiquetas": self.etiquetas,
            "evidencia": self.evidencia.a_diccionario() if self.evidencia else None,
            "primera_vez": self.primera_vez.isoformat() if self.primera_vez else None,
            "ultima_vez": self.ultima_vez.isoformat() if self.ultima_vez else None,
            "grupo_dedup": self.grupo_dedup, "tipo": self.tipo,
            "puerto": self.puerto, "ip_resuelta": self.ip_resuelta,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "cve_ids": self.cve_ids, "cwe_ids": self.cwe_ids,
            "remediacion": self.remediacion,
        }


class Host:
    def __init__(self, ip, hostnames=None, estado="unknown",
                 mac=None, mac_fabricante=None, sistema_operativo=None,
                 servicios=None, tecnologias=None, hallazgos=None,
                 endpoints=None, scripts_host=None):
        self.ip = ip
        self.hostnames = hostnames if hostnames else []
        self.estado = estado
        self.mac = mac
        self.mac_fabricante = mac_fabricante
        self.sistema_operativo = sistema_operativo
        self.servicios = servicios if servicios else []
        self.tecnologias = tecnologias if tecnologias else []
        self.hallazgos = hallazgos if hallazgos else []
        self.endpoints = endpoints if endpoints else []
        self.scripts_host = scripts_host if scripts_host else []

    def a_diccionario(self):
        return {
            "ip": self.ip, "hostnames": self.hostnames, "estado": self.estado,
            "mac": self.mac, "mac_fabricante": self.mac_fabricante,
            "sistema_operativo": self.sistema_operativo.a_diccionario() if self.sistema_operativo else None,
            "servicios": [s.a_diccionario() for s in self.servicios],
            "tecnologias": [t.a_diccionario() for t in self.tecnologias],
            "hallazgos": [h.a_diccionario() for h in self.hallazgos],
            "endpoints": [e.a_diccionario() for e in self.endpoints],
            "scripts_host": [s.a_diccionario() for s in self.scripts_host],
        }


class MetadatosEscaneo:
    def __init__(self, herramienta, comando, fecha_inicio,
                 id_escaneo=None, version_herramienta=None,
                 fecha_fin=None, tipo_escaneo=None, objetivo=None):
        self.id_escaneo = id_escaneo if id_escaneo else str(uuid4())
        self.herramienta = herramienta
        self.comando = comando
        self.fecha_inicio = fecha_inicio
        self.version_herramienta = version_herramienta
        self.fecha_fin = fecha_fin
        self.tipo_escaneo = tipo_escaneo
        self.objetivo = objetivo

    def a_diccionario(self):
        return {
            "id_escaneo": self.id_escaneo, "herramienta": self.herramienta,
            "comando": self.comando,
            "fecha_inicio": self.fecha_inicio.isoformat() if self.fecha_inicio else None,
            "version_herramienta": self.version_herramienta,
            "fecha_fin": self.fecha_fin.isoformat() if self.fecha_fin else None,
            "tipo_escaneo": self.tipo_escaneo, "objetivo": self.objetivo,
        }


class ResultadoCanonico:
    def __init__(self, metadatos, hosts=None, version_schema="1.0.0"):
        self.metadatos = metadatos
        self.hosts = hosts if hosts else []
        self.version_schema = version_schema

    def total_hosts(self):
        return len(self.hosts)

    def total_servicios(self):
        total = 0
        for host in self.hosts:
            total += len(host.servicios)
        return total

    def total_hallazgos(self):
        total = 0
        for host in self.hosts:
            total += len(host.hallazgos)
        return total

    def hosts_activos(self):
        total = 0
        for host in self.hosts:
            if host.estado == "up":
                total += 1
        return total

    def a_diccionario(self):
        return {
            "version_schema": self.version_schema,
            "metadatos": self.metadatos.a_diccionario(),
            "hosts": [h.a_diccionario() for h in self.hosts],
        }

    def a_json(self):
        return json.dumps(self.a_diccionario(), indent=2, ensure_ascii=False)

    def guardar_json(self, ruta_archivo):
        texto = self.a_json()
        with open(ruta_archivo, "w", encoding="utf-8") as f:
            f.write(texto)
        return len(texto)


def cargar_desde_json(texto_json):
    datos = json.loads(texto_json)
    meta = datos["metadatos"]
    metadatos = MetadatosEscaneo(
        id_escaneo=meta["id_escaneo"], herramienta=meta["herramienta"],
        comando=meta["comando"],
        fecha_inicio=datetime.fromisoformat(meta["fecha_inicio"]) if meta.get("fecha_inicio") else None,
        version_herramienta=meta.get("version_herramienta"),
        fecha_fin=datetime.fromisoformat(meta["fecha_fin"]) if meta.get("fecha_fin") else None,
        tipo_escaneo=meta.get("tipo_escaneo"), objetivo=meta.get("objetivo"),
    )
    lista_hosts = []
    for h in datos.get("hosts", []):
        servicios = []
        for s in h.get("servicios", []):
            scripts = [ResultadoScript(sc["script_id"], sc.get("salida", "")) for sc in s.get("scripts", [])]
            servicios.append(Servicio(
                puerto=s["puerto"], protocolo=s.get("protocolo", "tcp"),
                estado=s.get("estado", "open"), nombre_servicio=s.get("nombre_servicio"),
                producto=s.get("producto"), version=s.get("version"),
                info_extra=s.get("info_extra"), cpe=s.get("cpe", []),
                banner=s.get("banner"), scripts=scripts,
            ))
        so = None
        if h.get("sistema_operativo"):
            d = h["sistema_operativo"]
            so = InfoSO(d["nombre"], d.get("familia"), d.get("precision"), d.get("cpe"))
        tecnologias = [Tecnologia(t["nombre"], t.get("version"), t.get("categoria", "Other")) for t in h.get("tecnologias", [])]
        hallazgos = []
        for f in h.get("hallazgos", []):
            ev = None
            if f.get("evidencia"):
                e = f["evidencia"]
                ev = Evidencia(e.get("encontrado_en"), e.get("resultados_extraidos", []),
                               e.get("comando_curl"), e.get("peticion"), e.get("respuesta"), e.get("interaccion"))
            hallazgos.append(Hallazgo(
                id_hallazgo=f["id_hallazgo"], titulo=f["titulo"],
                severidad=f.get("severidad", "unknown"), descripcion=f.get("descripcion"),
                id_plantilla=f.get("id_plantilla"), url=f.get("url"),
                referencias=f.get("referencias", []), etiquetas=f.get("etiquetas", []),
                evidencia=ev, grupo_dedup=f.get("grupo_dedup"),
                tipo=f.get("tipo"), puerto=f.get("puerto"),
                cvss_score=f.get("cvss_score"), cvss_vector=f.get("cvss_vector"),
                cve_ids=f.get("cve_ids", []), cwe_ids=f.get("cwe_ids", []),
                remediacion=f.get("remediacion"),
            ))
        endpoints = [Endpoint(e.get("url"), e.get("ruta"), e.get("codigo_estado"),
                              e.get("tamano"), e.get("redirige_a"), e.get("tipo", "dir"),
                              e.get("subdominio"), e.get("ip")) for e in h.get("endpoints", [])]
        scripts_host = [ResultadoScript(sc["script_id"], sc.get("salida", "")) for sc in h.get("scripts_host", [])]
        lista_hosts.append(Host(
            ip=h["ip"], hostnames=h.get("hostnames", []), estado=h.get("estado", "unknown"),
            mac=h.get("mac"), mac_fabricante=h.get("mac_fabricante"),
            sistema_operativo=so, servicios=servicios, tecnologias=tecnologias,
            hallazgos=hallazgos, endpoints=endpoints, scripts_host=scripts_host,
        ))
    return ResultadoCanonico(metadatos=metadatos, hosts=lista_hosts,
                             version_schema=datos.get("version_schema", "1.0.0"))
