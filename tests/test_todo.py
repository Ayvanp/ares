"""
Tests de ARES — cubre parsers, modelo, BD, correlación, deduplicación y reportes.
Ejecutar: python -m unittest discover tests -v
"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")

def ruta(n): return os.path.join(SAMPLES, n)

from parsers.nmap import parsear_nmap
from parsers.whatweb import parsear_whatweb
from parsers.gobuster import parsear_gobuster
from parsers.nuclei import parsear_nuclei
from modelos import cargar_desde_json, Host, Hallazgo, MetadatosEscaneo, ResultadoCanonico
from base_datos.conexion import BaseDatos
from base_datos.operaciones import (
    guardar_resultado, guardar_resultado_combinado,
    obtener_todos_los_escaneos, obtener_hallazgos_por_severidad,
    obtener_resumen, buscar_duplicados,
)
from correlacion import correlacionar
from reportes.generador import generar_reporte_html, generar_reporte_csv


# ── Nmap ──
class TestNmap(unittest.TestCase):
    def setUp(self): self.r = parsear_nmap(ruta("nmap_sample.xml"))
    def test_herramienta(self): self.assertEqual(self.r.metadatos.herramienta, "nmap")
    def test_hosts(self): self.assertEqual(self.r.total_hosts(), 4)
    def test_servicios(self): self.assertEqual(self.r.total_servicios(), 10)
    def test_ip_correcta(self): ips = [h.ip for h in self.r.hosts]; self.assertIn("192.168.56.101", ips)
    def test_so_detectado(self):
        h = next(h for h in self.r.hosts if h.ip == "192.168.56.101")
        self.assertIsNotNone(h.sistema_operativo)
        self.assertIn("Linux", h.sistema_operativo.nombre)
    def test_archivo_no_existe(self):
        with self.assertRaises(FileNotFoundError): parsear_nmap("/no/existe.xml")
    def test_xml_invalido(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
        f.write("<nope/>"); f.close()
        with self.assertRaises(ValueError): parsear_nmap(f.name)
        os.unlink(f.name)


# ── WhatWeb ──
class TestWhatWeb(unittest.TestCase):
    def setUp(self): self.r = parsear_whatweb(ruta("whatweb_sample.json"))
    def test_herramienta(self): self.assertEqual(self.r.metadatos.herramienta, "whatweb")
    def test_tiene_hosts(self): self.assertTrue(self.r.total_hosts() >= 1)
    def test_detecta_wordpress(self):
        h = next(h for h in self.r.hosts if h.ip == "192.168.56.101")
        nombres = [t.nombre for t in h.tecnologias]
        self.assertIn("WordPress", nombres)
    def test_wordpress_version(self):
        h = next(h for h in self.r.hosts if h.ip == "192.168.56.101")
        wp = next(t for t in h.tecnologias if t.nombre == "WordPress")
        self.assertEqual(wp.version, "6.4.2")
    def test_no_duplica_tecnologias(self):
        for host in self.r.hosts:
            nombres = [t.nombre for t in host.tecnologias]
            self.assertEqual(len(nombres), len(set(nombres)))
    def test_ignora_plugins_informativos(self):
        for host in self.r.hosts:
            nombres = [t.nombre for t in host.tecnologias]
            self.assertNotIn("IP", nombres)
            self.assertNotIn("Title", nombres)


# ── Gobuster ──
class TestGobuster(unittest.TestCase):
    def test_modo_dir(self):
        r = parsear_gobuster(ruta("gobuster_sample.jsonl"))
        self.assertEqual(r.metadatos.tipo_escaneo, "dir")
        total_ep = sum(len(h.endpoints) for h in r.hosts)
        self.assertEqual(total_ep, 12)
    def test_endpoint_redireccion(self):
        r = parsear_gobuster(ruta("gobuster_sample.jsonl"))
        ep = next(e for h in r.hosts for e in h.endpoints if e.ruta == "/wp-admin")
        self.assertEqual(ep.codigo_estado, 301)
        self.assertIsNotNone(ep.redirige_a)
    def test_modo_dns(self):
        r = parsear_gobuster(ruta("gobuster_dns_sample.jsonl"))
        self.assertEqual(r.metadatos.tipo_escaneo, "dns")
        self.assertEqual(r.total_hosts(), 4)
    def test_formato_nuevo(self):
        r = parsear_gobuster(ruta("gobuster_new_format.json"))
        total_ep = sum(len(h.endpoints) for h in r.hosts)
        self.assertEqual(total_ep, 5)
    def test_salta_lineas_corruptas(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('{"status":200,"url":"http://1.2.3.4/","path":"/","size":100}\nNO ES JSON\n{"status":200,"url":"http://1.2.3.4/admin","path":"/admin","size":50}\n')
        f.close()
        r = parsear_gobuster(f.name)
        self.assertEqual(sum(len(h.endpoints) for h in r.hosts), 2)
        os.unlink(f.name)


# ── Nuclei ──
class TestNuclei(unittest.TestCase):
    def setUp(self): self.r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
    def test_herramienta(self): self.assertEqual(self.r.metadatos.herramienta, "nuclei")
    def test_ignora_linea_corrupta(self): self.assertEqual(self.r.total_hallazgos(), 6)
    def test_hosts(self): self.assertEqual(self.r.total_hosts(), 3)
    def test_cvss_score(self):
        h = next(f for ho in self.r.hosts for f in ho.hallazgos if f.id_plantilla == "CVE-2021-44228")
        self.assertEqual(h.cvss_score, 10.0)
    def test_cve_ids(self):
        h = next(f for ho in self.r.hosts for f in ho.hallazgos if f.id_plantilla == "CVE-2021-44228")
        self.assertIn("CVE-2021-44228", h.cve_ids)
    def test_peticion_respuesta(self):
        h = next(f for ho in self.r.hosts for f in ho.hallazgos if f.id_plantilla == "apache-detect")
        self.assertIsNotNone(h.evidencia.peticion)
        self.assertIsNotNone(h.evidencia.respuesta)
    def test_dedup_misma_linea(self):
        # No debe haber dos hallazgos con el mismo hash
        hashes = [f.grupo_dedup for ho in self.r.hosts for f in ho.hallazgos]
        self.assertEqual(len(hashes), len(set(hashes)))
    def test_archivo_vacio(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(""); f.close()
        r = parsear_nuclei(f.name)
        self.assertEqual(r.total_hosts(), 0); os.unlink(f.name)


# ── Modelo canónico ──
class TestModelos(unittest.TestCase):
    def test_roundtrip_nmap(self):
        original = parsear_nmap(ruta("nmap_sample.xml"))
        restaurado = cargar_desde_json(original.a_json())
        self.assertEqual(original.total_hosts(), restaurado.total_hosts())
        self.assertEqual(original.total_servicios(), restaurado.total_servicios())
    def test_roundtrip_nuclei(self):
        original = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        restaurado = cargar_desde_json(original.a_json())
        self.assertEqual(original.total_hallazgos(), restaurado.total_hallazgos())
    def test_conserva_cvss(self):
        original = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        restaurado = cargar_desde_json(original.a_json())
        f_orig = next(f for ho in original.hosts for f in ho.hallazgos if f.id_plantilla == "CVE-2021-44228")
        f_rest = next(f for ho in restaurado.hosts for f in ho.hallazgos if f.id_plantilla == "CVE-2021-44228")
        self.assertEqual(f_orig.cvss_score, f_rest.cvss_score)
    def test_guardar_json_archivo(self):
        r = parsear_nmap(ruta("nmap_sample.xml"))
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        f.close(); r.guardar_json(f.name)
        self.assertTrue(os.path.getsize(f.name) > 0); os.unlink(f.name)


# ── Base de datos ──
class BaseBD(unittest.TestCase):
    def setUp(self):
        self.bd = BaseDatos("sqlite:///:memory:")
        self.bd.crear_tablas()


class TestBD(BaseBD):
    def test_guardar_nmap(self):
        r = parsear_nmap(ruta("nmap_sample.xml"))
        e = guardar_resultado(self.bd, r, objetivo="192.168.56.0/24")
        res = obtener_resumen(self.bd, e.id)
        self.assertEqual(res["activos"], 4)
        self.assertEqual(res["servicios"], 10)

    def test_guardar_combinado(self):
        resultados = [parsear_nmap(ruta("nmap_sample.xml")),
                      parsear_nuclei(ruta("nuclei_sample.jsonl"))]
        e = guardar_resultado_combinado(self.bd, resultados, "192.168.56.0/24")
        res = obtener_resumen(self.bd, e.id)
        self.assertTrue(res["hallazgos"] > 0)
        self.assertTrue(res["servicios"] > 0)

    def test_dedup_bd(self):
        """El mismo hallazgo no debe guardarse dos veces en el mismo escaneo."""
        r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        # Guardar dos veces el mismo resultado
        e = guardar_resultado_combinado(self.bd, [r, r], "192.168.56.0/24")
        res = obtener_resumen(self.bd, e.id)
        # Con dedup debe haber el mismo número que sin duplicar
        r_original = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        e2 = guardar_resultado(self.bd, r_original)
        res2 = obtener_resumen(self.bd, e2.id)
        self.assertEqual(res["hallazgos"], res2["hallazgos"])

    def test_buscar_por_severidad(self):
        r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        guardar_resultado(self.bd, r)
        criticos = obtener_hallazgos_por_severidad(self.bd, "critical")
        self.assertEqual(len(criticos), 1)
        self.assertIn("Log4j", criticos[0].titulo)

    def test_no_host_duplicado_en_merge(self):
        resultados = [parsear_nmap(ruta("nmap_sample.xml")),
                      parsear_whatweb(ruta("whatweb_sample.json"))]
        e = guardar_resultado_combinado(self.bd, resultados, "192.168.56.0/24")
        from base_datos.tablas import TablaActivo
        sesion = self.bd.nueva_sesion()
        activos = sesion.query(TablaActivo).filter_by(escaneo_id=e.id).all()
        sesion.close()
        ips = [a.ip for a in activos]
        self.assertEqual(len(ips), len(set(ips)))


# ── Correlación ──
class TestCorrelacion(unittest.TestCase):
    def setUp(self):
        self.resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        self.reporte = correlacionar(self.resultados)

    def test_genera_reporte(self):
        self.assertIn("hosts", self.reporte)
        self.assertIn("estadisticas", self.reporte)

    def test_no_duplica_hosts(self):
        ips = [h["ip"] for h in self.reporte["hosts"]]
        self.assertEqual(len(ips), len(set(ips)))

    def test_cvss_linked_to_service(self):
        host = next((h for h in self.reporte["hosts"] if h["ip"] == "192.168.56.102"), None)
        self.assertIsNotNone(host)
        cve = next((c for c in host["correlaciones"] if "CVE-2023-25136" in (c.get("id_plantilla") or "")), None)
        self.assertIsNotNone(cve)
        tipos = [v["tipo"] for v in cve["vinculos"]]
        self.assertIn("servicio", tipos)

    def test_apache_software_cruzado(self):
        host = next((h for h in self.reporte["hosts"] if h["ip"] == "192.168.56.101"), None)
        self.assertIsNotNone(host)
        nombres = [sw["software"] for sw in host["software_multi_herramienta"]]
        self.assertIn("Apache", nombres)

    def test_confianza_valores_validos(self):
        for host in self.reporte["hosts"]:
            for c in host["correlaciones"]:
                self.assertIn(c["confianza"], ["alta", "media", "baja"])


# ── Reportes ──
class TestReportes(BaseBD):
    def setUp(self):
        super().setUp()
        resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        self.escaneo = guardar_resultado_combinado(self.bd, resultados, "192.168.56.0/24")
        os.makedirs("reportes/salida", exist_ok=True)

    def test_genera_html(self):
        ruta_out = tempfile.mktemp(suffix=".html")
        generar_reporte_html(self.bd, self.escaneo.id, ruta_out)
        self.assertTrue(os.path.exists(ruta_out))
        self.assertTrue(os.path.getsize(ruta_out) > 10000)
        with open(ruta_out) as f: contenido = f.read()
        self.assertIn("<!DOCTYPE html>", contenido)
        self.assertIn("192.168.56", contenido)
        os.unlink(ruta_out)

    def test_html_contiene_hallazgos(self):
        ruta_out = tempfile.mktemp(suffix=".html")
        generar_reporte_html(self.bd, self.escaneo.id, ruta_out)
        with open(ruta_out) as f: contenido = f.read()
        self.assertIn("Crítica", contenido)
        self.assertIn("Log4j", contenido)
        os.unlink(ruta_out)

    def test_genera_csv(self):
        ruta_out = tempfile.mktemp(suffix=".csv")
        generar_reporte_csv(self.bd, self.escaneo.id, ruta_out)
        self.assertTrue(os.path.exists(ruta_out))
        with open(ruta_out) as f: lineas = f.readlines()
        # Encabezado + hallazgos
        self.assertTrue(len(lineas) > 1)
        self.assertIn("Severidad", lineas[0])
        os.unlink(ruta_out)

    def test_csv_tiene_campos_correctos(self):
        ruta_out = tempfile.mktemp(suffix=".csv")
        generar_reporte_csv(self.bd, self.escaneo.id, ruta_out)
        with open(ruta_out) as f:
            import csv
            reader = csv.DictReader(f)
            filas = list(reader)
        self.assertTrue(len(filas) > 0)
        self.assertIn("IP", filas[0])
        self.assertIn("Severidad", filas[0])
        self.assertIn("Título", filas[0])
        os.unlink(ruta_out)

    def test_escaneo_no_encontrado(self):
        from reportes.generador import generar_reporte_html
        with self.assertRaises(ValueError):
            generar_reporte_html(self.bd, "id-falso-123")


if __name__ == "__main__":
    unittest.main()


# ── Tests adicionales Nmap ──
class TestNmapAdicional(unittest.TestCase):
    def setUp(self): self.r = parsear_nmap(ruta("nmap_sample.xml"))

    def test_servicios_tienen_puerto_entero(self):
        for h in self.r.hosts:
            for s in h.servicios: self.assertIsInstance(s.puerto, int)

    def test_host_tiene_mac_o_none(self):
        for h in self.r.hosts:
            if h.mac: self.assertIn(":", h.mac)

    def test_so_tiene_precision(self):
        for h in self.r.hosts:
            if h.sistema_operativo and h.sistema_operativo.precision:
                self.assertGreater(h.sistema_operativo.precision, 0)

    def test_servicios_tienen_estado(self):
        for h in self.r.hosts:
            for s in h.servicios:
                self.assertIn(s.estado, ["open","closed","filtered","open_filtered","unfiltered"])

    def test_roundtrip_preserva_servicios(self):
        original = self.r; restaurado = cargar_desde_json(original.a_json())
        puertos_orig = sorted([s.puerto for h in original.hosts for s in h.servicios])
        puertos_rest = sorted([s.puerto for h in restaurado.hosts for s in h.servicios])
        self.assertEqual(puertos_orig, puertos_rest)


# ── Tests adicionales Nuclei ──
class TestNucleiAdicional(unittest.TestCase):
    def setUp(self): self.r = parsear_nuclei(ruta("nuclei_sample.jsonl"))

    def test_hallazgos_tienen_titulo(self):
        for h in self.r.hosts:
            for f in h.hallazgos: self.assertIsNotNone(f.titulo)

    def test_hallazgos_tienen_severidad_valida(self):
        validas = {"critical","high","medium","low","info","unknown"}
        for h in self.r.hosts:
            for f in h.hallazgos: self.assertIn(f.severidad, validas)

    def test_hallazgo_critical_tiene_cvss(self):
        f = next(f for h in self.r.hosts for f in h.hallazgos if f.severidad == "critical")
        self.assertIsNotNone(f.cvss_score)
        self.assertGreater(f.cvss_score, 0)

    def test_hallazgo_tiene_grupo_dedup(self):
        for h in self.r.hosts:
            for f in h.hallazgos: self.assertIsNotNone(f.grupo_dedup)

    def test_hashes_dedup_unicos(self):
        hashes = [f.grupo_dedup for h in self.r.hosts for f in h.hallazgos]
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_cve_tiene_url_nvd(self):
        f = next(f for h in self.r.hosts for f in h.hallazgos if f.cve_ids)
        nvd_refs = [r for r in f.referencias if "nvd.nist.gov" in r]
        self.assertTrue(len(nvd_refs) > 0)

    def test_tipo_plantilla_valido(self):
        tipos_validos = {"http","network","dns","ssl","file","code",None}
        for h in self.r.hosts:
            for f in h.hallazgos:
                self.assertIn(f.tipo, tipos_validos)

    def test_evidencia_encontrado_en(self):
        for h in self.r.hosts:
            for f in h.hallazgos:
                if f.evidencia: self.assertIsNotNone(f.evidencia.encontrado_en)


# ── Tests adicionales Gobuster ──
class TestGobusterAdicional(unittest.TestCase):
    def test_endpoints_tienen_codigo_estado(self):
        r = parsear_gobuster(ruta("gobuster_sample.jsonl"))
        for h in r.hosts:
            for e in h.endpoints: self.assertIsNotNone(e.codigo_estado)

    def test_endpoints_tienen_ruta(self):
        r = parsear_gobuster(ruta("gobuster_sample.jsonl"))
        for h in r.hosts:
            for e in h.endpoints: self.assertIsNotNone(e.ruta)

    def test_dns_subdominios_tienen_hostname(self):
        r = parsear_gobuster(ruta("gobuster_dns_sample.jsonl"))
        for h in r.hosts: self.assertTrue(len(h.hostnames) > 0)

    def test_formato_nuevo_modo_dir(self):
        r = parsear_gobuster(ruta("gobuster_new_format.json"))
        self.assertEqual(r.metadatos.tipo_escaneo, "dir")

    def test_archivo_vacio_no_falla(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(""); f.close()
        r = parsear_gobuster(f.name)
        self.assertEqual(r.total_hosts(), 0); os.unlink(f.name)


# ── Tests adicionales WhatWeb ──
class TestWhatWebAdicional(unittest.TestCase):
    def setUp(self): self.r = parsear_whatweb(ruta("whatweb_sample.json"))

    def test_tecnologias_tienen_nombre(self):
        for h in self.r.hosts:
            for t in h.tecnologias: self.assertIsNotNone(t.nombre)

    def test_tecnologias_tienen_categoria(self):
        for h in self.r.hosts:
            for t in h.tecnologias: self.assertIsNotNone(t.categoria)

    def test_apache_tiene_categoria_web_server(self):
        for h in self.r.hosts:
            for t in h.tecnologias:
                if t.nombre == "Apache":
                    self.assertEqual(t.categoria, "Web Server")

    def test_json_invalido_lanza_error(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("no es json"); f.close()
        with self.assertRaises(ValueError): parsear_whatweb(f.name)
        os.unlink(f.name)


# ── Tests adicionales Modelos ──
class TestModelosAdicional(unittest.TestCase):
    def test_roundtrip_whatweb(self):
        original = parsear_whatweb(ruta("whatweb_sample.json"))
        restaurado = cargar_desde_json(original.a_json())
        t_orig = sum(len(h.tecnologias) for h in original.hosts)
        t_rest = sum(len(h.tecnologias) for h in restaurado.hosts)
        self.assertEqual(t_orig, t_rest)

    def test_roundtrip_gobuster(self):
        original = parsear_gobuster(ruta("gobuster_sample.jsonl"))
        restaurado = cargar_desde_json(original.a_json())
        e_orig = sum(len(h.endpoints) for h in original.hosts)
        e_rest = sum(len(h.endpoints) for h in restaurado.hosts)
        self.assertEqual(e_orig, e_rest)

    def test_total_hosts(self):
        r = parsear_nmap(ruta("nmap_sample.xml"))
        self.assertEqual(r.total_hosts(), len(r.hosts))

    def test_total_hallazgos(self):
        r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        conteo_manual = sum(len(h.hallazgos) for h in r.hosts)
        self.assertEqual(r.total_hallazgos(), conteo_manual)


# ── Tests adicionales BD ──
class TestBDAdicional(BaseBD):
    def test_guardar_cuatro_herramientas(self):
        resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        e = guardar_resultado_combinado(self.bd, resultados, "192.168.56.0/24")
        r = obtener_resumen(self.bd, e.id)
        self.assertTrue(r["tecnologias"] > 0)
        self.assertTrue(r["endpoints"] > 0)

    def test_escaneos_listados(self):
        r = parsear_nmap(ruta("nmap_sample.xml"))
        guardar_resultado(self.bd, r)
        guardar_resultado(self.bd, r)
        escaneos = obtener_todos_los_escaneos(self.bd)
        self.assertEqual(len(escaneos), 2)

    def test_escaneo_mas_reciente_primero(self):
        r = parsear_nmap(ruta("nmap_sample.xml"))
        guardar_resultado(self.bd, r)
        guardar_resultado(self.bd, r)
        escaneos = obtener_todos_los_escaneos(self.bd)
        self.assertGreaterEqual(str(escaneos[0].creado_en), str(escaneos[1].creado_en))


# ── Tests adicionales Correlación ──
class TestCorrelacionAdicional(unittest.TestCase):
    def setUp(self):
        self.resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        self.reporte = correlacionar(self.resultados)

    def test_estadisticas_tiene_totales(self):
        est = self.reporte["estadisticas"]
        self.assertIn("total_correlaciones", est)
        self.assertIn("total_hosts", est)

    def test_correlaciones_vacio_no_falla(self):
        r = correlacionar([])
        self.assertEqual(r["estadisticas"]["total_hosts"], 0)

    def test_hallazgo_sin_puerto_no_vincula_servicio(self):
        from modelos import Hallazgo, MetadatosEscaneo, ResultadoCanonico
        from datetime import datetime, timezone
        h = Host(ip="10.0.0.1", estado="up")
        h.hallazgos.append(Hallazgo("test-1", "Test hallazgo", "info"))
        res = ResultadoCanonico(
            metadatos=MetadatosEscaneo("nuclei","nuclei", datetime.now(tz=timezone.utc)),
            hosts=[h])
        reporte = correlacionar([res])
        corrs = reporte["hosts"][0]["correlaciones"]
        servicios = [v for c in corrs for v in c["vinculos"] if v["tipo"] == "servicio"]
        self.assertEqual(len(servicios), 0)

    def test_multiples_vinculos_dan_confianza_alta(self):
        hay_alta = any(
            c["confianza"] == "alta"
            for host in self.reporte["hosts"]
            for c in host["correlaciones"]
        )
        resultados_completos = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        reporte2 = correlacionar(resultados_completos)
        alta_completo = any(
            c["confianza"] == "alta"
            for host in reporte2["hosts"]
            for c in host["correlaciones"]
        )
        self.assertTrue(alta_completo)

    def test_razon_no_vacia(self):
        for host in self.reporte["hosts"]:
            for c in host["correlaciones"]:
                self.assertTrue(len(c["razon"]) > 0)

    def test_vinculos_tienen_tipo_valido(self):
        tipos_validos = {"servicio", "tecnologia", "endpoint"}
        resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        reporte = correlacionar(resultados)
        for host in reporte["hosts"]:
            for c in host["correlaciones"]:
                for v in c["vinculos"]:
                    self.assertIn(v["tipo"], tipos_validos)


class TestVhosts(unittest.TestCase):
    def test_descubrir_desde_cert(self):
        from datetime import datetime, timezone
        from modelos import (ResultadoCanonico, MetadatosEscaneo, Host,
                             Servicio, ResultadoScript)
        from vhosts import descubrir_hostnames
        sc = ResultadoScript("ssl-cert",
            "Subject: commonName=fireflow.htb\nDNS:fireflow.htb, DNS:*.fireflow.htb")
        svc = Servicio(puerto=443, nombre_servicio="https", scripts=[sc])
        host = Host(ip="10.10.10.10", servicios=[svc])
        meta = MetadatosEscaneo("nmap", "nmap", datetime.now(tz=timezone.utc))
        r = ResultadoCanonico(metadatos=meta, hosts=[host])
        self.assertIn("fireflow.htb", descubrir_hostnames(r))

    def test_agregar_y_limpiar_hosts(self):
        import tempfile, os
        from vhosts import agregar_a_etc_hosts, limpiar_etc_hosts
        f = tempfile.mktemp()
        with open(f, "w") as fh: fh.write("127.0.0.1 localhost\n")
        ag, _ = agregar_a_etc_hosts("10.1.1.1", ["fireflow.htb"], ruta=f)
        self.assertEqual(ag, ["fireflow.htb"])
        ag2, _ = agregar_a_etc_hosts("10.1.1.1", ["fireflow.htb"], ruta=f)  # idempotente
        self.assertEqual(ag2, [])
        n, _ = limpiar_etc_hosts(ruta=f)
        self.assertEqual(n, 1)
        with open(f) as fh: self.assertNotIn("fireflow.htb", fh.read())
        os.unlink(f)
