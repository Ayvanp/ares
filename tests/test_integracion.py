"""
Tests de integración — flujo completo de parseo, BD, correlación y reportes.
Ejecutar: python -m unittest tests.test_integracion -v
"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")

def ruta(n): return os.path.join(SAMPLES, n)

from parsers.nmap import parsear_nmap
from parsers.whatweb import parsear_whatweb
from parsers.gobuster import parsear_gobuster
from parsers.nuclei import parsear_nuclei
from base_datos.conexion import BaseDatos
from base_datos.operaciones import (
    guardar_resultado_combinado, obtener_resumen,
    obtener_correlaciones, obtener_resumen_correlacion,
    guardar_correlacion,
)
from reportes.generador import generar_reporte_html, generar_reporte_csv


class TestFlujoCuatroHerramientas(unittest.TestCase):
    """Parsear las 4 herramientas, guardar, correlacionar y reportar."""

    def setUp(self):
        self.bd = BaseDatos("sqlite:///:memory:")
        self.bd.crear_tablas()
        self.resultados = [
            parsear_nmap(ruta("nmap_sample.xml")),
            parsear_whatweb(ruta("whatweb_sample.json")),
            parsear_gobuster(ruta("gobuster_sample.jsonl")),
            parsear_nuclei(ruta("nuclei_sample.jsonl")),
        ]
        self.escaneo = guardar_resultado_combinado(
            self.bd, self.resultados, objetivo="192.168.56.0/24"
        )
        os.makedirs("reportes/salida", exist_ok=True)

    def test_escaneo_creado(self):
        self.assertIsNotNone(self.escaneo.id)
        self.assertEqual(self.escaneo.objetivo, "192.168.56.0/24")

    def test_resumen_completo(self):
        r = obtener_resumen(self.bd, self.escaneo.id)
        self.assertEqual(r["activos"], 4)
        self.assertEqual(r["servicios"], 10)
        self.assertTrue(r["tecnologias"] > 0)
        self.assertTrue(r["endpoints"] > 0)
        self.assertTrue(r["hallazgos"] > 0)

    def test_host_tiene_datos_de_todas_herramientas(self):
        from base_datos.tablas import TablaActivo, TablaServicio, TablaTecnologia, TablaEndpoint, TablaHallazgo
        sesion = self.bd.nueva_sesion()
        activo = sesion.query(TablaActivo).filter_by(
            escaneo_id=self.escaneo.id, ip="192.168.56.101").first()
        self.assertIsNotNone(activo)
        svcs = sesion.query(TablaServicio).filter_by(activo_id=activo.id).count()
        tecs = sesion.query(TablaTecnologia).filter_by(activo_id=activo.id).count()
        eps = sesion.query(TablaEndpoint).filter_by(activo_id=activo.id).count()
        halls = sesion.query(TablaHallazgo).filter_by(activo_id=activo.id).count()
        sesion.close()
        self.assertTrue(svcs > 0)   # Nmap
        self.assertTrue(tecs > 0)   # WhatWeb
        self.assertTrue(eps > 0)    # Gobuster
        self.assertTrue(halls > 0)  # Nuclei

    def test_no_ips_duplicadas(self):
        from base_datos.tablas import TablaActivo
        sesion = self.bd.nueva_sesion()
        activos = sesion.query(TablaActivo).filter_by(escaneo_id=self.escaneo.id).all()
        sesion.close()
        ips = [a.ip for a in activos]
        self.assertEqual(len(ips), len(set(ips)))

    def test_correlaciones_persistidas(self):
        corrs = obtener_correlaciones(self.bd, self.escaneo.id)
        self.assertTrue(len(corrs) > 0)

    def test_correlaciones_tienen_ip(self):
        corrs = obtener_correlaciones(self.bd, self.escaneo.id)
        for c in corrs:
            self.assertIsNotNone(c["ip"])
            self.assertTrue(len(c["ip"]) > 0)

    def test_resumen_correlacion(self):
        r = obtener_resumen_correlacion(self.bd, self.escaneo.id)
        self.assertIn("total_correlaciones", r)
        self.assertTrue(r["total_correlaciones"] > 0)

    def test_confianza_alta_existe(self):
        r = obtenet_resumen_correlacion = obtener_resumen_correlacion(self.bd, self.escaneo.id)
        self.assertTrue(r["confianza_alta"] > 0)

    def test_reporte_html_generado(self):
        ruta_out = tempfile.mktemp(suffix=".html")
        generar_reporte_html(self.bd, self.escaneo.id, ruta_out)
        self.assertTrue(os.path.exists(ruta_out))
        self.assertTrue(os.path.getsize(ruta_out) > 5000)
        os.unlink(ruta_out)

    def test_reporte_csv_generado(self):
        ruta_out = tempfile.mktemp(suffix=".csv")
        generar_reporte_csv(self.bd, self.escaneo.id, ruta_out)
        with open(ruta_out) as f:
            lineas = f.readlines()
        # Header + al menos 1 hallazgo
        self.assertTrue(len(lineas) > 1)
        os.unlink(ruta_out)


class TestDeduplicacionIntegracion(unittest.TestCase):
    """La deduplicación debe funcionar en el flujo completo."""

    def setUp(self):
        self.bd = BaseDatos("sqlite:///:memory:")
        self.bd.crear_tablas()

    def test_misma_herramienta_dos_veces_no_duplica(self):
        r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        # Guardar el mismo resultado dos veces
        escaneo = guardar_resultado_combinado(self.bd, [r, r], "192.168.56.0/24")
        resumen = obtener_resumen(self.bd, escaneo.id)
        # Una sola vez
        escaneo2 = guardar_resultado_combinado(self.bd, [r], "192.168.56.0/24")
        resumen2 = obtener_resumen(self.bd, escaneo2.id)
        self.assertEqual(resumen["hallazgos"], resumen2["hallazgos"])

    def test_linea_corrupta_ignorada_en_flujo(self):
        # El sample de nuclei tiene una línea corrupta
        r = parsear_nuclei(ruta("nuclei_sample.jsonl"))
        escaneo = guardar_resultado_combinado(self.bd, [r], "192.168.56.0/24")
        resumen = obtener_resumen(self.bd, escaneo.id)
        # 6 hallazgos válidos, no 7 (la línea corrupta no cuenta)
        self.assertEqual(resumen["hallazgos"], 6)


class TestRecorrelacion(unittest.TestCase):
    """Re-correlacionar un escaneo debe reemplazar, no duplicar."""

    def setUp(self):
        self.bd = BaseDatos("sqlite:///:memory:")
        self.bd.crear_tablas()
        resultados = [parsear_nmap(ruta("nmap_sample.xml")),
                      parsear_nuclei(ruta("nuclei_sample.jsonl"))]
        self.escaneo = guardar_resultado_combinado(self.bd, resultados, "192.168.56.0/24")

    def test_recorrelacion_no_duplica(self):
        conteo_original = len(obtener_correlaciones(self.bd, self.escaneo.id))
        resultados = [parsear_nmap(ruta("nmap_sample.xml")),
                      parsear_nuclei(ruta("nuclei_sample.jsonl"))]
        guardar_correlacion(self.bd, self.escaneo.id, resultados)
        conteo_nuevo = len(obtener_correlaciones(self.bd, self.escaneo.id))
        self.assertEqual(conteo_original, conteo_nuevo)


if __name__ == "__main__":
    unittest.main()
