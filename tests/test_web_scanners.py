"""
Tests del parser de dirb y los edge cases de Gobuster.

Ejecutar: python -m unittest tests.test_web_scanners -v
"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")

def ruta(n): return os.path.join(SAMPLES, n)

from parsers.dirb import parsear_dirb
from parsers.gobuster import parsear_gobuster
from modelos import Host, Servicio
from orquestador import (
    evaluar_primera_ronda, evaluar_tercera_ronda,
    _encontrar_wordlist, PERFILES,
)


# ── Parser dirb ──

class TestDirbParser(unittest.TestCase):

    def setUp(self):
        self.r = parsear_dirb(ruta("dirb_sample.txt"))

    def test_herramienta_es_dirb(self):
        self.assertEqual(self.r.metadatos.herramienta, "dirb")

    def test_encuentra_host(self):
        self.assertEqual(self.r.total_hosts(), 1)

    def test_cuenta_endpoints(self):
        total = sum(len(h.endpoints) for h in self.r.hosts)
        self.assertEqual(total, 13)

    def test_extrae_codigo_estado(self):
        host = self.r.hosts[0]
        login = next(e for e in host.endpoints if "wp-login" in e.ruta)
        self.assertEqual(login.codigo_estado, 200)

    def test_extrae_tamano(self):
        host = self.r.hosts[0]
        login = next(e for e in host.endpoints if "wp-login" in e.ruta)
        self.assertEqual(login.tamano, 6731)

    def test_directorios_tienen_codigo_301(self):
        host = self.r.hosts[0]
        dirs = [e for e in host.endpoints if e.ruta.endswith("/") and e.ruta != "/"]
        for d in dirs:
            self.assertEqual(d.codigo_estado, 301)

    def test_extrae_url_base(self):
        self.assertIn("192.168.56.101", self.r.metadatos.objetivo)

    def test_endpoints_tienen_ruta(self):
        for h in self.r.hosts:
            for e in h.endpoints:
                self.assertIsNotNone(e.ruta)
                self.assertTrue(e.ruta.startswith("/"))

    def test_archivo_vacio_no_falla(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write(""); f.close()
        r = parsear_dirb(f.name)
        self.assertEqual(r.total_hosts(), 0)
        os.unlink(f.name)

    def test_archivo_sin_resultados(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write("""
-----------------
DIRB v2.22
-----------------
URL_BASE: http://192.168.1.1/
GENERATED WORDS: 4612
---- Scanning URL: http://192.168.1.1/ ----
-----------------
END_TIME: Mon Jun 13 18:00:00 2024
DOWNLOADED: 4612 - FOUND: 0
"""); f.close()
        r = parsear_dirb(f.name)
        self.assertEqual(r.total_hosts(), 0)
        os.unlink(f.name)

    def test_no_duplica_urls(self):
        host = self.r.hosts[0]
        urls = [e.url for e in host.endpoints]
        self.assertEqual(len(urls), len(set(urls)))

    def test_archivo_no_existe(self):
        with self.assertRaises(FileNotFoundError):
            parsear_dirb("/ruta/que/no/existe.txt")


# ── Gobuster edge cases ──

class TestGobusterEdgeCases(unittest.TestCase):

    def test_wildcard_detectado(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('WARN: Wildcard response found: http://10.0.0.1/ => 200\n')
        f.write('{"status":200,"url":"http://10.0.0.1/abc","path":"/abc","size":100}\n')
        f.close()
        r = parsear_gobuster(f.name)
        # Wildcard detectado → tipo marcado como dir_wildcard
        self.assertIn("wildcard", r.metadatos.tipo_escaneo)
        os.unlink(f.name)

    def test_scan_parcial_parsea_lo_que_hay(self):
        """Si gobuster se interrumpe, parsea los resultados que llegó a escribir."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('{"status":200,"url":"http://10.0.0.1/admin","path":"/admin","size":100}\n')
        f.write('{"status":200,"url":"http://10.0.0.1/login","path":"/login","size":50}\n')
        # Línea corrupta (scan interrumpido)
        f.write('{"status":200,"url":"http://10')
        f.close()
        r = parsear_gobuster(f.name)
        total = sum(len(h.endpoints) for h in r.hosts)
        self.assertEqual(total, 2)
        os.unlink(f.name)

    def test_lineas_advertencia_ignoradas(self):
        """Líneas que empiezan con WARN:, ERROR:, [-] se ignoran."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('WARN: Timeout connecting to http://10.0.0.1\n')
        f.write('ERROR: could not connect\n')
        f.write('[-] Unable to connect\n')
        f.write('{"status":200,"url":"http://10.0.0.1/","path":"/","size":100}\n')
        f.close()
        r = parsear_gobuster(f.name)
        total = sum(len(h.endpoints) for h in r.hosts)
        self.assertEqual(total, 1)
        os.unlink(f.name)

    def test_sin_resultados_retorna_vacio(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(""); f.close()
        r = parsear_gobuster(f.name)
        self.assertEqual(r.total_hosts(), 0)
        os.unlink(f.name)

    def test_resultado_con_redirect(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('{"status":301,"url":"http://10.0.0.1/admin","path":"/admin","size":0,"redirectlocation":"http://10.0.0.1/admin/"}\n')
        f.close()
        r = parsear_gobuster(f.name)
        ep = r.hosts[0].endpoints[0]
        self.assertEqual(ep.codigo_estado, 301)
        self.assertIsNotNone(ep.redirige_a)
        os.unlink(f.name)

    def test_no_duplica_urls(self):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        # Misma URL dos veces (puede pasar con ciertos flags)
        f.write('{"status":200,"url":"http://10.0.0.1/admin","path":"/admin","size":100}\n')
        f.write('{"status":200,"url":"http://10.0.0.1/admin","path":"/admin","size":100}\n')
        f.close()
        r = parsear_gobuster(f.name)
        total = sum(len(h.endpoints) for h in r.hosts)
        self.assertEqual(total, 1)
        os.unlink(f.name)


# ── Tercera ronda: dirb → Gobuster reactivo ──

class TestTerceraRonda(unittest.TestCase):
    """Gobuster es el primario; dirb solo corre de respaldo si Gobuster no encontró nada."""

    def _host_con_rutas(self, *rutas):
        """Host simulado con los endpoints que encontraría Gobuster."""
        from modelos import Endpoint
        host = Host(ip="10.0.0.1", estado="up")
        for ruta in rutas:
            host.endpoints.append(Endpoint(
                url="http://10.0.0.1" + ruta,
                ruta=ruta,
                codigo_estado=200,
                tipo="dir",
            ))
        return host

    def test_gobuster_vacio_lanza_dirb_respaldo(self):
        host = self._host_con_rutas()  # Gobuster no encontró nada
        tareas = evaluar_tercera_ronda(
            host, "http://10.0.0.1", 80, PERFILES["completo"])
        self.assertEqual(len(tareas), 1)
        self.assertEqual(tareas[0]["herramienta"], "dirb")

    def test_gobuster_none_lanza_dirb_respaldo(self):
        tareas = evaluar_tercera_ronda(
            None, "http://10.0.0.1", 80, PERFILES["completo"])
        self.assertEqual(len(tareas), 1)
        self.assertEqual(tareas[0]["herramienta"], "dirb")

    def test_gobuster_con_rutas_no_lanza_dirb(self):
        host = self._host_con_rutas("/data", "/ip", "/netstat")
        tareas = evaluar_tercera_ronda(
            host, "http://10.0.0.1", 80, PERFILES["completo"])
        # Gobuster encontró rutas → no hace falta el respaldo de dirb
        self.assertEqual(tareas, [])

    def test_primera_ronda_usa_gobuster_no_dirb(self):
        host = Host(ip="10.0.0.1", estado="up")
        host.servicios.append(Servicio(
            puerto=80, protocolo="tcp", estado="open", nombre_servicio="http"))
        tareas = evaluar_primera_ronda(host, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertIn("gobuster", herramientas)
        # dirb no está en la primera ronda (queda para el respaldo)
        self.assertNotIn("dirb", herramientas)


class TestWordlists(unittest.TestCase):
    """Los constructores de wordlist deben encontrar algo o retornar una ruta."""

    def test_wordlist_comun_retorna_ruta(self):
        ruta = _encontrar_wordlist("comun")
        self.assertIsNotNone(ruta)
        self.assertTrue(ruta.endswith(".txt"))

    def test_wordlist_mediana_retorna_ruta(self):
        ruta = _encontrar_wordlist("mediana")
        self.assertIsNotNone(ruta)

    def test_wordlist_wordpress_retorna_ruta(self):
        ruta = _encontrar_wordlist("wordpress")
        self.assertIsNotNone(ruta)

    def test_tipo_invalido_retorna_comun(self):
        ruta = _encontrar_wordlist("tipo_inexistente_999")
        # Debe caer al default (wordlist comun)
        self.assertIsNotNone(ruta)


if __name__ == "__main__":
    unittest.main()
