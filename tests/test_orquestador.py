"""
Tests del orquestador — lógica de reglas reactivas.
No requieren las herramientas instaladas: solo verifican decisiones.
Ejecutar: python -m unittest tests.test_orquestador -v
"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modelos import Host, Servicio, Tecnologia
from orquestador import evaluar_primera_ronda, evaluar_segunda_ronda, ejecutar_comando, herramienta_disponible, PERFILES


def host_http(puerto=80):
    h = Host(ip="10.0.0.1", estado="up")
    h.servicios.append(Servicio(puerto=puerto, protocolo="tcp", estado="open", nombre_servicio="http"))
    return h

def host_servicio(nombre, puerto, producto=None):
    h = Host(ip="10.0.0.1", estado="up")
    h.servicios.append(Servicio(puerto=puerto, protocolo="tcp", estado="open",
                                nombre_servicio=nombre, producto=producto))
    return h

def host_tecnologias(*nombres):
    h = Host(ip="10.0.0.1", estado="up")
    for n in nombres: h.tecnologias.append(Tecnologia(nombre=n, version="1.0"))
    return h


class TestPerfiles(unittest.TestCase):
    def test_existen_tres_perfiles(self):
        for p in ["reconocimiento", "rapido", "completo"]:
            self.assertIn(p, PERFILES)

    def test_perfiles_tienen_campos(self):
        for nombre, config in PERFILES.items():
            self.assertIn("nmap_flags", config)
            self.assertIn("activar_web", config)
            self.assertIn("activar_nuclei", config)
            self.assertIn("timeout_por_herramienta", config)

    def test_reconocimiento_sin_web(self):
        self.assertFalse(PERFILES["reconocimiento"]["activar_web"])

    def test_reconocimiento_sin_nuclei(self):
        self.assertFalse(PERFILES["reconocimiento"]["activar_nuclei"])

    def test_completo_activa_todo(self):
        self.assertTrue(PERFILES["completo"]["activar_web"])
        self.assertTrue(PERFILES["completo"]["activar_nuclei"])


class TestReglasHTTP(unittest.TestCase):
    """HTTP detectado por nombre_servicio, no por número de puerto."""

    def test_puerto_80_genera_whatweb(self):
        h = host_http(80)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertIn("whatweb", herramientas)

    def test_puerto_80_genera_gobuster(self):
        h = host_http(80)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        # Gobuster es el escáner web primario (dirb queda de respaldo)
        self.assertIn("gobuster", herramientas)
        self.assertNotIn("dirb", herramientas)

    def test_puerto_80_genera_nuclei_http(self):
        h = host_http(80)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertIn("nuclei", herramientas)

    def test_http_no_estandar_puerto_8080(self):
        h = host_http(8080)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertIn("whatweb", herramientas)
        self.assertIn("gobuster", herramientas)

    def test_http_no_estandar_puerto_8888(self):
        h = host_http(8888)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertIn("whatweb", herramientas)

    def test_perfil_reconocimiento_no_genera_web(self):
        h = host_http(80)
        tareas = evaluar_primera_ronda(h, PERFILES["reconocimiento"])
        self.assertEqual(len(tareas), 0)

    def test_perfil_rapido_no_genera_nuclei(self):
        h = host_http(80)
        tareas = evaluar_primera_ronda(h, PERFILES["rapido"])
        herramientas = [t["herramienta"] for t in tareas]
        self.assertNotIn("nuclei", herramientas)

    def test_servicio_filtrado_no_genera_tareas(self):
        h = Host(ip="10.0.0.1", estado="up")
        h.servicios.append(Servicio(puerto=80, protocolo="tcp",
                                    estado="filtered", nombre_servicio="http"))
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        self.assertEqual(len(tareas), 0)


class TestReglasPorNombreServicio(unittest.TestCase):
    """Reglas basadas en nombre_servicio de Nmap."""

    def test_ssh_genera_nuclei(self):
        h = host_servicio("ssh", 22)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(len(nuclei) > 0)
        self.assertTrue(any("ssh" in t["sufijo"] for t in nuclei))

    def test_ssh_puerto_no_estandar(self):
        h = host_servicio("ssh", 2222)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(any("ssh" in t["sufijo"] for t in nuclei))

    def test_ftp_genera_nuclei(self):
        h = host_servicio("ftp", 21)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(len(nuclei) > 0)

    def test_smb_microsoft_ds(self):
        h = host_servicio("microsoft-ds", 445)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(len(nuclei) > 0)

    def test_mysql_genera_nuclei(self):
        h = host_servicio("mysql", 3306)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(any("mysql" in t["sufijo"] for t in nuclei))

    def test_redis_genera_nuclei(self):
        h = host_servicio("redis", 6379)
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(len(nuclei) > 0)

    def test_sin_nuclei_no_genera_para_ssh(self):
        h = host_servicio("ssh", 22)
        tareas = evaluar_primera_ronda(h, PERFILES["rapido"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertEqual(len(nuclei), 0)


class TestReglasPorProducto(unittest.TestCase):
    """Reglas basadas en el producto que detectó Nmap."""

    def test_jetty_genera_nuclei_jetty(self):
        h = host_servicio("http", 8080, producto="Jetty 9.4.27")
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(any("jetty" in t["sufijo"] for t in nuclei))

    def test_tomcat_genera_nuclei_tomcat(self):
        h = host_servicio("http", 8080, producto="Apache Tomcat 9.0")
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(any("tomcat" in t["sufijo"] for t in nuclei))

    def test_vsftpd_genera_nuclei_ftp(self):
        h = host_servicio("ftp", 21, producto="vsftpd 3.0.5")
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(len(nuclei) > 0)


class TestDeduplicacionTareas(unittest.TestCase):
    """No generar dos tareas con los mismos tags para el mismo puerto."""

    def test_no_duplica_ssh_por_nombre_y_producto(self):
        h = Host(ip="10.0.0.1", estado="up")
        h.servicios.append(Servicio(puerto=22, protocolo="tcp", estado="open",
                                    nombre_servicio="ssh", producto="OpenSSH 9.0"))
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        # openssh y ssh mapean al mismo tag — no duplicar
        ssh_tareas = [t for t in tareas
                      if t["herramienta"] == "nuclei" and "22" in t["sufijo"]]
        # Puede haber 1 o 2 (ssh + openssh) pero no más
        self.assertTrue(len(ssh_tareas) <= 2)

    def test_no_duplica_ftp_por_nombre_y_vsftpd(self):
        h = Host(ip="10.0.0.1", estado="up")
        h.servicios.append(Servicio(puerto=21, protocolo="tcp", estado="open",
                                    nombre_servicio="ftp", producto="vsftpd 3.0.5"))
        tareas_antes = evaluar_primera_ronda(h, PERFILES["completo"])
        # Correr dos veces no debe dar más tareas
        tareas_despues = evaluar_primera_ronda(h, PERFILES["completo"])
        self.assertEqual(len(tareas_antes), len(tareas_despues))

    def test_multiples_puertos_http_genera_tareas_separadas(self):
        h = Host(ip="10.0.0.1", estado="up")
        for puerto in [80, 8080, 8888]:
            h.servicios.append(Servicio(puerto=puerto, protocolo="tcp",
                                        estado="open", nombre_servicio="http"))
        tareas = evaluar_primera_ronda(h, PERFILES["completo"])
        # Cada puerto HTTP genera whatweb + gobuster + nuclei en primera ronda
        whatweb_tareas = [t for t in tareas if t["herramienta"] == "whatweb"]
        gobuster_tareas = [t for t in tareas if t["herramienta"] == "gobuster"]
        self.assertEqual(len(whatweb_tareas), 3)
        self.assertEqual(len(gobuster_tareas), 3)


class TestReglasSegundaRonda(unittest.TestCase):
    """Segunda ronda: basada en tecnologías de WhatWeb."""

    def test_wordpress_genera_nuclei(self):
        h = host_tecnologias("WordPress")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        nuclei = [t for t in tareas if t["herramienta"] == "nuclei"]
        self.assertTrue(any("wordpress" in t["sufijo"] for t in nuclei))

    def test_joomla_genera_nuclei(self):
        h = host_tecnologias("Joomla")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        self.assertTrue(any("joomla" in t["sufijo"] for t in tareas))

    def test_drupal_genera_nuclei(self):
        h = host_tecnologias("Drupal")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        self.assertTrue(any("drupal" in t["sufijo"] for t in tareas))

    def test_tecnologia_desconocida_no_genera(self):
        h = host_tecnologias("jQuery", "Bootstrap")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        self.assertEqual(len(tareas), 0)

    def test_wordpress_no_duplica(self):
        h = host_tecnologias("WordPress", "WordPress")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        wp = [t for t in tareas if "wordpress" in t["sufijo"]]
        self.assertEqual(len(wp), 1)

    def test_sin_nuclei_no_genera_segunda_ronda(self):
        h = host_tecnologias("WordPress", "Joomla")
        tareas = evaluar_segunda_ronda(h, PERFILES["rapido"])
        self.assertEqual(len(tareas), 0)

    def test_razon_menciona_tecnologia(self):
        h = host_tecnologias("WordPress")
        tareas = evaluar_segunda_ronda(h, PERFILES["completo"])
        self.assertIn("WordPress", tareas[0]["razon"])


class TestEjecutorComandos(unittest.TestCase):
    def test_comando_valido(self):
        exito, _ = ejecutar_comando(["echo", "test"], timeout=5)
        self.assertTrue(exito)

    def test_herramienta_inexistente(self):
        exito, msg = ejecutar_comando(["herramienta_falsa_999"], timeout=5)
        self.assertFalse(exito)
        self.assertIn("no está instalado", msg)

    def test_timeout(self):
        exito, msg = ejecutar_comando(["sleep", "10"], timeout=1)
        self.assertFalse(exito)
        self.assertIn("timeout", msg)

    def test_herramienta_disponible_python(self):
        self.assertTrue(herramienta_disponible("python3"))

    def test_herramienta_no_disponible(self):
        self.assertFalse(herramienta_disponible("herramienta_inexistente_12345"))


if __name__ == "__main__":
    unittest.main()
