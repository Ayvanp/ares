"""
Pruebas de la Etapa 0: autenticación, modelo de engagement, compuerta de
alcance, auditoría y cola de escaneos.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alcance import (
    objetivo_en_alcance, engagement_vigente, autorizado, _coincide_entrada,
)


class _EngFalso:
    """Engagement mínimo para probar la lógica pura sin base de datos."""
    def __init__(self, estado="active", nda=True, roe=True,
                 inicio=None, fin=None, alcances=None):
        self.estado = estado
        self.nda_firmado = nda
        self.roe_firmado = roe
        self.ventana_inicio = inicio
        self.ventana_fin = fin
        self.alcances = alcances or []


class PruebasAlcance(unittest.TestCase):
    def test_ip_exacta(self):
        self.assertTrue(_coincide_entrada("ip", "10.0.0.5", "10.0.0.5"))
        self.assertFalse(_coincide_entrada("ip", "10.0.0.5", "10.0.0.6"))

    def test_cidr(self):
        self.assertTrue(_coincide_entrada("cidr", "10.0.0.0/24", "10.0.0.200"))
        self.assertFalse(_coincide_entrada("cidr", "10.0.0.0/24", "10.0.1.1"))

    def test_hostname(self):
        self.assertTrue(_coincide_entrada("hostname", "App.Example.com", "app.example.com"))
        self.assertFalse(_coincide_entrada("hostname", "app.example.com", "otro.example.com"))

    def test_dominio_cubre_subdominios(self):
        self.assertTrue(_coincide_entrada("dominio", "example.com", "api.example.com"))
        self.assertTrue(_coincide_entrada("dominio", "example.com", "example.com"))
        self.assertFalse(_coincide_entrada("dominio", "example.com", "example.org"))
        self.assertFalse(_coincide_entrada("dominio", "example.com", "notexample.com"))

    def test_objetivo_en_alcance_mixto(self):
        alc = [("cidr", "192.168.1.0/24"), ("dominio", "cliente.cl")]
        self.assertTrue(objetivo_en_alcance(alc, "192.168.1.50"))
        self.assertTrue(objetivo_en_alcance(alc, "www.cliente.cl"))
        self.assertFalse(objetivo_en_alcance(alc, "8.8.8.8"))
        self.assertFalse(objetivo_en_alcance([], "10.0.0.1"))


class PruebasVigencia(unittest.TestCase):
    def test_activo_ok(self):
        ok, _ = engagement_vigente(_EngFalso())
        self.assertTrue(ok)

    def test_no_activo(self):
        ok, motivo = engagement_vigente(_EngFalso(estado="draft"))
        self.assertFalse(ok); self.assertIn("activo", motivo)

    def test_sin_nda_o_roe(self):
        self.assertFalse(engagement_vigente(_EngFalso(nda=False))[0])
        self.assertFalse(engagement_vigente(_EngFalso(roe=False))[0])

    def test_ventana(self):
        ahora = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
        futuro = _EngFalso(inicio=ahora + timedelta(hours=1))
        pasado = _EngFalso(fin=ahora - timedelta(hours=1))
        dentro = _EngFalso(inicio=ahora - timedelta(hours=1), fin=ahora + timedelta(hours=1))
        self.assertFalse(engagement_vigente(futuro, ahora=ahora)[0])
        self.assertFalse(engagement_vigente(pasado, ahora=ahora)[0])
        self.assertTrue(engagement_vigente(dentro, ahora=ahora)[0])

    def test_autorizado_combina(self):
        eng = _EngFalso(alcances=[("ip", "10.0.0.1")])
        self.assertTrue(autorizado(eng, "10.0.0.1")[0])
        self.assertFalse(autorizado(eng, "10.0.0.2")[0])          # fuera de alcance
        self.assertFalse(autorizado(_EngFalso(estado="draft", alcances=[("ip", "10.0.0.1")]), "10.0.0.1")[0])


class PruebasAutenticacion(unittest.TestCase):
    def setUp(self):
        from base_datos.conexion import BaseDatos
        self.bd = BaseDatos("sqlite:///" + tempfile.mktemp(suffix=".db"))
        self.bd.crear_tablas()

    def test_extraer_token(self):
        from autenticacion import extraer_token
        self.assertEqual(extraer_token("Bearer abc", None), "abc")
        self.assertEqual(extraer_token(None, "xyz"), "xyz")
        self.assertIsNone(extraer_token("Basic abc", None))
        self.assertIsNone(extraer_token(None, None))

    def test_token_db_y_revocacion(self):
        from autenticacion import crear_token, identidad_de_token, revocar_token
        datos = crear_token(self.bd, "pentester", es_admin=False)
        self.assertTrue(datos["valor"].startswith("ares_"))
        ident = identidad_de_token(self.bd, datos["valor"])
        self.assertEqual(ident["nombre"], "pentester")
        self.assertFalse(ident["es_admin"])
        self.assertIsNone(identidad_de_token(self.bd, "token-falso"))
        revocar_token(self.bd, datos["id"])
        self.assertIsNone(identidad_de_token(self.bd, datos["valor"]))

    def test_token_bootstrap_env(self):
        from autenticacion import identidad_de_token
        os.environ["ARES_API_TOKEN"] = "boot-xyz"
        try:
            ident = identidad_de_token(self.bd, "boot-xyz")
            self.assertTrue(ident["es_admin"])
        finally:
            del os.environ["ARES_API_TOKEN"]


class PruebasGestion(unittest.TestCase):
    def setUp(self):
        from base_datos.conexion import BaseDatos
        self.bd = BaseDatos("sqlite:///" + tempfile.mktemp(suffix=".db"))
        self.bd.crear_tablas()

    def test_flujo_engagement(self):
        from base_datos import gestion
        cli = gestion.crear_cliente(self.bd, "Cliente Demo")
        eng = gestion.crear_engagement(self.bd, cli["id"], "Auditoría web")
        # No se puede activar sin alcance
        with self.assertRaises(ValueError):
            gestion.activar_engagement(self.bd, eng["id"], True, True)
        gestion.agregar_alcance(self.bd, eng["id"], "cidr", "10.10.10.0/24")
        # No se puede activar sin NDA/RoE
        with self.assertRaises(ValueError):
            gestion.activar_engagement(self.bd, eng["id"], True, False)
        gestion.activar_engagement(self.bd, eng["id"], True, True)
        # Compuerta: dentro y fuera de alcance
        self.assertTrue(gestion.evaluar_autorizacion(self.bd, eng["id"], "10.10.10.5")["ok"])
        self.assertFalse(gestion.evaluar_autorizacion(self.bd, eng["id"], "1.2.3.4")["ok"])

    def test_tipo_alcance_invalido(self):
        from base_datos import gestion
        cli = gestion.crear_cliente(self.bd, "C")
        eng = gestion.crear_engagement(self.bd, cli["id"], "E")
        with self.assertRaises(ValueError):
            gestion.agregar_alcance(self.bd, eng["id"], "correo", "a@b.cl")

    def test_auditoria_append(self):
        from base_datos import gestion
        gestion.registrar_auditoria(self.bd, "tester", "escaneo.iniciar",
            objetivo="10.0.0.1", resultado="denegado", detalle="prueba")
        filas = gestion.listar_auditoria(self.bd)
        self.assertEqual(len(filas), 1)
        self.assertEqual(filas[0]["resultado"], "denegado")


class PruebasApi(unittest.TestCase):
    """Flujo completo contra la API con un runner falso (sin herramientas reales)."""
    @classmethod
    def setUpClass(cls):
        os.environ["ARES_DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(suffix=".db")
        os.environ["ARES_API_TOKEN"] = "admin-test"
        import importlib
        import api
        importlib.reload(api)
        cls.api = api
        from base_datos.tablas import TablaEscaneo

        def runner_falso(target, perfil_nombre, bd, escaneo_id):
            s = bd.nueva_sesion()
            e = s.query(TablaEscaneo).filter_by(id=escaneo_id).first()
            if e:
                e.estado = "completed"; s.commit()
            s.close()
        api.cola.runner = runner_falso

        from fastapi.testclient import TestClient
        cls.c = TestClient(api.app)
        cls.admin = {"X-API-Key": "admin-test"}

    @classmethod
    def tearDownClass(cls):
        del os.environ["ARES_API_TOKEN"]
        del os.environ["ARES_DATABASE_URL"]

    def _crear_engagement_activo(self):
        c, h = self.c, self.admin
        cli = c.post("/clientes", params={"nombre": "ACME"}, headers=h).json()
        eng = c.post("/engagements", params={"cliente_id": cli["id"], "nombre": "Pentest"},
                     headers=h).json()
        c.post("/engagements/" + eng["id"] + "/alcance",
               params={"tipo": "ip", "valor": "127.0.0.1"}, headers=h)
        c.post("/engagements/" + eng["id"] + "/activar",
               params={"nda_firmado": True, "roe_firmado": True}, headers=h)
        return eng["id"]

    def test_requiere_auth(self):
        self.assertEqual(self.c.get("/escaneos").status_code, 401)
        self.assertEqual(self.c.post("/clientes", params={"nombre": "x"}).status_code, 401)

    def test_admin_requerido(self):
        tok = self.c.post("/tokens", params={"nombre": "lector"}, headers=self.admin).json()
        headers_lector = {"X-API-Key": tok["valor"]}
        # Un token no-admin puede leer, pero no crear clientes
        self.assertEqual(self.c.get("/escaneos", headers=headers_lector).status_code, 200)
        self.assertEqual(
            self.c.post("/clientes", params={"nombre": "y"}, headers=headers_lector).status_code, 403)

    def test_scope_gate_deniega_fuera_de_alcance(self):
        eng = self._crear_engagement_activo()
        r = self.c.post("/escaneos/iniciar",
                        params={"engagement_id": eng, "target": "8.8.8.8", "perfil": "rapido"},
                        headers=self.admin)
        self.assertEqual(r.status_code, 403)
        # quedó auditado como denegado
        aud = self.c.get("/engagements/" + eng + "/auditoria", headers=self.admin).json()
        self.assertTrue(any(a["resultado"] == "denegado" for a in aud["auditoria"]))

    def test_scope_gate_deniega_engagement_en_borrador(self):
        c, h = self.c, self.admin
        cli = c.post("/clientes", params={"nombre": "Borrador"}, headers=h).json()
        eng = c.post("/engagements", params={"cliente_id": cli["id"], "nombre": "Draft"},
                     headers=h).json()
        c.post("/engagements/" + eng["id"] + "/alcance",
               params={"tipo": "ip", "valor": "127.0.0.1"}, headers=h)
        # sin activar
        r = c.post("/escaneos/iniciar",
                   params={"engagement_id": eng["id"], "target": "127.0.0.1"}, headers=h)
        self.assertEqual(r.status_code, 403)

    def test_scope_gate_permite_y_encola(self):
        eng = self._crear_engagement_activo()
        r = self.c.post("/escaneos/iniciar",
                        params={"engagement_id": eng, "target": "127.0.0.1", "perfil": "rapido"},
                        headers=self.admin)
        self.assertEqual(r.status_code, 200)
        datos = r.json()
        self.assertEqual(datos["estado"], "queued")
        self.api.cola.esperar()
        estado = self.c.get("/escaneos/" + datos["escaneo_id"] + "/estado",
                            headers=self.admin).json()
        self.assertEqual(estado["estado"], "completed")
        aud = self.c.get("/engagements/" + eng + "/auditoria", headers=self.admin).json()
        self.assertTrue(any(a["resultado"] == "permitido" for a in aud["auditoria"]))

    def test_engagement_inexistente(self):
        r = self.c.post("/escaneos/iniciar",
                        params={"engagement_id": "no-existe", "target": "127.0.0.1"},
                        headers=self.admin)
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
