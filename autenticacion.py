"""
Autenticación por token de la API de ARES.

La API dejó de ser abierta. Cada petición debe traer un token, en la cabecera
``Authorization: Bearer <token>`` o ``X-API-Key: <token>``.

- Los tokens se guardan solo como hash SHA-256. El valor en claro se muestra
  una única vez al crearlo (``crear_token``) y no se puede recuperar.
- Un token "admin" puede gestionar tokens y clientes/engagements.
- Para el arranque inicial (bootstrap) se acepta además el valor de la variable
  de entorno ``ARES_API_TOKEN`` como token admin, de modo que siempre haya una
  forma de crear el primer token sin tener ya uno.
"""

import hashlib
import hmac
import os
import secrets

from base_datos.tablas import TablaApiToken, hora_actual

PREFIJO = "ares_"


def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generar_valor_token():
    return PREFIJO + secrets.token_urlsafe(32)


def crear_token(bd, nombre, es_admin=False):
    """Crea un token nuevo y devuelve su valor en claro (mostrar una sola vez)."""
    valor = generar_valor_token()
    sesion = bd.nueva_sesion()
    try:
        fila = TablaApiToken(nombre=nombre, hash_token=_hash(valor),
                             es_admin=bool(es_admin), activo=True)
        sesion.add(fila)
        sesion.commit()
        return {"valor": valor, "id": fila.id, "nombre": nombre, "es_admin": bool(es_admin)}
    finally:
        sesion.close()


def revocar_token(bd, token_id):
    sesion = bd.nueva_sesion()
    try:
        fila = sesion.query(TablaApiToken).filter_by(id=token_id).first()
        if not fila:
            return False
        fila.activo = False
        sesion.commit()
        return True
    finally:
        sesion.close()


def listar_tokens(bd):
    sesion = bd.nueva_sesion()
    try:
        filas = sesion.query(TablaApiToken).all()
        return [{"id": f.id, "nombre": f.nombre, "es_admin": bool(f.es_admin),
                 "activo": bool(f.activo),
                 "creado_en": str(f.creado_en) if f.creado_en else None,
                 "ultimo_uso": str(f.ultimo_uso) if f.ultimo_uso else None}
                for f in filas]
    finally:
        sesion.close()


def identidad_de_token(bd, valor):
    """
    Devuelve la identidad {"nombre", "es_admin"} del token, o None si no es
    válido. Comprueba primero el token admin de entorno (bootstrap).
    """
    if not valor:
        return None

    env = os.environ.get("ARES_API_TOKEN")
    if env and hmac.compare_digest(valor, env):
        return {"nombre": "bootstrap-admin", "es_admin": True}

    sesion = bd.nueva_sesion()
    try:
        fila = sesion.query(TablaApiToken).filter_by(
            hash_token=_hash(valor), activo=True).first()
        if not fila:
            return None
        fila.ultimo_uso = hora_actual()
        sesion.commit()
        return {"nombre": fila.nombre, "es_admin": bool(fila.es_admin)}
    finally:
        sesion.close()


def extraer_token(authorization=None, x_api_key=None):
    """Saca el token de las cabeceras Authorization (Bearer) o X-API-Key."""
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        partes = authorization.strip().split(None, 1)
        if len(partes) == 2 and partes[0].lower() == "bearer":
            return partes[1].strip()
    return None
