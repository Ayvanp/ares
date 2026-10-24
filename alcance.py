"""
Compuerta de alcance de ARES.

Lógica pura (sin base de datos) que decide si un escaneo puede ejecutarse:

  1. ``engagement_vigente`` — el engagement está activo, con NDA y RoE
     firmados, y la hora actual cae dentro de la ventana autorizada.
  2. ``objetivo_en_alcance`` — el objetivo pedido coincide con alguna de las
     entradas de alcance autorizadas (IP exacta, rango CIDR, hostname o dominio).

Ambas condiciones deben cumplirse para que un escaneo activo arranque. Es una
compuerta dura del flujo, no una recomendación: si falta cualquiera, ARES no
ejecuta nada y registra el intento denegado en la auditoría.
"""

import ipaddress
from datetime import datetime, timezone


def _a_utc(fecha):
    """Normaliza una fecha a UTC con zona horaria. Trata las naive como UTC."""
    if fecha is None:
        return None
    if fecha.tzinfo is None:
        return fecha.replace(tzinfo=timezone.utc)
    return fecha.astimezone(timezone.utc)


def engagement_vigente(engagement, ahora=None):
    """
    Devuelve (True, "") si el engagement habilita escaneos activos ahora mismo,
    o (False, motivo) explicando por qué no.
    """
    if engagement is None:
        return False, "No existe el engagement"
    if ahora is None:
        ahora = datetime.now(tz=timezone.utc)
    ahora = _a_utc(ahora)

    if engagement.estado != "active":
        return False, "El engagement no está activo (estado: " + str(engagement.estado) + ")"
    if not engagement.nda_firmado:
        return False, "Falta registrar el NDA firmado"
    if not engagement.roe_firmado:
        return False, "Faltan registrar las Reglas de Enganchamiento (RoE) firmadas"

    inicio = _a_utc(engagement.ventana_inicio)
    fin = _a_utc(engagement.ventana_fin)
    if inicio and ahora < inicio:
        return False, "La ventana autorizada todavía no comienza"
    if fin and ahora > fin:
        return False, "La ventana autorizada ya terminó"
    return True, ""


def _normalizar_host(valor):
    return (valor or "").strip().strip(".").lower()


def _es_ip(valor):
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def _coincide_entrada(tipo, valor, objetivo):
    tipo = (tipo or "").lower().strip()
    valor = (valor or "").strip()
    objetivo = (objetivo or "").strip()
    if not valor or not objetivo:
        return False

    if tipo == "ip":
        if _es_ip(objetivo) and _es_ip(valor):
            return ipaddress.ip_address(objetivo) == ipaddress.ip_address(valor)
        return False

    if tipo == "cidr":
        if not _es_ip(objetivo):
            return False
        try:
            red = ipaddress.ip_network(valor, strict=False)
        except ValueError:
            return False
        return ipaddress.ip_address(objetivo) in red

    if tipo == "hostname":
        return _normalizar_host(valor) == _normalizar_host(objetivo)

    if tipo == "dominio":
        dom = _normalizar_host(valor)
        obj = _normalizar_host(objetivo)
        # El dominio cubre al propio dominio y a cualquier subdominio.
        return obj == dom or obj.endswith("." + dom)

    return False


def objetivo_en_alcance(alcances, objetivo):
    """
    ``alcances``: iterable de objetos/tuplas con ``tipo`` y ``valor``.
    Devuelve True si ``objetivo`` coincide con al menos una entrada.
    """
    for entrada in alcances or []:
        if isinstance(entrada, (tuple, list)):
            tipo, valor = entrada[0], entrada[1]
        else:
            tipo, valor = getattr(entrada, "tipo", None), getattr(entrada, "valor", None)
        if _coincide_entrada(tipo, valor, objetivo):
            return True
    return False


def autorizado(engagement, objetivo, ahora=None):
    """
    Combina ambas comprobaciones. Devuelve (True, "") o (False, motivo).
    """
    ok, motivo = engagement_vigente(engagement, ahora=ahora)
    if not ok:
        return False, motivo
    if not objetivo_en_alcance(getattr(engagement, "alcances", []), objetivo):
        return False, "El objetivo '" + str(objetivo) + "' no está dentro del alcance autorizado"
    return True, ""
