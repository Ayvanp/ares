"""
Operaciones de base de datos para clientes, engagements, alcance y auditoría.

Separado de ``operaciones.py`` (que maneja resultados de escaneo) porque este
módulo es la gestión del trabajo autorizado, no de los hallazgos.
"""

from datetime import datetime, timezone

from alcance import autorizado
from base_datos.tablas import (
    TablaCliente, TablaEngagement, TablaAlcance, TablaAuditoria, hora_actual,
)

TIPOS_ALCANCE = {"ip", "cidr", "hostname", "dominio"}


def _parsear_fecha(valor):
    """Acepta None, datetime o texto ISO-8601 y devuelve datetime UTC o None."""
    if valor is None or valor == "":
        return None
    if isinstance(valor, datetime):
        return valor
    texto = str(valor).replace("Z", "+00:00")
    dt = datetime.fromisoformat(texto)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ── Clientes ──

def crear_cliente(bd, nombre, notas=None):
    sesion = bd.nueva_sesion()
    try:
        cliente = TablaCliente(nombre=nombre, notas=notas)
        sesion.add(cliente)
        sesion.commit()
        return {"id": cliente.id, "nombre": cliente.nombre}
    finally:
        sesion.close()


def listar_clientes(bd):
    sesion = bd.nueva_sesion()
    try:
        return [{"id": c.id, "nombre": c.nombre, "notas": c.notas,
                 "creado_en": str(c.creado_en) if c.creado_en else None}
                for c in sesion.query(TablaCliente).all()]
    finally:
        sesion.close()


# ── Engagements ──

def crear_engagement(bd, cliente_id, nombre, ventana_inicio=None, ventana_fin=None):
    sesion = bd.nueva_sesion()
    try:
        if not sesion.query(TablaCliente).filter_by(id=cliente_id).first():
            raise ValueError("No existe el cliente " + str(cliente_id))
        eng = TablaEngagement(
            cliente_id=cliente_id, nombre=nombre, estado="draft",
            ventana_inicio=_parsear_fecha(ventana_inicio),
            ventana_fin=_parsear_fecha(ventana_fin),
        )
        sesion.add(eng)
        sesion.commit()
        return {"id": eng.id, "nombre": eng.nombre, "estado": eng.estado}
    finally:
        sesion.close()


def agregar_alcance(bd, engagement_id, tipo, valor):
    tipo = (tipo or "").lower().strip()
    if tipo not in TIPOS_ALCANCE:
        raise ValueError("Tipo de alcance inválido: " + str(tipo) +
                         " (use uno de: " + ", ".join(sorted(TIPOS_ALCANCE)) + ")")
    sesion = bd.nueva_sesion()
    try:
        if not sesion.query(TablaEngagement).filter_by(id=engagement_id).first():
            raise ValueError("No existe el engagement " + str(engagement_id))
        entrada = TablaAlcance(engagement_id=engagement_id, tipo=tipo, valor=valor.strip())
        sesion.add(entrada)
        sesion.commit()
        return {"id": entrada.id, "tipo": entrada.tipo, "valor": entrada.valor}
    finally:
        sesion.close()


def activar_engagement(bd, engagement_id, nda_firmado, roe_firmado):
    """
    Pasa un engagement a "active". Exige NDA y RoE firmados y al menos una
    entrada de alcance; si no, lanza ValueError (la compuerta empieza aquí).
    """
    sesion = bd.nueva_sesion()
    try:
        eng = sesion.query(TablaEngagement).filter_by(id=engagement_id).first()
        if not eng:
            raise ValueError("No existe el engagement " + str(engagement_id))
        if not (nda_firmado and roe_firmado):
            raise ValueError("No se puede activar sin NDA y RoE firmados")
        if not eng.alcances:
            raise ValueError("No se puede activar sin al menos una entrada de alcance")
        eng.nda_firmado = bool(nda_firmado)
        eng.roe_firmado = bool(roe_firmado)
        eng.estado = "active"
        eng.activado_en = hora_actual()
        sesion.commit()
        return {"id": eng.id, "estado": eng.estado}
    finally:
        sesion.close()


def cerrar_engagement(bd, engagement_id):
    sesion = bd.nueva_sesion()
    try:
        eng = sesion.query(TablaEngagement).filter_by(id=engagement_id).first()
        if not eng:
            return None
        eng.estado = "closed"
        sesion.commit()
        return {"id": eng.id, "estado": eng.estado}
    finally:
        sesion.close()


def obtener_engagement(bd, engagement_id):
    """Devuelve el engagement con sus alcances resueltos, o None."""
    sesion = bd.nueva_sesion()
    try:
        eng = sesion.query(TablaEngagement).filter_by(id=engagement_id).first()
        if not eng:
            return None
        return {
            "id": eng.id, "cliente_id": eng.cliente_id, "nombre": eng.nombre,
            "estado": eng.estado, "nda_firmado": bool(eng.nda_firmado),
            "roe_firmado": bool(eng.roe_firmado),
            "ventana_inicio": str(eng.ventana_inicio) if eng.ventana_inicio else None,
            "ventana_fin": str(eng.ventana_fin) if eng.ventana_fin else None,
            "alcances": [{"tipo": a.tipo, "valor": a.valor} for a in eng.alcances],
        }
    finally:
        sesion.close()


def listar_engagements(bd):
    sesion = bd.nueva_sesion()
    try:
        filas = sesion.query(TablaEngagement).all()
        return [{"id": e.id, "cliente_id": e.cliente_id, "nombre": e.nombre,
                 "estado": e.estado, "alcances": len(e.alcances)} for e in filas]
    finally:
        sesion.close()


# ── Compuerta de alcance ──

def evaluar_autorizacion(bd, engagement_id, objetivo, ahora=None):
    """
    Evalúa, dentro de una sesión abierta (para resolver los alcances), si el
    engagement autoriza escanear ``objetivo`` ahora. Devuelve un dict con
    ``existe``, ``ok`` y ``motivo``.
    """
    sesion = bd.nueva_sesion()
    try:
        eng = sesion.query(TablaEngagement).filter_by(id=engagement_id).first()
        if not eng:
            return {"existe": False, "ok": False, "motivo": "No existe el engagement"}
        ok, motivo = autorizado(eng, objetivo, ahora=ahora)
        return {"existe": True, "ok": ok, "motivo": motivo}
    finally:
        sesion.close()


# ── Auditoría (solo agregar) ──

def registrar_auditoria(bd, actor, accion, objetivo=None, engagement_id=None,
                        escaneo_id=None, resultado="permitido", detalle=None):
    sesion = bd.nueva_sesion()
    try:
        fila = TablaAuditoria(
            actor=actor, accion=accion, objetivo=objetivo,
            engagement_id=engagement_id, escaneo_id=escaneo_id,
            resultado=resultado, detalle=detalle,
        )
        sesion.add(fila)
        sesion.commit()
        return fila.id
    finally:
        sesion.close()


def listar_auditoria(bd, engagement_id=None, limite=200):
    sesion = bd.nueva_sesion()
    try:
        q = sesion.query(TablaAuditoria)
        if engagement_id:
            q = q.filter_by(engagement_id=engagement_id)
        q = q.order_by(TablaAuditoria.creado_en.desc()).limit(limite)
        return [{"id": a.id, "creado_en": str(a.creado_en) if a.creado_en else None,
                 "actor": a.actor, "accion": a.accion, "objetivo": a.objetivo,
                 "engagement_id": a.engagement_id, "escaneo_id": a.escaneo_id,
                 "resultado": a.resultado, "detalle": a.detalle}
                for a in q.all()]
    finally:
        sesion.close()
