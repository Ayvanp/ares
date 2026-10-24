import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import DeclarativeBase, relationship

def generar_id(): return str(uuid.uuid4())
def hora_actual(): return datetime.now(tz=timezone.utc)

class Base(DeclarativeBase): pass

class TablaEscaneo(Base):
    __tablename__ = "escaneos"
    id = Column(String(36), primary_key=True, default=generar_id)
    objetivo = Column(String(255)); perfil = Column(String(100))
    estado = Column(String(20), default="pending")
    # Engagement bajo cuyo alcance se autorizó este escaneo. Nullable para
    # mantener compatibilidad con los escaneos creados por parseo manual.
    engagement_id = Column(String(36), ForeignKey("engagements.id"))
    creado_en = Column(DateTime, default=hora_actual); completado_en = Column(DateTime)
    tareas = relationship("TablaTarea", back_populates="escaneo", cascade="all, delete-orphan")
    activos = relationship("TablaActivo", back_populates="escaneo", cascade="all, delete-orphan")
    engagement = relationship("TablaEngagement", back_populates="escaneos")

class TablaTarea(Base):
    __tablename__ = "tareas"
    id = Column(String(36), primary_key=True, default=generar_id)
    escaneo_id = Column(String(36), ForeignKey("escaneos.id"))
    nombre_herramienta = Column(String(50)); estado = Column(String(20), default="pending")
    comando = Column(Text); razon = Column(Text)
    iniciado_en = Column(DateTime); terminado_en = Column(DateTime)
    escaneo = relationship("TablaEscaneo", back_populates="tareas")

class TablaActivo(Base):
    __tablename__ = "activos"
    id = Column(String(36), primary_key=True, default=generar_id)
    escaneo_id = Column(String(36), ForeignKey("escaneos.id"))
    ip = Column(String(45)); hostname = Column(String(255))
    mac = Column(String(17)); mac_fabricante = Column(String(100))
    estado = Column(String(20), default="unknown")
    so_nombre = Column(String(255)); so_familia = Column(String(100))
    so_precision = Column(Integer); so_cpe = Column(String(255))
    escaneo = relationship("TablaEscaneo", back_populates="activos")
    servicios = relationship("TablaServicio", back_populates="activo", cascade="all, delete-orphan")
    tecnologias = relationship("TablaTecnologia", back_populates="activo", cascade="all, delete-orphan")
    endpoints = relationship("TablaEndpoint", back_populates="activo", cascade="all, delete-orphan")
    hallazgos = relationship("TablaHallazgo", back_populates="activo", cascade="all, delete-orphan")

class TablaServicio(Base):
    __tablename__ = "servicios"
    id = Column(String(36), primary_key=True, default=generar_id)
    activo_id = Column(String(36), ForeignKey("activos.id"))
    puerto = Column(Integer); protocolo = Column(String(10), default="tcp")
    estado = Column(String(20), default="open"); nombre_servicio = Column(String(100))
    producto = Column(String(200)); version = Column(String(100)); cpe = Column(String(500))
    activo = relationship("TablaActivo", back_populates="servicios")

class TablaTecnologia(Base):
    __tablename__ = "tecnologias"
    id = Column(String(36), primary_key=True, default=generar_id)
    activo_id = Column(String(36), ForeignKey("activos.id"))
    nombre = Column(String(200)); version = Column(String(100)); categoria = Column(String(100))
    activo = relationship("TablaActivo", back_populates="tecnologias")

class TablaEndpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String(36), primary_key=True, default=generar_id)
    activo_id = Column(String(36), ForeignKey("activos.id"))
    url = Column(String(2000)); ruta = Column(String(500)); codigo_estado = Column(Integer)
    tamano = Column(Integer); redirige_a = Column(String(2000))
    activo = relationship("TablaActivo", back_populates="endpoints")

class TablaHallazgo(Base):
    __tablename__ = "hallazgos"
    id = Column(String(36), primary_key=True, default=generar_id)
    escaneo_id = Column(String(36), ForeignKey("escaneos.id"))
    activo_id = Column(String(36), ForeignKey("activos.id"))
    titulo = Column(String(500)); severidad = Column(String(20), default="unknown")
    descripcion = Column(Text); id_plantilla = Column(String(200)); url = Column(String(2000))
    etiquetas = Column(Text); referencias = Column(Text); hash_dedup = Column(String(64))
    herramienta = Column(String(50))
    activo = relationship("TablaActivo", back_populates="hallazgos")
    evidencias = relationship("TablaEvidencia", back_populates="hallazgo", cascade="all, delete-orphan")

class TablaEvidencia(Base):
    __tablename__ = "evidencias"
    id = Column(String(36), primary_key=True, default=generar_id)
    hallazgo_id = Column(String(36), ForeignKey("hallazgos.id"))
    encontrado_en = Column(String(2000)); comando_curl = Column(Text)
    resultados_extraidos = Column(Text)
    hallazgo = relationship("TablaHallazgo", back_populates="evidencias")

class TablaCorrelacion(Base):
    __tablename__ = "correlaciones"
    id = Column(String(36), primary_key=True, default=generar_id)
    escaneo_id = Column(String(36), ForeignKey("escaneos.id"))
    activo_id = Column(String(36), ForeignKey("activos.id"))
    hallazgo_titulo = Column(String(500)); hallazgo_severidad = Column(String(20))
    hallazgo_id_plantilla = Column(String(200)); confianza = Column(String(10)); razon = Column(Text)
    vinculos = relationship("TablaVinculo", back_populates="correlacion", cascade="all, delete-orphan")

class TablaVinculo(Base):
    __tablename__ = "vinculos"
    id = Column(String(36), primary_key=True, default=generar_id)
    correlacion_id = Column(String(36), ForeignKey("correlaciones.id"))
    tipo = Column(String(20)); descripcion = Column(String(500))
    correlacion = relationship("TablaCorrelacion", back_populates="vinculos")


# ── Etapa 0: clientes, engagements, alcance, tokens y auditoría ──
#
# Estas tablas sostienen la "compuerta dura" de ARES: ningún escaneo activo
# arranca sin un engagement vigente (NDA + RoE firmados y ventana horaria
# abierta) y con el objetivo dentro de un alcance autorizado. Todo intento
# —permitido o denegado— queda en la tabla de auditoría, que es de solo
# agregar: se escribe una vez y no se edita.

class TablaCliente(Base):
    __tablename__ = "clientes"
    id = Column(String(36), primary_key=True, default=generar_id)
    nombre = Column(String(255), nullable=False)
    notas = Column(Text)
    creado_en = Column(DateTime, default=hora_actual)
    engagements = relationship("TablaEngagement", back_populates="cliente",
                               cascade="all, delete-orphan")


class TablaEngagement(Base):
    __tablename__ = "engagements"
    id = Column(String(36), primary_key=True, default=generar_id)
    cliente_id = Column(String(36), ForeignKey("clientes.id"))
    nombre = Column(String(255), nullable=False)
    # draft → active → (expired | closed). Solo "active" habilita escaneos.
    estado = Column(String(20), default="draft")
    nda_firmado = Column(Boolean, default=False)
    roe_firmado = Column(Boolean, default=False)
    # Ventana horaria autorizada (UTC). Fuera de ella no se ejecuta nada.
    ventana_inicio = Column(DateTime)
    ventana_fin = Column(DateTime)
    creado_en = Column(DateTime, default=hora_actual)
    activado_en = Column(DateTime)
    cliente = relationship("TablaCliente", back_populates="engagements")
    alcances = relationship("TablaAlcance", back_populates="engagement",
                            cascade="all, delete-orphan")
    escaneos = relationship("TablaEscaneo", back_populates="engagement")


class TablaAlcance(Base):
    __tablename__ = "alcances"
    id = Column(String(36), primary_key=True, default=generar_id)
    engagement_id = Column(String(36), ForeignKey("engagements.id"))
    # tipo: "ip", "cidr", "hostname" o "dominio".
    tipo = Column(String(20), nullable=False)
    valor = Column(String(255), nullable=False)
    engagement = relationship("TablaEngagement", back_populates="alcances")


class TablaApiToken(Base):
    __tablename__ = "api_tokens"
    id = Column(String(36), primary_key=True, default=generar_id)
    nombre = Column(String(120), nullable=False)
    # Solo se guarda el hash SHA-256 del token; el valor en claro se muestra
    # una única vez al crearlo y no se puede recuperar después.
    hash_token = Column(String(64), nullable=False, unique=True)
    es_admin = Column(Boolean, default=False)
    activo = Column(Boolean, default=True)
    creado_en = Column(DateTime, default=hora_actual)
    ultimo_uso = Column(DateTime)


class TablaAuditoria(Base):
    __tablename__ = "auditoria"
    id = Column(String(36), primary_key=True, default=generar_id)
    creado_en = Column(DateTime, default=hora_actual)
    actor = Column(String(120))          # nombre del token que originó la acción
    accion = Column(String(80))          # p. ej. "escaneo.iniciar"
    objetivo = Column(String(255))       # IP/host sobre el que se pidió actuar
    engagement_id = Column(String(36))   # sin FK dura: la auditoría sobrevive aunque se borre el engagement
    escaneo_id = Column(String(36))
    resultado = Column(String(20))       # "permitido" | "denegado"
    detalle = Column(Text)
