import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, relationship

def generar_id(): return str(uuid.uuid4())
def hora_actual(): return datetime.now(tz=timezone.utc)

class Base(DeclarativeBase): pass

class TablaEscaneo(Base):
    __tablename__ = "escaneos"
    id = Column(String(36), primary_key=True, default=generar_id)
    objetivo = Column(String(255)); perfil = Column(String(100))
    estado = Column(String(20), default="pending")
    creado_en = Column(DateTime, default=hora_actual); completado_en = Column(DateTime)
    tareas = relationship("TablaTarea", back_populates="escaneo", cascade="all, delete-orphan")
    activos = relationship("TablaActivo", back_populates="escaneo", cascade="all, delete-orphan")

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
