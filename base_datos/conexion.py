from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from base_datos.tablas import Base

# Columnas agregadas después de la versión inicial. create_all() no altera
# tablas que ya existen, así que las añadimos a mano en BDs viejas.
COLUMNAS_NUEVAS = {
    "tareas": {"razon": "TEXT"},
    "escaneos": {"engagement_id": "VARCHAR(36)"},
}

class BaseDatos:
    def __init__(self, url="sqlite:///ares.db"):
        # SQLite: la cola de escaneos usa hilos trabajadores, así que la
        # conexión tiene que poder compartirse entre hilos. Para Postgres y
        # otros motores activamos pre-ping para no arrastrar conexiones muertas.
        if url.startswith("sqlite"):
            self.engine = create_engine(url, connect_args={"check_same_thread": False})
        else:
            self.engine = create_engine(url, pool_pre_ping=True)
        self.Sesion = sessionmaker(bind=self.engine, expire_on_commit=False)
    def crear_tablas(self):
        Base.metadata.create_all(self.engine)
        self._migrar()
    def _migrar(self):
        """Migración simple: agrega columnas nuevas a tablas ya existentes."""
        insp = inspect(self.engine)
        tablas = insp.get_table_names()
        for tabla, columnas in COLUMNAS_NUEVAS.items():
            if tabla not in tablas:
                continue
            existentes = [c["name"] for c in insp.get_columns(tabla)]
            for col, tipo in columnas.items():
                if col not in existentes:
                    with self.engine.begin() as conn:
                        conn.execute(text("ALTER TABLE " + tabla + " ADD COLUMN " + col + " " + tipo))
    def eliminar_tablas(self): Base.metadata.drop_all(self.engine)
    def nueva_sesion(self): return self.Sesion()
