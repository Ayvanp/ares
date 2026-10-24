"""
Cola de escaneos de ARES.

Hasta ahora la API ejecutaba el escaneo con ``BackgroundTasks``, lo que no da
control sobre cuántos corren a la vez ni deja un estado "en cola" explícito.

Esta cola es un pool de hilos trabajadores en el mismo proceso (sin broker
externo): la API encola el trabajo y responde de inmediato, y los trabajadores
lo toman en orden (FIFO). Es suficiente para la Etapa 0 y deja la puerta
abierta a mover la ejecución a Celery/RQ más adelante sin tocar la API.

El ``runner`` (por defecto ``orquestador.orquestar``) es inyectable para poder
probar la cola sin lanzar herramientas reales.
"""

import queue
import threading

from base_datos.tablas import TablaEscaneo, hora_actual


def _marcar_estado(bd, escaneo_id, estado):
    sesion = bd.nueva_sesion()
    try:
        escaneo = sesion.query(TablaEscaneo).filter_by(id=escaneo_id).first()
        if escaneo:
            escaneo.estado = estado
            if estado == "failed":
                escaneo.completado_en = hora_actual()
            sesion.commit()
    finally:
        sesion.close()


class ColaEscaneos:
    def __init__(self, bd, runner=None, trabajadores=1):
        self.bd = bd
        self.runner = runner
        self._cola = queue.Queue()
        self._hilos = []
        self._arrancada = False
        self._lock = threading.Lock()
        self.trabajadores = max(1, int(trabajadores))

    def _asegurar_arranque(self):
        # Arranque perezoso: los hilos se crean en el primer encolado, para no
        # dejar hilos vivos cuando la API solo se importa (p. ej. en pruebas).
        with self._lock:
            if self._arrancada:
                return
            for _ in range(self.trabajadores):
                h = threading.Thread(target=self._trabajar, daemon=True)
                h.start()
                self._hilos.append(h)
            self._arrancada = True

    def encolar(self, escaneo_id, target, perfil):
        self._asegurar_arranque()
        _marcar_estado(self.bd, escaneo_id, "queued")
        self._cola.put((escaneo_id, target, perfil))

    def _trabajar(self):
        while True:
            item = self._cola.get()
            if item is None:            # señal de parada
                self._cola.task_done()
                break
            escaneo_id, target, perfil = item
            try:
                runner = self.runner
                if runner is None:
                    from orquestador import orquestar as runner
                runner(target=target, perfil_nombre=perfil,
                       bd=self.bd, escaneo_id=escaneo_id)
            except Exception:
                _marcar_estado(self.bd, escaneo_id, "failed")
            finally:
                self._cola.task_done()

    def esperar(self, timeout=None):
        """Bloquea hasta que la cola se vacíe. Útil en pruebas."""
        self._cola.join()

    def pendientes(self):
        return self._cola.qsize()
