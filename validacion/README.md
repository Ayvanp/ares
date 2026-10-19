# Evidencia de validación de ARES

Material que respalda el Capítulo 6 y el Anexo F de la tesis.

## linea_base_manual/ (14 de octubre de 2026)

Una carpeta por máquina (cap, fireflow, snapped). Respalda la sección 6.4, la Tabla E.2 y las Figuras 5, 8, 10, 20 y 21.

- `corrida_1` a `corrida_3`: los comandos del perfil completo ejecutados fuera de ARES, uno tras otro. Cada `corrida_N.json` registra el comando, su duración y su código de salida, y `crudo/` guarda la salida original.
- `ares_escaneo.json`, `ares_data/ares.db` y `ares_evidencias/`: el escaneo de ARES del mismo día, con su base de datos y sus salidas crudas.
- `log_orquestacion_corridas.txt`: el registro de la serie.

## pruebas_funcionales/ (21 al 26 de agosto de 2026)

Respalda las pruebas PF-01 a PF-07 de la sección 6.2.

- `evidencias/<id_escaneo>/`: las salidas crudas de cada escaneo, tal como las guardó ARES.
- `ares.db`: la base de datos sobre la que se ejecutaron las pruebas.
- `reportes/`: los reportes HTML y CSV generados.
- `capturas/`: las capturas de PF-01 a PF-07.

## Lo que no está

No se conservaron los archivos crudos de los doce escaneos del 27 de septiembre de 2026 (Tablas 12 y E.1, Figuras 17 a 19). Sus cifras están en la tesis, pero no pueden recalcularse con este material.

Las pruebas automatizadas están en `tests/` y `samples/`. Se ejecutan con `python -m unittest discover tests`.
