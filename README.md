# ARES — Sistema Automatizado de Evaluación de Seguridad

Sistema que orquesta Nmap, WhatWeb, Gobuster, dirb y Nuclei,
normaliza sus resultados en un modelo canónico, los correlaciona
automáticamente y genera reportes HTML y CSV.

---

## Requisitos

- Docker
- Docker Compose
- Python 3.10+ (solo para el CLI en tu máquina)

---

## Inicio rápido

### 1. Levantar el servidor

```bash
docker-compose up -d
```

Esto construye la imagen con todas las herramientas instaladas
(Nmap, WhatWeb, Gobuster, dirb y Nuclei) y levanta la API en el puerto 8000.

La primera vez tarda unos minutos mientras descarga e instala todo.
Las veces siguientes arranca en segundos.

### 2. Instalar el CLI en tu máquina

```bash
pip install -r requirements.txt
```

O con virtual environment:

```bash
python -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

### 3. Verificar que todo funciona

```bash
python ares.py herramientas
```

Deberías ver todas las herramientas como "instalada".

---

## Uso con HackTheBox

### 1. Conectar la VPN de HTB

```bash
sudo openvpn tu_archivo.ovpn
```

### 2. Iniciar un escaneo

```bash
python ares.py iniciar 10.129.244.208 --perfil completo
```

El CLI muestra el progreso en tiempo real. Al terminar:

```bash
# Ver hallazgos por severidad
python ares.py hallazgos
python ares.py hallazgos --severidad high

# Ver hallazgos correlacionados con contexto
python ares.py correlacion

# Generar reporte HTML y CSV
python ares.py reporte
```

---

## Perfiles de escaneo

| Perfil | Qué hace |
|---|---|
| `reconocimiento` | Solo Nmap, sin web ni Nuclei |
| `rapido` | Nmap + WhatWeb + Gobuster, sin Nuclei |
| `completo` | Todas las herramientas con reglas reactivas |

---

## Comandos del CLI

```bash
ares iniciar <target> [--perfil completo|rapido|reconocimiento]
ares estado [--id UUID]
ares hallazgos [--severidad critical|high|medium|low|info]
ares correlacion [--id UUID]
ares ver [--id UUID]
ares escaneos
ares reporte [--id UUID]
ares herramientas
ares servidor <url>
```

---

## Estructura del proyecto

```
ares/
  api.py              API REST (FastAPI)
  ares.py             CLI del auditor
  modelos.py          Modelo canónico
  correlacion.py      Motor de correlación
  orquestador.py      Orquestador reactivo
  vhosts.py           Descubrimiento de vHosts
  parsers/
    nmap.py           Parser XML
    whatweb.py        Parser JSON
    gobuster.py       Parser JSONL/JSON (dir, dns, vhost)
    nuclei.py         Parser JSONL con deduplicación
    dirb.py           Parser de texto plano
  base_datos/
    tablas.py         10 tablas SQLAlchemy
    conexion.py       Conexión SQLite/PostgreSQL
    operaciones.py    Guardado y consultas
  reportes/
    generador.py      HTML y CSV
  Dockerfile
  docker-compose.yml
```

---

## Gestión del servidor Docker

```bash
# Ver logs en tiempo real
docker-compose logs -f

# Detener el servidor
docker-compose down

# Reiniciar
docker-compose restart

# Reconstruir la imagen (tras cambios en el código)
docker-compose up -d --build

# Ver estado
docker-compose ps
```

---

## Acceder a los datos generados

Los volúmenes Docker persisten los datos. Para copiarlos a tu máquina:

```bash
# Copiar reportes generados
docker cp ares-server:/app/reportes/salida ./reportes_local/

# Copiar evidencias (outputs crudos de las herramientas)
docker cp ares-server:/app/evidencias ./evidencias_local/
```

O acceder directamente a la API:

```bash
# Ver todos los escaneos
curl http://localhost:8000/escaneos | python3 -m json.tool

# Descargar reporte HTML
curl -X POST http://localhost:8000/escaneos/<ID>/reporte/html -o reporte.html
```

---

## macOS y Windows

En macOS y Windows, Docker Desktop usa una VM interna y
`network_mode: host` no funciona. Para usar con HTB:

1. Comenta `network_mode: host` en `docker-compose.yml`
2. Descomenta la sección `ports`
3. Las herramientas escanearán desde la VM de Docker, no desde el host

Para HTB con VPN en macOS/Windows se recomienda correr
las herramientas directamente en el host o usar una VM Linux.

---

## Tests

```bash
# Desde el directorio del proyecto (sin Docker)
pip install -r requirements.txt pytest
python -m pytest -q          # 159 pruebas
```

---

## Tecnologías

- **API**: FastAPI + Uvicorn
- **Base de datos**: SQLAlchemy (SQLite desarrollo, PostgreSQL producción)
- **Herramientas**: Nmap, WhatWeb, Gobuster, dirb, Nuclei
- **Contenedores**: Docker + Docker Compose

---

## Uso responsable

ARES ejecuta escáneres activos. Úsalo solo contra sistemas propios o para los que
tengas autorización explícita, como las máquinas de laboratorio de Hack The Box.
La API no tiene autenticación: no la expongas a redes compartidas.

## Contexto

ARES fue desarrollado como proyecto de título de Ingeniería Civil en Informática
(Universidad Austral de Chile).
