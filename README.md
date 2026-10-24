# ARES — Sistema Automatizado de Evaluación de Seguridad

Sistema que orquesta Nmap, WhatWeb, Gobuster, dirb y Nuclei,
normaliza sus resultados en un modelo canónico, los correlaciona
automáticamente y genera reportes HTML y CSV.

Desde la Etapa 0, la API exige **autenticación por token** y ningún escaneo
activo arranca sin un **engagement autorizado** (NDA + RoE firmados y ventana
horaria vigente) que cubra el objetivo en su **alcance**. Es una compuerta
dura: todo intento, permitido o denegado, queda en una **auditoría** de solo
agregar. Los escaneos corren en una **cola** asíncrona y la base de datos puede
ser SQLite (desarrollo) o PostgreSQL (producción).

---

## Requisitos

- Docker
- Docker Compose
- Python 3.10+ (opcional, si ejecutas el CLI fuera de Docker)
- En Windows: Docker Desktop con contenedores Linux

---

## Inicio rápido

### 1. Levantar el servidor

```bash
# Kali/Linux
docker compose up -d

# Windows con Docker Desktop
docker compose -f docker-compose.windows.yml up --build -d
```

Esto construye la imagen con todas las herramientas instaladas
(Nmap, WhatWeb, Gobuster, Dirb y Nuclei) y levanta la API en el puerto 8000.

La primera vez tarda unos minutos mientras descarga e instala todo.
Las veces siguientes arranca en segundos.

### 2. Usar el CLI

```bash
# Linux/Kali, con el servidor ya iniciado
python ares.py herramientas
```

En Windows, ejecuta el CLI dentro del contenedor como se muestra en la sección
[Windows (Docker Desktop)](#windows-docker-desktop); no hace falta instalar
Python ni las herramientas de escaneo en Windows.

### 3. Verificar que todo funciona

```bash
# Kali/Linux
python ares.py herramientas

# Windows con Docker Desktop
docker compose -f docker-compose.windows.yml exec ares python ares.py herramientas
```

Deberías ver todas las herramientas como "instalada".

---

## Autenticación y alcance autorizado (Etapa 0)

La API dejó de ser abierta. Antes de escanear hay que (1) tener un token y
(2) dejar un engagement activo que cubra el objetivo. Todo esto se hace una vez,
con el CLI de administración local `ares_admin.py` (opera directo sobre la BD,
no necesita un token previo):

```bash
# 1. Crear un token admin y apuntarlo en el CLI
python ares_admin.py token-crear "admin" --admin        # imprime el token una sola vez
python ares.py token ares_XXXXXXXX...                    # lo guarda en ~/.ares_config.json

# 2. Registrar cliente y engagement, definir alcance y activarlo
python ares_admin.py cliente-crear "Laboratorio HTB"
python ares_admin.py engagement-crear <cliente_id> "Máquinas HTB"
python ares_admin.py alcance-agregar <engagement_id> cidr 10.129.0.0/16
python ares_admin.py engagement-activar <engagement_id> --nda --roe
python ares.py engagement <engagement_id>                # engagement por defecto del CLI
```

El engagement solo se puede activar con NDA y RoE marcados y al menos una
entrada de alcance. Tipos de alcance: `ip`, `cidr`, `hostname`, `dominio`
(este último cubre subdominios). Un escaneo contra un objetivo fuera del
alcance, o con el engagement no vigente, se rechaza con `403` y queda auditado.

Revisa la auditoría en `GET /engagements/<id>/auditoria` o `GET /auditoria`.

## Uso con HackTheBox

### 1. Conectar la VPN de HTB

```bash
sudo openvpn tu_archivo.ovpn
```

### 2. Iniciar un escaneo

Con el token y el engagement ya configurados (ver sección anterior):

```bash
python ares.py iniciar 10.129.244.208 --perfil completo --engagement <engagement_id>
```

(Si fijaste el engagement por defecto con `ares engagement <id>`, puedes omitir
`--engagement`.)

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
ares iniciar <target> --engagement <ID> [--perfil completo|rapido|reconocimiento]
ares estado [--id UUID]
ares hallazgos [--severidad critical|high|medium|low|info]
ares correlacion [--id UUID]
ares ver [--id UUID]
ares escaneos
ares reporte [--id UUID]
ares herramientas
ares servidor <url>
ares token <valor>           # guarda el token de API
ares engagement <ID>         # fija el engagement activo por defecto
```

Gestión local (sobre la BD, sin pasar por la API):

```bash
ares_admin token-crear <nombre> [--admin]
ares_admin cliente-crear <nombre>
ares_admin engagement-crear <cliente_id> <nombre> [--ventana-inicio ISO] [--ventana-fin ISO]
ares_admin alcance-agregar <engagement_id> <ip|cidr|hostname|dominio> <valor>
ares_admin engagement-activar <engagement_id> --nda --roe
```

---

## Estructura del proyecto

```
ares/
  api.py              API REST (FastAPI) con autenticación y compuerta de alcance
  ares.py             CLI del auditor
  ares_admin.py       CLI local de gestión (tokens, clientes, engagements)
  autenticacion.py    Tokens de API (hash SHA-256, Bearer / X-API-Key)
  alcance.py          Compuerta de alcance y vigencia del engagement
  cola.py             Cola asíncrona de escaneos (pool de hilos)
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
    tablas.py         Tablas SQLAlchemy (incluye clientes, engagements, alcance, tokens, auditoría)
    conexion.py       Conexión SQLite/PostgreSQL
    operaciones.py    Guardado y consultas de resultados
    gestion.py        Clientes, engagements, alcance y auditoría
  reportes/
    generador.py      HTML y CSV
  Dockerfile
  docker-compose.yml
  docker-compose.windows.yml
  tests/              Pruebas automatizadas
  samples/            Salidas de ejemplo para las pruebas
```

---

## Gestión del servidor Docker

```bash
# Kali/Linux: ver logs en tiempo real
docker compose logs -f

# Kali/Linux: detener el servidor
docker compose down

# Kali/Linux: reiniciar
docker compose restart

# Kali/Linux: reconstruir la imagen (tras cambios en el código)
docker compose up -d --build

# Kali/Linux: ver estado
docker compose ps
```

En Windows, añade `-f docker-compose.windows.yml` a esos comandos; por ejemplo:

```powershell
docker compose -f docker-compose.windows.yml logs -f
docker compose -f docker-compose.windows.yml up --build -d
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
# Ver todos los escaneos (requiere token)
curl -H "Authorization: Bearer $ARES_TOKEN" http://localhost:8000/escaneos | python3 -m json.tool

# Descargar reporte HTML
curl -X POST -H "Authorization: Bearer $ARES_TOKEN" http://localhost:8000/escaneos/<ID>/reporte/html -o reporte.html
```

---

## Windows (Docker Desktop)

ARES y sus escáneres corren dentro de un contenedor Linux. En Windows se
necesita Docker Desktop con el motor de contenedores Linux iniciado. Desde
PowerShell, en la carpeta `ares_final`, ejecuta:

```powershell
docker compose -f docker-compose.windows.yml up --build -d
```

La API queda en <http://localhost:8000> y su documentación interactiva en
<http://localhost:8000/docs>. La configuración de Windows guarda la base de
datos en `data/`, las evidencias en `evidencias/` y los reportes en
`reportes/salida/`, dentro de esta carpeta del proyecto.

Para comprobar las herramientas y ejecutar la suite incluida (184 pruebas):

```powershell
docker compose -f docker-compose.windows.yml exec ares python ares.py herramientas
docker compose -f docker-compose.windows.yml exec ares python -m unittest discover -s tests -v
```

También puedes iniciar escaneos desde el contenedor:

```powershell
docker compose -f docker-compose.windows.yml exec ares python ares.py iniciar OBJETIVO --perfil rapido
```

Reemplaza `OBJETIVO` por la IP o el hostname de un equipo al que tengas
autorización para escanear y que sea accesible desde el contenedor.

Desde el contenedor, `127.0.0.1` identifica al propio contenedor ARES. Para
escanear un servicio que se ejecuta en Windows, usa `host.docker.internal` como
objetivo y asegúrate de que el servicio acepte conexiones desde Docker. Para
escanear otro contenedor en la misma red Compose, usa el nombre de ese servicio.
La ruta de una VPN de HTB en Windows puede no estar disponible dentro de Docker
Desktop; para ese caso conviene usar una VM Linux/Kali o WSL con la VPN y la ruta
de red configuradas.

---

## Tests

```bash
# Desde el directorio del proyecto (sin Docker)
python -m unittest discover tests -v   # 184 pruebas
```

En Windows, ejecuta la misma suite dentro del contenedor con el comando de la
sección [Windows (Docker Desktop)](#windows-docker-desktop).

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
