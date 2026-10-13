#!/usr/bin/env python3
"""ARES CLI — Interfaz de línea de comandos."""

import argparse, itertools, json, os, re, sys, time, urllib.request, urllib.error
from datetime import datetime

ARCHIVO_CONFIG = os.path.expanduser("~/.ares_config.json")
CONFIG_DEFAULT = {"servidor": "http://localhost:8000", "escaneo_actual": None}
ANCHO = 54  # ancho de las reglas

def cargar_config():
    if os.path.exists(ARCHIVO_CONFIG):
        with open(ARCHIVO_CONFIG) as f: return json.load(f)
    return CONFIG_DEFAULT.copy()

def guardar_config(config):
    with open(ARCHIVO_CONFIG, "w") as f: json.dump(config, f, indent=2)

# ── Color ──
def rojo(t): return "\033[91m" + t + "\033[0m"
def verde(t): return "\033[92m" + t + "\033[0m"
def amarillo(t): return "\033[93m" + t + "\033[0m"
def cyan(t): return "\033[96m" + t + "\033[0m"
def negrita(t): return "\033[1m" + t + "\033[0m"
def dim(t): return "\033[2m" + t + "\033[0m"

COLORES_SEV = {"critical": rojo, "high": rojo, "medium": amarillo, "low": cyan, "info": dim}
NOMBRE_SEV = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFO"}
PERFIL_DESC = {"reconocimiento": "solo Nmap", "rapido": "Nmap + herramientas web",
               "completo": "Nmap + web + Nuclei (recomendado)"}

# ── Formato ──
_ANSI = re.compile(r"\033\[[0-9;]*m")

def _slen(t):
    """Largo visible del texto (sin contar los códigos de color)."""
    return len(_ANSI.sub("", t))

def pad(t, ancho):
    """Rellena a la derecha hasta 'ancho' columnas visibles."""
    return t + " " * max(0, ancho - _slen(t))

def encabezado(titulo, sub=None):
    print()
    print("  " + negrita(titulo))
    if sub: print("  " + dim(sub))
    print("  " + dim("─" * ANCHO))

def campo(clave, valor):
    print("  " + dim(pad(clave, 11)) + " " + str(valor))

def hint(texto):
    print("  " + dim("› " + texto))

def etiqueta_sev(sev):
    col = COLORES_SEV.get(sev, dim)
    return col("[" + NOMBRE_SEV.get(sev, sev.upper()) + "]")

def _icono_estado(e):
    return {"completed": verde("✓"), "running": amarillo("●"),
            "failed": rojo("✗"), "pending": dim("○"),
            "skipped": dim("–")}.get(e, dim("·"))

# ── Cliente HTTP ──
def llamar_api(metodo, ruta, datos=None, config=None):
    if config is None: config = cargar_config()
    url = config["servidor"].rstrip("/") + ruta
    try:
        cuerpo = json.dumps(datos).encode() if datos else None
        req = urllib.request.Request(url, data=cuerpo,
            headers={"Content-Type": "application/json"}, method=metodo)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try: msg = json.loads(e.read()).get("detail", str(e))
        except: msg = str(e)
        print(); print("  " + rojo("✗ Error: ") + msg); print(); sys.exit(1)
    except urllib.error.URLError:
        print()
        print("  " + rojo("✗ No se pudo conectar al servidor ") + dim("(" + config["servidor"] + ")"))
        hint("¿Está corriendo? Arrancalo con:  python api.py")
        print(); sys.exit(1)

def get(ruta, config=None): return llamar_api("GET", ruta, config=config)
def post(ruta, params=None, config=None):
    if params:
        query = "&".join(k + "=" + str(v) for k, v in params.items())
        ruta = ruta + "?" + query
    return llamar_api("POST", ruta, config=config)

def _sin_escaneo():
    print()
    print("  " + amarillo("No hay un escaneo activo."))
    hint("Lanzá uno con:  ares iniciar <ip>")
    hint("O elegí uno viejo con:  ares escaneos")
    print()

def _formato_estado(estado):
    return {"completed": verde("completado"), "running": amarillo("en progreso"),
            "failed": rojo("fallido"), "pending": dim("pendiente"),
            "skipped": dim("omitido")}.get(estado, dim(estado))

def _hora(s):
    """De '2026-08-26 21:55:20...' a '21:55:20'."""
    return s[11:19] if s and len(s) >= 19 else ""

def _dur_seg(ini, fin):
    """Segundos entre dos timestamps 'YYYY-mm-dd HH:MM:SS…', o None."""
    try:
        a = datetime.strptime(ini[:19], "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(fin[:19], "%Y-%m-%d %H:%M:%S")
        return int((b - a).total_seconds())
    except Exception:
        return None

def _linea_final(t):
    """Línea de una tarea ya terminada, con su duración y motivo."""
    e = t["estado"]
    dur = _dur_seg(t.get("iniciado"), t.get("terminado"))
    extra = ("  " + dim("%ds" % dur)) if dur is not None else ""
    print("  " + _icono_estado(e) + "  " + pad(t["herramienta"], 24) + " " + _formato_estado(e) + extra)
    if t.get("razon"):
        print(dim("       " + t["razon"]))

def _mostrar_tarea(tarea, detalle=False):
    e = tarea["estado"]
    print("  " + _icono_estado(e) + "  " + pad(tarea["herramienta"], 24) + " " + _formato_estado(e))
    ini = _hora(tarea.get("iniciado")); fin = _hora(tarea.get("terminado"))
    sub = []
    if ini: sub.append(ini + (" → " + fin if fin else ""))
    if tarea.get("razon"): sub.append(tarea["razon"])
    if sub:
        print(dim("        " + "  ·  ".join(sub)))
    if detalle and tarea.get("comando"):
        print(dim("        $ " + tarea["comando"]))

def _mostrar_resumen(resumen):
    if not resumen: return
    pares = [("Activos", resumen.get("activos", 0)), ("Servicios", resumen.get("servicios", 0)),
             ("Tecnologías", resumen.get("tecnologias", 0)), ("Endpoints", resumen.get("endpoints", 0)),
             ("Hallazgos", resumen.get("hallazgos", 0))]
    partes = [negrita(str(v)) + " " + dim(n.lower()) for n, v in pares if v]
    if partes:
        print("  " + "   ".join(partes))
    por_sev = resumen.get("por_severidad", {})
    tags = [etiqueta_sev(s) + dim(" " + str(por_sev[s]))
            for s in ["critical", "high", "medium", "low", "info"] if s in por_sev]
    if tags:
        print("  " + "  ".join(tags))

# ── Comandos ──
def cmd_iniciar(args, config):
    target = args.target; perfil = getattr(args, "perfil", "completo")
    encabezado("Nuevo escaneo", target)
    campo("Perfil", perfil + dim("  (" + PERFIL_DESC.get(perfil, "") + ")"))
    respuesta = post("/escaneos/iniciar", {"target": target, "perfil": perfil}, config=config)
    escaneo_id = respuesta["escaneo_id"]
    config["escaneo_actual"] = escaneo_id; guardar_config(config)
    campo("ID", dim(escaneo_id[:8] + "…"))
    print()
    print("  " + verde("✓") + " Escaneo iniciado. Siguiendo el progreso" + dim(" (Ctrl-C para dejarlo en segundo plano)"))
    print()

    def _borrar_spinner(activo):
        if activo:
            sys.stdout.write("\r\033[K")

    finalizadas = set()      # herramientas ya mostradas como terminadas
    inicio_local = {}        # cuándo el CLI vio por primera vez cada tarea corriendo
    spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    estado = None; hay_spinner = False
    ultima_consulta = 0.0; t0 = time.time()

    while time.time() - t0 < 1200:  # tope de 20 min
        # Refrescar el estado desde la API cada ~1.5 s (el spinner anima más rápido)
        if estado is None or time.time() - ultima_consulta >= 1.5:
            estado = get("/escaneos/" + escaneo_id + "/estado", config=config)
            ultima_consulta = time.time()
            for t in estado.get("tareas", []):
                nom, e = t["herramienta"], t["estado"]
                if e == "running" and nom not in inicio_local:
                    inicio_local[nom] = time.time()
                if e in ("completed", "failed", "skipped") and nom not in finalizadas:
                    _borrar_spinner(hay_spinner); hay_spinner = False
                    _linea_final(t)
                    finalizadas.add(nom)
            est = estado["estado"]
            if est in ("completed", "failed"):
                _borrar_spinner(hay_spinner); hay_spinner = False
                print()
                if est == "completed":
                    print("  " + verde("✓ Escaneo completado")); print()
                    _mostrar_resumen(estado.get("resumen", {}))
                    print()
                    hint("Ver detalle:      ares ver")
                    hint("Ver hallazgos:    ares hallazgos")
                    hint("Generar informe:  ares reporte")
                else:
                    print("  " + rojo("✗ El escaneo falló."))
                print(); return

        # Dibujar el spinner de la herramienta que está corriendo ahora
        corriendo = [t for t in estado.get("tareas", [])
                     if t["estado"] == "running" and t["herramienta"] not in finalizadas]
        if corriendo:
            t = corriendo[-1]; nom = t["herramienta"]
            seg = int(time.time() - inicio_local.get(nom, time.time()))
            sys.stdout.write("\r\033[K  " + amarillo(next(spinner)) + "  " +
                             pad(nom, 24) + " " + dim("ejecutando… %ds" % seg))
            sys.stdout.flush(); hay_spinner = True
        elif not finalizadas:
            sys.stdout.write("\r\033[K  " + amarillo(next(spinner)) + "  " + dim("iniciando…"))
            sys.stdout.flush(); hay_spinner = True
        time.sleep(0.12)

    _borrar_spinner(hay_spinner)
    print(); print("  " + amarillo("Sigue en progreso.")); hint("Seguí con:  ares estado"); print()

def cmd_estado(args, config):
    escaneo_id = getattr(args, "id", None) or config.get("escaneo_actual")
    if not escaneo_id: _sin_escaneo(); return
    estado = get("/escaneos/" + escaneo_id + "/estado", config=config)
    encabezado("Estado del escaneo", estado["target"])
    campo("Perfil", estado.get("perfil", "?"))
    campo("Estado", _formato_estado(estado["estado"]))
    if estado.get("creado"): campo("Inicio", dim(estado["creado"][:19]))
    if estado.get("completado"): campo("Fin", dim(estado["completado"][:19]))
    if estado.get("tareas"):
        print()
        print("  " + negrita("Cronología de ejecución"))
        for t in estado["tareas"]: _mostrar_tarea(t, detalle=True)
    if estado.get("resumen"):
        print(); _mostrar_resumen(estado["resumen"])
    print()

def cmd_hallazgos(args, config):
    severidad = getattr(args, "severidad", None)
    ruta = "/hallazgos" + ("?severidad=" + severidad if severidad else "")
    datos = get(ruta, config=config); hallazgos = datos.get("hallazgos", [])
    encabezado("Hallazgos" + (" — " + NOMBRE_SEV.get(severidad, severidad.upper()) if severidad else ""))
    if not hallazgos:
        print("  " + dim("No se encontraron hallazgos.")); print(); return
    por_ip = {}
    conteo = {}
    for h in hallazgos:
        por_ip.setdefault(h.get("ip_host", "?"), []).append(h)
        conteo[h["severidad"]] = conteo.get(h["severidad"], 0) + 1
    tags = [etiqueta_sev(s) + dim(" " + str(conteo[s]))
            for s in ["critical", "high", "medium", "low", "info"] if s in conteo]
    if tags: print("  " + "  ".join(tags)); print()
    for ip, lista in sorted(por_ip.items()):
        print("  " + cyan(ip))
        for h in lista:
            print("    " + pad(etiqueta_sev(h["severidad"]), 12) + " " + h["titulo"])
        print()
    print("  " + dim("Total: " + str(len(hallazgos)) + " hallazgo(s)")); print()

def cmd_correlacion(args, config):
    escaneo_id = getattr(args, "id", None) or config.get("escaneo_actual")
    if not escaneo_id: _sin_escaneo(); return
    datos = get("/escaneos/" + escaneo_id + "/correlacion", config=config)
    correlaciones = datos.get("correlaciones", []); resumen = datos.get("resumen", {})
    encabezado("Hallazgos correlacionados")
    if not correlaciones:
        print("  " + dim("No hay correlaciones disponibles.")); print(); return
    print("  " + verde(str(resumen.get("con_vinculos", 0))) + dim(" con contexto") +
          "   " + amarillo(str(resumen.get("confianza_alta", 0))) + dim(" de confianza alta"))
    print()
    por_ip = {}
    for c in correlaciones:
        por_ip.setdefault(c.get("ip", "?"), []).append(c)
    for ip, lista in sorted(por_ip.items()):
        print("  " + cyan(ip))
        for c in lista:
            conf = c.get("confianza", "?")
            c_col = verde if conf == "alta" else (amarillo if conf == "media" else dim)
            print("    " + pad(etiqueta_sev(c["severidad"]), 12) + " " + c["hallazgo"] +
                  "  " + dim("(") + c_col(conf) + dim(")"))
            for v in c.get("vinculos", []):
                print("       " + dim("→ " + v["descripcion"]))
        print()

def cmd_escaneos(args, config):
    datos = get("/escaneos", config=config); escaneos = datos.get("escaneos", [])
    encabezado("Escaneos guardados")
    if not escaneos:
        print("  " + dim("No hay escaneos guardados.")); hint("Lanzá uno con:  ares iniciar <ip>"); print(); return
    actual = config.get("escaneo_actual", "")
    print("  " + dim(pad("ID", 10) + pad("OBJETIVO", 22) + pad("ESTADO", 14) + "FECHA"))
    for e in escaneos:
        marca = amarillo("  ←") if e["id"] == actual else ""
        fecha = e.get("creado_en", "")[:19] if e.get("creado_en") else ""
        print("  " + pad(dim(e["id"][:8]), 10) + pad(e["objetivo"], 22) +
              pad(_formato_estado(e["estado"]), 14) + dim(fecha) + marca)
    print(); print("  " + dim("Total: " + str(len(escaneos)) + " escaneo(s)  ·  ← escaneo actual")); print()

def cmd_ver(args, config):
    escaneo_id = getattr(args, "id", None) or config.get("escaneo_actual")
    if not escaneo_id: _sin_escaneo(); return
    datos = get("/escaneos/" + escaneo_id, config=config)
    encabezado("Escaneo — " + datos.get("objetivo", "?"), "ID " + datos["id"][:8] + "…")
    for activo in datos.get("activos", []):
        so = activo.get("sistema_operativo", {}); so_n = so.get("nombre", "") if so else ""
        hn = activo.get("hostname", "") or ""
        print()
        print("  " + cyan(negrita(activo["ip"])) + (dim("  " + hn) if hn else "") + (dim("  ·  " + so_n) if so_n else ""))
        for s in activo.get("servicios", []):
            prod = ((s.get("producto") or "") + " " + (s.get("version") or "")).strip()
            estado_col = verde if s.get("estado") == "open" else dim
            print("    " + pad(s["puerto"] and (str(s["puerto"]) + "/" + s["protocolo"]) or "", 11) +
                  pad(estado_col(s.get("estado", "")), 12) + dim(prod))
        if activo.get("tecnologias"):
            techs = ", ".join(t["nombre"] + (" " + t["version"] if t.get("version") else "") for t in activo["tecnologias"])
            print("    " + dim("Tecnologías: ") + techs)
        for h in activo.get("hallazgos", []):
            print("    " + pad(etiqueta_sev(h["severidad"]), 12) + " " + h["titulo"])
    print()

def cmd_reporte(args, config):
    """Genera el reporte HTML y CSV del escaneo actual."""
    escaneo_id = getattr(args, "id", None) or config.get("escaneo_actual")
    if not escaneo_id: _sin_escaneo(); return
    servidor = config["servidor"].rstrip("/")
    encabezado("Generar informe")
    def _descargar(sufijo, nombre):
        req = urllib.request.Request(servidor + "/escaneos/" + escaneo_id + sufijo, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            with open(nombre, "wb") as f: f.write(resp.read())
    try:
        n = "reporte_" + escaneo_id[:8] + ".html"; _descargar("/reporte/html", n)
        print("  " + verde("✓") + " HTML  " + dim(n))
    except Exception as e:
        print("  " + rojo("✗") + " HTML  " + dim(str(e)))
    try:
        n = "hallazgos_" + escaneo_id[:8] + ".csv"; _descargar("/reporte/csv", n)
        print("  " + verde("✓") + " CSV   " + dim(n))
    except Exception as e:
        print("  " + rojo("✗") + " CSV   " + dim(str(e)))
    print()

def cmd_evidencia(args, config):
    """Lista los archivos de salida cruda que dejó el escaneo."""
    escaneo_id = getattr(args, "id", None) or config.get("escaneo_actual")
    if not escaneo_id: _sin_escaneo(); return
    datos = get("/escaneos/" + escaneo_id + "/evidencias", config=config)
    evs = datos.get("evidencias", [])
    encabezado("Evidencia recopilada")
    if not evs:
        print("  " + dim("No hay archivos de evidencia.")); print(); return
    print("  " + dim(datos.get("carpeta", "")))
    for e in evs:
        print("    " + pad(cyan(e["archivo"]), 44) + dim("%7.1f KB" % (e["tamano"] / 1024)))
    print(); print("  " + dim("Total: " + str(len(evs)) + " archivo(s)")); print()

def cmd_comparar(args, config):
    """Compara el escaneo actual contra otro anterior del mismo objetivo."""
    nuevo = getattr(args, "id", None) or config.get("escaneo_actual")
    if not nuevo: _sin_escaneo(); return
    base = args.base
    if not base:
        escs = get("/escaneos", config=config).get("escaneos", [])
        actual = next((e for e in escs if e["id"] == nuevo), None)
        if actual:
            previos = [e for e in escs if e["objetivo"] == actual["objetivo"]
                       and e["id"] != nuevo
                       and (e.get("creado_en", "") or "") < (actual.get("creado_en", "") or "")]
            previos.sort(key=lambda e: e.get("creado_en", "") or "", reverse=True)
            if previos: base = previos[0]["id"]
        if not base:
            encabezado("Comparación de escaneos")
            print("  " + amarillo("No hay un escaneo anterior del mismo objetivo."))
            hint("Indicá el base a mano:  ares comparar <id_base>"); print(); return
    dif = get("/escaneos/" + nuevo + "/comparar/" + base, config=config)
    encabezado("Comparación de escaneos")
    campo("Base", dim(dif["base"]["id"][:8] + "…") + "  " + dim(dif["base"]["creado"]))
    campo("Nuevo", dim(dif["nuevo"]["id"][:8] + "…") + "  " + dim(dif["nuevo"]["creado"]))
    print()
    def _bloque(titulo, items, colf, signo):
        print("  " + negrita(titulo) + dim("  (" + str(len(items)) + ")"))
        if not items:
            print("    " + dim("— sin cambios"))
        for it in items:
            print("    " + colf(signo + " " + it))
        print()
    _bloque("Puertos nuevos", dif["puertos_nuevos"], verde, "+")
    _bloque("Puertos cerrados", dif["puertos_cerrados"], rojo, "−")
    _bloque("Hallazgos nuevos", dif["hallazgos_nuevos"], amarillo, "+")
    _bloque("Hallazgos resueltos", dif["hallazgos_resueltos"], verde, "−")

def cmd_hosts(args, config):
    """Muestra o limpia las entradas que ARES agregó a /etc/hosts."""
    import vhosts
    if getattr(args, "limpiar", False):
        n, msg = vhosts.limpiar_etc_hosts()
        print(); print("  " + (verde("✓ " + msg) if n else dim(msg))); print()
        return
    try:
        with open("/etc/hosts") as f:
            lineas = [l.rstrip() for l in f if vhosts.MARCA in l]
    except OSError as e:
        print("  " + rojo("No se pudo leer /etc/hosts: " + str(e))); return
    encabezado("vHosts en /etc/hosts", "entradas agregadas por ARES")
    if not lineas:
        print("  " + dim("(ninguna)")); print(); return
    for l in lineas:
        print("    " + cyan(l))
    print(); hint("Limpiar:  ares hosts --limpiar"); print()

def cmd_herramientas(args, config):
    datos = get("/herramientas/estado", config=config)
    encabezado("Herramientas del servidor")
    for nombre, estado in datos.get("herramientas", {}).items():
        ok = estado == "instalada"
        ic = verde("✓") if ok else rojo("✗")
        print("  " + ic + "  " + pad(nombre, 12) + (verde(estado) if ok else rojo(estado)))
    print()
    if datos.get("puede_orquestar"):
        print("  " + verde("✓") + " El servidor puede ejecutar escaneos orquestados")
    else:
        print("  " + amarillo("! Nmap no está instalado — no se puede orquestar"))
    print()

def cmd_servidor(args, config):
    config["servidor"] = args.url.rstrip("/"); guardar_config(config)
    encabezado("Servidor")
    try:
        datos = get("/", config=config)
        print("  " + verde("✓ Conectado a ") + config["servidor"] + dim("   ARES v" + datos.get("version", "?")))
    except SystemExit:
        print("  " + amarillo("URL guardada, pero el servidor no respondió."))
    print()

# ── Ayuda ──
def mostrar_ayuda():
    print()
    print("  " + negrita("ARES") + dim("   Sistema Automatizado de Evaluación de Seguridad"))
    print("  " + dim("─" * ANCHO))
    print("  " + dim("Uso:  ") + "ares <comando> [opciones]")
    print()
    grupos = [
        ("Escaneo", [
            ("iniciar <ip> [--perfil P]", "Lanza un escaneo y sigue el progreso"),
            ("estado", "Cronología del escaneo actual (con comandos)"),
            ("ver", "Servicios, tecnologías y hallazgos"),
        ]),
        ("Resultados", [
            ("hallazgos [--severidad S]", "Lista de hallazgos por severidad"),
            ("correlacion", "Hallazgos junto a su contexto"),
            ("comparar [id_base]", "Diferencias contra un escaneo anterior"),
            ("evidencia", "Archivos crudos que dejó el escaneo"),
            ("reporte", "Genera el informe HTML y el CSV"),
        ]),
        ("Gestión", [
            ("escaneos", "Historial de escaneos guardados"),
            ("hosts [--limpiar]", "vHosts que ARES puso en /etc/hosts"),
            ("herramientas", "Estado de las herramientas del servidor"),
            ("servidor <url>", "Apunta el CLI a otro servidor"),
        ]),
    ]
    for titulo, items in grupos:
        print("  " + cyan(titulo))
        for cmd, desc in items:
            print("    " + pad(verde(cmd), 32) + dim(desc))
        print()
    print("  " + dim("Perfiles:  ") + "reconocimiento  ·  rapido  ·  completo")
    print("  " + dim("Ejemplo:   ") + "ares iniciar 10.129.96.69 --perfil completo")
    print()

def main():
    config = cargar_config()
    parser = argparse.ArgumentParser(prog="ares", add_help=True,
        description="ARES — Sistema automatizado de evaluación de seguridad")
    subparsers = parser.add_subparsers(dest="comando")
    p = subparsers.add_parser("iniciar", help="Lanza un escaneo"); p.add_argument("target")
    p.add_argument("--perfil", default="completo", choices=["reconocimiento", "rapido", "completo"])
    p = subparsers.add_parser("estado", help="Estado y cronología del escaneo"); p.add_argument("--id", default=None)
    p = subparsers.add_parser("hallazgos", help="Lista de hallazgos")
    p.add_argument("--severidad", choices=["critical", "high", "medium", "low", "info"], default=None)
    p = subparsers.add_parser("correlacion", help="Hallazgos con contexto"); p.add_argument("--id", default=None)
    subparsers.add_parser("escaneos", help="Historial de escaneos")
    p = subparsers.add_parser("ver", help="Detalle del escaneo"); p.add_argument("--id", default=None)
    p = subparsers.add_parser("reporte", help="Genera HTML y CSV"); p.add_argument("--id", default=None)
    p = subparsers.add_parser("evidencia", help="Archivos crudos del escaneo"); p.add_argument("--id", default=None)
    p = subparsers.add_parser("comparar", help="Compara contra un escaneo anterior")
    p.add_argument("base", nargs="?", default=None); p.add_argument("--id", default=None)
    p = subparsers.add_parser("hosts", help="vHosts en /etc/hosts"); p.add_argument("--limpiar", action="store_true")
    subparsers.add_parser("herramientas", help="Estado de las herramientas")
    p = subparsers.add_parser("servidor", help="Configura el servidor"); p.add_argument("url")
    args = parser.parse_args()
    if not args.comando: mostrar_ayuda(); return
    comandos = {"iniciar": cmd_iniciar, "estado": cmd_estado, "hallazgos": cmd_hallazgos,
        "correlacion": cmd_correlacion, "escaneos": cmd_escaneos, "ver": cmd_ver,
        "reporte": cmd_reporte, "evidencia": cmd_evidencia, "comparar": cmd_comparar,
        "hosts": cmd_hosts, "herramientas": cmd_herramientas, "servidor": cmd_servidor}
    fn = comandos.get(args.comando)
    if fn: fn(args, config)

if __name__ == "__main__":
    main()
