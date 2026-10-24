#!/usr/bin/env python3
"""
ARES admin — gestión local de tokens, clientes y engagements.

Opera directamente sobre la base de datos (no pasa por la API ni necesita un
token), así que es la forma de arrancar: crear el primer token admin, registrar
un cliente y dejar un engagement autorizado antes de lanzar cualquier escaneo.

Usa la misma BD que la API (variable ARES_DATABASE_URL, por defecto
sqlite:///ares.db).

Ejemplos:
    python ares_admin.py token-crear "admin" --admin
    python ares_admin.py cliente-crear "ACME SpA"
    python ares_admin.py engagement-crear <cliente_id> "Pentest web Q4"
    python ares_admin.py alcance-agregar <engagement_id> cidr 10.10.10.0/24
    python ares_admin.py engagement-activar <engagement_id> --nda --roe
    python ares_admin.py engagement-ver <engagement_id>
"""

import argparse
import os
import sys

from base_datos.conexion import BaseDatos
from base_datos import gestion
from autenticacion import crear_token, listar_tokens


def _bd():
    bd = BaseDatos(os.environ.get("ARES_DATABASE_URL", "sqlite:///ares.db"))
    bd.crear_tablas()
    return bd


def main():
    p = argparse.ArgumentParser(prog="ares_admin", description="Gestión local de ARES")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("token-crear", help="Crea un token de API")
    s.add_argument("nombre"); s.add_argument("--admin", action="store_true")
    sub.add_parser("token-listar", help="Lista los tokens (sin el valor en claro)")

    s = sub.add_parser("cliente-crear"); s.add_argument("nombre"); s.add_argument("--notas", default=None)
    sub.add_parser("cliente-listar")

    s = sub.add_parser("engagement-crear")
    s.add_argument("cliente_id"); s.add_argument("nombre")
    s.add_argument("--ventana-inicio", default=None); s.add_argument("--ventana-fin", default=None)
    sub.add_parser("engagement-listar")
    s = sub.add_parser("engagement-ver"); s.add_argument("engagement_id")

    s = sub.add_parser("alcance-agregar")
    s.add_argument("engagement_id"); s.add_argument("tipo", choices=sorted(gestion.TIPOS_ALCANCE))
    s.add_argument("valor")

    s = sub.add_parser("engagement-activar")
    s.add_argument("engagement_id")
    s.add_argument("--nda", action="store_true", help="NDA firmado")
    s.add_argument("--roe", action="store_true", help="RoE firmadas")

    args = p.parse_args()
    if not args.cmd:
        p.print_help(); return
    bd = _bd()

    try:
        if args.cmd == "token-crear":
            datos = crear_token(bd, args.nombre, es_admin=args.admin)
            print("Token creado (guárdalo ahora, no se vuelve a mostrar):")
            print("  " + datos["valor"])
        elif args.cmd == "token-listar":
            for t in listar_tokens(bd):
                print(t)
        elif args.cmd == "cliente-crear":
            print(gestion.crear_cliente(bd, args.nombre, args.notas))
        elif args.cmd == "cliente-listar":
            for c in gestion.listar_clientes(bd):
                print(c)
        elif args.cmd == "engagement-crear":
            print(gestion.crear_engagement(bd, args.cliente_id, args.nombre,
                                           args.ventana_inicio, args.ventana_fin))
        elif args.cmd == "engagement-listar":
            for e in gestion.listar_engagements(bd):
                print(e)
        elif args.cmd == "engagement-ver":
            eng = gestion.obtener_engagement(bd, args.engagement_id)
            print(eng if eng else "No existe ese engagement")
        elif args.cmd == "alcance-agregar":
            print(gestion.agregar_alcance(bd, args.engagement_id, args.tipo, args.valor))
        elif args.cmd == "engagement-activar":
            print(gestion.activar_engagement(bd, args.engagement_id, args.nda, args.roe))
    except ValueError as e:
        print("Error: " + str(e)); sys.exit(1)


if __name__ == "__main__":
    main()
