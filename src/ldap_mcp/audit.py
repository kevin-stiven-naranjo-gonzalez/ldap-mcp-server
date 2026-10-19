"""Lógica de auditoría de accesos. No depende de LDAP, así que se prueba sin servidor."""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import date, timedelta

from .models import Usuario

COLUMNAS_CSV = ("usuario", "aplicacion", "rol")


def cuentas_inactivas(
    usuarios: list[Usuario], hoy: date, dias_sin_cambio_clave: int = 90
) -> list[dict]:
    """Cuentas expiradas o con la clave sin cambiar en más de N días."""
    limite = hoy - timedelta(days=dias_sin_cambio_clave)
    hallazgos = []
    for u in usuarios:
        motivos = []
        if u.expirada(hoy):
            motivos.append("cuenta_expirada")
        if u.ultimo_cambio_clave is not None and u.ultimo_cambio_clave < limite:
            motivos.append(f"clave_sin_cambiar_mas_de_{dias_sin_cambio_clave}_dias")
        if motivos:
            hallazgos.append(
                {
                    "uid": u.uid,
                    "nombre": u.nombre,
                    "motivos": motivos,
                    "grupos": u.grupos,
                    "expira": u.expira.isoformat() if u.expira else None,
                    "ultimo_cambio_clave": (
                        u.ultimo_cambio_clave.isoformat() if u.ultimo_cambio_clave else None
                    ),
                }
            )
    return hallazgos


def leer_csv_accesos(csv_texto: str) -> list[dict]:
    lector = csv.DictReader(io.StringIO(csv_texto.strip()))
    if lector.fieldnames is None:
        raise ValueError("El CSV está vacío.")
    columnas = [c.strip().lower() for c in lector.fieldnames]
    faltan = [c for c in COLUMNAS_CSV if c not in columnas]
    if faltan:
        raise ValueError(
            f"Faltan columnas en el CSV: {', '.join(faltan)}. Se esperan: {', '.join(COLUMNAS_CSV)}."
        )
    filas = []
    for fila in lector:
        normal = {k.strip().lower(): (v or "").strip() for k, v in fila.items() if k}
        if any(normal.get(c) for c in COLUMNAS_CSV):
            filas.append({c: normal.get(c, "") for c in COLUMNAS_CSV})
    return filas


def cruzar_accesos(usuarios: list[Usuario], csv_texto: str, hoy: date) -> dict:
    """Cruza un listado de accesos (usuario, aplicacion, rol) contra el directorio.

    Estados por fila:
      - ok: el usuario existe y está vigente.
      - usuario_no_existe: el acceso pertenece a alguien que no está en el directorio.
      - cuenta_expirada: el usuario existe pero su cuenta está vencida.
    Además marca inconsistencias: un mismo usuario con varios roles en la misma aplicación.
    """
    filas = leer_csv_accesos(csv_texto)
    por_uid = {u.uid.lower(): u for u in usuarios}

    resultados = []
    roles_por_app: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in filas:
        uid = f["usuario"].lower()
        u = por_uid.get(uid)
        if u is None:
            estado = "usuario_no_existe"
        elif u.expirada(hoy):
            estado = "cuenta_expirada"
        else:
            estado = "ok"
        roles_por_app[(uid, f["aplicacion"].lower())].add(f["rol"])
        resultados.append({**f, "estado": estado})

    inconsistencias = [
        {"usuario": uid, "aplicacion": app, "roles": sorted(roles), "tipo": "roles_multiples"}
        for (uid, app), roles in roles_por_app.items()
        if len(roles) > 1
    ]

    conteo = Counter(r["estado"] for r in resultados)
    return {
        "resumen": {
            "filas": len(resultados),
            "ok": conteo.get("ok", 0),
            "usuario_no_existe": conteo.get("usuario_no_existe", 0),
            "cuenta_expirada": conteo.get("cuenta_expirada", 0),
            "inconsistencias": len(inconsistencias),
        },
        "hallazgos": [r for r in resultados if r["estado"] != "ok"],
        "inconsistencias": inconsistencias,
    }
