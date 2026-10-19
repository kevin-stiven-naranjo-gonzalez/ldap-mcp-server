import asyncio
from pathlib import Path

import pytest

from ldap_mcp import server

DATA = Path(__file__).resolve().parent.parent / "data"


def test_herramientas_registradas():
    nombres = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert nombres == {
        "buscar_usuario",
        "listar_grupos_de_usuario",
        "detectar_cuentas_inactivas",
        "cruzar_accesos",
    }


def test_buscar_usuario(directorio):
    res = server.buscar_usuario("garcia")
    assert [u["uid"] for u in res] == ["ana.garcia"]
    assert res[0]["expira"] == "2040-01-01"


def test_buscar_usuario_vacio(directorio):
    with pytest.raises(ValueError):
        server.buscar_usuario("  ")


def test_listar_grupos(directorio):
    assert server.listar_grupos_de_usuario("ana.garcia")["grupos"] == ["admin-sistemas", "vpn"]
    assert server.listar_grupos_de_usuario("nadie")["encontrado"] is False


def test_detectar_cuentas_inactivas(directorio):
    r = server.detectar_cuentas_inactivas(90)
    assert r["total"] == 2


def test_cruzar_accesos_desde_archivo(directorio):
    r = server.cruzar_accesos(ruta_csv=str(DATA / "accesos_ejemplo.csv"))
    assert r["resumen"]["usuario_no_existe"] == 2  # pedro.ramirez y valentina.lopez (no está en el falso)
    assert r["resumen"]["inconsistencias"] == 1


def test_cruzar_accesos_rechaza_no_csv(directorio, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("usuario,aplicacion,rol\n")
    with pytest.raises(ValueError, match=".csv"):
        server.cruzar_accesos(ruta_csv=str(f))
