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


def test_cruzar_accesos_desde_archivo(directorio, monkeypatch):
    monkeypatch.setenv("LDAP_MCP_CSV_DIR", str(DATA))
    r = server.cruzar_accesos(ruta_csv="accesos_ejemplo.csv")
    assert r["resumen"]["usuario_no_existe"] == 2  # pedro.ramirez y valentina.lopez (no está en el falso)
    assert r["resumen"]["inconsistencias"] == 1


def test_cruzar_accesos_rechaza_no_csv(directorio, tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_MCP_CSV_DIR", str(tmp_path))
    (tmp_path / "x.txt").write_text("usuario,aplicacion,rol\n")
    with pytest.raises(ValueError, match=".csv"):
        server.cruzar_accesos(ruta_csv="x.txt")


@pytest.mark.parametrize(
    "ruta",
    [
        "../secreto.csv",
        "sub/../../secreto.csv",
        "C:/Windows/secreto.csv",
        r"\\servidor\share\a.csv",
        "/etc/secreto.csv",
    ],
)
def test_cruzar_accesos_rechaza_rutas_fuera_de_la_carpeta(directorio, tmp_path, monkeypatch, ruta):
    base = tmp_path / "permitido"
    base.mkdir()
    (tmp_path / "secreto.csv").write_text("usuario,aplicacion,rol\nx,y,z\n")
    monkeypatch.setenv("LDAP_MCP_CSV_DIR", str(base))
    with pytest.raises(ValueError):
        server.cruzar_accesos(ruta_csv=ruta)


def test_cruzar_accesos_limita_tamano(directorio, tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_MCP_CSV_DIR", str(tmp_path))
    monkeypatch.setattr(server, "MAX_CSV_BYTES", 10)
    (tmp_path / "grande.csv").write_text("usuario,aplicacion,rol\n" * 5)
    with pytest.raises(ValueError, match="tamaño"):
        server.cruzar_accesos(ruta_csv="grande.csv")
