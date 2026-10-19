from datetime import date

import pytest

from ldap_mcp import audit
from ldap_mcp.models import dias_a_fecha

HOY = date(2026, 10, 18)


def test_dias_a_fecha():
    assert dias_a_fecha("20454") == date(2026, 1, 1)
    assert dias_a_fecha(None) is None
    assert dias_a_fecha("-1") is None
    assert dias_a_fecha("abc") is None


def test_cuentas_inactivas(usuarios):
    hallazgos = {h["uid"]: h["motivos"] for h in audit.cuentas_inactivas(usuarios, HOY, 90)}
    assert hallazgos == {
        "luis.martinez": ["clave_sin_cambiar_mas_de_90_dias"],
        "sofia.rojas": ["cuenta_expirada"],
    }


def test_cruzar_accesos(usuarios):
    csv_texto = (
        "usuario,aplicacion,rol\n"
        "ana.garcia,ERP,admin\n"
        "sofia.rojas,ERP,consulta\n"
        "pedro.ramirez,ERP,aprobador\n"
        "diego.torres,CRM,vendedor\n"
        "Diego.Torres,crm,supervisor\n"
    )
    r = audit.cruzar_accesos(usuarios, csv_texto, HOY)
    assert r["resumen"] == {
        "filas": 5,
        "ok": 3,
        "usuario_no_existe": 1,
        "cuenta_expirada": 1,
        "inconsistencias": 1,
    }
    assert {h["usuario"]: h["estado"] for h in r["hallazgos"]} == {
        "sofia.rojas": "cuenta_expirada",
        "pedro.ramirez": "usuario_no_existe",
    }
    assert r["inconsistencias"][0]["roles"] == ["supervisor", "vendedor"]


def test_csv_con_columnas_faltantes(usuarios):
    with pytest.raises(ValueError, match="Faltan columnas"):
        audit.cruzar_accesos(usuarios, "usuario,app\nana,ERP\n", HOY)


def test_csv_ignora_filas_vacias_y_bom(usuarios):
    r = audit.cruzar_accesos(usuarios, "Usuario, Aplicacion ,ROL\nana.garcia,ERP,x\n,,\n", HOY)
    assert r["resumen"]["filas"] == 1
