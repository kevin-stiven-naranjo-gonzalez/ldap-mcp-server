"""Pruebas contra el OpenLDAP de docker-compose. Se ejecutan solo con LDAP_INTEGRATION=1."""

import os
from datetime import date

import pytest

from ldap_mcp import audit
from ldap_mcp.directory import ConfigLdap, DirectorioLdap

pytestmark = pytest.mark.skipif(
    os.environ.get("LDAP_INTEGRATION") != "1", reason="Requiere LDAP_INTEGRATION=1 y docker compose up"
)


@pytest.fixture
def d():
    return DirectorioLdap(
        ConfigLdap(
            url=os.environ.get("LDAP_URL", "ldap://localhost:389"),
            bind_dn=os.environ.get("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"),
            bind_password=os.environ.get("LDAP_BIND_PASSWORD", "admin_demo_local"),
            base_dn=os.environ.get("LDAP_BASE_DN", "dc=example,dc=org"),
        )
    )


def test_buscar_y_grupos(d):
    ana = d.obtener("ana.garcia")
    assert ana is not None
    assert ana.grupos == ["admin-sistemas", "vpn"]
    assert [u.uid for u in d.buscar("ventas")] == []  # departamento no entra en la búsqueda
    assert {u.uid for u in d.buscar("example.org")} >= {"ana.garcia", "diego.torres"}


def test_filtro_escapado(d):
    assert d.buscar("*)(uid=*") == []


def test_auditoria_completa(d):
    hoy = date(2026, 10, 18)
    inactivas = {h["uid"] for h in audit.cuentas_inactivas(d.todos(), hoy, 90)}
    assert inactivas == {"luis.martinez", "sofia.rojas", "valentina.lopez"}
