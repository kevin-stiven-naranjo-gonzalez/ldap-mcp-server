from datetime import date

import pytest

from ldap_mcp import server
from ldap_mcp.models import Usuario

HOY = date(2026, 10, 18)


class DirectorioFalso:
    def __init__(self, usuarios):
        self.usuarios = usuarios

    def buscar(self, texto, limite=20):
        t = texto.lower()
        res = [
            u
            for u in self.usuarios
            if t in u.uid.lower() or t in u.nombre.lower() or t in (u.email or "").lower()
        ]
        return res[:limite]

    def obtener(self, uid):
        return next((u for u in self.usuarios if u.uid == uid), None)

    def todos(self):
        return list(self.usuarios)


@pytest.fixture
def usuarios():
    return [
        Usuario("ana.garcia", "Ana García", "ana.garcia@example.org", "Tecnología",
                ["admin-sistemas", "vpn"], date(2040, 1, 1), date(2026, 10, 1)),
        Usuario("luis.martinez", "Luis Martínez", "luis.martinez@example.org", "Ventas",
                ["crm-ventas"], date(2040, 1, 1), date(2026, 1, 1)),
        Usuario("sofia.rojas", "Sofía Rojas", "sofia.rojas@example.org", "Finanzas",
                ["vpn"], date(2025, 1, 1), date(2026, 10, 1)),
        Usuario("diego.torres", "Diego Torres", "diego.torres@example.org", "Ventas",
                ["crm-ventas"], None, None),
    ]


@pytest.fixture
def directorio(usuarios, monkeypatch):
    d = DirectorioFalso(usuarios)
    server.set_directorio(d)
    monkeypatch.setattr(server, "_hoy", lambda: HOY)
    yield d
    server.set_directorio(None)
