"""Acceso de solo lectura al directorio LDAP."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from ldap3 import SUBTREE, Connection, Server
from ldap3.utils.conv import escape_filter_chars

from .models import Usuario, dias_a_fecha

ATRIBUTOS_USUARIO = [
    "uid",
    "cn",
    "mail",
    "departmentNumber",
    "shadowExpire",
    "shadowLastChange",
]


class Directorio(Protocol):
    def buscar(self, texto: str, limite: int = 20) -> list[Usuario]: ...
    def obtener(self, uid: str) -> Usuario | None: ...
    def todos(self) -> list[Usuario]: ...


@dataclass
class ConfigLdap:
    url: str
    bind_dn: str
    bind_password: str
    base_dn: str
    users_ou: str = "ou=people"
    groups_ou: str = "ou=groups"

    @classmethod
    def desde_entorno(cls) -> "ConfigLdap":
        faltan = [
            v
            for v in ("LDAP_URL", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN")
            if not os.environ.get(v)
        ]
        if faltan:
            raise RuntimeError(
                "Faltan variables de entorno: " + ", ".join(faltan) + ". Revisa .env.example."
            )
        return cls(
            url=os.environ["LDAP_URL"],
            bind_dn=os.environ["LDAP_BIND_DN"],
            bind_password=os.environ["LDAP_BIND_PASSWORD"],
            base_dn=os.environ["LDAP_BASE_DN"],
            users_ou=os.environ.get("LDAP_USERS_OU", "ou=people"),
            groups_ou=os.environ.get("LDAP_GROUPS_OU", "ou=groups"),
        )

    @property
    def users_base(self) -> str:
        return f"{self.users_ou},{self.base_dn}"

    @property
    def groups_base(self) -> str:
        return f"{self.groups_ou},{self.base_dn}"


def _primero(entry, attr: str) -> str | None:
    valor = entry.get(attr)
    if isinstance(valor, list):
        return str(valor[0]) if valor else None
    return str(valor) if valor not in (None, "") else None


class DirectorioLdap:
    """Implementación con ldap3. Solo hace búsquedas: nunca modifica el directorio."""

    def __init__(self, config: ConfigLdap):
        self.config = config

    def _conectar(self) -> Connection:
        server = Server(self.config.url, connect_timeout=5)
        return Connection(
            server,
            user=self.config.bind_dn,
            password=self.config.bind_password,
            auto_bind=True,
            read_only=True,
            receive_timeout=10,
        )

    def _grupos_por_dn(self, conn: Connection) -> dict[str, list[str]]:
        conn.search(
            self.config.groups_base,
            "(objectClass=groupOfNames)",
            SUBTREE,
            attributes=["cn", "member"],
        )
        mapa: dict[str, list[str]] = {}
        for e in conn.response or []:
            if e.get("type") != "searchResEntry":
                continue
            attrs = e["attributes"]
            cn = _primero(attrs, "cn")
            for miembro in attrs.get("member", []) or []:
                mapa.setdefault(str(miembro).lower(), []).append(cn)
        return mapa

    def _usuarios(self, conn: Connection, filtro: str, limite: int = 0) -> list[Usuario]:
        conn.search(
            self.config.users_base,
            filtro,
            SUBTREE,
            attributes=ATRIBUTOS_USUARIO,
            size_limit=limite,
        )
        # Copiar la respuesta antes de buscar grupos: cada búsqueda reemplaza conn.response.
        entradas = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
        grupos = self._grupos_por_dn(conn) if entradas else {}
        usuarios = []
        for e in entradas:
            if e.get("type") != "searchResEntry":
                continue
            a = e["attributes"]
            usuarios.append(
                Usuario(
                    uid=_primero(a, "uid") or "",
                    nombre=_primero(a, "cn") or "",
                    email=_primero(a, "mail"),
                    departamento=_primero(a, "departmentNumber"),
                    grupos=sorted(grupos.get(e["dn"].lower(), [])),
                    expira=dias_a_fecha(_primero(a, "shadowExpire")),
                    ultimo_cambio_clave=dias_a_fecha(_primero(a, "shadowLastChange")),
                )
            )
        return usuarios

    def buscar(self, texto: str, limite: int = 20) -> list[Usuario]:
        t = escape_filter_chars(texto.strip())
        filtro = f"(&(objectClass=inetOrgPerson)(|(uid=*{t}*)(cn=*{t}*)(mail=*{t}*)))"
        with self._conectar() as conn:
            return self._usuarios(conn, filtro, limite)

    def obtener(self, uid: str) -> Usuario | None:
        filtro = f"(&(objectClass=inetOrgPerson)(uid={escape_filter_chars(uid.strip())}))"
        with self._conectar() as conn:
            res = self._usuarios(conn, filtro, 1)
        return res[0] if res else None

    def todos(self) -> list[Usuario]:
        with self._conectar() as conn:
            return self._usuarios(conn, "(objectClass=inetOrgPerson)")
