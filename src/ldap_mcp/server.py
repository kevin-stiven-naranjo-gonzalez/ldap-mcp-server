"""Servidor MCP: expone el directorio LDAP como herramientas para agentes de IA."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from . import audit
from .directory import ConfigLdap, Directorio, DirectorioLdap

mcp = MCPServer("ldap-directory")

_directorio: Directorio | None = None
MAX_CSV_BYTES = 2_000_000


def set_directorio(directorio: Directorio | None) -> None:
    """Permite inyectar otro directorio (por ejemplo, uno falso en las pruebas)."""
    global _directorio
    _directorio = directorio


def _dir() -> Directorio:
    global _directorio
    if _directorio is None:
        _directorio = DirectorioLdap(ConfigLdap.desde_entorno())
    return _directorio


def _hoy() -> date:
    return date.today()


@mcp.tool()
def buscar_usuario(texto: str, limite: int = 20) -> list[dict]:
    """Busca usuarios por uid, nombre o correo (coincidencia parcial).

    Args:
        texto: Texto a buscar, por ejemplo "garcia" o "ana.".
        limite: Máximo de resultados (1-100).
    """
    if not texto.strip():
        raise ValueError("Indica un texto para buscar.")
    limite = max(1, min(int(limite), 100))
    return [u.to_dict() for u in _dir().buscar(texto, limite)]


@mcp.tool()
def listar_grupos_de_usuario(uid: str) -> dict:
    """Devuelve los grupos a los que pertenece un usuario.

    Args:
        uid: Identificador exacto del usuario, por ejemplo "ana.garcia".
    """
    u = _dir().obtener(uid)
    if u is None:
        return {"uid": uid, "encontrado": False, "grupos": []}
    return {"uid": u.uid, "encontrado": True, "nombre": u.nombre, "grupos": u.grupos}


@mcp.tool()
def detectar_cuentas_inactivas(dias_sin_cambio_clave: int = 90) -> dict:
    """Lista cuentas expiradas o con la clave sin cambiar en más de N días.

    Args:
        dias_sin_cambio_clave: Umbral en días (por defecto 90).
    """
    if dias_sin_cambio_clave < 1:
        raise ValueError("El umbral debe ser de al menos 1 día.")
    hallazgos = audit.cuentas_inactivas(_dir().todos(), _hoy(), dias_sin_cambio_clave)
    return {"total": len(hallazgos), "cuentas": hallazgos}


@mcp.tool()
def cruzar_accesos(csv_texto: str = "", ruta_csv: str = "") -> dict:
    """Cruza un listado de accesos contra el directorio y marca hallazgos.

    El CSV debe tener las columnas: usuario, aplicacion, rol.
    Devuelve usuarios inexistentes, cuentas expiradas y usuarios con varios roles
    en la misma aplicación.

    Args:
        csv_texto: Contenido del CSV.
        ruta_csv: Alternativa: ruta local a un archivo .csv.
    """
    if not csv_texto and ruta_csv:
        ruta = Path(ruta_csv).expanduser()
        if ruta.suffix.lower() != ".csv":
            raise ValueError("Solo se aceptan archivos .csv.")
        if ruta.stat().st_size > MAX_CSV_BYTES:
            raise ValueError("El archivo supera el tamaño máximo (2 MB).")
        csv_texto = ruta.read_text(encoding="utf-8-sig")
    if not csv_texto.strip():
        raise ValueError("Envía csv_texto o ruta_csv.")
    return audit.cruzar_accesos(_dir().todos(), csv_texto, _hoy())


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
