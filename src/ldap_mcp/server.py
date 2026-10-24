"""Servidor MCP: expone el directorio LDAP como herramientas para agentes de IA."""

from __future__ import annotations

from datetime import date
import os
from pathlib import Path, PurePath

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


def _dir_csv() -> Path:
    """Única carpeta desde la que se pueden leer CSV (LDAP_MCP_CSV_DIR, por defecto ./data)."""
    return Path(os.environ.get("LDAP_MCP_CSV_DIR", "data")).resolve(strict=True)


def _leer_csv_permitido(ruta_csv: str) -> str:
    """Lee un CSV solo si está dentro de la carpeta permitida.

    Evita que un agente (o un prompt inyectado) lea archivos arbitrarios del equipo
    o rutas de red UNC. Se acepta un nombre de archivo o una ruta relativa a esa carpeta.
    """
    base = _dir_csv()
    nombre = PurePath(ruta_csv)
    if nombre.is_absolute() or nombre.drive or nombre.anchor or ".." in nombre.parts:
        raise ValueError(f"Usa una ruta relativa dentro de la carpeta permitida ({base.name}).")
    candidato = base / nombre
    if candidato.is_symlink():
        raise ValueError("No se permiten enlaces simbólicos.")
    ruta = candidato.resolve(strict=True)
    if not ruta.is_relative_to(base) or not ruta.is_file():
        raise ValueError("El archivo no está en la carpeta permitida.")
    if ruta.suffix.lower() != ".csv":
        raise ValueError("Solo se aceptan archivos .csv.")
    with ruta.open("rb") as f:
        datos = f.read(MAX_CSV_BYTES + 1)
    if len(datos) > MAX_CSV_BYTES:
        raise ValueError("El archivo supera el tamaño máximo (2 MB).")
    return datos.decode("utf-8-sig")


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
        ruta_csv: Alternativa: nombre de un .csv dentro de la carpeta permitida
            (LDAP_MCP_CSV_DIR, por defecto ./data), por ejemplo "accesos_ejemplo.csv".
    """
    if not csv_texto and ruta_csv:
        csv_texto = _leer_csv_permitido(ruta_csv)
    if not csv_texto.strip():
        raise ValueError("Envía csv_texto o ruta_csv.")
    return audit.cruzar_accesos(_dir().todos(), csv_texto, _hoy())


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
