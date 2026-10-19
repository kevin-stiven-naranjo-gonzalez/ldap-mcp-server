from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, timedelta

EPOCH = date(1970, 1, 1)


def dias_a_fecha(dias: int | str | None) -> date | None:
    """Convierte un valor shadow* (días desde 1970-01-01) a fecha."""
    if dias in (None, "", []):
        return None
    try:
        n = int(dias)
    except (TypeError, ValueError):
        return None
    if n < 0:
        return None
    return EPOCH + timedelta(days=n)


@dataclass
class Usuario:
    uid: str
    nombre: str
    email: str | None = None
    departamento: str | None = None
    grupos: list[str] = field(default_factory=list)
    expira: date | None = None
    ultimo_cambio_clave: date | None = None

    def expirada(self, hoy: date) -> bool:
        return self.expira is not None and self.expira < hoy

    def to_dict(self) -> dict:
        d = asdict(self)
        d["expira"] = self.expira.isoformat() if self.expira else None
        d["ultimo_cambio_clave"] = (
            self.ultimo_cambio_clave.isoformat() if self.ultimo_cambio_clave else None
        )
        return d
