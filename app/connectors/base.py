from dataclasses import dataclass
from datetime import date
from typing import Protocol


@dataclass(frozen=True)
class Hit:
    """Résultat normalisé d'une source : jamais de mot de passe, seulement des métadonnées."""

    identifier: str
    source: str
    breach: str
    breach_date: date | None = None
    data_classes: tuple[str, ...] = ()


class ConnectorError(Exception):
    """Source indisponible ou refusée. retry_after (secondes) si la source l'indique."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class Connector(Protocol):
    name: str

    def check_domain(self, domain: str) -> list[Hit]: ...
