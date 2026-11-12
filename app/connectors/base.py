from dataclasses import dataclass
from datetime import date
from typing import Protocol


@dataclass(frozen=True)
class Hit:
    """Normalized result from a source: never a password, only metadata."""

    identifier: str
    source: str
    breach: str
    breach_date: date | None = None
    data_classes: tuple[str, ...] = ()


class ConnectorError(Exception):
    """Source unavailable or refusing. retry_after (seconds) when the source says so."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class Connector(Protocol):
    name: str

    def check_domain(self, domain: str) -> list[Hit]: ...
