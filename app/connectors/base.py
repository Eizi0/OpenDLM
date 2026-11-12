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


class AddressConnector(Protocol):
    """A source that can only be asked about one address at a time (free tiers, mostly)."""

    name: str
    min_interval: float  # seconds to wait between two calls
    batch_size: int  # addresses checked per run
    daily_budget: int | None  # maximum checks per 24 h across all domains (None: no known cap)

    def check_address(self, address: str) -> list[Hit]: ...
