import hashlib
from datetime import date

import httpx

from .base import ConnectorError, Hit

API = "https://leakcheck.io/api/public"


def address_hash(address: str) -> str:
    """SHA-256 of the lowercased address, truncated to 24 hex characters (the format the API accepts)."""
    return hashlib.sha256(address.strip().lower().encode()).hexdigest()[:24]


def _month(raw: str | None) -> date | None:
    try:
        year, month = (raw or "").split("-")[:2]
        return date(int(year), int(month), 1)
    except (ValueError, TypeError):
        return None


class LeakCheckConnector:
    """LeakCheck public API: free, no key, commercial use allowed with a "Powered by LeakCheck" link.

    Privacy: the address itself is never sent, only a truncated SHA-256 hash. The API returns the names
    and dates of the breaches an identifier appears in, plus the kinds of data across all of them (it cannot
    say which breach exposed what), so findings are marked with the address only and rated by default.
    """

    name = "LeakCheck"
    min_interval = 1.1  # the public API allows 1 request per second
    batch_size = 60
    daily_budget = None

    def __init__(self, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"user-agent": user_agent, "accept": "application/json"}
        self._client = client or httpx.Client(timeout=20)

    def check_address(self, address: str) -> list[Hit]:
        try:
            r = self._client.get(API, params={"check": address_hash(address)}, headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"LeakCheck unreachable: {e}") from e
        if r.status_code == 429:
            raise ConnectorError("LeakCheck: rate limit reached", retry_after=_retry_after(r))
        if r.status_code >= 500:
            raise ConnectorError(f"LeakCheck: service error ({r.status_code})")
        try:
            body = r.json()
        except ValueError as e:
            raise ConnectorError("LeakCheck: unreadable response") from e
        if not isinstance(body, dict):
            raise ConnectorError("LeakCheck: unexpected format")
        if not body.get("success"):
            if str(body.get("error", "")).lower() == "not found":
                return []  # not in any known breach
            raise ConnectorError(f"LeakCheck: {str(body.get('error') or 'request refused')[:120]}")
        hits = []
        for src in body.get("sources") or []:
            if not isinstance(src, dict) or not src.get("name"):
                continue
            hits.append(Hit(identifier=address, source=self.name, breach=str(src["name"])[:255],
                            breach_date=_month(src.get("date")), data_classes=("Email addresses",)))
        return hits


def _retry_after(r: httpx.Response) -> int:
    try:
        return int(r.headers.get("retry-after", "60"))
    except ValueError:
        return 60
