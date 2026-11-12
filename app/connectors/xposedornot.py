import threading
import time
from datetime import date, datetime

import httpx

from .base import ConnectorError, Hit

API = "https://api.xposedornot.com/v1"
CATALOG_TTL = 24 * 3600

_catalog_lock = threading.Lock()
_catalog: dict[str, dict] = {}
_catalog_at = 0.0


def reset_catalog() -> None:
    global _catalog, _catalog_at
    with _catalog_lock:
        _catalog, _catalog_at = {}, 0.0


class XposedOrNotConnector:
    """XposedOrNot free API: no key, "for personal and low-volume use".

    Free limits are per IP: 2 requests/second, 25 per hour and 100 per day for e-mail checks, so the
    batch is small and a daily budget below the cap is enforced. The address is sent in clear to
    api.xposedornot.com (the service has no hash lookup): this connector is opt-in.
    """

    name = "XposedOrNot"
    min_interval = 1.0
    batch_size = 20
    daily_budget = 90

    def __init__(self, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"user-agent": user_agent, "accept": "application/json"}
        self._client = client or httpx.Client(timeout=30)

    def _get(self, path: str) -> httpx.Response:
        try:
            r = self._client.get(f"{API}{path}", headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"XposedOrNot unreachable: {e}") from e
        if r.status_code == 429:
            raise ConnectorError("XposedOrNot: rate limit reached", retry_after=_retry_after(r))
        if r.status_code >= 500:
            raise ConnectorError(f"XposedOrNot: service error ({r.status_code})")
        return r

    def _breach_catalog(self) -> dict[str, dict]:
        """Breach id -> details (date, data classes), cached for a day: one call serves every address."""
        global _catalog, _catalog_at
        with _catalog_lock:
            if _catalog and time.monotonic() - _catalog_at < CATALOG_TTL:
                return _catalog
        r = self._get("/breaches")
        if r.status_code != 200:
            raise ConnectorError(f"XposedOrNot: breach catalog unavailable ({r.status_code})")
        try:
            items = r.json().get("exposedBreaches") or []
        except (ValueError, AttributeError) as e:
            raise ConnectorError("XposedOrNot: unreadable breach catalog") from e
        with _catalog_lock:
            _catalog = {b["breachID"]: b for b in items if isinstance(b, dict) and b.get("breachID")}
            _catalog_at = time.monotonic()
            return _catalog

    def check_address(self, address: str) -> list[Hit]:
        r = self._get(f"/check-email/{address}")
        try:
            body = r.json()
        except ValueError as e:
            raise ConnectorError("XposedOrNot: unreadable response") from e
        if r.status_code == 404 or (isinstance(body, dict) and body.get("Error") == "Not found"):
            return []  # the API answers 200 with an "Error: Not found" body when nothing is known
        if r.status_code != 200 or not isinstance(body, dict):
            raise ConnectorError(f"XposedOrNot: unexpected response ({r.status_code})")
        names: list[str] = []
        for group in body.get("breaches") or []:  # a list of lists of breach ids
            names.extend(group if isinstance(group, list) else [group])
        if not names:
            return []
        catalog = self._breach_catalog()
        hits = []
        for name in dict.fromkeys(str(n) for n in names):
            meta = catalog.get(name, {})
            hits.append(Hit(identifier=address, source=self.name, breach=name[:255], breach_date=_day(meta.get("breachedDate")),
                            data_classes=tuple(meta.get("exposedData") or ("Email addresses",))))
        return hits


def _day(raw: str | None) -> date | None:
    try:
        return datetime.fromisoformat((raw or "").replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _retry_after(r: httpx.Response) -> int:
    try:
        return int(r.headers.get("retry-after", "3600"))
    except ValueError:
        return 3600
