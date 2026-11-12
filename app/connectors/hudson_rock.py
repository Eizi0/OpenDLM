import hashlib
from datetime import date, datetime

import httpx

from .base import ConnectorError, Hit

API = "https://api.hudsonrock.com/json/v3"
DATA_CLASSES = ("Stealer logs", "Passwords", "Email addresses")


def _day(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


class HudsonRockConnector:
    """Hudson Rock Cavalier (API v3): accounts of your domains stolen by infostealer malware.

    Needs a key whose plan grants the "search-by-domain" permission. Only the 20 most recent
    infections are read (sorted by date, newest first), which is enough to spot new ones on each pass.
    No password, IP address or machine name is kept.
    """

    name = "Hudson Rock"

    def __init__(self, api_key: str, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"api-key": api_key, "user-agent": user_agent, "accept": "application/json"}
        self._client = client or httpx.Client(timeout=100)  # the API can take up to 90 s

    def check_domain(self, domain: str) -> list[Hit]:
        body = {"domains": [domain], "types": ["employees"], "sort_by": "date_compromised", "sort_direction": "desc"}
        try:
            r = self._client.post(f"{API}/search-by-domain", json=body, headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"Hudson Rock unreachable: {e}") from e
        if r.status_code == 429:
            raise ConnectorError("Hudson Rock: rate limit reached", retry_after=_retry_after(r))
        if r.status_code == 401:
            raise ConnectorError("Hudson Rock: API key rejected")
        if r.status_code == 403:
            raise ConnectorError("Hudson Rock: the \"search-by-domain\" permission is missing from your plan, or the domain is not allowed")
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            raise ConnectorError(f"Hudson Rock: unexpected response ({r.status_code})")
        try:
            data = r.json().get("data") or []
        except (ValueError, AttributeError) as e:
            raise ConnectorError("Hudson Rock: unreadable response") from e
        return list(_hits(data, domain))


def _retry_after(r: httpx.Response) -> int:
    try:
        return int(r.headers.get("retry-after", "10"))
    except ValueError:
        return 10


def _hits(stealers: list, domain: str):
    suffix = "@" + domain
    for s in stealers:
        if not isinstance(s, dict):
            continue
        day = _day(s.get("date_compromised"))
        family = str(s.get("stealer_family") or "unknown")[:40]
        # Stable but irreversible machine id: tells two infections of the same day apart.
        machine = hashlib.sha256(f"{s.get('computer_name', '')}|{s.get('ip', '')}|{s.get('stealer', '')}".encode()).hexdigest()[:6]
        breach = f"Infostealer logs {family} · {day.isoformat() if day else 'unknown date'} · machine {machine}"
        for c in s.get("credentials") or []:
            if not isinstance(c, dict):
                continue
            user = str(c.get("username") or "").strip().lower()
            # Masked usernames (••••) do not identify the address: say so instead of guessing.
            identifier = user if user.endswith(suffix) and "•" not in user else f"[masked address]{suffix}"
            yield Hit(identifier=identifier[:320], source=HudsonRockConnector.name, breach=breach, breach_date=day, data_classes=DATA_CLASSES)
