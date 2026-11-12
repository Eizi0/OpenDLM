"""Hudson Rock free tools: the keyless endpoints behind hudsonrock.com/free-tools.

Unofficial use: Hudson Rock reserves its documented API for paid/granted keys. These endpoints are the ones
its free tools (and open-source tools such as theHarvester) use, with no key, but their terms for automated use
are not explicit. The source is on by default and switches itself off as soon as an official key is saved,
which gives more detail (the affected addresses themselves).

Only counts, dates and a one-way machine id are kept. The responses also contain computer names, partial IP
addresses and masked logins/passwords of real people: all of it is discarded.
"""

import hashlib
from datetime import date, datetime

import httpx

from .base import ConnectorError, Hit

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
NAME = "Hudson Rock (free)"
DATA_CLASSES = ("Stealer logs", "Passwords", "Email addresses")


def _day(raw: str | None) -> date | None:
    try:
        return datetime.fromisoformat((raw or "").replace("Z", "+00:00")).date()
    except ValueError:
        return None


class _Base:
    name = NAME

    def __init__(self, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"user-agent": user_agent, "accept": "application/json"}
        self._client = client or httpx.Client(timeout=60)  # big domains can take a while

    def _get(self, endpoint: str, params: dict) -> dict:
        try:
            r = self._client.get(f"{API}/{endpoint}", params=params, headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"Hudson Rock (free) unreachable: {e}") from e
        if r.status_code == 429:
            raise ConnectorError("Hudson Rock (free): rate limit reached", retry_after=_retry_after(r))
        if r.status_code in (401, 403):
            raise ConnectorError("Hudson Rock (free): access refused (automated use may be blocked)")
        if r.status_code >= 500:
            raise ConnectorError(f"Hudson Rock (free): service error ({r.status_code})")
        if r.status_code != 200:
            raise ConnectorError(f"Hudson Rock (free): unexpected response ({r.status_code})")
        try:
            body = r.json()
        except ValueError as e:  # a challenge page instead of JSON
            raise ConnectorError("Hudson Rock (free): unreadable response (automated use may be blocked)") from e
        if not isinstance(body, dict):
            raise ConnectorError("Hudson Rock (free): unexpected format")
        return body


class HudsonRockFreeDomain(_Base):
    """Domain-wide counts of employee accounts found in infostealer logs (no addresses: only a number).

    One finding per count value: when the number grows, a new finding is created and you are alerted.
    Customer accounts are left out on purpose: that number grows daily for large sites and would only add noise.
    """

    def check_domain(self, domain: str) -> list[Hit]:
        body = self._get("search-by-domain", {"domain": domain})
        employees = body.get("employees")
        if not isinstance(employees, int) or employees <= 0:
            return []
        return [Hit(identifier=f"[domain-wide]@{domain}", source=self.name,
                    breach=f"Employee accounts in infostealer logs: {employees}",
                    breach_date=_day(body.get("last_employee_compromised")), data_classes=DATA_CLASSES)]


class HudsonRockFreeAddress(_Base):
    """Infections linked to one monitored address. The address is sent in clear (no hash lookup exists)."""

    min_interval = 2.0
    batch_size = 30
    daily_budget = 300  # no published limit: stay modest

    def check_address(self, address: str) -> list[Hit]:
        body = self._get("search-by-email", {"email": address})
        hits = []
        for s in body.get("stealers") or []:
            if not isinstance(s, dict):
                continue
            day = _day(s.get("date_compromised"))
            machine = hashlib.sha256(f"{s.get('computer_name', '')}|{s.get('date_compromised', '')}".encode()).hexdigest()[:6]
            hits.append(Hit(identifier=address, source=self.name,
                            breach=f"Infostealer infection · {day.isoformat() if day else 'unknown date'} · machine {machine}",
                            breach_date=day, data_classes=DATA_CLASSES))
        return hits


def _retry_after(r: httpx.Response) -> int:
    try:
        return int(r.headers.get("retry-after", "60"))
    except ValueError:
        return 60
