"""Connection tests: check an API key without running a scan.

Each check returns (ok, message id, params); the message is translated when displayed.
"""

import httpx

from ..i18n import N_

from . import hibp, hudson_rock, ransomware_live

CONNECTOR_IDS = ("hibp", "hudson_rock", "ransomware_live")


def _client(client: httpx.Client | None) -> httpx.Client:
    return client or httpx.Client(timeout=30)


def check_hibp(key: str, user_agent: str, client: httpx.Client | None = None) -> tuple[bool, str, dict]:
    try:
        r = _client(client).get(f"{hibp.API}/subscribeddomains", headers={"hibp-api-key": key, "user-agent": user_agent})
    except httpx.HTTPError as e:
        return False, N_("Unreachable: %(error)s"), {"error": str(e)}
    if r.status_code == 200:
        try:
            n = len(r.json())
        except ValueError:
            n = 0
        return True, N_("Key accepted, %(n)d verified domain(s) on your HIBP account"), {"n": n}
    if r.status_code == 401:
        return False, N_("API key rejected"), {}
    if r.status_code == 429:
        return False, N_("Rate limit reached, try again shortly"), {}
    return False, N_("Unexpected response (%(status)d)"), {"status": r.status_code}


def check_hudson_rock(key: str, user_agent: str, client: httpx.Client | None = None) -> tuple[bool, str, dict]:
    body = {"domains": ["example.com"], "types": ["employees"], "sort_by": "date_compromised", "sort_direction": "desc"}
    try:
        r = _client(client).post(
            f"{hudson_rock.API}/search-by-domain", json=body, headers={"api-key": key, "user-agent": user_agent, "accept": "application/json"}
        )
    except httpx.HTTPError as e:
        return False, N_("Unreachable: %(error)s"), {"error": str(e)}
    if r.status_code == 200:
        return True, N_("Key accepted with the search-by-domain permission"), {}
    if r.status_code == 401:
        return False, N_("API key rejected"), {}
    if r.status_code == 403:
        return False, N_("Key valid, but the search-by-domain permission is missing from your plan"), {}
    if r.status_code == 429:
        return False, N_("Rate limit reached, try again shortly"), {}
    return False, N_("Unexpected response (%(status)d)"), {"status": r.status_code}


def check_ransomware_live(key: str, user_agent: str, client: httpx.Client | None = None) -> tuple[bool, str, dict]:
    try:
        r = _client(client).get(f"{ransomware_live.API}/victims/recent", headers={"X-API-KEY": key, "user-agent": user_agent})
    except httpx.HTTPError as e:
        return False, N_("Unreachable: %(error)s"), {"error": str(e)}
    if r.status_code == 200:
        return True, N_("Key accepted"), {}
    if r.status_code in (401, 403):
        return False, N_("API key rejected"), {}
    if r.status_code == 429:
        return False, N_("Rate limit reached, try again shortly"), {}
    return False, N_("Unexpected response (%(status)d)"), {"status": r.status_code}


CHECKS = {"hibp": check_hibp, "hudson_rock": check_hudson_rock, "ransomware_live": check_ransomware_live}


def check(connector_id: str, key: str, user_agent: str, client: httpx.Client | None = None) -> tuple[bool, str, dict]:
    return CHECKS[connector_id](key, user_agent, client)
