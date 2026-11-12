from datetime import datetime, timezone

import httpx

from ..feeds import FeedError, NewsEntry, clean_text

API = "https://api-pro.ransomware.live"


def _date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def fetch_recent(client: httpx.Client, api_key: str, user_agent: str) -> list[NewsEntry]:
    """Revendications récentes de groupes de rançongiciel (API PRO, clé gratuite).

    Ce sont des revendications, pas des faits établis : la fiabilité est « claimed ».
    """
    try:
        r = client.get(f"{API}/victims/recent", headers={"X-API-KEY": api_key, "user-agent": user_agent}, timeout=30)
    except httpx.HTTPError as e:
        raise FeedError(f"ransomware.live injoignable : {e}") from e
    if r.status_code in (401, 403):
        raise FeedError("ransomware.live : clé API refusée")
    if r.status_code == 429:
        raise FeedError("ransomware.live : limite de débit atteinte")
    if r.status_code != 200:
        raise FeedError(f"ransomware.live : réponse HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError as e:
        raise FeedError("ransomware.live : réponse illisible") from e
    if not isinstance(data, list):
        raise FeedError("ransomware.live : format inattendu")

    entries = []
    for v in data[:200]:
        if not isinstance(v, dict):
            continue
        name = clean_text(str(v.get("victim") or v.get("name") or ""), 300)
        group = clean_text(str(v.get("group") or ""), 80)
        when = _date(v.get("discovered") or v.get("attackdate"))
        if not name:
            continue
        detail = " · ".join(p for p in (f"Revendiqué par {group}" if group else "", v.get("country") or "", v.get("activity") or "") if p)
        guid = f"{group}|{name}|{when.date() if when else ''}"
        page = v.get("url") if isinstance(v.get("url"), str) and v["url"].startswith("https://www.ransomware.live/") else "https://www.ransomware.live/"
        entries.append(NewsEntry(guid=guid[:512], title=name, url=page, excerpt=clean_text(detail), published_at=when, reliability="claimed"))
    return entries
