"""RSS/Atom feed reading: everything coming from the network is treated as untrusted."""

import html
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx
from defusedxml import ElementTree as ET

from .ssrf import UnsafeURL, check_url

MAX_BYTES = 5_000_000
MAX_ITEMS = 200
MAX_REDIRECTS = 3
EXCERPT_LEN = 400

# Reliability levels published by FrenchBreaches (<category> tag).
RELIABILITY = {"confirmed": "confirmed", "credible": "credible", "unreliable": "unreliable", "low": "unreliable"}


class FeedError(Exception):
    pass


@dataclass(frozen=True)
class NewsEntry:
    guid: str
    title: str
    url: str
    excerpt: str = ""
    published_at: datetime | None = None
    reliability: str | None = None


@dataclass
class FetchResult:
    not_modified: bool = False
    content: bytes = b""
    etag: str | None = None
    last_modified: str | None = None


def clean_text(raw: str | None, limit: int = EXCERPT_LEN) -> str:
    """Plain text: tags removed, entities decoded, whitespace normalized, length bounded."""
    text = re.sub(r"<[^>]+>", " ", html.unescape(raw or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def safe_url(raw: str | None) -> str:
    """Keep http(s) links only: never javascript: or data: in a page."""
    url = (raw or "").strip()
    return url[:1000] if url.lower().startswith(("http://", "https://")) else ""


def fetch(client: httpx.Client, url: str, etag: str | None, last_modified: str | None, user_agent: str, allow_private: bool) -> FetchResult:
    headers = {"user-agent": user_agent, "accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"}
    if etag:
        headers["if-none-match"] = etag
    if last_modified:
        headers["if-modified-since"] = last_modified
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            check_url(current, allow_private)
        except UnsafeURL as e:
            raise FeedError(str(e)) from e
        try:
            with client.stream("GET", current, headers=headers, follow_redirects=False) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("location")
                    if not location:
                        raise FeedError("Redirect without a destination")
                    current = str(httpx.URL(current).join(location))
                    continue
                if r.status_code == 304:
                    return FetchResult(not_modified=True)
                if r.status_code != 200:
                    raise FeedError(f"HTTP response {r.status_code}")
                body = bytearray()
                for chunk in r.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        raise FeedError("Feed too large")
                return FetchResult(content=bytes(body), etag=r.headers.get("etag"), last_modified=r.headers.get("last-modified"))
        except httpx.HTTPError as e:
            raise FeedError(f"Source unreachable: {e}") from e
    raise FeedError("Too many redirects")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el, name: str) -> str | None:
    for c in el:
        if _local(c.tag) == name and c.text:
            return c.text
    return None


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_feed(content: bytes) -> list[NewsEntry]:
    try:
        root = ET.fromstring(content)
    except Exception as e:  # invalid XML or refused (external entities, etc.)
        raise FeedError(f"Unreadable feed: {e}") from e
    entries: list[NewsEntry] = []
    nodes = [el for el in root.iter() if _local(el.tag) in ("item", "entry")]
    for el in nodes[:MAX_ITEMS]:
        title = clean_text(_child_text(el, "title"), 300)
        link = ""
        for c in el:
            if _local(c.tag) == "link":
                link = safe_url(c.get("href") or c.text)
                if link:
                    break
        guid = (_child_text(el, "guid") or _child_text(el, "id") or link or title).strip()[:512]
        if not title or not guid:
            continue
        summary = _child_text(el, "description") or _child_text(el, "summary") or ""
        category = (_child_text(el, "category") or "").strip().lower()
        entries.append(
            NewsEntry(
                guid=guid,
                title=title,
                url=link,
                excerpt=clean_text(summary),
                published_at=_parse_date(_child_text(el, "pubDate") or _child_text(el, "published") or _child_text(el, "updated")),
                reliability=RELIABILITY.get(category),
            )
        )
    return entries


def normalize(text: str) -> str:
    """Lowercase without accents, to compare names."""
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def match_terms(text: str, terms: list[str]) -> list[str]:
    """Terms present as whole words in the text (ignoring accents and case)."""
    haystack = normalize(text)
    found = []
    for term in terms:
        needle = normalize(term).strip()
        if len(needle) >= 3 and re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack):
            found.append(term)
    return found
