import logging
from dataclasses import dataclass, field
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import feeds
from .config import settings
from .runtime_config import cfg
from .connectors import ransomware_live
from .i18n import t
from .labels import reliability_label
from .models import Domain, NewsItem, NewsSource, WatchWord, utcnow
from .notifier import Notifier

log = logging.getLogger("opendlm.news")

DEFAULT_SOURCES = [
    # name, kind, url, enabled
    ("FrenchBreaches", "rss", "https://frenchbreaches.com/feed.xml", True),
    ("ransomware.live", "ransomware_live", None, True),
    # The CERT-FR feed covers vulnerabilities, not leaks: disabled by default.
    ("CERT-FR (security advisories)", "rss", "https://www.cert.ssi.gouv.fr/feed/", False),
]


def seed_default_sources(session: Session) -> None:
    existing = {n for (n,) in session.execute(select(NewsSource.name))}
    for name, kind, url, enabled in DEFAULT_SOURCES:
        if name not in existing:
            session.add(NewsSource(name=name, kind=kind, url=url, enabled=enabled, builtin=True))
    session.commit()


def watch_terms(session: Session) -> list[str]:
    """Watched words: the ones entered plus the followed domain names."""
    words = [t for (t,) in session.execute(select(WatchWord.term))]
    domains = [n for (n,) in session.execute(select(Domain.name))]
    return list(dict.fromkeys(words + domains))


@dataclass
class RefreshResult:
    new: int = 0
    mentions: list[NewsItem] = field(default_factory=list)
    skipped: str | None = None
    error: str | None = None
    not_modified: bool = False


def format_mention(items: list[NewsItem]) -> tuple[str, str]:
    title = t("[OpenDLM] %(n)d news item(s) mention your watched words", n=len(items))
    lines = []
    for it in items:
        rel = reliability_label(it.reliability)
        lines.append(f"- [{', '.join(it.matched)}] {it.title} ({it.source.name}{' · ' + rel if rel else ''}) {it.url}".rstrip())
    return title, "\n".join(lines)


def refresh_source(session: Session, source: NewsSource, notifier: Notifier | None = None, client: httpx.Client | None = None) -> RefreshResult:
    """Fetch a source, store what is new and warn when a watched word appears.

    First successful pass: silent baseline (no alert on the history).
    """
    result = RefreshResult()
    owns_client = client is None
    client = client or httpx.Client(timeout=30)
    try:
        entries = _fetch_entries(source, client, result)
    except feeds.FeedError as e:
        result.error = str(e)
        _record(session, source, ok=False, error=str(e))
        log.warning("source %s failed: %s", source.name, e)
        return result
    finally:
        if owns_client:
            client.close()

    if result.skipped:
        # Unconfigured source: not an outage (the Sources page says so, the report does not flag it).
        source.last_ok, source.last_error = None, None
        session.commit()
        return result
    if result.not_modified:
        _record(session, source, ok=True)
        return result

    guids = [e.guid for e in entries]
    known = {g for (g,) in session.execute(select(NewsItem.guid).where(NewsItem.source_id == source.id, NewsItem.guid.in_(guids)))} if guids else set()
    terms = watch_terms(session)
    baseline = not source.baselined
    created: list[NewsItem] = []
    for e in entries:
        if e.guid in known:
            continue
        known.add(e.guid)
        matched = feeds.match_terms(f"{e.title} {e.excerpt}", terms)
        created.append(
            NewsItem(
                source_id=source.id, guid=e.guid, title=e.title, url=e.url, excerpt=e.excerpt,
                published_at=e.published_at, reliability=e.reliability, matched=matched,
                notified=baseline or not matched,
            )
        )
    session.add_all(created)
    source.baselined = True
    _record(session, source, ok=True)
    result.new = len(created)
    result.mentions = [] if baseline else [c for c in created if c.matched]
    session.execute(delete(NewsItem).where(NewsItem.published_at < utcnow() - timedelta(days=cfg.news_retention_days)))
    session.commit()

    if result.mentions and notifier:
        notifier.send(*format_mention(result.mentions))
    return result


def _fetch_entries(source: NewsSource, client: httpx.Client, result: RefreshResult) -> list[feeds.NewsEntry]:
    if source.kind == "ransomware_live":
        if not cfg.ransomware_live_key:
            result.skipped = "API key missing"
            return []
        return ransomware_live.fetch_recent(client, cfg.ransomware_live_key, settings.user_agent)
    if not source.url:
        raise feeds.FeedError("Feed URL missing")
    fetched = feeds.fetch(client, source.url, source.etag, source.last_modified, settings.user_agent, cfg.allow_private_feeds)
    if fetched.not_modified:
        result.not_modified = True
        return []
    source.etag, source.last_modified = fetched.etag, fetched.last_modified
    return feeds.parse_feed(fetched.content)


def _record(session: Session, source: NewsSource, ok: bool, error: str | None = None) -> None:
    source.last_fetch_at = utcnow()
    source.last_ok = ok
    source.last_error = None if ok else error
    session.commit()


def refresh_all(session: Session, notifier: Notifier | None = None) -> dict[str, RefreshResult]:
    out = {}
    for source in session.scalars(select(NewsSource).where(NewsSource.enabled.is_(True))):
        out[source.name] = refresh_source(session, source, notifier)
    return out
