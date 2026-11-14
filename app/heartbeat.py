"""Heartbeat to a push monitor (Uptime Kuma "Push" monitor, Healthchecks.io, Better Stack...).

Every minute OpenDLM calls the configured URL. If OpenDLM stops, the monitor stops receiving calls and
warns you. When the application runs but its scanner does not (no scan for 26 h while there are domains
to watch), the call says status=down so the monitor warns as well.
"""

import logging
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import health
from .config import settings
from .connectors import active_source_names
from .models import Domain, Finding, ScanRun, utcnow
from .runtime_config import cfg

log = logging.getLogger("opendlm.heartbeat")

INTERVAL_MINUTES = 1  # matches the 60-second default of an Uptime Kuma Push monitor


def valid_url(url: str) -> bool:
    parts = urlsplit(url.strip())
    return parts.scheme in ("http", "https") and bool(parts.netloc) and not any(c.isspace() for c in url.strip())


def state(session: Session) -> tuple[str, str]:
    """("up" | "down", short message). The message never contains an address or a breach name."""
    now = utcnow()
    verified = (session.scalar(select(func.count(Domain.id)).where(Domain.verified.is_(True))) or 0) > 0
    last_scan = session.scalar(select(func.max(ScanRun.started_at)))
    if health.scanner_stale(last_scan, now, has_work=verified and bool(active_source_names())):
        return "down", "no scan for more than 26 h"
    since = now - health.STALE_AFTER
    recent = session.execute(select(ScanRun.ok).where(ScanRun.started_at > since)).scalars().all()
    if recent and not any(recent):
        return "down", "every source failed during the last scan"
    open_leaks = session.scalar(select(func.count(Finding.id)).where(Finding.status == "new")) or 0
    return "up", f"OK, {open_leaks} new leak(s) to handle"


def push(url: str, status: str, message: str) -> bool:
    try:
        r = httpx.get(url, params={"status": status, "msg": message}, timeout=10, follow_redirects=True,
                      headers={"User-Agent": settings.user_agent})
        if r.status_code >= 400:
            log.warning("heartbeat refused: HTTP %s", r.status_code)
            return False
        return True
    except httpx.HTTPError as e:
        log.warning("heartbeat failed: %s", e.__class__.__name__)
        return False


def beat(session: Session) -> bool | None:
    url = cfg.heartbeat_url
    if not url:
        return None
    status, message = state(session)
    return push(url, status, message)
