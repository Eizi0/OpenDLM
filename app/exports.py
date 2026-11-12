"""CSV and JSON exports of findings and news, and the Prometheus metrics text."""

import csv
import io
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from . import __version__, health
from .models import Domain, Finding, NewsItem, NewsSource, ScanRun, utcnow

MAX_ROWS = 50_000
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

FINDING_FIELDS = ["domain", "identifier", "source", "breach", "breach_date", "data_classes", "severity", "status", "first_seen"]
NEWS_FIELDS = ["source", "title", "url", "excerpt", "published_at", "reliability", "matched"]


def parse_since(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError("since must be an ISO date or datetime") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def findings_rows(session: Session, domain: str | None, status: str | None, severity: str | None, since: datetime | None, limit: int) -> list[dict]:
    query = select(Finding, Domain.name).join(Domain, Domain.id == Finding.domain_id)
    if domain:
        query = query.where(Domain.name == domain.strip().lower())
    if status:
        query = query.where(Finding.status == status)
    if severity:
        query = query.where(Finding.severity == severity)
    if since:
        query = query.where(Finding.first_seen >= since)
    rows = session.execute(query.order_by(Finding.first_seen.desc(), Finding.id.desc()).limit(min(limit, MAX_ROWS))).all()
    return [
        {"domain": name, "identifier": f.identifier, "source": f.source, "breach": f.breach,
         "breach_date": f.breach_date.isoformat() if f.breach_date else None, "data_classes": list(f.data_classes or []),
         "severity": f.severity, "status": f.status, "first_seen": _iso(f.first_seen)}
        for f, name in rows
    ]


def news_rows(session: Session, source: int | None, mentions: bool, since: datetime | None, limit: int) -> list[dict]:
    query = select(NewsItem, NewsSource.name).join(NewsSource, NewsSource.id == NewsItem.source_id)
    if source:
        query = query.where(NewsItem.source_id == source)
    if mentions:
        query = query.where(cast(NewsItem.matched, String) != "[]")
    if since:
        query = query.where(func.coalesce(NewsItem.published_at, NewsItem.first_seen) >= since)
    rows = session.execute(query.order_by(NewsItem.published_at.desc().nulls_last(), NewsItem.id.desc()).limit(min(limit, MAX_ROWS))).all()
    return [
        {"source": name, "title": i.title, "url": i.url, "excerpt": i.excerpt, "published_at": _iso(i.published_at),
         "reliability": i.reliability, "matched": list(i.matched or [])}
        for i, name in rows
    ]


def _cell(value) -> str:
    if value is None:
        return ""
    text = ";".join(value) if isinstance(value, list) else str(value)
    # Spreadsheet formula injection: a cell starting with = + - @ would be executed by Excel/LibreOffice.
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(rows: list[dict], fields: list[str]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(fields)
    for row in rows:
        writer.writerow([_cell(row.get(f)) for f in fields])
    return out.getvalue()


# --- Prometheus -------------------------------------------------------------------------------------


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metrics_text(session: Session) -> str:
    now = utcnow()
    lines: list[str] = []

    def metric(name: str, help_text: str, kind: str = "gauge"):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")

    metric("opendlm_info", "OpenDLM build information.")
    lines.append(f'opendlm_info{{version="{_label(__version__)}"}} 1')

    metric("opendlm_domains", "Monitored domains.")
    for verified in (True, False):
        n = session.scalar(select(func.count(Domain.id)).where(Domain.verified.is_(verified))) or 0
        lines.append(f'opendlm_domains{{verified="{str(verified).lower()}"}} {n}')

    metric("opendlm_findings", "Recorded findings by status and severity.")
    counts = {(s, sev): n for s, sev, n in session.execute(select(Finding.status, Finding.severity, func.count(Finding.id)).group_by(Finding.status, Finding.severity))}
    for (status, severity), n in sorted(counts.items()):
        lines.append(f'opendlm_findings{{status="{_label(status)}",severity="{_label(severity)}"}} {n}')

    last_scan = session.scalar(select(func.max(ScanRun.started_at)))
    metric("opendlm_last_scan_timestamp_seconds", "Unix time of the last scan (0 if none).")
    ts = 0 if last_scan is None else (last_scan if last_scan.tzinfo else last_scan.replace(tzinfo=timezone.utc)).timestamp()
    lines.append(f"opendlm_last_scan_timestamp_seconds {ts:.0f}")

    has_verified = bool(session.scalar(select(func.count(Domain.id)).where(Domain.verified.is_(True))))
    from .connectors import build_connectors  # local import: avoids loading connectors at module import

    stale = health.scanner_stale(last_scan, now, has_work=has_verified and bool(build_connectors()))
    metric("opendlm_scanner_stale", "1 when verified domains exist but no scan ran for over 26 hours.")
    lines.append(f"opendlm_scanner_stale {int(stale)}")

    metric("opendlm_scan_failures_24h", "Failed source queries during the last 24 hours.")
    failures = session.scalar(select(func.count(ScanRun.id)).where(ScanRun.ok.is_(False), ScanRun.started_at > now - timedelta(hours=24))) or 0
    lines.append(f"opendlm_scan_failures_24h {failures}")

    metric("opendlm_news_items", "Stored news items.")
    lines.append(f"opendlm_news_items {session.scalar(select(func.count(NewsItem.id))) or 0}")

    metric("opendlm_news_source_up", "1 when the last fetch of an enabled news source succeeded.")
    for src in session.scalars(select(NewsSource).where(NewsSource.enabled.is_(True)).order_by(NewsSource.name)):
        if src.last_ok is not None:
            lines.append(f'opendlm_news_source_up{{source="{_label(src.name)}"}} {int(bool(src.last_ok))}')
    return "\n".join(lines) + "\n"
