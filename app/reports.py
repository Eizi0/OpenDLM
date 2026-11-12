"""Daily and monthly reports.

Archived data is language-neutral (codes and ISO dates); labels, dates and sentences are
produced at display or send time in the current language.
"""

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from .i18n import N_, fmt_date, month_name, t
from .labels import SEVERITY_ORDER, reliability_label, severity_label
from .models import Domain, Finding, NewsItem, NewsSource, Report, ScanRun, utcnow
from .notifier import Notifier
from .runtime_config import cfg

log = logging.getLogger("opendlm.reports")

KINDS = ("daily", "monthly")
_KIND_LABEL = {"daily": N_("daily"), "monthly": N_("monthly")}
ATTRIBUTION = N_(
    "Leak data: Have I Been Pwned (haveibeenpwned.com), licensed CC BY 4.0. "
    "OpenDLM does not store any password or leaked content."
)


def kind_label(kind: str) -> str:
    return t(_KIND_LABEL[kind])


def _tz() -> ZoneInfo:
    return ZoneInfo(cfg.timezone)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite returns naive datetimes


def period_for(kind: str, now: datetime) -> tuple[datetime, datetime, dict]:
    """Daily: the last 24 hours. Monthly: the previous calendar month (configured timezone).

    Returns start, end (UTC) and a neutral label descriptor.
    """
    now = now.astimezone(timezone.utc)
    if kind == "daily":
        local = now.astimezone(_tz())
        return now - timedelta(hours=24), now, {"type": "day", "date": local.date().isoformat()}
    local = now.astimezone(_tz())
    first_this = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    first_prev = (first_this - timedelta(days=1)).replace(day=1)
    return (
        first_prev.astimezone(timezone.utc),
        first_this.astimezone(timezone.utc),
        {"type": "month", "year": first_prev.year, "month": first_prev.month},
    )


def label_text(label: dict) -> str:
    if isinstance(label, str):  # reports archived before the language-neutral format
        return label
    if label["type"] == "month":
        return f"{month_name(label['month'])} {label['year']}"
    return fmt_date(label["date"])


def title_text(report: Report) -> str:
    d = report.data
    n = d["totals"]["new_findings"]
    tail = t("%(n)d new leak(s)", n=n) if n else t("nothing to report") if d["empty"] else t("to review")
    return t("[OpenDLM] %(kind)s report · %(label)s · %(tail)s", kind=kind_label(d["kind"]), label=label_text(d["label"]), tail=tail)


def build_report(session: Session, kind: str, now: datetime | None = None) -> Report:
    if kind not in KINDS:
        raise ValueError(f"unknown report type: {kind}")
    now = now or utcnow()
    start, end, label = period_for(kind, now)

    domains = []
    total_new = 0
    for d in session.scalars(select(Domain).where(Domain.verified.is_(True)).order_by(Domain.name)):
        new = session.scalars(
            select(Finding).where(Finding.domain_id == d.id, Finding.first_seen >= start, Finding.first_seen < end, Finding.status != "known")
        ).all()
        new = sorted(new, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.identifier))
        open_total = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id, Finding.status == "new")) or 0
        total_new += len(new)
        domains.append({
            "name": d.name,
            "open_total": open_total,
            "new": [
                {"identifier": f.identifier, "severity": f.severity, "breach": f.breach, "source": f.source,
                 "breach_date": f.breach_date.isoformat() if f.breach_date else None, "data_classes": list(f.data_classes or [])}
                for f in new
            ],
        })

    when = func.coalesce(NewsItem.published_at, NewsItem.first_seen)
    items = session.scalars(
        select(NewsItem).where(when >= start, when < end, cast(NewsItem.matched, String) != "[]").order_by(when.desc()).limit(100)
    ).all()
    mentions = [
        {"title": i.title, "url": i.url, "source": i.source.name, "matched": list(i.matched), "reliability": i.reliability,
         "published": _aware(i.published_at or i.first_seen).astimezone(_tz()).date().isoformat()}
        for i in items
    ]
    news_total = session.scalar(select(func.count(NewsItem.id)).where(when >= start, when < end)) or 0

    problems = []
    for r in session.scalars(select(ScanRun).where(ScanRun.ok.is_(False), ScanRun.started_at >= start, ScanRun.started_at < end).order_by(ScanRun.started_at.desc())):
        entry = {"source": r.source, "message": r.error or ""}
        if entry not in problems:
            problems.append(entry)
    for s in session.scalars(select(NewsSource).where(NewsSource.enabled.is_(True), NewsSource.last_ok.is_(False))):
        problems.append({"source": s.name, "message": s.last_error or ""})

    data = {
        "kind": kind, "label": label,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "totals": {"domains": len(domains), "new_findings": total_new, "mentions": len(mentions), "news": news_total,
                   "open": sum(d["open_total"] for d in domains)},
        "domains": domains, "mentions": mentions, "problems": problems,
        "empty": not total_new and not mentions and not problems,
        "generated": now.astimezone(_tz()).date().isoformat(),
    }
    report = Report(kind=kind, period_start=start, period_end=end, title="", data=data)
    report.title = title_text(report)[:200]  # default language snapshot; display recomputes it
    session.add(report)
    session.commit()
    return report


def render_markdown(report: Report) -> str:
    d = report.data
    tot = d["totals"]
    lines = [t("# %(kind)s report · %(label)s", kind=kind_label(d["kind"]).capitalize(), label=label_text(d["label"])), ""]
    lines.append(
        t("**%(new)d new leak(s)** · %(mentions)d news mention(s) · %(domains)d monitored domain(s) · %(open)d leak(s) left to handle",
          new=tot["new_findings"], mentions=tot["mentions"], domains=tot["domains"], open=tot["open"])
    )
    if d["empty"]:
        lines += ["", t("Nothing to report for this period.")]
    for dom in d["domains"]:
        if not dom["new"]:
            continue
        lines += ["", f"## {dom['name']}"]
        for f in dom["new"]:
            when = t(" · leaked on %(date)s", date=fmt_date(f["breach_date"])) if f["breach_date"] else ""
            data = t(" · data: %(classes)s", classes=", ".join(f["data_classes"])) if f["data_classes"] else ""
            lines.append(f"- **{severity_label(f['severity'])}** · `{f['identifier']}` · {f['breach']} ({f['source']}){when}{data}")
    if d["mentions"]:
        lines += ["", "## " + t("News that concerns you")]
        for m in d["mentions"]:
            rel = reliability_label(m["reliability"])
            rel = f" · {rel}" if rel else ""
            link = f" {m['url']}" if m["url"] else ""
            lines.append(f"- [{', '.join(m['matched'])}] {m['title']} ({m['source']}{rel}){link}")
    if d["problems"]:
        lines += ["", "## " + t("Source status")] + [f"- {p['source']}: {t(p['message'])}" for p in d["problems"]]
    lines += ["", f"_{t(ATTRIBUTION)}_"]
    return "\n".join(lines)


def send_report(session: Session, report: Report, notifier: Notifier) -> bool:
    ok = notifier.send(title_text(report), render_markdown(report), markdown=True)
    if ok:
        report.sent_at = utcnow()
        session.commit()
    return ok


def run_scheduled(session: Session, kind: str, notifier: Notifier) -> Report | None:
    """Build and send the scheduled report. An empty report is sent only if configured (heartbeat)."""
    report = build_report(session, kind)
    if report.data["empty"] and not cfg.report_send_empty:
        log.info("report %s is empty: not sent", kind)
        return report
    send_report(session, report, notifier)
    return report
