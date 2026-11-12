import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from .config import settings
from .models import Domain, Finding, NewsItem, NewsSource, Report, ScanRun, utcnow
from .news import RELIABILITY_LABEL
from .notifier import SEVERITY_LABEL, SEVERITY_ORDER, Notifier

log = logging.getLogger("opendlm.reports")

KIND_LABEL = {"daily": "quotidien", "monthly": "mensuel"}
MONTHS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]
ATTRIBUTION = (
    "Données de fuites : Have I Been Pwned (haveibeenpwned.com), licence CC BY 4.0. "
    "OpenDLM ne conserve aucun mot de passe ni contenu de fuite."
)


def _tz() -> ZoneInfo:
    return ZoneInfo(settings.timezone)


def _fr_date(dt: datetime) -> str:
    local = dt.astimezone(_tz())
    return f"{local.day} {MONTHS[local.month - 1]} {local.year}"


def period_for(kind: str, now: datetime) -> tuple[datetime, datetime, str]:
    """Quotidien : les dernières 24 h. Mensuel : le mois civil précédent (fuseau configuré)."""
    now = now.astimezone(timezone.utc)
    if kind == "daily":
        return now - timedelta(hours=24), now, _fr_date(now)
    local = now.astimezone(_tz())
    first_this = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    first_prev = (first_this - timedelta(days=1)).replace(day=1)
    return first_prev.astimezone(timezone.utc), first_this.astimezone(timezone.utc), f"{MONTHS[first_prev.month - 1]} {first_prev.year}"


def build_report(session: Session, kind: str, now: datetime | None = None) -> Report:
    if kind not in KIND_LABEL:
        raise ValueError(f"type de rapport inconnu : {kind}")
    now = now or utcnow()
    start, end, label = period_for(kind, now)

    domains = []
    total_new = 0
    for d in session.scalars(select(Domain).where(Domain.verified.is_(True)).order_by(Domain.name)):
        new = session.scalars(
            select(Finding)
            .where(Finding.domain_id == d.id, Finding.first_seen >= start, Finding.first_seen < end, Finding.status != "known")
        ).all()
        new = sorted(new, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.identifier))
        open_total = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id, Finding.status == "new")) or 0
        total_new += len(new)
        domains.append({
            "name": d.name,
            "open_total": open_total,
            "new": [
                {
                    "identifier": f.identifier, "severity": f.severity, "severity_label": SEVERITY_LABEL.get(f.severity, f.severity),
                    "breach": f.breach, "source": f.source,
                    "breach_date": f.breach_date.strftime("%d/%m/%Y") if f.breach_date else None,
                    "data_classes": list(f.data_classes or []),
                }
                for f in new
            ],
        })

    when = func.coalesce(NewsItem.published_at, NewsItem.first_seen)
    items = session.scalars(
        select(NewsItem).where(when >= start, when < end, cast(NewsItem.matched, String) != "[]").order_by(when.desc()).limit(100)
    ).all()
    mentions = [
        {"title": i.title, "url": i.url, "source": i.source.name, "matched": list(i.matched),
         "reliability": RELIABILITY_LABEL.get(i.reliability or "", ""), "published": _fr_date(i.published_at or i.first_seen)}
        for i in items
    ]
    news_total = session.scalar(select(func.count(NewsItem.id)).where(when >= start, when < end)) or 0

    problems = []
    for r in session.scalars(select(ScanRun).where(ScanRun.ok.is_(False), ScanRun.started_at >= start, ScanRun.started_at < end).order_by(ScanRun.started_at.desc())):
        line = f"{r.source} : {r.error}"
        if line not in problems:
            problems.append(line)
    for s in session.scalars(select(NewsSource).where(NewsSource.enabled.is_(True), NewsSource.last_ok.is_(False))):
        problems.append(f"{s.name} : {s.last_error}")

    data = {
        "kind": kind, "label": label,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "totals": {"domains": len(domains), "new_findings": total_new, "mentions": len(mentions), "news": news_total,
                   "open": sum(d["open_total"] for d in domains)},
        "domains": domains, "mentions": mentions, "problems": problems,
        "empty": not total_new and not mentions and not problems,
        "generated": _fr_date(now),
    }
    title = (
        f"[OpenDLM] Rapport {KIND_LABEL[kind]} · {label} · "
        + (f"{total_new} nouvelle(s) fuite(s)" if total_new else "rien à signaler" if data["empty"] else "à consulter")
    )
    report = Report(kind=kind, period_start=start, period_end=end, title=title[:200], data=data)
    session.add(report)
    session.commit()
    return report


def render_markdown(report: Report) -> str:
    d = report.data
    t = d["totals"]
    lines = [f"# Rapport {KIND_LABEL[d['kind']]} · {d['label']}", ""]
    lines.append(
        f"**{t['new_findings']} nouvelle(s) fuite(s)** · {t['mentions']} mention(s) d'actus · "
        f"{t['domains']} domaine(s) surveillé(s) · {t['open']} fuite(s) restant à traiter"
    )
    if d["empty"]:
        lines += ["", "Rien à signaler sur la période."]
    for dom in d["domains"]:
        if not dom["new"]:
            continue
        lines += ["", f"## {dom['name']}"]
        for f in dom["new"]:
            when = f" · fuite du {f['breach_date']}" if f["breach_date"] else ""
            data = f" · données : {', '.join(f['data_classes'])}" if f["data_classes"] else ""
            lines.append(f"- **{f['severity_label']}** · `{f['identifier']}` · {f['breach']} ({f['source']}){when}{data}")
    if d["mentions"]:
        lines += ["", "## Actus qui vous concernent"]
        for m in d["mentions"]:
            rel = f" · {m['reliability']}" if m["reliability"] else ""
            link = f" {m['url']}" if m["url"] else ""
            lines.append(f"- « {', '.join(m['matched'])} » : {m['title']} ({m['source']}{rel}){link}")
    if d["problems"]:
        lines += ["", "## État des sources"] + [f"- {p}" for p in d["problems"]]
    lines += ["", f"_{ATTRIBUTION}_"]
    return "\n".join(lines)


def send_report(session: Session, report: Report, notifier: Notifier) -> bool:
    ok = notifier.send(report.title, render_markdown(report), markdown=True)
    if ok:
        report.sent_at = utcnow()
        session.commit()
    return ok


def run_scheduled(session: Session, kind: str, notifier: Notifier) -> Report | None:
    """Génère et envoie le rapport planifié. Un rapport vide n'est envoyé que si configuré (signal de vie)."""
    report = build_report(session, kind)
    if report.data["empty"] and not settings.report_send_empty:
        log.info("rapport %s vide : non envoyé", kind)
        return report
    send_report(session, report, notifier)
    return report
