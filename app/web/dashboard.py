"""Dashboard, domains and findings."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import health, verification
from ..config import settings
from ..connectors import build_connectors
from ..deps import get_session, require_user
from ..i18n import t
from ..models import Domain, Finding, NewsItem, ScanRun, utcnow
from ..notifier import Notifier
from ..scanner import run_scan
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_user)])

FINDING_STATUSES = {"ack", "resolved", "new"}


def domain_or_404(session: Session, domain_id: int) -> Domain:
    domain = session.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(404, t("Unknown domain"))
    return domain


@router.get("/")
def dashboard(request: Request, session: Session = Depends(get_session)):
    rows = []
    now = utcnow()
    for d in session.scalars(select(Domain).order_by(Domain.name)):
        new = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id, Finding.status == "new")) or 0
        total = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id)) or 0
        last = session.scalar(select(ScanRun).where(ScanRun.domain_id == d.id).order_by(ScanRun.started_at.desc()).limit(1))
        runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == d.id, ScanRun.started_at > now - timedelta(days=health.DAYS + 1))).all()
        bars = health.build_bars(runs, now)
        rows.append({"domain": d, "new": new, "total": total, "last": last, "bars": bars, "streak": health.clean_streak(bars)})
    totals = {"domains": len(rows), "new": sum(r["new"] for r in rows), "total": sum(r["total"] for r in rows)}
    connectors = [c.name for c in build_connectors()]
    recent = session.scalars(select(NewsItem).where(NewsItem.first_seen > now - timedelta(days=7)).order_by(NewsItem.first_seen.desc()).limit(200)).all()
    mentions = [i for i in recent if i.matched]
    last_scan = session.scalar(select(func.max(ScanRun.started_at)))
    verified = any(r["domain"].verified for r in rows)
    stale = health.scanner_stale(last_scan, now, has_work=verified and bool(connectors))
    return render(
        request, "dashboard.html",
        {"rows": rows, "totals": totals, "connectors": connectors, "mentions": mentions, "stale": stale, "last_scan": last_scan},
    )


@router.post("/domains")
def add_domain(name: str = Form(...), session: Session = Depends(get_session)):
    normalized = verification.normalize_domain(name)
    if normalized is None:
        raise HTTPException(422, t("Invalid domain name"))
    if session.scalar(select(Domain).where(Domain.name == normalized)):
        raise HTTPException(409, t("Domain already monitored"))
    domain = Domain(name=normalized, verify_token=verification.new_token(), verified=settings.demo)
    session.add(domain)
    session.commit()
    return redirect(f"/domains/{domain.id}")


@router.get("/domains/{domain_id}")
def domain_detail(request: Request, domain_id: int, session: Session = Depends(get_session)):
    domain = domain_or_404(session, domain_id)
    findings = session.scalars(
        select(Finding).where(Finding.domain_id == domain.id).order_by(Finding.status.asc(), Finding.first_seen.desc())
    ).all()
    runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain.id).order_by(ScanRun.started_at.desc()).limit(10)).all()
    return render(
        request, "domain.html",
        {"domain": domain, "findings": findings, "runs": runs, "txt": verification.txt_value(domain.verify_token), "has_connectors": bool(build_connectors())},
    )


@router.post("/domains/{domain_id}/verify")
def verify_domain(domain_id: int, session: Session = Depends(get_session)):
    domain = domain_or_404(session, domain_id)
    if verification.check_dns_txt(domain.name, domain.verify_token):
        domain.verified = True
        session.commit()
    return redirect(f"/domains/{domain.id}")


@router.post("/domains/{domain_id}/scan")
def scan_domain(domain_id: int, session: Session = Depends(get_session)):
    domain = domain_or_404(session, domain_id)
    connectors = build_connectors()
    if not connectors:
        raise HTTPException(409, t("No active connector: enable the demo mode or set an API key in Sources"))
    try:
        run_scan(session, domain, connectors, Notifier())
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return redirect(f"/domains/{domain.id}")


@router.post("/findings/{finding_id}/status")
def set_finding_status(finding_id: int, status: str = Form(...), session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, t("Unknown finding"))
    if status not in FINDING_STATUSES:
        raise HTTPException(422, t("Invalid status"))
    finding.status = status
    session.commit()
    return redirect(f"/domains/{finding.domain_id}")


@router.post("/findings/{finding_id}/ack")
def ack_finding(finding_id: int, session: Session = Depends(get_session)):
    return set_finding_status(finding_id, "ack", session)


@router.post("/domains/{domain_id}/delete")
def delete_domain(domain_id: int, confirm: str = Form(""), session: Session = Depends(get_session)):
    domain = domain_or_404(session, domain_id)
    if confirm.strip().lower() != domain.name:
        raise HTTPException(422, t("Type the exact domain name to confirm the deletion"))
    session.delete(domain)
    session.commit()
    return redirect("/")
