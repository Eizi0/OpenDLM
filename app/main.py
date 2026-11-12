import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import migrate, scheduler, verification
from .config import settings
from .connectors import build_connectors
from .db import SessionLocal
from .models import Domain, Finding, ScanRun
from .notifier import SEVERITY_LABEL, Notifier
from .scanner import run_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    migrate.upgrade()
    sched = scheduler.start() if settings.scheduler_enabled else None
    yield
    if sched:
        sched.shutdown(wait=False)


app = FastAPI(title="OpenDLM", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals.update(severity_label=SEVERITY_LABEL, demo=settings.demo)


@app.middleware("http")
async def same_origin_for_writes(request: Request, call_next):
    """Refuse les POST venant d'un autre site (pas d'authentification pour l'instant)."""
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "origine refusée"}, status_code=403)
    return await call_next(request)


def get_session():
    with SessionLocal() as session:
        yield session


def _domain_or_404(session: Session, domain_id: int) -> Domain:
    domain = session.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(404, "Domaine inconnu")
    return domain


@app.get("/healthz")
def healthz(session: Session = Depends(get_session)):
    session.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/")
def dashboard(request: Request, session: Session = Depends(get_session)):
    rows = []
    for d in session.scalars(select(Domain).order_by(Domain.name)):
        new = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id, Finding.status == "new")) or 0
        total = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id)) or 0
        last = session.scalar(select(ScanRun).where(ScanRun.domain_id == d.id).order_by(ScanRun.started_at.desc()).limit(1))
        rows.append({"domain": d, "new": new, "total": total, "last": last})
    totals = {
        "domains": len(rows),
        "new": sum(r["new"] for r in rows),
        "total": sum(r["total"] for r in rows),
    }
    connectors = [c.name for c in build_connectors()]
    return templates.TemplateResponse(request, "dashboard.html", {"rows": rows, "totals": totals, "connectors": connectors})


@app.post("/domains")
def add_domain(name: str = Form(...), session: Session = Depends(get_session)):
    normalized = verification.normalize_domain(name)
    if normalized is None:
        raise HTTPException(422, "Nom de domaine invalide")
    if session.scalar(select(Domain).where(Domain.name == normalized)):
        raise HTTPException(409, "Domaine déjà suivi")
    domain = Domain(name=normalized, verify_token=verification.new_token(), verified=settings.demo)
    session.add(domain)
    session.commit()
    return RedirectResponse(f"/domains/{domain.id}", status_code=303)


@app.get("/domains/{domain_id}")
def domain_detail(request: Request, domain_id: int, session: Session = Depends(get_session)):
    domain = _domain_or_404(session, domain_id)
    findings = session.scalars(
        select(Finding).where(Finding.domain_id == domain.id).order_by(Finding.status.asc(), Finding.first_seen.desc())
    ).all()
    runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == domain.id).order_by(ScanRun.started_at.desc()).limit(10)).all()
    return templates.TemplateResponse(
        request,
        "domain.html",
        {"domain": domain, "findings": findings, "runs": runs, "txt": verification.txt_value(domain.verify_token), "has_connectors": bool(build_connectors())},
    )


@app.post("/domains/{domain_id}/verify")
def verify_domain(domain_id: int, session: Session = Depends(get_session)):
    domain = _domain_or_404(session, domain_id)
    if verification.check_dns_txt(domain.name, domain.verify_token):
        domain.verified = True
        session.commit()
    return RedirectResponse(f"/domains/{domain.id}", status_code=303)


@app.post("/domains/{domain_id}/scan")
def scan_domain(domain_id: int, session: Session = Depends(get_session)):
    domain = _domain_or_404(session, domain_id)
    connectors = build_connectors()
    if not connectors:
        raise HTTPException(409, "Aucun connecteur actif : activer le mode démo ou renseigner une clé HIBP")
    try:
        run_scan(session, domain, connectors, Notifier())
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return RedirectResponse(f"/domains/{domain.id}", status_code=303)


@app.post("/findings/{finding_id}/ack")
def ack_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Fuite inconnue")
    finding.status = "ack"
    session.commit()
    return RedirectResponse(f"/domains/{finding.domain_id}", status_code=303)
