import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import migrate, news, scheduler, verification
from .config import settings
from .connectors import build_connectors
from .db import SessionLocal
from .deps import LoginRequired, get_session, has_users, require_user
from .models import Domain, Finding, ScanRun, User
from .notifier import SEVERITY_LABEL, Notifier
from .scanner import run_scan
from .security import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    LoginThrottle,
    authenticate,
    get_secret,
    hash_password,
    make_session_token,
    password_problem,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    migrate.upgrade()
    with SessionLocal() as session:
        news.seed_default_sources(session)
    sched = scheduler.start() if settings.scheduler_enabled else None
    yield
    if sched:
        sched.shutdown(wait=False)


app = FastAPI(title="OpenDLM", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals.update(severity_label=SEVERITY_LABEL, demo=settings.demo)
throttle = LoginThrottle()


@app.middleware("http")
async def same_origin_for_writes(request: Request, call_next):
    """Refuse les POST venant d'un autre site (en plus du cookie SameSite=Lax)."""
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "origine refusée"}, status_code=403)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
    return response


@app.exception_handler(LoginRequired)
async def login_required_handler(request: Request, _: LoginRequired):
    with SessionLocal() as session:
        target = "/login" if has_users(session) else "/setup"
    return RedirectResponse(target, status_code=303)


def _set_session_cookie(response: RedirectResponse, user: User, session: Session) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        make_session_token(user, get_secret(session)),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )


# --- Pages publiques ---------------------------------------------------------


@app.get("/healthz")
def healthz(session: Session = Depends(get_session)):
    session.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/setup")
def setup_page(request: Request, session: Session = Depends(get_session)):
    if has_users(session):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", {"error": None})


@app.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    session: Session = Depends(get_session),
):
    if has_users(session):
        raise HTTPException(403, "Le compte administrateur existe déjà")
    username = username.strip().lower()
    error = None
    if not (3 <= len(username) <= 64) or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
        error = "Nom d'utilisateur invalide (3 à 64 caractères : lettres, chiffres, - _ .)."
    elif password != confirm:
        error = "Les deux mots de passe ne correspondent pas."
    else:
        error = password_problem(password)
    if error:
        return templates.TemplateResponse(request, "setup.html", {"error": error}, status_code=422)
    user = User(username=username, password_hash=hash_password(password))
    session.add(user)
    session.commit()
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, user, session)
    return response


@app.get("/login")
def login_page(request: Request, session: Session = Depends(get_session)):
    if not has_users(session):
        return RedirectResponse("/setup", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    key = request.client.host if request.client else "inconnu"
    wait = throttle.retry_after(key)
    if wait:
        return templates.TemplateResponse(
            request, "login.html", {"error": f"Trop d'essais. Réessayez dans {wait} s."}, status_code=429
        )
    user = authenticate(session, username, password)
    if user is None:
        throttle.fail(key)
        return templates.TemplateResponse(request, "login.html", {"error": "Identifiants incorrects."}, status_code=401)
    throttle.reset(key)
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, user, session)
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# --- Pages protégées ---------------------------------------------------------

router = APIRouter(dependencies=[Depends(require_user)])


def _domain_or_404(session: Session, domain_id: int) -> Domain:
    domain = session.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(404, "Domaine inconnu")
    return domain


@router.get("/")
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


@router.post("/domains")
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


@router.get("/domains/{domain_id}")
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


@router.post("/domains/{domain_id}/verify")
def verify_domain(domain_id: int, session: Session = Depends(get_session)):
    domain = _domain_or_404(session, domain_id)
    if verification.check_dns_txt(domain.name, domain.verify_token):
        domain.verified = True
        session.commit()
    return RedirectResponse(f"/domains/{domain.id}", status_code=303)


@router.post("/domains/{domain_id}/scan")
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


@router.post("/findings/{finding_id}/ack")
def ack_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Fuite inconnue")
    finding.status = "ack"
    session.commit()
    return RedirectResponse(f"/domains/{finding.domain_id}", status_code=303)


app.include_router(router)
