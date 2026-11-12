import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, cast, func, select, text
from sqlalchemy.orm import Session

from . import channels, health, migrate, news, reports, scheduler, verification
from .config import settings
from .runtime_config import cfg
from .connectors import build_connectors
from .db import SessionLocal
from .deps import LoginRequired, get_session, has_users, require_user
from .models import Domain, Finding, NewsItem, NewsSource, Report, ScanRun, User, WatchWord, utcnow
from .ssrf import UnsafeURL, check_url
from .news import RELIABILITY_LABEL
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


def fmt_local(value: datetime | None, pattern: str = "%d/%m/%Y %H:%M") -> str:
    """Date dans le fuseau configuré (les dates sont stockées en UTC)."""
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(cfg.timezone)).strftime(pattern)


templates.env.filters["local"] = fmt_local
templates.env.globals.update(severity_label=SEVERITY_LABEL, reliability_label=RELIABILITY_LABEL, demo=settings.demo)
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
    now = utcnow()
    for d in session.scalars(select(Domain).order_by(Domain.name)):
        new = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id, Finding.status == "new")) or 0
        total = session.scalar(select(func.count(Finding.id)).where(Finding.domain_id == d.id)) or 0
        last = session.scalar(select(ScanRun).where(ScanRun.domain_id == d.id).order_by(ScanRun.started_at.desc()).limit(1))
        runs = session.scalars(select(ScanRun).where(ScanRun.domain_id == d.id, ScanRun.started_at > now - timedelta(days=health.DAYS + 1))).all()
        bars = health.build_bars(runs, now)
        rows.append({"domain": d, "new": new, "total": total, "last": last, "bars": bars, "streak": health.clean_streak(bars)})
    totals = {
        "domains": len(rows),
        "new": sum(r["new"] for r in rows),
        "total": sum(r["total"] for r in rows),
    }
    connectors = [c.name for c in build_connectors()]
    recent = session.scalars(select(NewsItem).where(NewsItem.first_seen > utcnow() - timedelta(days=7)).order_by(NewsItem.first_seen.desc()).limit(200)).all()
    mentions = [i for i in recent if i.matched]
    last_scan = session.scalar(select(func.max(ScanRun.started_at)))
    verified = any(r["domain"].verified for r in rows)
    stale = health.scanner_stale(last_scan, now, has_work=verified and bool(connectors))
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"rows": rows, "totals": totals, "connectors": connectors, "mentions": mentions, "stale": stale, "last_scan": last_scan},
    )


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


FINDING_STATUSES = {"ack", "resolved", "new"}


@router.post("/findings/{finding_id}/status")
def set_finding_status(finding_id: int, status: str = Form(...), session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Fuite inconnue")
    if status not in FINDING_STATUSES:
        raise HTTPException(422, "Statut invalide")
    finding.status = status
    session.commit()
    return RedirectResponse(f"/domains/{finding.domain_id}", status_code=303)


@router.post("/findings/{finding_id}/ack")
def ack_finding(finding_id: int, session: Session = Depends(get_session)):
    return set_finding_status(finding_id, "ack", session)


@router.post("/domains/{domain_id}/delete")
def delete_domain(domain_id: int, confirm: str = Form(""), session: Session = Depends(get_session)):
    domain = _domain_or_404(session, domain_id)
    if confirm.strip().lower() != domain.name:
        raise HTTPException(422, "Saisissez le nom exact du domaine pour confirmer la suppression")
    session.delete(domain)
    session.commit()
    return RedirectResponse("/", status_code=303)


def _mask_channel(url: str) -> str:
    """Affiche le type de canal sans jamais montrer les jetons contenus dans l'URL."""
    scheme = url.split("://", 1)[0] if "://" in url else "inconnu"
    return f"{scheme}://…"


@router.get("/notifications")
def notifications_page(request: Request):
    masked = [_mask_channel(u) for u in channels.all_urls()]
    return templates.TemplateResponse(
        request, "notifications.html",
        {"channels": masked, "min_severity": cfg.alert_min_severity, "notice": request.query_params.get("notice"), "error": request.query_params.get("error")},
    )


@router.post("/notifications/test")
def notifications_test():
    if not channels.all_urls():
        return RedirectResponse("/notifications?error=Aucun canal configuré (OPENDLM_NOTIFY_URLS)", status_code=303)
    ok = Notifier().send("[OpenDLM] Message de test", "Si vous lisez ce message, ce canal reçoit bien les alertes et les rapports d'OpenDLM.")
    flag = "notice=Message de test envoyé" if ok else "error=Échec de l'envoi : vérifiez l'URL du canal dans les journaux"
    return RedirectResponse(f"/notifications?{flag}", status_code=303)


PAGE_SIZE = 30


@router.get("/news")
def news_page(
    request: Request,
    source: int | None = None,
    reliability: str | None = None,
    mentions: int = 0,
    page: int = 1,
    session: Session = Depends(get_session),
):
    page = max(page, 1)
    query = select(NewsItem).join(NewsSource)
    if source:
        query = query.where(NewsItem.source_id == source)
    if reliability in RELIABILITY_LABEL:
        query = query.where(NewsItem.reliability == reliability)
    if mentions:
        # Cast en texte : le type JSON de PostgreSQL n'a pas d'opérateur d'égalité.
        query = query.where(cast(NewsItem.matched, String) != "[]")
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = session.scalars(
        query.order_by(NewsItem.published_at.desc().nulls_last(), NewsItem.id.desc()).limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)
    ).all()
    recent_mentions = session.scalars(
        select(NewsItem).where(NewsItem.first_seen > utcnow() - timedelta(days=7)).order_by(NewsItem.first_seen.desc()).limit(50)
    ).all()
    recent_mentions = [i for i in recent_mentions if i.matched]
    return templates.TemplateResponse(
        request,
        "news.html",
        {
            "items": items, "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE)),
            "sources": session.scalars(select(NewsSource).order_by(NewsSource.name)).all(),
            "words": session.scalars(select(WatchWord).order_by(WatchWord.term)).all(),
            "filters": {"source": source, "reliability": reliability, "mentions": mentions},
            "recent_mentions": recent_mentions[:5],
        },
    )


@router.post("/watch-words")
def add_watch_word(term: str = Form(...), session: Session = Depends(get_session)):
    term = " ".join(term.split())
    if not (3 <= len(term) <= 120):
        raise HTTPException(422, "Le mot surveillé doit contenir entre 3 et 120 caractères")
    if not session.scalar(select(WatchWord).where(func.lower(WatchWord.term) == term.lower())):
        session.add(WatchWord(term=term))
        session.commit()
    return RedirectResponse("/news", status_code=303)


@router.post("/watch-words/{word_id}/delete")
def delete_watch_word(word_id: int, session: Session = Depends(get_session)):
    word = session.get(WatchWord, word_id)
    if word:
        session.delete(word)
        session.commit()
    return RedirectResponse("/news", status_code=303)


KIND_LABEL = {"rss": "Flux RSS/Atom", "ransomware_live": "API ransomware.live PRO"}


def _source_status(src: NewsSource) -> tuple[str, str]:
    if not src.enabled:
        return "Désactivée", ""
    if src.kind == "ransomware_live" and not cfg.ransomware_live_key:
        return "Clé API manquante", "warn"
    if src.last_ok is None:
        return "En attente du premier passage", ""
    return ("Active", "ok") if src.last_ok else ("En erreur", "warn")


@router.get("/sources")
def sources_page(request: Request, session: Session = Depends(get_session)):
    rows = []
    for src in session.scalars(select(NewsSource).order_by(NewsSource.builtin.desc(), NewsSource.name)):
        label, tone = _source_status(src)
        rows.append({"src": src, "status": label, "tone": tone, "kind": KIND_LABEL.get(src.kind, src.kind),
                     "count": session.scalar(select(func.count(NewsItem.id)).where(NewsItem.source_id == src.id)) or 0})
    leak_sources = [
        {"name": "Have I Been Pwned", "ok": bool(cfg.hibp_api_key), "detail": "Clé API configurée" if cfg.hibp_api_key else "Clé API manquante (OPENDLM_HIBP_API_KEY)"},
        {"name": "Hudson Rock (logs infostealer)", "ok": bool(cfg.hudson_rock_key), "detail": "Clé API configurée" if cfg.hudson_rock_key else "Clé API manquante (OPENDLM_HUDSON_ROCK_KEY)"},
        {"name": "Connecteur de démonstration", "ok": settings.demo, "detail": "Actif : données fictives" if settings.demo else "Désactivé"},
    ]
    return templates.TemplateResponse(
        request, "sources.html",
        {"rows": rows, "leak_sources": leak_sources, "notify_count": len(channels.all_urls()), "error": request.query_params.get("error")},
    )


@router.post("/sources")
def add_source(name: str = Form(...), url: str = Form(...), session: Session = Depends(get_session)):
    name, url = " ".join(name.split()), url.strip()
    if not (2 <= len(name) <= 80):
        return RedirectResponse("/sources?error=Nom invalide (2 à 80 caractères)", status_code=303)
    try:
        check_url(url, cfg.allow_private_feeds)
    except UnsafeURL as e:
        return RedirectResponse(f"/sources?error={e}", status_code=303)
    if session.scalar(select(NewsSource).where(NewsSource.name == name)):
        return RedirectResponse("/sources?error=Ce nom est déjà utilisé", status_code=303)
    session.add(NewsSource(name=name, kind="rss", url=url[:1000], enabled=True))
    session.commit()
    return RedirectResponse("/sources", status_code=303)


def _source_or_404(session: Session, source_id: int) -> NewsSource:
    src = session.get(NewsSource, source_id)
    if src is None:
        raise HTTPException(404, "Source inconnue")
    return src


@router.post("/sources/{source_id}/toggle")
def toggle_source(source_id: int, session: Session = Depends(get_session)):
    src = _source_or_404(session, source_id)
    src.enabled = not src.enabled
    session.commit()
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/{source_id}/refresh")
def refresh_source_now(source_id: int, session: Session = Depends(get_session)):
    src = _source_or_404(session, source_id)
    news.refresh_source(session, src, Notifier())
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/{source_id}/delete")
def delete_source(source_id: int, session: Session = Depends(get_session)):
    src = _source_or_404(session, source_id)
    if src.builtin:
        raise HTTPException(403, "Une source intégrée ne peut pas être supprimée, seulement désactivée")
    session.delete(src)
    session.commit()
    return RedirectResponse("/sources", status_code=303)


@router.get("/reports")
@router.get("/reports/{report_id}")
def reports_page(request: Request, report_id: int | None = None, session: Session = Depends(get_session)):
    archive = session.scalars(select(Report).order_by(Report.created_at.desc()).limit(60)).all()
    selected = session.get(Report, report_id) if report_id else (archive[0] if archive else None)
    if report_id and selected is None:
        raise HTTPException(404, "Rapport inconnu")
    schedule = {
        "daily": cfg.report_daily, "monthly": cfg.report_monthly, "hour": cfg.report_hour,
        "timezone": cfg.timezone, "send_empty": cfg.report_send_empty,
        "channels": len(channels.all_urls()), "min_severity": cfg.alert_min_severity,
    }
    return templates.TemplateResponse(
        request, "reports.html",
        {"archive": archive, "selected": selected, "schedule": schedule, "kind_label": reports.KIND_LABEL,
         "attribution": reports.ATTRIBUTION, "error": request.query_params.get("error"), "notice": request.query_params.get("notice")},
    )


@router.post("/reports/generate")
def generate_report(kind: str = Form(...), session: Session = Depends(get_session)):
    if kind not in reports.KIND_LABEL:
        raise HTTPException(422, "Type de rapport invalide")
    report = reports.build_report(session, kind)
    return RedirectResponse(f"/reports/{report.id}", status_code=303)


@router.post("/reports/{report_id}/send")
def send_report_now(report_id: int, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "Rapport inconnu")
    if not channels.all_urls():
        return RedirectResponse(f"/reports/{report.id}?error=Aucun canal configuré (OPENDLM_NOTIFY_URLS)", status_code=303)
    ok = reports.send_report(session, report, Notifier())
    flag = "notice=Rapport envoyé" if ok else "error=Échec de l'envoi, voir les journaux"
    return RedirectResponse(f"/reports/{report.id}?{flag}", status_code=303)


def _export_name(report: Report, ext: str) -> str:
    return f"opendlm-rapport-{report.kind}-{report.created_at.strftime('%Y%m%d')}.{ext}"


@router.get("/reports/{report_id}/export.md")
def export_markdown(report_id: int, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "Rapport inconnu")
    return PlainTextResponse(
        reports.render_markdown(report), media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_export_name(report, "md")}"'},
    )


@router.get("/reports/{report_id}/export.html")
def export_html(request: Request, report_id: int, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "Rapport inconnu")
    response = templates.TemplateResponse(request, "report_doc.html", {"report": report, "d": report.data, "kind_label": reports.KIND_LABEL, "attribution": reports.ATTRIBUTION})
    response.headers["Content-Disposition"] = f'attachment; filename="{_export_name(report, "html")}"'
    return response


app.include_router(router)
