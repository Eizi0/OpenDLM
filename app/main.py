import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from . import migrate, news, scheduler
from .config import settings
from .db import SessionLocal
from .deps import LoginRequired, has_users
from .i18n import LANGUAGES, reset_language, set_language, t
from .security import SESSION_COOKIE, get_secret, user_from_token
from .web import api, auth, dashboard, news_pages, notifications, reports_pages, settings_pages, sources, tokens, users
from .web.common import BASE

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


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


def _preferred_language(request: Request) -> str | None:
    """User preference, then language cookie; None means the instance default."""
    with SessionLocal() as session:
        user = user_from_token(session, request.cookies.get(SESSION_COOKIE), get_secret(session))
        if user is not None and user.language in LANGUAGES:
            return user.language
    cookie = request.cookies.get(auth.LANG_COOKIE)
    return cookie if cookie in LANGUAGES else None


@app.middleware("http")
async def language(request: Request, call_next):
    token = set_language(await run_in_threadpool(_preferred_language, request))
    try:
        return await call_next(request)
    finally:
        reset_language(token)


@app.middleware("http")
async def same_origin_for_writes(request: Request, call_next):
    """Refuse POSTs coming from another site (on top of the SameSite=Lax cookie)."""
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": t("origin refused")}, status_code=403)
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


@app.get("/healthz")
def healthz():
    with SessionLocal() as session:
        session.execute(text("SELECT 1"))
    return {"status": "ok"}


for module in (auth, dashboard, news_pages, sources, notifications, reports_pages, settings_pages):
    app.include_router(module.router)
app.include_router(users.admin_router)
app.include_router(tokens.router)
app.include_router(api.router)
app.include_router(users.profile_router)
