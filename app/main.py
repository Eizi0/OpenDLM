import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from . import audit, migrate, news, scheduler
from .config import settings
from .db import SessionLocal
from .deps import LoginRequired, TwoFactorSetupRequired, has_users
from .i18n import LANGUAGES, N_, reset_language, set_language, t
from .security import SESSION_COOKIE, get_secret, request_ip, user_from_token
from .web import api, audit_page, auth, dashboard, news_pages, notifications, reports_pages, settings_pages, sources, tokens, users
from .web.common import BASE, render

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
async def audit_trail(request: Request, call_next):
    """Record every write request made by a signed-in user (route and path parameters only, never the body)."""
    response = await call_next(request)
    if request.method == "POST":
        route = request.scope.get("route")
        path = getattr(route, "path", None) or request.url.path
        user = getattr(request.state, "user", None)
        if user is not None and path not in audit.SELF_RECORDED:
            outcome = audit.outcome_of(response.status_code, response.headers.get("location"))
            await run_in_threadpool(audit.record, path, outcome, user.username, request_ip(request), request.scope.get("path_params") or {})
    return response


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


@app.exception_handler(TwoFactorSetupRequired)
async def twofa_required_handler(request: Request, _: TwoFactorSetupRequired):
    return RedirectResponse("/profile?e=twofa_required", status_code=303)


MACHINE_PATHS = ("/api/", "/metrics", "/healthz")
HEADINGS = {
    400: N_("Bad request"), 401: N_("Sign-in required"), 403: N_("Access refused"), 404: N_("Page not found"),
    405: N_("Action not allowed"), 409: N_("Not possible right now"), 422: N_("Invalid input"), 429: N_("Too many requests"),
}


def _wants_page(request: Request) -> bool:
    return not request.url.path.startswith(MACHINE_PATHS) and "text/html" in request.headers.get("accept", "text/html")


def _error_page(request: Request, status: int, detail: str | None):
    heading = t(HEADINGS.get(status, N_("Something went wrong")))
    return render(request, "error.html", {"status": status, "heading": heading, "detail": detail or ""}, status_code=status)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if not _wants_page(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))
    detail = exc.detail if isinstance(exc.detail, str) and exc.detail not in ("Not Found", "Method Not Allowed") else None
    if exc.status_code == 404 and detail is None:
        detail = t("This page does not exist, or the item was deleted.")
    return _error_page(request, exc.status_code, detail)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    if not _wants_page(request):
        return JSONResponse({"detail": exc.errors()}, status_code=422)
    return _error_page(request, 422, t("A required field is missing or has an invalid value."))


@app.exception_handler(Exception)
async def server_error(request: Request, exc: Exception):
    logging.getLogger("opendlm").exception("unhandled error on %s %s", request.method, request.url.path)
    if not _wants_page(request):
        return JSONResponse({"detail": "internal error"}, status_code=500)
    return _error_page(request, 500, t("An unexpected error occurred. It has been written to the logs."))


@app.get("/healthz")
def healthz():
    with SessionLocal() as session:
        session.execute(text("SELECT 1"))
    return {"status": "ok"}


for module in (auth, dashboard, news_pages, sources, notifications, reports_pages, settings_pages):
    app.include_router(module.router)
app.include_router(users.admin_router)
app.include_router(tokens.router)
app.include_router(audit_page.router)
app.include_router(api.router)
app.include_router(users.profile_router)
