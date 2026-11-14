"""Public routes: first-run setup, login, logout, language switch."""

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..deps import get_session, has_users
from ..runtime_config import cfg
from ..i18n import LANGUAGES, t
from ..models import User
from .. import twofa
from ..security import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    LoginThrottle,
    authenticate,
    get_secret,
    hash_password,
    make_session_token,
    password_problem,
    request_ip,
    user_from_token,
)
from .common import render

router = APIRouter()
throttle = LoginThrottle()
LANG_COOKIE = "opendlm_lang"


def set_session_cookie(response: RedirectResponse, user: User, session: Session) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        make_session_token(user, get_secret(session)),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )


def username_problem(username: str) -> str | None:
    if not (3 <= len(username) <= 64) or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return t("Invalid username (3 to 64 characters: letters, digits, - _ .).")
    return None


@router.get("/setup")
def setup_page(request: Request, session: Session = Depends(get_session)):
    if has_users(session):
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html", {"error": None, "username": "", "twofa_next": cfg.require_2fa != "off"})


@router.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    session: Session = Depends(get_session),
):
    if has_users(session):
        raise HTTPException(403, t("The administrator account already exists"))
    username = username.strip().lower()
    error = username_problem(username)
    if not error:
        error = t("The two passwords do not match.") if password != confirm else password_problem(password)
    if error:
        return render(request, "setup.html", {"error": error, "username": username, "twofa_next": cfg.require_2fa != "off"}, status_code=422)
    user = User(username=username, password_hash=hash_password(password), role="admin")
    session.add(user)
    session.commit()
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, user, session)
    return response


@router.get("/login")
def login_page(request: Request, session: Session = Depends(get_session)):
    if not has_users(session):
        return RedirectResponse("/setup", status_code=303)
    return render(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    key = request_ip(request)
    wait = throttle.retry_after(key)
    if wait:
        return render(request, "login.html", {"error": t("Too many attempts. Try again in %(s)d s.", s=wait), "username": username}, status_code=429)
    user = authenticate(session, username, password)
    if user is None:
        throttle.fail(key)
        return render(request, "login.html", {"error": t("Incorrect username or password."), "username": username}, status_code=401)
    throttle.reset(key)
    if user.totp_enabled:
        # Password accepted but no session yet: the second factor is required.
        response = RedirectResponse("/login/2fa", status_code=303)
        response.set_cookie(twofa.PENDING_COOKIE, twofa.make_pending_token(user), max_age=twofa.PENDING_MAX_AGE, httponly=True, samesite="lax", secure=settings.cookie_secure)
        return response
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, user, session)
    return response


@router.get("/login/2fa")
def twofa_page(request: Request, session: Session = Depends(get_session)):
    if twofa.user_from_pending(session, request.cookies.get(twofa.PENDING_COOKIE)) is None:
        return RedirectResponse("/login", status_code=303)
    return render(request, "login_2fa.html", {"error": None})


@router.post("/login/2fa")
def twofa_submit(request: Request, code: str = Form(...), session: Session = Depends(get_session)):
    user = twofa.user_from_pending(session, request.cookies.get(twofa.PENDING_COOKIE))
    if user is None:
        return RedirectResponse("/login", status_code=303)
    key = f"2fa:{user.id}:{request_ip(request)}"
    wait = throttle.retry_after(key)
    if wait:
        return render(request, "login_2fa.html", {"error": t("Too many attempts. Try again in %(s)d s.", s=wait)}, status_code=429)
    if not (twofa.verify_code(user, code) or twofa.use_recovery_code(user, code)):
        throttle.fail(key)
        return render(request, "login_2fa.html", {"error": t("Invalid code. Try again.")}, status_code=401)
    session.commit()  # persists the used time step or the consumed recovery code
    throttle.reset(key)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, user, session)
    response.delete_cookie(twofa.PENDING_COOKIE)
    return response


@router.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


def _safe_back(request: Request) -> str:
    """Path of the referring page on this site, else the home page (never an external URL)."""
    referer = request.headers.get("referer")
    if referer:
        parsed = urlparse(referer)
        if parsed.netloc == request.headers.get("host") and parsed.path.startswith("/") and not parsed.path.startswith("//"):
            return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return "/"


@router.get("/lang/{code}")
def switch_language(code: str, request: Request, session: Session = Depends(get_session)):
    if code not in LANGUAGES:
        raise HTTPException(404, t("Unknown language"))
    user = user_from_token(session, request.cookies.get(SESSION_COOKIE), get_secret(session))
    if user is not None:
        user.language = code
        session.commit()
    response = RedirectResponse(_safe_back(request), status_code=303)
    response.set_cookie(LANG_COOKIE, code, max_age=365 * 24 * 3600, samesite="lax", secure=settings.cookie_secure)
    return response
