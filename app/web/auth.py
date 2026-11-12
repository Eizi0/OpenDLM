"""Public routes: first-run setup, login, logout, language switch."""

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..deps import get_session, has_users
from ..i18n import LANGUAGES, t
from ..models import User
from ..security import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    LoginThrottle,
    authenticate,
    get_secret,
    hash_password,
    make_session_token,
    password_problem,
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
    return render(request, "setup.html", {"error": None})


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
        return render(request, "setup.html", {"error": error}, status_code=422)
    user = User(username=username, password_hash=hash_password(password))
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
    key = request.client.host if request.client else "unknown"
    wait = throttle.retry_after(key)
    if wait:
        return render(request, "login.html", {"error": t("Too many attempts. Try again in %(s)d s.", s=wait)}, status_code=429)
    user = authenticate(session, username, password)
    if user is None:
        throttle.fail(key)
        return render(request, "login.html", {"error": t("Incorrect username or password.")}, status_code=401)
    throttle.reset(key)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, user, session)
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
