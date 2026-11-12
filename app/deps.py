from fastapi import Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal
from . import twofa
from .i18n import t
from .models import User
from .security import SESSION_COOKIE, get_secret, user_from_token


def get_session():
    with SessionLocal() as session:
        yield session


class LoginRequired(Exception):
    """Raised when a protected page is requested without a valid session."""


class TwoFactorSetupRequired(Exception):
    """Raised when the policy requires two-factor authentication and the user has not set it up yet."""


def has_users(session: Session) -> bool:
    return (session.scalar(select(func.count(User.id))) or 0) > 0


ROLES = ("admin", "viewer")
SELF_SERVICE_PREFIX = "/profile"  # every user may change their own password and settings


def require_user(request: Request, session: Session = Depends(get_session)) -> User:
    """Any signed-in user. Viewers are read-only: they may not change anything except their own profile."""
    user = user_from_token(session, request.cookies.get(SESSION_COOKIE), get_secret(session))
    if user is None:
        raise LoginRequired()
    request.state.user = user
    if twofa.required_for(user) and not user.totp_enabled and not request.url.path.startswith(SELF_SERVICE_PREFIX):
        raise TwoFactorSetupRequired()  # only the profile (where it is set up) stays reachable
    if request.method not in ("GET", "HEAD") and user.role != "admin" and not request.url.path.startswith(SELF_SERVICE_PREFIX):
        raise HTTPException(403, t("Read-only account: this action requires an administrator"))
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, t("This page requires an administrator"))
    return user
