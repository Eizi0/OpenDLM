from fastapi import Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User
from .security import SESSION_COOKIE, get_secret, user_from_token


def get_session():
    with SessionLocal() as session:
        yield session


class LoginRequired(Exception):
    """Levée quand une page protégée est demandée sans session valide."""


def has_users(session: Session) -> bool:
    return (session.scalar(select(func.count(User.id))) or 0) > 0


def require_user(request: Request, session: Session = Depends(get_session)) -> User:
    user = user_from_token(session, request.cookies.get(SESSION_COOKIE), get_secret(session))
    if user is None:
        raise LoginRequired()
    request.state.user = user
    return user
