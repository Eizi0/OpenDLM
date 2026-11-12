"""User management (administrators) and the personal profile (everyone)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..deps import ROLES, get_session, require_admin, require_user
from ..i18n import t
from ..models import User
from ..security import hash_password, password_problem, verify_password
from .auth import set_session_cookie, username_problem
from .common import redirect, render

admin_router = APIRouter(dependencies=[Depends(require_admin)])
profile_router = APIRouter(dependencies=[Depends(require_user)])


def user_or_404(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(404, t("Unknown user"))
    return user


def admin_count(session: Session) -> int:
    return session.scalar(select(func.count(User.id)).where(User.role == "admin")) or 0


@admin_router.get("/users")
def users_page(request: Request, session: Session = Depends(get_session)):
    users = session.scalars(select(User).order_by(User.username)).all()
    return render(request, "users.html", {"users": users, "roles": ROLES})


@admin_router.post("/users")
def create_user(username: str = Form(...), password: str = Form(...), role: str = Form("viewer"), session: Session = Depends(get_session)):
    username = username.strip().lower()
    if role not in ROLES or username_problem(username) or password_problem(password):
        return redirect("/users", error="user_invalid")
    if session.scalar(select(User).where(User.username == username)):
        return redirect("/users", error="user_exists")
    session.add(User(username=username, password_hash=hash_password(password), role=role))
    session.commit()
    return redirect("/users", notice="user_created")


@admin_router.post("/users/{user_id}/role")
def change_role(user_id: int, role: str = Form(...), session: Session = Depends(get_session)):
    user = user_or_404(session, user_id)
    if role not in ROLES:
        raise HTTPException(422, t("Invalid role"))
    if user.role == "admin" and role != "admin" and admin_count(session) <= 1:
        return redirect("/users", error="last_admin")
    user.role = role
    session.commit()
    return redirect("/users", notice="user_updated")


@admin_router.post("/users/{user_id}/password")
def reset_password(user_id: int, password: str = Form(...), session: Session = Depends(get_session)):
    user = user_or_404(session, user_id)
    if password_problem(password):
        return redirect("/users", error="user_invalid")
    user.password_hash = hash_password(password)  # signs the user out everywhere (session fingerprint)
    session.commit()
    return redirect("/users", notice="user_updated")


@admin_router.post("/users/{user_id}/delete")
def delete_user(request: Request, user_id: int, session: Session = Depends(get_session)):
    user = user_or_404(session, user_id)
    if user.id == request.state.user.id:
        return redirect("/users", error="own_account")
    if user.role == "admin" and admin_count(session) <= 1:
        return redirect("/users", error="last_admin")
    session.delete(user)
    session.commit()
    return redirect("/users", notice="user_deleted")


@profile_router.get("/profile")
def profile_page(request: Request):
    return render(request, "profile.html", {})


@profile_router.post("/profile/password")
def change_password(
    request: Request,
    current: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    session: Session = Depends(get_session),
):
    user = session.get(User, request.state.user.id)
    if not verify_password(current, user.password_hash):
        return redirect("/profile", error="password_wrong")
    if password != confirm:
        return redirect("/profile", error="password_mismatch")
    if password_problem(password):
        return redirect("/profile", error="user_invalid")
    user.password_hash = hash_password(password)
    session.commit()
    response = redirect("/profile", notice="password_changed")
    set_session_cookie(response, user, session)  # the old session is invalidated by the new hash: keep this one signed in
    return response
