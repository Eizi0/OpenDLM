"""API tokens (administrators)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import api_tokens
from ..deps import get_session, require_admin
from ..i18n import t
from ..models import ApiToken
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/tokens")
def tokens_page(request: Request, session: Session = Depends(get_session)):
    return render(request, "tokens.html", {"tokens": session.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())).all(), "new_token": None})


@router.post("/tokens")
def create_token(request: Request, name: str = Form(...), session: Session = Depends(get_session)):
    try:
        token, _ = api_tokens.create_token(session, name, request.state.user.username)
    except ValueError:
        return redirect("/tokens", error="token_name")
    response = render(
        request, "tokens.html",
        {"tokens": session.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())).all(), "new_token": token},
    )
    response.headers["Cache-Control"] = "no-store"  # the token is shown once: never cached
    return response


@router.post("/tokens/{token_id}/delete")
def revoke_token(token_id: int, session: Session = Depends(get_session)):
    token = session.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(404, t("Unknown token"))
    session.delete(token)
    session.commit()
    return redirect("/tokens", notice="token_revoked")
