"""Audit trail page (administrators)."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..deps import get_session, require_admin
from ..i18n import t
from ..models import AuditEvent
from .common import render

router = APIRouter(dependencies=[Depends(require_admin)])

PAGE_SIZE = 100
OUTCOMES = ("ok", "refused", "failed")


@router.get("/audit")
def audit_page(request: Request, user: str = "", outcome: str = "", page: int = 1, session: Session = Depends(get_session)):
    query = select(AuditEvent)
    if user:
        query = query.where(AuditEvent.username == user)
    if outcome in OUTCOMES:
        query = query.where(AuditEvent.outcome == outcome)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    page = max(1, page)
    events = session.scalars(query.order_by(AuditEvent.at.desc(), AuditEvent.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    users = session.scalars(select(AuditEvent.username).where(AuditEvent.username.is_not(None)).distinct().order_by(AuditEvent.username)).all()
    rows = [
        {"at": e.at, "user": e.username, "ip": e.ip, "label": t(audit.LABELS[e.action]) if e.action in audit.LABELS else e.action,
         "params": ", ".join(f"{k}={v}" for k, v in (e.params or {}).items()), "outcome": e.outcome}
        for e in events
    ]
    return render(request, "audit.html", {
        "rows": rows, "users": users, "user": user, "outcome": outcome, "page": page,
        "has_next": page * PAGE_SIZE < total, "total": total,
    })
