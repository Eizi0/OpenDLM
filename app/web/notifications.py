"""Notification channels."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import channels
from ..config import settings
from ..deps import get_session, require_admin
from ..i18n import t
from ..models import Channel
from ..notifier import Notifier
from ..runtime_config import cfg
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_admin)])


def channel_or_404(session: Session, channel_id: int) -> Channel:
    channel = session.get(Channel, channel_id)
    if channel is None:
        raise HTTPException(404, t("Unknown channel"))
    return channel


@router.get("/notifications")
def notifications_page(request: Request, session: Session = Depends(get_session)):
    stored = []
    for ch in session.scalars(select(Channel).order_by(Channel.name)):
        url = channels.channel_url(ch)
        stored.append({"ch": ch, "kind": channels.mask(url) if url else None})
    from_env = [channels.mask(u) for u in settings.notify_url_list]
    return render(request, "notifications.html", {"stored": stored, "from_env": from_env, "min_severity": cfg.alert_min_severity})


@router.post("/notifications/channels")
def add_channel(name: str = Form(...), url: str = Form(...), session: Session = Depends(get_session)):
    try:
        channels.add_channel(session, name, url)
    except ValueError as e:
        return redirect("/notifications", error="channel_duplicate" if str(e) == "duplicate" else "channel_invalid")
    return redirect("/notifications", notice="channel_added")


@router.post("/notifications/channels/{channel_id}/toggle")
def toggle_channel(channel_id: int, session: Session = Depends(get_session)):
    channel = channel_or_404(session, channel_id)
    channel.enabled = not channel.enabled
    session.commit()
    return redirect("/notifications")


@router.post("/notifications/channels/{channel_id}/delete")
def delete_channel(channel_id: int, session: Session = Depends(get_session)):
    session.delete(channel_or_404(session, channel_id))
    session.commit()
    return redirect("/notifications", notice="channel_deleted")


@router.post("/notifications/channels/{channel_id}/test")
def test_channel(channel_id: int, session: Session = Depends(get_session)):
    url = channels.channel_url(channel_or_404(session, channel_id))
    ok = bool(url) and channels.send_test(url, t("[OpenDLM] Test message"), t("If you can read this, this channel receives OpenDLM alerts and reports."))
    return redirect("/notifications", notice="test_sent" if ok else None, error=None if ok else "test_failed")


@router.post("/notifications/test")
def notifications_test():
    if not channels.all_urls():
        return redirect("/notifications", error="no_channel")
    ok = Notifier().send(t("[OpenDLM] Test message"), t("If you can read this, this channel receives OpenDLM alerts and reports."))
    return redirect("/notifications", notice="test_sent" if ok else None, error=None if ok else "test_failed")
