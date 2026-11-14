"""Notification channels and the heartbeat to a push monitor."""

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import channels, heartbeat, scheduler
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
    hb = cfg.heartbeat_url
    return render(request, "notifications.html", {
        "stored": stored, "from_env": from_env, "min_severity": cfg.alert_min_severity,
        "heartbeat_host": urlsplit(hb).netloc if hb else None, "heartbeat_origin": cfg.source("heartbeat_url"),
    })


@router.post("/notifications/heartbeat")
def save_heartbeat(url: str = Form(...), session: Session = Depends(get_session)):
    if not heartbeat.valid_url(url):
        return redirect("/notifications", error="invalid_url")
    cfg.save(session, {"heartbeat_url": url.strip()})
    scheduler.apply_schedule()
    return redirect("/notifications", notice="heartbeat_saved")


@router.post("/notifications/heartbeat/delete")
def delete_heartbeat(session: Session = Depends(get_session)):
    cfg.clear(session, "heartbeat_url")
    scheduler.apply_schedule()
    return redirect("/notifications", notice="heartbeat_removed")


@router.post("/notifications/heartbeat/test")
def test_heartbeat(session: Session = Depends(get_session)):
    ok = heartbeat.beat(session)
    return redirect("/notifications", notice="test_sent" if ok else None, error=None if ok else "test_failed")


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
