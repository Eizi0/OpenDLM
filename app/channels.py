"""Notification channels stored in the database (Apprise URLs, encrypted)."""

import logging

import apprise
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import crypto
from .config import settings
from .db import SessionLocal
from .models import Channel

log = logging.getLogger("opendlm.channels")


def is_valid_url(url: str) -> bool:
    return bool(apprise.Apprise().add(url))


def mask(url: str) -> str:
    """Channel type only: the URL itself holds tokens and must never be displayed."""
    scheme = url.split("://", 1)[0] if "://" in url else "unknown"
    return f"{scheme}://…"


def add_channel(session: Session, name: str, url: str) -> Channel:
    name, url = " ".join(name.split()), url.strip()
    if not 2 <= len(name) <= 80:
        raise ValueError("name")
    if not is_valid_url(url):
        raise ValueError("url")
    if session.scalar(select(Channel).where(Channel.name == name)):
        raise ValueError("duplicate")
    channel = Channel(name=name, url_enc=crypto.encrypt(url))
    session.add(channel)
    session.commit()
    return channel


def channel_url(channel: Channel) -> str | None:
    try:
        return crypto.decrypt(channel.url_enc)
    except crypto.DecryptionError:
        log.warning("channel %s cannot be decrypted; re-create it", channel.name)
        return None


def active_urls(session: Session) -> list[str]:
    urls = []
    for channel in session.scalars(select(Channel).where(Channel.enabled.is_(True))):
        url = channel_url(channel)
        if url:
            urls.append(url)
    return urls


def all_urls() -> list[str]:
    """Enabled channels from the interface, plus those from OPENDLM_NOTIFY_URLS."""
    try:
        with SessionLocal() as session:
            urls = active_urls(session)
    except SQLAlchemyError:
        urls = []
    return urls + settings.notify_url_list


def send_test(url: str, title: str, body: str) -> bool:
    ap = apprise.Apprise()
    if not ap.add(url):
        return False
    return bool(ap.notify(title=title, body=body))
