"""Read-only API tokens (exports and metrics)."""

import hashlib
import hmac
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ApiToken, utcnow

TOKEN_PREFIX = "odlm_"
TOUCH_EVERY = timedelta(seconds=60)  # do not write on every scrape


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(session: Session, name: str, created_by: str) -> tuple[str, ApiToken]:
    name = " ".join(name.split())
    if not 2 <= len(name) <= 80:
        raise ValueError("name")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(name=name, token_hash=_hash(token), prefix=token[:12], created_by=created_by)
    session.add(row)
    session.commit()
    return token, row


def authenticate(session: Session, token: str) -> ApiToken | None:
    if not token.startswith(TOKEN_PREFIX) or len(token) > 128:
        return None
    digest = _hash(token)
    row = session.scalar(select(ApiToken).where(ApiToken.token_hash == digest))
    if row is None or not hmac.compare_digest(row.token_hash, digest):
        return None
    now = utcnow()
    last = row.last_used_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=now.tzinfo)
    if last is None or now - last > TOUCH_EVERY:
        row.last_used_at = now
        session.commit()
    return row
