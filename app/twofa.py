"""Two-factor authentication (TOTP, RFC 6238) with single-use recovery codes."""

import hashlib
import hmac
import secrets
import time

import pyotp
import segno
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from . import crypto
from .models import User

ISSUER = "OpenDLM"
PENDING_MAX_AGE = 300  # seconds between the password step and the code step
RECOVERY_CODES = 10
PENDING_COOKIE = "opendlm_2fa"


def required_for(user: User) -> bool:
    """True when the instance policy makes two-factor authentication mandatory for this user."""
    from .runtime_config import cfg  # local import: runtime_config does not depend on this module

    policy = cfg.require_2fa
    return policy == "all" or (policy == "admins" and user.role == "admin")


def new_secret() -> str:
    return pyotp.random_base32()


def secret_of(user: User) -> str | None:
    if not user.totp_secret_enc:
        return None
    try:
        return crypto.decrypt(user.totp_secret_enc)
    except crypto.DecryptionError:
        return None


def provisioning_uri(user: User, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=ISSUER)


def qr_svg(uri: str) -> str:
    """Inline SVG of the QR code (generated locally: the secret never leaves the server)."""
    return segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#0D1117", light="#FFFFFF")


def _step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // 30)


def verify_code(user: User, code: str, now: float | None = None) -> bool:
    """Check a 6-digit code. A time step can be used once: a replayed code is refused."""
    secret = secret_of(user)
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    at = now if now is not None else time.time()
    for offset in (0, -1, 1):  # tolerate one step of clock drift
        step = _step(at) + offset
        if hmac.compare_digest(totp.at(step * 30), code):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False
            user.totp_last_step = step
            return True
    return False


# --- Recovery codes --------------------------------------------------------------------------------


def _normalize(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def _hash(code: str) -> str:
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def generate_recovery_codes() -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def use_recovery_code(user: User, code: str) -> bool:
    """Consume a recovery code (single use)."""
    digest = _hash(code)
    hashes = list(user.recovery_hashes or [])
    for h in hashes:
        if hmac.compare_digest(h, digest):
            hashes.remove(h)
            user.recovery_hashes = hashes  # reassign so the JSON change is detected
            return True
    return False


# --- Enrollment and lifecycle ------------------------------------------------------------------------


def start_enrollment(session: Session, user: User) -> str:
    secret = new_secret()
    user.totp_secret_enc = crypto.encrypt(secret)
    user.totp_enabled = False
    user.totp_last_step = None
    session.commit()
    return secret


def finish_enrollment(session: Session, user: User, code: str) -> list[str] | None:
    """Enable 2FA if the code is valid; returns the recovery codes (shown once) or None."""
    if user.totp_enabled or not verify_code(user, code):
        return None
    codes = generate_recovery_codes()
    user.totp_enabled = True
    user.recovery_hashes = [_hash(c) for c in codes]
    session.commit()
    return codes


def regenerate_recovery_codes(session: Session, user: User) -> list[str]:
    codes = generate_recovery_codes()
    user.recovery_hashes = [_hash(c) for c in codes]
    session.commit()
    return codes


def disable(session: Session, user: User) -> None:
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    user.recovery_hashes = None
    session.commit()


# --- Short-lived token between the password step and the code step ---------------------------------


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(crypto.derive("2fa-pending").hex(), salt="opendlm-2fa-pending")


def make_pending_token(user: User) -> str:
    return _serializer().dumps({"u": user.id, "f": hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]})


def user_from_pending(session: Session, token: str | None) -> User | None:
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=PENDING_MAX_AGE)
    except BadSignature:
        return None
    user = session.get(User, data.get("u"))
    if user is None or not user.totp_enabled:
        return None
    if not hmac.compare_digest(hashlib.sha256(user.password_hash.encode()).hexdigest()[:16], str(data.get("f", ""))):
        return None
    return user
