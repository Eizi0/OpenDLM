import base64
import hashlib
import hmac
import os
import time
from collections.abc import Callable

from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from . import crypto
from .models import User

SESSION_COOKIE = "opendlm_session"
SESSION_MAX_AGE = 12 * 3600
MIN_PASSWORD_LENGTH = 12

_N, _R, _P = 2**15, 8, 1


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=2**26, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, key = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(key)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), maxmem=2**26, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


# Hash factice : on vérifie quand même un mot de passe quand l'utilisateur n'existe pas,
# pour ne pas révéler les noms valides par le temps de réponse.
_DUMMY_HASH = hash_password("mot-de-passe-factice-pour-le-timing")


def authenticate(session: Session, username: str, password: str) -> User | None:
    user = session.query(User).filter(User.username == username.strip().lower()).one_or_none()
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères."
    return None


# --- Session signing key, derived from the master key (never stored in the database) ---


def get_secret(session: Session | None = None) -> str:
    return crypto.derive("session").hex()


def _fingerprint(user: User) -> str:
    # Changer de mot de passe invalide les sessions existantes.
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]


def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="opendlm-session")


def make_session_token(user: User, secret: str) -> str:
    return _serializer(secret).dumps({"u": user.id, "f": _fingerprint(user)})


def user_from_token(session: Session, token: str | None, secret: str) -> User | None:
    if not token:
        return None
    try:
        data = _serializer(secret).loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None
    user = session.get(User, data.get("u"))
    if user is None or not hmac.compare_digest(_fingerprint(user), str(data.get("f", ""))):
        return None
    return user


class LoginThrottle:
    """Bloque temporairement après trop d'échecs de connexion depuis la même adresse."""

    def __init__(self, max_failures: int = 5, window: int = 300, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_failures, self.window, self.clock = max_failures, window, clock
        self._fails: dict[str, list[float]] = {}

    def _recent(self, key: str) -> list[float]:
        now = self.clock()
        recent = [t for t in self._fails.get(key, []) if now - t < self.window]
        self._fails[key] = recent
        return recent

    def retry_after(self, key: str) -> int:
        recent = self._recent(key)
        if len(recent) < self.max_failures:
            return 0
        return max(1, int(self.window - (self.clock() - recent[0])))

    def fail(self, key: str) -> None:
        self._recent(key).append(self.clock())

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)
