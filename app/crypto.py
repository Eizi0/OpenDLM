"""Encryption of secrets stored in the database.

The master key never lives in the database: it comes from OPENDLM_SECRET_KEY, or from a file
in the data volume (generated on first start, readable by the app user only). A leaked database
dump alone therefore does not reveal API keys or notification URLs.
"""

import base64
import hashlib
import hmac
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_lock = threading.Lock()
_master: bytes | None = None


class DecryptionError(Exception):
    """A stored secret cannot be decrypted (master key changed or lost)."""


def _key_path() -> Path:
    return Path(settings.data_dir) / "secret.key"


def _load_master() -> bytes:
    if settings.secret_key:
        return hashlib.sha256(settings.secret_key.encode()).digest()
    path = _key_path()
    try:
        return base64.urlsafe_b64decode(path.read_text().strip())
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process created it first
        return base64.urlsafe_b64decode(path.read_text().strip())
    with os.fdopen(fd, "w") as f:
        f.write(base64.urlsafe_b64encode(key).decode())
    return key


def master_key() -> bytes:
    global _master
    with _lock:
        if _master is None:
            _master = _load_master()
        return _master


def reset_cache() -> None:
    """For tests: forget the loaded master key."""
    global _master
    with _lock:
        _master = None


def derive(purpose: str) -> bytes:
    """Independent 32-byte key per purpose (HMAC of the master key)."""
    return hmac.new(master_key(), f"opendlm:{purpose}".encode(), hashlib.sha256).digest()


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive("fernet")))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError) as e:
        raise DecryptionError("stored secret cannot be decrypted") from e
