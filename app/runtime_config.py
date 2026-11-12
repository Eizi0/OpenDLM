"""Settings that can be changed from the web interface.

Precedence: value saved in the interface, then the environment variable, then the default.
Secrets (API keys) are encrypted in the database; see crypto.py.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import crypto
from .config import settings
from .db import SessionLocal
from .models import ConfigValue, utcnow

log = logging.getLogger("opendlm.config")


@dataclass(frozen=True)
class Spec:
    key: str
    kind: str  # secret | str | int | bool | choice
    group: str
    choices: tuple[str, ...] = ()
    low: int = 0
    high: int = 0


SPECS: dict[str, Spec] = {s.key: s for s in [
    Spec("hibp_api_key", "secret", "hibp"),
    Spec("hudson_rock_key", "secret", "hudson_rock"),
    Spec("ransomware_live_key", "secret", "ransomware_live"),
    Spec("leakcheck_enabled", "bool", "leakcheck"),
    Spec("xposedornot_enabled", "bool", "xposedornot"),
    Spec("alert_min_severity", "choice", "alerts", choices=("low", "high", "critical")),
    Spec("scan_hour", "int", "scheduling", low=0, high=23),
    Spec("report_daily", "bool", "reports"),
    Spec("report_monthly", "bool", "reports"),
    Spec("report_hour", "int", "reports", low=0, high=23),
    Spec("report_send_empty", "bool", "reports"),
    Spec("news_interval_minutes", "int", "news", low=5, high=1440),
    Spec("news_retention_days", "int", "news", low=1, high=3650),
    Spec("allow_private_feeds", "bool", "news"),
    Spec("timezone", "str", "general"),
    Spec("language", "choice", "general", choices=("en", "fr")),
]}

CACHE_TTL = 5.0


def parse(spec: Spec, raw: str):
    """Validate and convert a raw form value. Raises ValueError with a short English reason."""
    raw = (raw or "").strip()
    if spec.kind == "secret":
        if not raw or len(raw) > 512 or any(c.isspace() for c in raw):
            raise ValueError("invalid secret")
        return raw
    if spec.kind == "bool":
        if raw.lower() in ("1", "true", "on", "yes"):
            return True
        if raw.lower() in ("0", "false", "off", "no", ""):
            return False
        raise ValueError("invalid boolean")
    if spec.kind == "int":
        try:
            value = int(raw)
        except ValueError as e:
            raise ValueError("invalid number") from e
        if not spec.low <= value <= spec.high:
            raise ValueError(f"must be between {spec.low} and {spec.high}")
        return value
    if spec.kind == "choice":
        if raw not in spec.choices:
            raise ValueError("invalid choice")
        return raw
    if spec.key == "timezone":
        try:
            ZoneInfo(raw)
        except (ZoneInfoNotFoundError, ValueError, OSError) as e:
            raise ValueError("unknown timezone") from e
    return raw


def _serialize(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


class RuntimeConfig:
    def __init__(self) -> None:
        self._values: dict[str, object] = {}
        self._loaded_at = 0.0
        self._lock = threading.Lock()
        self._overrides: dict[str, object] = {}  # tests only

    # --- reading -------------------------------------------------------------

    def _load(self) -> None:
        values: dict[str, object] = {}
        try:
            with SessionLocal() as session:
                for row in session.scalars(select(ConfigValue)):
                    spec = SPECS.get(row.key)
                    if spec is None:
                        continue
                    try:
                        values[row.key] = parse(spec, crypto.decrypt(row.value)) if spec.kind == "secret" else parse(spec, row.value)
                    except (crypto.DecryptionError, ValueError):
                        log.warning("setting %s is unreadable and was ignored; save it again in the interface", row.key)
        except SQLAlchemyError:
            pass  # tables not created yet (very early start): fall back to the environment
        self._values, self._loaded_at = values, time.monotonic()

    def get(self, key: str):
        if key in self._overrides:
            return self._overrides[key]
        if key not in SPECS:
            raise KeyError(key)
        with self._lock:
            if time.monotonic() - self._loaded_at > CACHE_TTL:
                self._load()
            if key in self._values:
                return self._values[key]
        return getattr(settings, key)

    def __getattr__(self, name: str):
        if name in SPECS:
            return self.get(name)
        raise AttributeError(name)

    def source(self, key: str) -> str:
        """Where the effective value comes from: ui, env or default."""
        if key in self._overrides:
            return "ui"
        self.get(key)
        if key in self._values:
            return "ui"
        return "env" if f"OPENDLM_{key.upper()}" in os.environ else "default"

    def is_set(self, key: str) -> bool:
        return bool(self.get(key))

    # --- writing -------------------------------------------------------------

    def invalidate(self) -> None:
        with self._lock:
            self._loaded_at = 0.0

    def save(self, session: Session, updates: dict[str, str]) -> None:
        """Validate then store several settings in one transaction. Nothing is written if one is invalid."""
        parsed = {}
        for key, raw in updates.items():
            spec = SPECS.get(key)
            if spec is None:
                raise ValueError(f"unknown setting: {key}")
            try:
                parsed[key] = parse(spec, raw)
            except ValueError as e:
                raise ValueError(f"{key}: {e}") from e
        for key, value in parsed.items():
            spec = SPECS[key]
            stored = crypto.encrypt(value) if spec.kind == "secret" else _serialize(value)
            row = session.get(ConfigValue, key)
            if row is None:
                session.add(ConfigValue(key=key, value=stored, secret=spec.kind == "secret"))
            else:
                row.value, row.secret, row.updated_at = stored, spec.kind == "secret", utcnow()
        session.commit()
        self.invalidate()

    def clear(self, session: Session, key: str) -> None:
        """Remove the interface value so the environment (or default) applies again."""
        row = session.get(ConfigValue, key)
        if row is not None:
            session.delete(row)
            session.commit()
        self.invalidate()


cfg = RuntimeConfig()
