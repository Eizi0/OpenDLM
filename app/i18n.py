"""Minimal gettext-style translation: English message ids, catalogs per language.

    t("Page %(page)s of %(pages)s", page=1, pages=3)

The current language is a context variable set per request (user preference, cookie, then the
instance default). Background jobs (alerts, scheduled reports) use the instance default.
Message ids are the English text itself; a missing translation falls back to English.
"""

import contextvars
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from .locale.fr import MESSAGES as FR

LANGUAGES = {"en": "English", "fr": "Français"}
CATALOGS = {"fr": FR}

DATETIME_FORMAT = {"en": "%Y-%m-%d %H:%M", "fr": "%d/%m/%Y %H:%M"}
DATE_FORMAT = {"en": "%Y-%m-%d", "fr": "%d/%m/%Y"}
MONTHS = {
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
    "fr": ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
}

_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("opendlm_lang", default=None)


def N_(msgid: str) -> str:
    """Mark a message id for extraction without translating it now (translated at display time)."""
    return msgid


def default_language() -> str:
    from .runtime_config import cfg  # imported lazily: runtime_config does not depend on i18n

    lang = cfg.language
    return lang if lang in LANGUAGES else "en"


def current_language() -> str:
    lang = _current.get()
    return lang if lang in LANGUAGES else default_language()


def set_language(lang: str | None):
    """Set the language for the current context; returns a token for reset_language."""
    return _current.set(lang if lang in LANGUAGES else None)


def reset_language(token) -> None:
    _current.reset(token)


def t(msgid: str, **params) -> str:
    text = CATALOGS.get(current_language(), {}).get(msgid, msgid)
    return text % params if params else text


def fmt_datetime(value: datetime | None, tz_name: str) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(tz_name)).strftime(DATETIME_FORMAT[current_language()])


def fmt_date(value: date | datetime | str | None, tz_name: str | None = None) -> str:
    """Date in the current language's format. Strings must be ISO dates."""
    if value is None or value == "":
        return "—"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if isinstance(value, datetime) and tz_name:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(ZoneInfo(tz_name))
    return value.strftime(DATE_FORMAT[current_language()])


def month_name(month: int) -> str:
    return MONTHS[current_language()][month - 1]
