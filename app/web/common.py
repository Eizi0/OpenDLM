"""Shared web helpers: templates, flash messages, formatting."""

from pathlib import Path
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import reports
from ..config import settings
from ..i18n import LANGUAGES, N_, current_language, fmt_date, fmt_datetime, t
from ..labels import RELIABILITY_CODES, reliability_label, severity_label
from ..runtime_config import cfg

BASE = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE / "templates")


def _local(value, style: str = "datetime") -> str:
    """Date in the configured timezone and the current language's format (stored in UTC)."""
    return fmt_datetime(value, cfg.timezone) if style == "datetime" else fmt_date(value, cfg.timezone)


templates.env.filters["local"] = _local
templates.env.globals.update(
    _=t,
    severity_label=severity_label,
    reliability_label=reliability_label,
    reliability_codes=RELIABILITY_CODES,
    languages=LANGUAGES,
    current_language=current_language,
    demo=settings.demo,
    kind_label=reports.kind_label,
    report_label=reports.label_text,
    report_title=reports.title_text,
    fmt_date=fmt_date,
    attribution=lambda: t(reports.ATTRIBUTION),
)

# Flash messages travel as short codes in the query string, never as free text:
# a crafted link cannot display arbitrary wording inside the application.
FLASH = {
    "test_sent": N_("Test message sent."),
    "test_failed": N_("Sending failed: check the channel URL in the logs."),
    "no_channel": N_("No notification channel is configured."),
    "report_sent": N_("Report sent."),
    "report_failed": N_("Sending failed, see the logs."),
    "feed_name": N_("Invalid name (2 to 80 characters)."),
    "feed_taken": N_("This name is already used."),
    "invalid_url": N_("Invalid URL: http or https expected."),
    "credentials": N_("Credentials in the URL are refused."),
    "unresolved": N_("Host not found."),
    "private": N_("Internal or private addresses are refused."),
    "saved": N_("Settings saved."),
    "invalid_value": N_("One of the values is invalid; nothing was saved."),
    "key_saved": N_("API key saved."),
    "key_removed": N_("API key removed."),
    "channel_added": N_("Channel added."),
    "channel_invalid": N_("Invalid name or notification URL."),
    "channel_duplicate": N_("A channel with this name already exists."),
    "conn_ok": N_("Connection successful."),
    "conn_failed": N_("Connection failed."),
    "no_key": N_("No API key is set for this connector."),
    "user_created": N_("User created."),
    "user_updated": N_("User updated."),
    "user_deleted": N_("User deleted."),
    "own_account": N_("You cannot delete your own account."),
    "user_invalid": N_("Invalid username or password."),
    "user_exists": N_("This username is already taken."),
    "password_changed": N_("Password changed."),
    "password_wrong": N_("Current password is incorrect."),
    "password_mismatch": N_("The two passwords do not match."),
    "last_admin": N_("You cannot remove or demote the last administrator."),
    "twofa_enabled": N_("Two-factor authentication enabled."),
    "twofa_disabled": N_("Two-factor authentication disabled."),
    "twofa_bad_code": N_("Invalid code. Try again."),
    "token_created": N_("API token created. Copy it now: it is shown only once."),
}


def redirect(url: str, notice: str | None = None, error: str | None = None) -> RedirectResponse:
    params = []
    if notice:
        params.append(f"n={quote(notice)}")
    if error:
        params.append(f"e={quote(error)}")
    if params:
        url += ("&" if "?" in url else "?") + "&".join(params)
    return RedirectResponse(url, status_code=303)


def get_flash(request: Request) -> dict:
    notice, error = request.query_params.get("n"), request.query_params.get("e")
    return {
        "notice": t(FLASH[notice]) if notice in FLASH else None,
        "error": t(FLASH[error]) if error in FLASH else None,
    }


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    ctx = {**(context or {}), "flash": get_flash(request), "lang": current_language()}
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
