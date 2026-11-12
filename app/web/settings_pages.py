"""Settings editable from the interface (administrators)."""

from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import scheduler
from ..deps import get_session, require_admin
from ..i18n import LANGUAGES, t
from ..runtime_config import SPECS, cfg
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_admin)])

SECTIONS = {
    "general": ("language", "timezone"),
    "scheduling": ("scan_hour", "report_daily", "report_monthly", "report_hour", "report_send_empty"),
    "alerts": ("alert_min_severity",),
    "news": ("news_interval_minutes", "news_retention_days", "allow_private_feeds"),
}


def _section_or_404(section: str) -> tuple[str, ...]:
    if section not in SECTIONS:
        raise HTTPException(404, t("Unknown section"))
    return SECTIONS[section]


@router.get("/settings")
def settings_page(request: Request):
    values = {key: cfg.get(key) for keys in SECTIONS.values() for key in keys}
    origins = {key: cfg.source(key) for key in values}
    return render(
        request, "settings.html",
        {"v": values, "origins": origins, "languages": LANGUAGES, "timezones": sorted(available_timezones()), "bool_keys": {k for k, s in SPECS.items() if s.kind == "bool"}},
    )


@router.post("/settings/{section}")
async def save_section(section: str, request: Request, session: Session = Depends(get_session)):
    keys = _section_or_404(section)
    form = await request.form()
    updates = {}
    for key in keys:
        if SPECS[key].kind == "bool":
            updates[key] = "1" if form.get(key) else "0"  # an unchecked box is simply absent from the form
        else:
            updates[key] = str(form.get(key, ""))
    try:
        cfg.save(session, updates)
    except ValueError:
        return redirect("/settings", error="invalid_value")
    scheduler.apply_schedule()
    return redirect("/settings", notice="saved")


@router.post("/settings/{section}/reset")
def reset_section(section: str, session: Session = Depends(get_session)):
    for key in _section_or_404(section):
        cfg.clear(session, key)
    scheduler.apply_schedule()
    return redirect("/settings", notice="saved")
