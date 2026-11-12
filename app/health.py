from collections import defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .i18n import fmt_date, t
from .runtime_config import cfg

DAYS = 60
STALE_AFTER = timedelta(hours=26)  # a daily scan plus a margin


def _day_state(runs) -> tuple[str, str]:
    """Summary of one day of scans, from most to least serious."""
    new = sum(r.new_count for r in runs if r.ok and not r.baseline)
    if new:
        return "bad", t("%(n)d new leak(s)", n=new)
    if any(not r.ok for r in runs):
        return "warn", t("partial scan (a source failed)")
    if any(r.ok for r in runs):
        return "ok", t("no new leak")
    return "none", t("no scan")


def build_bars(runs, now: datetime, days: int = DAYS) -> list[dict]:
    """One bar per day (configured timezone), oldest first, ending today."""
    tz = ZoneInfo(cfg.timezone)
    today = now.astimezone(tz).date()
    by_day = defaultdict(list)
    for r in runs:
        started = r.started_at if r.started_at.tzinfo else r.started_at.replace(tzinfo=timezone.utc)
        by_day[started.astimezone(tz).date()].append(r)
    bars = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        state, text = _day_state(by_day.get(day, []))
        bars.append({"cls": state, "label": f"{fmt_date(day)}: {text}"})
    return bars


def clean_streak(bars: list[dict]) -> int:
    """Recent consecutive days with a successful scan and no new leak."""
    n = 0
    for b in reversed(bars):
        if b["cls"] not in ("ok", "warn"):
            break
        n += 1
    return n


def scanner_stale(last_scan: datetime | None, now: datetime, has_work: bool) -> bool:
    """True when verified domains exist but no scan ran for more than 26 h."""
    if not has_work:
        return False
    if last_scan is None:
        return True
    if last_scan.tzinfo is None:
        last_scan = last_scan.replace(tzinfo=timezone.utc)
    return now - last_scan > STALE_AFTER
