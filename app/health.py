from collections import defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .config import settings

DAYS = 60
STALE_AFTER = timedelta(hours=26)  # un scan quotidien + une marge


def _day_state(runs) -> tuple[str, str]:
    """Résumé d'une journée de scans, du plus grave au moins grave."""
    new = sum(r.new_count for r in runs if r.ok and not r.baseline)
    if new:
        return "bad", f"{new} nouvelle(s) fuite(s)"
    if any(not r.ok for r in runs):
        return "warn", "scan partiel (source en erreur)"
    if any(r.ok for r in runs):
        return "ok", "aucune nouvelle fuite"
    return "none", "pas de scan"


def build_bars(runs, now: datetime, days: int = DAYS) -> list[dict]:
    """Une barre par jour (fuseau configuré), de la plus ancienne à aujourd'hui."""
    tz = ZoneInfo(settings.timezone)
    today = now.astimezone(tz).date()
    by_day = defaultdict(list)
    for r in runs:
        started = r.started_at if r.started_at.tzinfo else r.started_at.replace(tzinfo=timezone.utc)
        by_day[started.astimezone(tz).date()].append(r)
    bars = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        state, text = _day_state(by_day.get(day, []))
        bars.append({"cls": state, "label": f"{day.strftime('%d/%m/%Y')} : {text}"})
    return bars


def clean_streak(bars: list[dict]) -> int:
    """Jours consécutifs récents avec scan réussi et sans nouvelle fuite."""
    n = 0
    for b in reversed(bars):
        if b["cls"] not in ("ok", "warn"):
            break
        n += 1
    return n


def scanner_stale(last_scan: datetime | None, now: datetime, has_work: bool) -> bool:
    """Vrai si des domaines vérifiés existent mais qu'aucun scan n'a eu lieu depuis plus de 26 h."""
    if not has_work:
        return False
    if last_scan is None:
        return True
    if last_scan.tzinfo is None:
        last_scan = last_scan.replace(tzinfo=timezone.utc)
    return now - last_scan > STALE_AFTER
