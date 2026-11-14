import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from . import news, reports, retention, scan_jobs
from .config import settings
from .runtime_config import cfg
from .connectors import build_address_connectors, build_connectors
from .db import SessionLocal
from .models import Domain
from .notifier import Notifier
from .scanner import run_scan, scan_addresses

log = logging.getLogger("opendlm.scheduler")


def scan_all() -> None:
    connectors = build_connectors()
    if not connectors:
        log.warning("No active connector (no demo, no API key): scan skipped")
        return
    notifier = Notifier()
    with SessionLocal() as session:
        for domain in session.scalars(select(Domain).where(Domain.verified.is_(True))):
            try:
                result = scan_jobs.run_locked(domain.id, lambda: run_scan(session, domain, connectors, notifier))
                log.info("scan %s: %d new, %d error(s)", domain.name, len(result.new), len(result.errors))
            except Exception:
                log.exception("scan %s failed", domain.name)


def scan_addresses_all() -> None:
    """Hourly: a bounded batch of monitored addresses for each per-address source that is switched on."""
    connectors = build_address_connectors()
    if not connectors:
        return
    notifier = Notifier()
    with SessionLocal() as session:
        for domain in session.scalars(select(Domain).where(Domain.verified.is_(True))):
            try:
                result = scan_jobs.run_locked(domain.id, lambda: scan_addresses(session, domain, connectors, notifier))
                if result.new or result.errors:
                    log.info("addresses %s: %d new, %d error(s)", domain.name, len(result.new), len(result.errors))
            except Exception:
                log.exception("address scan %s failed", domain.name)


def refresh_news() -> None:
    notifier = Notifier()
    with SessionLocal() as session:
        for name, res in news.refresh_all(session, notifier).items():
            log.info("news %s: %d new, %d mention(s)%s", name, res.new, len(res.mentions), f", error: {res.error or res.skipped}" if (res.error or res.skipped) else "")


def run_report(kind: str) -> None:
    with SessionLocal() as session:
        try:
            reports.run_scheduled(session, kind, Notifier())
        except Exception:
            log.exception("report %s failed", kind)


def run_retention() -> None:
    with SessionLocal() as session:
        try:
            retention.purge(session)
        except Exception:
            log.exception("retention purge failed")


_scheduler: BackgroundScheduler | None = None


def apply_schedule() -> None:
    """(Re)build the jobs from the current configuration. Called at startup and after settings change."""
    if _scheduler is None:
        return
    tz = cfg.timezone
    _scheduler.add_job(scan_all, "cron", hour=cfg.scan_hour, minute=0, timezone=tz, id="daily-scan", replace_existing=True, max_instances=1, coalesce=True)
    for job_id, kind, enabled, extra in (
        ("report-daily", "daily", cfg.report_daily, {"minute": 0}),
        ("report-monthly", "monthly", cfg.report_monthly, {"day": 1, "minute": 5}),
    ):
        if enabled:
            _scheduler.add_job(run_report, "cron", args=[kind], hour=cfg.report_hour, timezone=tz, id=job_id, replace_existing=True, max_instances=1, coalesce=True, **extra)
        elif _scheduler.get_job(job_id):
            _scheduler.remove_job(job_id)
    _scheduler.add_job(run_retention, "cron", hour=3, minute=30, timezone=tz, id="retention", replace_existing=True, max_instances=1, coalesce=True)
    if _scheduler.get_job("address-scan") is None:
        _scheduler.add_job(scan_addresses_all, "interval", hours=1, id="address-scan", max_instances=1, coalesce=True,
                           next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2))
    existing = _scheduler.get_job("news")
    if existing is None:
        first = datetime.now(timezone.utc) + timedelta(seconds=15)
        _scheduler.add_job(refresh_news, "interval", minutes=cfg.news_interval_minutes, id="news", max_instances=1, coalesce=True, next_run_time=first)
    else:
        _scheduler.reschedule_job("news", trigger="interval", minutes=cfg.news_interval_minutes)
    log.info("Schedule: scan %02d:00, reports %02d:00, news every %d min (%s)", cfg.scan_hour, cfg.report_hour, cfg.news_interval_minutes, tz)


def start() -> BackgroundScheduler:
    global _scheduler
    _scheduler = BackgroundScheduler(timezone=cfg.timezone)
    _scheduler.start()
    apply_schedule()
    return _scheduler
