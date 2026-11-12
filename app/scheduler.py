import logging

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from .config import settings
from .connectors import build_connectors
from .db import SessionLocal
from .models import Domain
from .notifier import Notifier
from .scanner import run_scan

log = logging.getLogger("opendlm.scheduler")


def scan_all() -> None:
    connectors = build_connectors()
    if not connectors:
        log.warning("Aucun connecteur actif (ni démo, ni clé HIBP) : scan ignoré")
        return
    notifier = Notifier()
    with SessionLocal() as session:
        for domain in session.scalars(select(Domain).where(Domain.verified.is_(True))):
            try:
                result = run_scan(session, domain, connectors, notifier)
                log.info("scan %s : %d nouvelle(s), %d erreur(s)", domain.name, len(result.new), len(result.errors))
            except Exception:
                log.exception("scan %s en échec", domain.name)


def start() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone=settings.timezone)
    scheduler.add_job(scan_all, "cron", hour=settings.scan_hour, minute=0, id="daily-scan", max_instances=1, coalesce=True)
    scheduler.start()
    log.info("Scan quotidien programmé à %02d:00 (%s)", settings.scan_hour, settings.timezone)
    return scheduler
