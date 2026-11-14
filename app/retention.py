"""Nightly purge of old history. Leaks (findings) are never purged: a deleted finding would come back as
new at the next scan and alert again."""

import logging
from datetime import timedelta

from sqlalchemy import and_, delete, func, select
from sqlalchemy.orm import Session

from .models import AuditEvent, Report, ScanRun, utcnow
from .runtime_config import cfg

log = logging.getLogger("opendlm.retention")


def purge(session: Session) -> dict[str, int]:
    counts = {"scan_runs": 0, "reports": 0, "audit_events": 0}
    now = utcnow()
    days = cfg.history_retention_days
    if days > 0:
        cutoff = now - timedelta(days=days)
        # Keep the latest successful run of each source on each domain: it is what tells the scanner the
        # silent baseline is already done. Without it the next scan would baseline again and hide new leaks.
        keep = select(func.max(ScanRun.id)).where(ScanRun.ok.is_(True)).group_by(ScanRun.domain_id, ScanRun.source)
        counts["scan_runs"] = session.execute(
            delete(ScanRun).where(and_(ScanRun.started_at < cutoff, ScanRun.id.not_in(keep)))
        ).rowcount or 0
        counts["reports"] = session.execute(delete(Report).where(Report.created_at < cutoff)).rowcount or 0
    if cfg.audit_retention_days > 0:
        cutoff = now - timedelta(days=cfg.audit_retention_days)
        counts["audit_events"] = session.execute(delete(AuditEvent).where(AuditEvent.at < cutoff)).rowcount or 0
    session.commit()
    if any(counts.values()):
        log.info("purged %s", ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    return counts
