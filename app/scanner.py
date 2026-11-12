import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .connectors.base import Connector, ConnectorError, Hit
from .models import Domain, Finding, ScanRun
from .config import settings
from .runtime_config import cfg
from .i18n import t
from .labels import SEVERITY_ORDER
from .notifier import Notifier

log = logging.getLogger("opendlm.scanner")


def severity(hit: Hit) -> str:
    """Severity derived from the kinds of data exposed (simple rule)."""
    classes = {c.lower() for c in hit.data_classes}
    if classes & {"session cookies", "stealer logs", "browser cookies"}:
        return "critical"
    if classes & {"passwords", "password hashes", "auth tokens"}:
        return "high"
    return "low"


@dataclass
class ScanResult:
    new: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    baselined_sources: list[str] = field(default_factory=list)


def run_scan(session: Session, domain: Domain, connectors: list[Connector], notifier: Notifier | None = None) -> ScanResult:
    """Query every source for a domain.

    First successful pass of a source on a domain: silent baseline (status "known", no alert).
    After that, only new findings are stored as "new" and notified.
    """
    if not domain.verified:
        raise PermissionError(t("Ownership of %(domain)s has not been verified", domain=domain.name))

    result = ScanResult()
    for connector in connectors:
        run = ScanRun(domain_id=domain.id, source=connector.name)
        try:
            hits = connector.check_domain(domain.name)
        except ConnectorError as e:
            run.ok, run.error = False, str(e)
            session.add(run)
            session.commit()
            result.errors.append(f"{connector.name}: {e}")
            log.warning("source %s failed for %s: %s", connector.name, domain.name, e)
            continue

        had_success = session.scalar(
            select(ScanRun.id).where(ScanRun.domain_id == domain.id, ScanRun.source == connector.name, ScanRun.ok.is_(True)).limit(1)
        )
        baseline = had_success is None

        known = {
            (f.identifier, f.breach)
            for f in session.scalars(select(Finding).where(Finding.domain_id == domain.id, Finding.source == connector.name))
        }
        created: list[Finding] = []
        for hit in hits:
            if (hit.identifier, hit.breach) in known:
                continue
            known.add((hit.identifier, hit.breach))
            created.append(
                Finding(
                    domain_id=domain.id,
                    identifier=hit.identifier,
                    source=hit.source,
                    breach=hit.breach,
                    breach_date=hit.breach_date,
                    data_classes=list(hit.data_classes),
                    severity=severity(hit),
                    status="known" if baseline else "new",
                )
            )
        session.add_all(created)
        run.baseline = baseline
        run.new_count = 0 if baseline else len(created)
        session.add(run)
        session.commit()

        if baseline:
            result.baselined_sources.append(connector.name)
        else:
            result.new.extend(created)

    # Below the configured threshold a finding is not alerted immediately: it appears in the report.
    threshold = SEVERITY_ORDER.get(cfg.alert_min_severity, SEVERITY_ORDER["low"])
    urgent = [f for f in result.new if SEVERITY_ORDER.get(f.severity, 3) <= threshold]
    if urgent and notifier:
        notifier.alert(domain.name, urgent)
    return result
