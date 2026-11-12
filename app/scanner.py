import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .connectors.base import AddressConnector, Connector, ConnectorError, Hit
from .models import Domain, Finding, MonitoredAddress, ScanRun, utcnow
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


RECHECK_AFTER = timedelta(hours=20)  # an address is asked about at most about once a day per source


def _last_check(address: MonitoredAddress, source: str) -> datetime | None:
    raw = (address.checked or {}).get(source)
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _checks_last_24h(session: Session, source: str, now: datetime) -> int:
    count = 0
    for (checked,) in session.execute(select(MonitoredAddress.checked)):
        raw = (checked or {}).get(source)
        if raw:
            try:
                dt = datetime.fromisoformat(raw)
            except ValueError:
                continue
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            if now - dt < timedelta(hours=24):
                count += 1
    return count


def scan_addresses(
    session: Session,
    domain: Domain,
    connectors: list[AddressConnector],
    notifier: Notifier | None = None,
    limit: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> ScanResult:
    """Ask per-address sources about the monitored addresses of a domain, a bounded batch at a time.

    Stalest addresses first; each source keeps to its own batch size, pause and daily budget, so a free tier
    is never hammered. The baseline is per address and per source: the first time a source checks an address,
    what it already knows is recorded silently ("known"); only later discoveries are new and alerted.
    """
    if not domain.verified:
        raise PermissionError(t("Ownership of %(domain)s has not been verified", domain=domain.name))
    result = ScanResult()
    now = utcnow()
    addresses = session.scalars(select(MonitoredAddress).where(MonitoredAddress.domain_id == domain.id)).all()
    for connector in connectors:
        due = [a for a in addresses if (lc := _last_check(a, connector.name)) is None or now - lc > RECHECK_AFTER]
        due.sort(key=lambda a: (_last_check(a, connector.name) or datetime.min.replace(tzinfo=timezone.utc), a.id))
        room = connector.batch_size
        if connector.daily_budget is not None:
            room = min(room, connector.daily_budget - _checks_last_24h(session, connector.name, now))
        if limit is not None:
            room = min(room, limit)
        batch = due[: max(room, 0)]
        if not batch:
            continue

        known = {
            (f.identifier, f.breach)
            for f in session.scalars(select(Finding).where(Finding.domain_id == domain.id, Finding.source == connector.name))
        }
        run = ScanRun(domain_id=domain.id, source=connector.name)
        created: list[Finding] = []
        checked = new_count = 0
        all_baseline = True
        for index, address in enumerate(batch):
            if index:
                sleep(connector.min_interval)
            try:
                hits = connector.check_address(address.address)
            except ConnectorError as e:
                run.ok, run.error = False, str(e)
                result.errors.append(f"{connector.name}: {e}")
                log.warning("source %s failed for %s: %s", connector.name, address.address, e)
                break  # stop this source for now: the next run resumes with the stalest addresses
            first_time = connector.name not in (address.checked or {})
            for hit in hits:
                if (hit.identifier, hit.breach) in known:
                    continue
                known.add((hit.identifier, hit.breach))
                created.append(
                    Finding(
                        domain_id=domain.id, identifier=hit.identifier, source=hit.source, breach=hit.breach,
                        breach_date=hit.breach_date, data_classes=list(hit.data_classes), severity=severity(hit),
                        status="known" if first_time else "new",
                    )
                )
                if not first_time:
                    new_count += 1
            address.checked = {**(address.checked or {}), connector.name: now.isoformat()}  # reassign: JSON change detection
            checked += 1
            if not first_time:
                all_baseline = False
        if not checked and run.ok:
            continue
        run.baseline = checked > 0 and all_baseline
        run.new_count = new_count
        session.add_all(created)
        session.add(run)
        session.commit()
        result.new.extend(f for f in created if f.status == "new")
        if run.baseline:
            result.baselined_sources.append(connector.name)

    threshold = SEVERITY_ORDER.get(cfg.alert_min_severity, SEVERITY_ORDER["low"])
    urgent = [f for f in result.new if SEVERITY_ORDER.get(f.severity, 3) <= threshold]
    if urgent and notifier:
        notifier.alert(domain.name, urgent)
    return result
