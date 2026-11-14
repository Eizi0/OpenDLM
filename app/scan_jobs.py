"""Scans of one domain, never two at once.

A manual scan runs in a background thread so the page answers right away, and a per-domain lock keeps
it from overlapping the scheduled scan (both would otherwise insert the same findings).
"""

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone

log = logging.getLogger("opendlm.scan_jobs")

_guard = threading.Lock()
_locks: dict[int, threading.Lock] = {}
_running: dict[int, datetime] = {}
_threads: dict[int, threading.Thread] = {}


def _lock(domain_id: int) -> threading.Lock:
    with _guard:
        return _locks.setdefault(domain_id, threading.Lock())


def running_since(domain_id: int) -> datetime | None:
    return _running.get(domain_id)


class Busy(Exception):
    pass


def run_locked(domain_id: int, work: Callable[[], object], wait: bool = True):
    """Run work() holding the domain's lock. wait=False raises Busy if a scan is already running."""
    lock = _lock(domain_id)
    if not lock.acquire(blocking=wait):
        raise Busy
    _running[domain_id] = datetime.now(timezone.utc)
    try:
        return work()
    finally:
        _running.pop(domain_id, None)
        lock.release()


def start(domain_id: int, work: Callable[[], object]) -> bool:
    """Start work() in the background for this domain. False if a scan of the domain is already running."""
    lock = _lock(domain_id)
    if not lock.acquire(blocking=False):
        return False
    _running[domain_id] = datetime.now(timezone.utc)

    def target():
        try:
            work()
        except Exception:
            log.exception("manual scan of domain %s failed", domain_id)
        finally:
            _running.pop(domain_id, None)
            lock.release()

    thread = threading.Thread(target=target, name=f"scan-{domain_id}", daemon=True)
    _threads[domain_id] = thread
    thread.start()
    return True


def wait(domain_id: int, timeout: float = 30) -> None:
    """Wait for a background scan of the domain to finish (tests, shutdown)."""
    thread = _threads.get(domain_id)
    if thread is not None:
        thread.join(timeout)
