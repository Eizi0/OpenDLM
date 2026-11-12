import hashlib
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest

from app import scanner, scheduler
from app.connectors import active_source_names, build_address_connectors, leakcheck, xposedornot
from app.connectors.base import ConnectorError, Hit
from app.connectors.leakcheck import LeakCheckConnector, address_hash
from app.connectors.xposedornot import XposedOrNotConnector
from app.db import SessionLocal
from app.models import Domain, Finding, MonitoredAddress, ScanRun
from app.scanner import scan_addresses
from app.verification import parse_addresses

CATALOG = {"status": "success", "exposedBreaches": [
    {"breachID": "Adobe", "breachedDate": "2013-10-04T00:00:00+00:00", "exposedData": ["Email addresses", "Passwords"]},
    {"breachID": "Forum", "breachedDate": "2020-01-02T00:00:00+00:00", "exposedData": ["Email addresses", "Usernames"]},
]}


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# --- LeakCheck --------------------------------------------------------------------------------------


def test_leakcheck_sends_only_a_hash_never_the_address():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"success": True, "found": 2, "fields": ["password", "username"],
                                         "sources": [{"name": "Zynga.com", "date": "2019-09"}, {"name": "Old.net", "date": ""}]})

    hits = LeakCheckConnector("ua", client_for(handler)).check_address("Direction@Exemple.FR")
    expected = hashlib.sha256(b"direction@exemple.fr").hexdigest()[:24]
    assert seen["url"].endswith(f"check={expected}") and "exemple" not in seen["url"].lower() and "@" not in seen["url"]
    assert address_hash("  Direction@Exemple.FR ") == expected and len(expected) == 24
    assert [(h.identifier, h.breach, h.breach_date) for h in hits] == [("Direction@Exemple.FR", "Zynga.com", date(2019, 9, 1)), ("Direction@Exemple.FR", "Old.net", None)]
    assert all(h.source == "LeakCheck" and h.data_classes == ("Email addresses",) for h in hits)  # per-breach data is unknown: never claims passwords


def test_leakcheck_not_found_is_empty_and_errors_are_explicit():
    nf = httpx.Response(200, json={"success": False, "error": "Not found"})
    assert LeakCheckConnector("ua", client_for(lambda r: nf)).check_address("a@b.fr") == []
    for response, needle in ((httpx.Response(429, headers={"retry-after": "7"}), "rate limit"), (httpx.Response(503), "service error"),
                             (httpx.Response(200, text="<html>"), "unreadable"), (httpx.Response(200, json=[1]), "unexpected"),
                             (httpx.Response(200, json={"success": False, "error": "Invalid query"}), "Invalid query")):
        with pytest.raises(ConnectorError, match=needle):
            LeakCheckConnector("ua", client_for(lambda r, resp=response: resp)).check_address("a@b.fr")


def test_leakcheck_rate_limit_carries_retry_after():
    with pytest.raises(ConnectorError) as e:
        LeakCheckConnector("ua", client_for(lambda r: httpx.Response(429, headers={"retry-after": "9"}))).check_address("a@b.fr")
    assert e.value.retry_after == 9


# --- XposedOrNot ------------------------------------------------------------------------------------


def xon_client(check_body, status=200, catalog_calls=None):
    def handler(request):
        if request.url.path.endswith("/breaches"):
            if catalog_calls is not None:
                catalog_calls.append(1)
            return httpx.Response(200, json=CATALOG)
        return httpx.Response(status, json=check_body)
    return client_for(handler)


def test_xposedornot_maps_nested_breach_lists_with_catalog_details():
    xposedornot.reset_catalog()
    hits = XposedOrNotConnector("ua", xon_client({"breaches": [["Adobe", "Forum", "Adobe"]], "email": "a@b.fr", "status": "success"})).check_address("a@b.fr")
    assert [(h.breach, h.breach_date, h.data_classes) for h in hits] == [
        ("Adobe", date(2013, 10, 4), ("Email addresses", "Passwords")), ("Forum", date(2020, 1, 2), ("Email addresses", "Usernames"))]
    assert scanner.severity(hits[0]) == "high" and scanner.severity(hits[1]) == "low"


def test_xposedornot_not_found_body_with_http_200_means_nothing_known():
    xposedornot.reset_catalog()
    assert XposedOrNotConnector("ua", xon_client({"Error": "Not found", "email": None})).check_address("a@b.fr") == []


def test_xposedornot_catalog_is_fetched_once_for_many_addresses():
    xposedornot.reset_catalog()
    calls = []
    c = XposedOrNotConnector("ua", xon_client({"breaches": [["Adobe"]]}, catalog_calls=calls))
    for _ in range(5):
        c.check_address("a@b.fr")
    assert len(calls) == 1
    xposedornot.reset_catalog()


def test_xposedornot_unknown_breach_still_reported_and_errors_explicit():
    xposedornot.reset_catalog()
    (h,) = XposedOrNotConnector("ua", xon_client({"breaches": [["NotInCatalog"]]})).check_address("a@b.fr")
    assert h.breach == "NotInCatalog" and h.breach_date is None and h.data_classes == ("Email addresses",)
    for status, needle in ((429, "rate limit"), (502, "service error"), (418, "unexpected")):
        with pytest.raises(ConnectorError, match=needle):
            XposedOrNotConnector("ua", xon_client({}, status=status)).check_address("a@b.fr")


# --- Scan engine ------------------------------------------------------------------------------------


class FakeSource:
    name = "Fake"
    min_interval = 0.5
    batch_size = 3
    daily_budget = None

    def __init__(self, results, fail_at=None):
        self.results, self.calls, self.fail_at = results, [], fail_at

    def check_address(self, address):
        self.calls.append(address)
        if self.fail_at is not None and len(self.calls) > self.fail_at:
            raise ConnectorError("rate limit reached", retry_after=60)
        return [Hit(address, self.name, b, date(2024, 1, 1), ("Email addresses",)) for b in self.results.get(address, [])]


class Spy:
    def __init__(self):
        self.sent = []

    def alert(self, domain, findings):
        self.sent.append(list(findings))


def setup_domain(session, names=("a", "b", "c", "d", "e")):
    d = Domain(name="exemple.fr", verify_token="t", verified=True)
    session.add(d)
    session.commit()
    session.add_all(MonitoredAddress(domain_id=d.id, address=f"{n}@exemple.fr", checked={}) for n in names)
    session.commit()
    return d


def test_batches_are_bounded_stalest_first_and_pause_between_calls(session):
    d, src, pauses = setup_domain(session), FakeSource({}), []
    scan_addresses(session, d, [src], Spy(), sleep=pauses.append)
    assert src.calls == ["a@exemple.fr", "b@exemple.fr", "c@exemple.fr"] and pauses == [0.5, 0.5]  # batch of 3, pause between calls only
    src2 = FakeSource({})
    scan_addresses(session, d, [src2], Spy(), sleep=lambda s: None)
    assert src2.calls == ["d@exemple.fr", "e@exemple.fr"]  # the ones not yet checked come next; a-c were checked less than 20 h ago
    src3 = FakeSource({})
    scan_addresses(session, d, [src3], Spy(), sleep=lambda s: None)
    assert src3.calls == []  # everything was checked recently: nothing to do, no empty run recorded
    assert session.query(ScanRun).count() == 2


def test_baseline_is_per_address_and_per_source(session):
    d, spy = setup_domain(session, ("a", "b")), Spy()
    src = FakeSource({"a@exemple.fr": ["Old breach"], "b@exemple.fr": ["Other old"]})
    r1 = scan_addresses(session, d, [src], spy, sleep=lambda s: None)
    assert r1.new == [] and spy.sent == [] and {f.status for f in session.query(Finding)} == {"known"}
    run = session.query(ScanRun).one()
    assert run.baseline is True and run.new_count == 0
    # a day later, a new breach appears for one address
    for a in session.query(MonitoredAddress):
        a.checked = {"Fake": (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()}
    session.commit()
    src.results["a@exemple.fr"] = ["Old breach", "Fresh breach"]
    r2 = scan_addresses(session, d, [src], spy, sleep=lambda s: None)
    assert [f.breach for f in r2.new] == ["Fresh breach"] and len(spy.sent) == 1
    # a *new* address added later is baselined silently, even though the source already knows the others
    session.add(MonitoredAddress(domain_id=d.id, address="z@exemple.fr", checked={}))
    session.commit()
    src.results["z@exemple.fr"] = ["Ancient"]
    r3 = scan_addresses(session, d, [src], spy, sleep=lambda s: None)
    assert r3.new == [] and len(spy.sent) == 1
    assert session.query(Finding).filter_by(identifier="z@exemple.fr").one().status == "known"


def test_source_error_stops_the_batch_and_resumes_later(session):
    d, spy = setup_domain(session), Spy()
    src = FakeSource({}, fail_at=1)  # first call ok, second hits the rate limit
    r = scan_addresses(session, d, [src], spy, sleep=lambda s: None)
    assert r.errors and "rate limit" in r.errors[0] and len(src.calls) == 2
    run = session.query(ScanRun).one()
    assert run.ok is False and "rate limit" in run.error
    checked = [a.address for a in session.query(MonitoredAddress) if "Fake" in (a.checked or {})]
    assert checked == ["a@exemple.fr"]  # only the successful one is marked: the failed one is retried first next time
    nxt = FakeSource({})
    scan_addresses(session, d, [nxt], spy, sleep=lambda s: None)
    assert nxt.calls[0] == "b@exemple.fr"


def test_daily_budget_is_shared_across_domains(session):
    d, src = setup_domain(session), FakeSource({})
    src.batch_size, src.daily_budget = 10, 4
    other = Domain(name="autre.fr", verify_token="t", verified=True)
    session.add(other)
    session.commit()
    session.add(MonitoredAddress(domain_id=other.id, address="x@autre.fr", checked={"Fake": datetime.now(timezone.utc).isoformat()}))
    session.commit()
    scan_addresses(session, d, [src], Spy(), sleep=lambda s: None)
    assert len(src.calls) == 3  # budget 4, one already used in the last 24 h elsewhere


def test_manual_limit_and_unverified_domain(session):
    d, src = setup_domain(session), FakeSource({})
    scan_addresses(session, d, [src], Spy(), limit=1, sleep=lambda s: None)
    assert len(src.calls) == 1
    d.verified = False
    with pytest.raises(PermissionError):
        scan_addresses(session, d, [src], Spy())


def test_alert_threshold_applies_to_address_findings(session, cfg_override):
    cfg_override(alert_min_severity="high")
    d, spy = setup_domain(session, ("a",)), Spy()

    class Src(FakeSource):
        def check_address(self, address):
            return [Hit(address, "Fake", "Low one", None, ("Email addresses",)), Hit(address, "Fake", "High one", None, ("Passwords",))] if self.calls.append(address) is None and len(self.calls) > 1 else self.calls_noop()

        def calls_noop(self):
            return []

    s = Src({})
    scan_addresses(session, d, [s], spy, sleep=lambda x: None)  # baseline pass
    session.query(MonitoredAddress).update({"checked": {"Fake": (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()}})
    session.commit()
    r = scan_addresses(session, d, [s], spy, sleep=lambda x: None)
    assert len(r.new) == 2 and [f.breach for f in spy.sent[0]] == ["High one"]  # the low one waits for the report


# --- Parsing and wiring -----------------------------------------------------------------------------


def test_parse_addresses_accepts_only_the_domain_and_dedupes():
    valid, invalid = parse_addresses("A@Exemple.fr, b@exemple.fr;\n a@exemple.fr  evil@autre.fr nope @exemple.fr x@sub.exemple.fr", "exemple.fr")
    assert valid == ["a@exemple.fr", "b@exemple.fr"]
    assert set(invalid) == {"evil@autre.fr", "nope", "@exemple.fr", "x@sub.exemple.fr"}
    assert parse_addresses("", "exemple.fr") == ([], [])
    assert parse_addresses("a" * 70 + "@exemple.fr", "exemple.fr")[0] == []


def test_connectors_are_opt_in(cfg_override):
    cfg_override(leakcheck_enabled=False, xposedornot_enabled=False)
    assert build_address_connectors() == []
    cfg_override(leakcheck_enabled=True)
    assert [c.name for c in build_address_connectors()] == ["LeakCheck"]
    cfg_override(xposedornot_enabled=True)
    assert [c.name for c in build_address_connectors()] == ["LeakCheck", "XposedOrNot"]
    assert {"LeakCheck", "XposedOrNot"} <= set(active_source_names())


def test_hourly_address_job_is_scheduled(cfg_override):
    sched = scheduler.start()
    try:
        assert sched.get_job("address-scan") is not None
    finally:
        sched.shutdown(wait=False)
        scheduler._scheduler = None
