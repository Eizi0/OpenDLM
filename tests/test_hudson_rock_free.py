from datetime import date

import httpx
import pytest

from app.config import settings
from app.connectors import build_address_connectors, build_connectors
from app.connectors.base import ConnectorError
from app.connectors.hudson_rock_free import HudsonRockFreeAddress, HudsonRockFreeDomain
from app.models import Domain
from app.scanner import run_scan, scan_addresses, severity

# Shapes taken from the real endpoints (trimmed).
DOMAIN_OK = {"total": 12993, "totalStealers": 37260258, "employees": 56, "users": 12896, "third_parties": 41,
             "last_employee_compromised": "2026-09-08T21:57:10.000Z", "last_user_compromised": "2026-11-08T01:13:19.000Z",
             "data": {"employees_urls": [{"occurrence": 57, "type": "Employee", "url": "https://jira.exemple.fr/login"}]}}
DOMAIN_CLEAN = {"total": 0, "totalStealers": 37260258, "employees": 0, "users": 0, "third_parties": 0}
EMAIL_INFECTED = {"message": "This email address is associated with a computer that was infected by an info-stealer",
                  "stealers": [{"total_corporate_services": 0, "total_user_services": 251, "date_compromised": "2026-11-09T21:19:54.000Z",
                                "computer_name": "DESKTOP-E8YGSRD (Maria)", "operating_system": "Windows 11", "malware_path": "C:\\Users\\HP\\evil.exe",
                                "ip": "165.101.**.***", "top_passwords": ["m*********4"], "top_logins": ["m*****@gmail.com"]}],
                  "total_corporate_services": 0, "total_user_services": 251}
EMAIL_CLEAN = {"message": "This email address is not associated with a computer infected by an info-stealer.", "stealers": [],
               "total_corporate_services": 0, "total_user_services": 0}


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def respond(body, status=200):
    return client(lambda r: httpx.Response(status, json=body))


def test_domain_count_becomes_one_critical_finding_with_the_count_in_its_name():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json=DOMAIN_OK)

    (h,) = HudsonRockFreeDomain("ua", client(handler)).check_domain("exemple.fr")
    assert "search-by-domain" in seen["url"] and "domain=exemple.fr" in seen["url"]
    assert h.identifier == "[domain-wide]@exemple.fr" and h.breach == "Employee accounts in infostealer logs: 56"
    assert h.breach_date == date(2026, 9, 8) and h.source == "Hudson Rock (free)" and severity(h) == "critical"
    assert "12896" not in repr(h) and "jira" not in repr(h)  # customer accounts and login pages are not kept


def test_clean_or_malformed_domain_gives_no_finding():
    assert HudsonRockFreeDomain("ua", respond(DOMAIN_CLEAN)).check_domain("exemple.fr") == []
    assert HudsonRockFreeDomain("ua", respond({"employees": "many"})).check_domain("exemple.fr") == []


def test_address_infection_keeps_only_date_and_an_anonymous_machine_id():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json=EMAIL_INFECTED)

    (h,) = HudsonRockFreeAddress("ua", client(handler)).check_address("direction@exemple.fr")
    assert "search-by-email" in seen["url"] and "direction%40exemple.fr" in seen["url"]
    assert h.identifier == "direction@exemple.fr" and h.breach_date == date(2026, 11, 9) and severity(h) == "critical"
    blob = repr(h)
    for secret in ("DESKTOP-E8YGSRD", "Maria", "165.101", "evil.exe", "m*********4", "gmail", "251"):
        assert secret not in blob
    assert h.breach.startswith("Infostealer infection · 2026-11-09 · machine ") and len(h.breach.split("machine ")[1]) == 6


def test_clean_address_and_two_infections_are_distinguished():
    assert HudsonRockFreeAddress("ua", respond(EMAIL_CLEAN)).check_address("a@b.fr") == []
    second = dict(EMAIL_INFECTED["stealers"][0], computer_name="LAPTOP-OTHER", date_compromised="2026-11-10T08:00:00.000Z")
    body = {"stealers": [EMAIL_INFECTED["stealers"][0], second]}
    hits = HudsonRockFreeAddress("ua", respond(body)).check_address("a@b.fr")
    assert len({h.breach for h in hits}) == 2


@pytest.mark.parametrize("status,needle", [(429, "rate limit"), (403, "refused"), (503, "service error"), (418, "unexpected")])
def test_errors_are_explicit(status, needle):
    with pytest.raises(ConnectorError, match=needle):
        HudsonRockFreeDomain("ua", respond({}, status)).check_domain("exemple.fr")


def test_a_challenge_page_is_reported_not_crashed():
    c = client(lambda r: httpx.Response(200, text="<html>Just a moment...</html>"))
    with pytest.raises(ConnectorError, match="unreadable"):
        HudsonRockFreeAddress("ua", c).check_address("a@b.fr")
    with pytest.raises(ConnectorError, match="unreachable"):
        def boom(request):
            raise httpx.ConnectTimeout("slow")
        HudsonRockFreeDomain("ua", client(boom)).check_domain("exemple.fr")


def test_it_is_on_by_default_in_the_application(monkeypatch):
    from app.config import Settings

    assert Settings().hudson_rock_free_enabled is False  # the test environment turns it off...
    monkeypatch.delenv("OPENDLM_HUDSON_ROCK_FREE_ENABLED")
    assert Settings().hudson_rock_free_enabled is True  # ...the real default is on


def test_official_key_replaces_the_free_source(cfg_override, monkeypatch):
    monkeypatch.setattr(settings, "demo", False)
    cfg_override(hibp_api_key="", hudson_rock_key="", hudson_rock_free_enabled=True, leakcheck_enabled=False, xposedornot_enabled=False)
    assert [c.name for c in build_connectors()] == ["Hudson Rock (free)"]
    assert [c.name for c in build_address_connectors()] == ["Hudson Rock (free)"]
    cfg_override(hudson_rock_key="official-key")
    assert [c.name for c in build_connectors()] == ["Hudson Rock"]  # no duplicate alerts
    assert build_address_connectors() == []
    cfg_override(hudson_rock_key="", hudson_rock_free_enabled=False)
    assert build_connectors() == [] and build_address_connectors() == []


def test_full_flow_baseline_then_growth_alerts(session):
    d = Domain(name="exemple.fr", verify_token="t", verified=True)
    session.add(d)
    session.commit()
    bodies = [dict(DOMAIN_OK, employees=56), dict(DOMAIN_OK, employees=56), dict(DOMAIN_OK, employees=58)]
    c = HudsonRockFreeDomain("ua", client(lambda r: httpx.Response(200, json=bodies.pop(0))))
    sent = []

    class Spy:
        def alert(self, domain, findings):
            sent.append([f.breach for f in findings])

    r1 = run_scan(session, d, [c], Spy())
    assert r1.new == [] and sent == []  # the existing exposure is the baseline
    assert run_scan(session, d, [c], Spy()).new == []  # same count: nothing new
    r3 = run_scan(session, d, [c], Spy())
    assert sent == [["Employee accounts in infostealer logs: 58"]] and r3.new[0].severity == "critical"


def test_sources_page_shows_it_enabled_and_toggle_works(logged_client):
    logged_client.post("/connectors/hudson_rock_free/toggle")  # test env starts with it off
    from app.runtime_config import cfg

    assert cfg.hudson_rock_free_enabled is True
    page = logged_client.get("/sources").text
    assert "Hudson Rock (free tools)" in page and "Hudson Rock (official API)" in page
    assert "switches itself off" in page and "https://www.hudsonrock.com/free-tools" in page


def test_active_source_names_list_a_two_part_source_once(cfg_override, monkeypatch):
    from app.connectors import active_source_names

    monkeypatch.setattr(settings, "demo", False)
    cfg_override(hibp_api_key="", hudson_rock_key="", hudson_rock_free_enabled=True, leakcheck_enabled=False, xposedornot_enabled=False)
    assert active_source_names() == ["Hudson Rock (free)"]
