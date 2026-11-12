from datetime import date

import httpx
import pytest

from app.config import settings
from app.connectors import build_connectors
from app.connectors.base import ConnectorError
from app.connectors.hudson_rock import HudsonRockConnector
from app.models import Domain
from app.scanner import run_scan, severity

SAMPLE = {
    "data": [
        {
            "stealer": "abc-123", "stealer_family": "RedLine", "date_compromised": "2026-11-09T14:22:00.000Z",
            "ip": "203.0.113.7", "computer_name": "PC-COMPTA-01", "malware_path": "C:\\Users\\x\\AppData\\evil.exe",
            "credentials": [
                {"url": "https://vpn.exemple.fr/login", "domain": "exemple.fr", "username": "C.Martin@exemple.fr", "password": "SuperSecret!", "type": "employee"},
                {"url": "https://crm.exemple.fr", "domain": "exemple.fr", "username": "c.martin@exemple.fr", "password": "SuperSecret!", "type": "employee"},
                {"url": "https://x.exemple.fr", "domain": "exemple.fr", "username": "••••.••••@exemple.fr", "password": "••••", "type": "employee"},
            ],
        },
        "n'importe quoi",
    ]
}


def connector(handler):
    return HudsonRockConnector("cle", "OpenDLM-test", httpx.Client(transport=httpx.MockTransport(handler)))


def test_request_shape_and_hit_mapping():
    seen = {}

    def handler(request: httpx.Request):
        seen["headers"], seen["body"], seen["url"] = request.headers, request.read(), str(request.url)
        return httpx.Response(200, json=SAMPLE)

    hits = connector(handler).check_domain("exemple.fr")
    assert seen["url"].endswith("/json/v3/search-by-domain") and seen["headers"]["api-key"] == "cle"
    assert b'"domains":["exemple.fr"]' in seen["body"].replace(b" ", b"") and b"employees" in seen["body"]
    ids = sorted({h.identifier for h in hits})
    assert ids == ["[adresse masquée]@exemple.fr", "c.martin@exemple.fr"]  # minuscules, masqué signalé sans être deviné
    h = next(h for h in hits if h.identifier == "c.martin@exemple.fr")
    assert h.breach_date == date(2026, 11, 9) and h.source == "Hudson Rock"
    assert "RedLine" in h.breach and "09/11/2026" in h.breach
    assert severity(h) == "critical"


def test_no_secret_or_machine_detail_leaks_into_hits():
    hits = connector(lambda r: httpx.Response(200, json=SAMPLE)).check_domain("exemple.fr")
    blob = repr(hits)
    for secret in ("SuperSecret", "203.0.113.7", "PC-COMPTA-01", "evil.exe", "abc-123"):
        assert secret not in blob


def test_same_infection_collapses_but_two_machines_stay_distinct():
    a = {"stealer_family": "X", "date_compromised": "2026-11-09T00:00:00Z", "computer_name": "A", "ip": "1.1.1.1",
         "credentials": [{"username": "u@exemple.fr"}]}
    b = dict(a, computer_name="B", ip="2.2.2.2")
    hits = connector(lambda r: httpx.Response(200, json={"data": [a, b]})).check_domain("exemple.fr")
    assert len({(h.identifier, h.breach) for h in hits}) == 2


@pytest.mark.parametrize("response,needle", [
    (httpx.Response(401), "clé"), (httpx.Response(403), "permission"), (httpx.Response(500), "500"),
    (httpx.Response(200, text="pas du json"), "illisible"),
])
def test_errors_are_explicit(response, needle):
    with pytest.raises(ConnectorError, match=needle):
        connector(lambda r: response).check_domain("exemple.fr")


def test_rate_limit_exposes_retry_after_and_404_is_empty():
    with pytest.raises(ConnectorError) as e:
        connector(lambda r: httpx.Response(429, headers={"retry-after": "7"})).check_domain("exemple.fr")
    assert e.value.retry_after == 7
    assert connector(lambda r: httpx.Response(404)).check_domain("exemple.fr") == []


def test_full_scan_flow_silent_baseline_then_critical_alert(session):
    d = Domain(name="exemple.fr", verify_token="t", verified=True)
    session.add(d)
    session.commit()
    first = {"data": [dict(SAMPLE["data"][0], credentials=[{"username": "ancien@exemple.fr"}])]}
    payloads = [first, SAMPLE]
    c = connector(lambda r: httpx.Response(200, json=payloads.pop(0)))

    sent = []

    class Spy:
        def alert(self, domain, findings):
            sent.append(findings)

    r1 = run_scan(session, d, [c], Spy())
    assert r1.new == [] and sent == []
    r2 = run_scan(session, d, [c], Spy())
    assert {f.identifier for f in r2.new} == {"c.martin@exemple.fr", "[adresse masquée]@exemple.fr"}
    assert all(f.severity == "critical" for f in r2.new) and len(sent) == 1


def test_connector_enabled_only_with_a_key(monkeypatch):
    monkeypatch.setattr(settings, "hudson_rock_key", "")
    monkeypatch.setattr(settings, "hibp_api_key", "")
    monkeypatch.setattr(settings, "demo", False)
    assert build_connectors() == []
    monkeypatch.setattr(settings, "hudson_rock_key", "abc")
    assert [c.name for c in build_connectors()] == ["Hudson Rock"]
