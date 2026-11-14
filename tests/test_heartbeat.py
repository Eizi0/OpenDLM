from datetime import timedelta

import httpx

from app import heartbeat
from app.models import Domain, Finding, ScanRun, utcnow


def test_valid_url():
    assert heartbeat.valid_url("https://kuma.example.com/api/push/abc")
    assert heartbeat.valid_url("http://10.0.0.5:3001/api/push/abc")
    assert not heartbeat.valid_url("ftp://x/y")
    assert not heartbeat.valid_url("https://")
    assert not heartbeat.valid_url("https://a b")


def _domain(session):
    d = Domain(name="exemple.fr", verify_token="x", verified=True)
    session.add(d)
    session.commit()
    return d


def test_state_up_with_open_leaks(session, monkeypatch):
    monkeypatch.setattr(heartbeat, "active_source_names", lambda: ["Demo"])
    d = _domain(session)
    session.add_all([ScanRun(domain_id=d.id, source="Demo", ok=True),
                     Finding(domain_id=d.id, identifier="a@exemple.fr", source="Demo", breach="X", data_classes=[], severity="low", status="new")])
    session.commit()
    status, msg = heartbeat.state(session)
    assert status == "up" and "1 new leak" in msg and "exemple.fr" not in msg


def test_state_down_when_scanner_stale(session, monkeypatch):
    monkeypatch.setattr(heartbeat, "active_source_names", lambda: ["Demo"])
    d = _domain(session)
    session.add(ScanRun(domain_id=d.id, source="Demo", ok=True, started_at=utcnow() - timedelta(hours=30)))
    session.commit()
    assert heartbeat.state(session)[0] == "down"


def test_state_down_when_every_source_failed(session, monkeypatch):
    monkeypatch.setattr(heartbeat, "active_source_names", lambda: ["Demo"])
    d = _domain(session)
    session.add(ScanRun(domain_id=d.id, source="Demo", ok=False, error="401"))
    session.commit()
    assert heartbeat.state(session) == ("down", "every source failed during the last scan")


def test_no_domain_is_up(session):
    assert heartbeat.state(session)[0] == "up"


def test_push_sends_status_and_message(monkeypatch):
    seen = {}

    def fake_get(url, params, **kw):
        seen.update(url=url, **params)
        return httpx.Response(200, request=httpx.Request("GET", url))
    monkeypatch.setattr(heartbeat.httpx, "get", fake_get)
    assert heartbeat.push("https://kuma/api/push/t", "down", "x")
    assert seen == {"url": "https://kuma/api/push/t", "status": "down", "msg": "x"}

    def broken(url, **kw):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(heartbeat.httpx, "get", broken)
    assert heartbeat.push("https://kuma/api/push/t", "up", "x") is False


def test_heartbeat_settings_page(logged_client, monkeypatch):
    calls = []
    monkeypatch.setattr(heartbeat, "push", lambda url, status, msg: calls.append((url, status)) or True)
    assert "e=invalid_url" in logged_client.post("/notifications/heartbeat", data={"url": "not a url"}).headers["location"]
    r = logged_client.post("/notifications/heartbeat", data={"url": "https://kuma.example.com/api/push/SECRET123"})
    assert "n=heartbeat_saved" in r.headers["location"]
    page = logged_client.get("/notifications").text
    assert "<b>kuma.example.com</b>" in page and "SECRET123" not in page
    assert "n=test_sent" in logged_client.post("/notifications/heartbeat/test").headers["location"]
    assert calls == [("https://kuma.example.com/api/push/SECRET123", "up")]
    logged_client.post("/notifications/heartbeat/delete")
    assert "<b>kuma.example.com</b>" not in logged_client.get("/notifications").text
