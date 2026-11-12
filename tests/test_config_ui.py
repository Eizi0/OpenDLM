import httpx
import pytest

from app import channels, scheduler
from app.config import settings
from app.connectors import build_connectors, testing
from app.db import SessionLocal
from app.models import Channel, ConfigValue
from app.runtime_config import cfg
from app.web import sources as sources_web

SECRET = "SUPER-SECRET-API-KEY-12345"


# --- Connector keys ------------------------------------------------------------------------------


def test_save_key_encrypts_applies_and_is_never_shown(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "demo", False)
    assert build_connectors() == []
    r = logged_client.post("/connectors/hibp/key", data={"api_key": SECRET})
    assert "n=key_saved" in r.headers["location"]
    with SessionLocal() as s:
        row = s.get(ConfigValue, "hibp_api_key")
        assert row.secret is True and SECRET not in row.value
    assert [c.name for c in build_connectors()] == ["HIBP"]  # active immediately, no restart
    page = logged_client.get("/sources").text
    assert SECRET not in page and "Key set" in page


def test_invalid_key_is_rejected_without_saving(logged_client):
    for bad in ("has space", "x" * 600, "  "):
        r = logged_client.post("/connectors/hibp/key", data={"api_key": bad})
        assert "e=invalid_value" in r.headers["location"]
    with SessionLocal() as s:
        assert s.get(ConfigValue, "hibp_api_key") is None


def test_unknown_connector_is_404(logged_client):
    assert logged_client.post("/connectors/nope/key", data={"api_key": "abc"}).status_code == 404
    assert logged_client.post("/connectors/nope/test").status_code == 404


def test_remove_key_falls_back_to_environment(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "hudson_rock_key", "from-env-key")
    monkeypatch.setenv("OPENDLM_HUDSON_ROCK_KEY", "from-env-key")
    logged_client.post("/connectors/hudson_rock/key", data={"api_key": SECRET})
    assert cfg.hudson_rock_key == SECRET
    assert "n=key_removed" in logged_client.post("/connectors/hudson_rock/key/delete").headers["location"]
    assert cfg.hudson_rock_key == "from-env-key" and cfg.source("hudson_rock_key") == "env"
    assert "from the environment" in logged_client.get("/sources").text


def test_connection_test_flow(logged_client, monkeypatch):
    assert "e=no_key" in logged_client.post("/connectors/hibp/test").headers["location"]
    logged_client.post("/connectors/hibp/key", data={"api_key": SECRET})
    seen = {}

    def fake_check(cid, key, ua):
        seen.update(cid=cid, key=key, ua=ua)
        return True, "Key accepted, %(n)d verified domain(s) on your HIBP account", {"n": 2}

    monkeypatch.setattr(sources_web.testing, "check", fake_check)
    r = logged_client.post("/connectors/hibp/test")
    assert "n=conn_ok" in r.headers["location"] and seen["key"] == SECRET and seen["cid"] == "hibp"
    assert "2 verified domain(s)" in logged_client.get("/sources").text
    monkeypatch.setattr(sources_web.testing, "check", lambda *a: (False, "API key rejected", {}))
    assert "e=conn_failed" in logged_client.post("/connectors/hibp/test").headers["location"]
    assert "API key rejected" in logged_client.get("/sources").text


@pytest.mark.parametrize("fn,status,ok", [
    (testing.check_hibp, 200, True), (testing.check_hibp, 401, False), (testing.check_hibp, 429, False), (testing.check_hibp, 500, False),
    (testing.check_hudson_rock, 200, True), (testing.check_hudson_rock, 401, False), (testing.check_hudson_rock, 403, False),
    (testing.check_ransomware_live, 200, True), (testing.check_ransomware_live, 403, False),
])
def test_connection_checks_map_status_codes(fn, status, ok):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(status, json=["a.fr", "b.fr"] if status == 200 else {})))
    result_ok, msgid, params = fn("key", "ua", client)
    assert result_ok is ok and isinstance(msgid, str) and isinstance(params, dict)


def test_connection_check_sends_the_right_credentials():
    seen = {}

    def handler(request):
        seen[request.url.host] = dict(request.headers)
        return httpx.Response(200, json=[])

    c = httpx.Client(transport=httpx.MockTransport(handler))
    testing.check_hibp("K1", "ua", c)
    testing.check_hudson_rock("K2", "ua", c)
    testing.check_ransomware_live("K3", "ua", c)
    assert seen["haveibeenpwned.com"]["hibp-api-key"] == "K1"
    assert seen["api.hudsonrock.com"]["api-key"] == "K2"
    assert seen["api-pro.ransomware.live"]["x-api-key"] == "K3"


def test_unreachable_service_is_reported_not_raised():
    def boom(request):
        raise httpx.ConnectError("no route")

    ok, msgid, params = testing.check_hibp("k", "ua", httpx.Client(transport=httpx.MockTransport(boom)))
    assert ok is False and "no route" in params["error"]


# --- Settings ------------------------------------------------------------------------------------


def test_settings_page_requires_admin_and_renders(logged_client):
    page = logged_client.get("/settings")
    assert page.status_code == 200 and "Daily scan hour" in page.text and 'value="Europe/Paris"' in page.text


def test_save_scheduling_applies_live(logged_client, monkeypatch):
    applied = []
    monkeypatch.setattr(scheduler, "apply_schedule", lambda: applied.append(True))
    r = logged_client.post("/settings/scheduling", data={"scan_hour": "3", "report_hour": "9", "report_daily": "1"})
    assert "n=saved" in r.headers["location"] and applied == [True]
    assert cfg.scan_hour == 3 and cfg.report_hour == 9
    assert cfg.report_daily is True and cfg.report_monthly is False and cfg.report_send_empty is False  # unchecked boxes are absent
    assert cfg.source("scan_hour") == "ui"


def test_invalid_settings_save_nothing(logged_client):
    for data in ({"scan_hour": "99", "report_hour": "9"}, {"scan_hour": "x", "report_hour": "9"}):
        assert "e=invalid_value" in logged_client.post("/settings/scheduling", data=data).headers["location"]
    assert "e=invalid_value" in logged_client.post("/settings/general", data={"language": "de", "timezone": "Europe/Paris"}).headers["location"]
    assert "e=invalid_value" in logged_client.post("/settings/general", data={"language": "fr", "timezone": "Mars/Olympus"}).headers["location"]
    with SessionLocal() as s:
        assert s.query(ConfigValue).count() == 0
    assert logged_client.post("/settings/unknown", data={}).status_code == 404


def test_general_settings_change_default_language_and_timezone(logged_client):
    logged_client.post("/settings/general", data={"language": "fr", "timezone": "America/Montreal"})
    assert cfg.language == "fr" and cfg.timezone == "America/Montreal"
    logged_client.get("/lang/en")  # the admin's own preference still wins over the instance default
    assert "Dashboard" in logged_client.get("/").text


def test_alert_threshold_and_news_settings(logged_client):
    logged_client.post("/settings/alerts", data={"alert_min_severity": "critical"})
    logged_client.post("/settings/news", data={"news_interval_minutes": "10", "news_retention_days": "30"})
    assert cfg.alert_min_severity == "critical" and cfg.news_interval_minutes == 10 and cfg.allow_private_feeds is False
    assert "e=invalid_value" in logged_client.post("/settings/news", data={"news_interval_minutes": "1", "news_retention_days": "30"}).headers["location"]
    assert cfg.news_interval_minutes == 10


def test_reset_section_restores_defaults(logged_client):
    logged_client.post("/settings/alerts", data={"alert_min_severity": "critical"})
    assert cfg.alert_min_severity == "critical"
    assert "n=saved" in logged_client.post("/settings/alerts/reset").headers["location"]
    assert cfg.alert_min_severity == settings.alert_min_severity and cfg.source("alert_min_severity") != "ui"


# --- Channels ------------------------------------------------------------------------------------


def test_channel_lifecycle_and_secret_never_displayed(logged_client, monkeypatch):
    url = "json://hooks.example.com/path?token=TOP-SECRET-TOKEN"
    assert "n=channel_added" in logged_client.post("/notifications/channels", data={"name": "SOC", "url": url}).headers["location"]
    page = logged_client.get("/notifications").text
    assert "SOC" in page and "json://…" in page and "TOP-SECRET-TOKEN" not in page and "hooks.example.com" not in page
    assert channels.all_urls() == [url]
    cid = SessionLocal().query(Channel).one().id

    logged_client.post(f"/notifications/channels/{cid}/toggle")
    assert channels.all_urls() == []
    logged_client.post(f"/notifications/channels/{cid}/toggle")

    sent = []
    monkeypatch.setattr(channels, "send_test", lambda u, title, body: sent.append(u) or True)
    assert "n=test_sent" in logged_client.post(f"/notifications/channels/{cid}/test").headers["location"]
    assert sent == [url]
    monkeypatch.setattr(channels, "send_test", lambda *a: False)
    assert "e=test_failed" in logged_client.post(f"/notifications/channels/{cid}/test").headers["location"]

    assert "n=channel_deleted" in logged_client.post(f"/notifications/channels/{cid}/delete").headers["location"]
    assert channels.all_urls() == [] and logged_client.post("/notifications/channels/999/delete").status_code == 404


def test_channel_validation_and_duplicates(logged_client):
    for data in ({"name": "x", "url": "json://a.example.com/h"}, {"name": "Good name", "url": "not a url"}):
        assert "e=channel_invalid" in logged_client.post("/notifications/channels", data=data).headers["location"]
    logged_client.post("/notifications/channels", data={"name": "SOC", "url": "json://a.example.com/h"})
    assert "e=channel_duplicate" in logged_client.post("/notifications/channels", data={"name": "SOC", "url": "json://b.example.com/h"}).headers["location"]


def test_environment_channels_are_listed_read_only(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "notify_urls", "ntfy://ntfy.sh/secret-topic")
    page = logged_client.get("/notifications").text
    assert "ntfy://…" in page and "secret-topic" not in page and "Set by OPENDLM_NOTIFY_URLS" in page


def test_viewer_cannot_use_configuration_endpoints(logged_client):
    logged_client.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    from fastapi.testclient import TestClient
    from app import main

    v = TestClient(main.app, follow_redirects=False)
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    for method, path, data in (("get", "/settings", None), ("post", "/settings/alerts", {"alert_min_severity": "low"}),
                               ("post", "/connectors/hibp/key", {"api_key": "abc"}), ("post", "/notifications/channels", {"name": "x1", "url": "json://a.b/c"})):
        assert getattr(v, method)(path, **({"data": data} if data else {})).status_code == 403, path
    assert cfg.hibp_api_key == ""
