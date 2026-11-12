import csv
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import api_tokens, exports
from app.db import SessionLocal
from app.models import ApiToken, Domain, Finding, NewsItem, NewsSource, ScanRun


def seed():
    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        d1 = Domain(name="exemple.fr", verify_token="t", verified=True)
        d2 = Domain(name="autre.fr", verify_token="t", verified=True)
        s.add_all([d1, d2])
        s.commit()
        s.add_all([
            Finding(domain_id=d1.id, identifier="a@exemple.fr", source="HIBP", breach="B1", severity="high", status="new", first_seen=now, data_classes=["Passwords", "Emails"]),
            Finding(domain_id=d1.id, identifier="=HYPERLINK(\"http://evil\")@exemple.fr", source="HIBP", breach="+cmd|calc", severity="low", status="known", first_seen=now - timedelta(days=40), data_classes=[]),
            Finding(domain_id=d2.id, identifier="b@autre.fr", source="Demo", breach="B2", severity="critical", status="resolved", first_seen=now - timedelta(days=2), data_classes=["Stealer logs"]),
        ])
        src = s.query(NewsSource).filter_by(name="FrenchBreaches").one()  # seeded at startup
        src.last_ok = True
        s.query(NewsSource).filter(NewsSource.name != "FrenchBreaches").update({"enabled": False})  # keep the metrics predictable
        s.add(NewsSource(name='Flux "cassé"', kind="rss", enabled=True, last_ok=False))
        s.commit()
        s.add_all([
            NewsItem(source_id=src.id, guid="1", title="Fuite chez Ciblex", url="https://x.fr/1", excerpt="ex", published_at=now, reliability="credible", matched=["Ciblex"], notified=True),
            NewsItem(source_id=src.id, guid="2", title="Autre", url="https://x.fr/2", published_at=now - timedelta(days=3), matched=[], notified=True),
        ])
        s.add(ScanRun(domain_id=d1.id, source="HIBP", ok=True, started_at=now))
        s.commit()


def make_token(logged_client, name="Prometheus"):
    r = logged_client.post("/tokens", data={"name": name})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    token = [w for w in r.text.replace("<", " ").replace(">", " ").split() if w.startswith("odlm_")][0]
    return token


@pytest.fixture
def api(logged_client):
    seed()
    return logged_client


def bearer(token):
    c = TestClient(__import__("app.main", fromlist=["app"]).app, follow_redirects=False)
    c.headers["authorization"] = f"Bearer {token}"
    return c


# --- tokens -------------------------------------------------------------------------------------


def test_token_is_shown_once_and_stored_hashed(logged_client):
    token = make_token(logged_client)
    assert token.startswith("odlm_") and len(token) > 40
    with SessionLocal() as s:
        row = s.query(ApiToken).one()
        assert token not in (row.token_hash, row.prefix) and row.token_hash != token and token.startswith(row.prefix)
    page = logged_client.get("/tokens").text
    assert token not in page and row.prefix in page


def test_token_authentication_rules(logged_client):
    token = make_token(logged_client)
    with SessionLocal() as s:
        assert api_tokens.authenticate(s, token) is not None
        assert api_tokens.authenticate(s, token + "x") is None
        assert api_tokens.authenticate(s, "odlm_" + "a" * 43) is None
        assert api_tokens.authenticate(s, "not-a-token") is None
        assert api_tokens.authenticate(s, "odlm_" + "a" * 500) is None
        assert s.query(ApiToken).one().last_used_at is not None


def test_token_name_validation_and_revocation(logged_client):
    assert "e=token_name" in logged_client.post("/tokens", data={"name": "x"}).headers["location"]
    token = make_token(logged_client)
    with SessionLocal() as s:
        tid = s.query(ApiToken).one().id
    assert bearer(token).get("/api/v1/status").status_code == 200
    assert "n=token_revoked" in logged_client.post(f"/tokens/{tid}/delete").headers["location"]
    assert bearer(token).get("/api/v1/status").status_code == 401
    assert logged_client.post("/tokens/999/delete").status_code == 404


def test_only_administrators_manage_tokens(logged_client):
    logged_client.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    v = TestClient(__import__("app.main", fromlist=["app"]).app, follow_redirects=False)
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    assert v.get("/tokens").status_code == 403 and v.post("/tokens", data={"name": "evil"}).status_code == 403


# --- authentication of the API ---------------------------------------------------------------------


def test_api_requires_authentication_and_never_redirects(client):
    for path in ("/api/v1/status", "/api/v1/findings", "/api/v1/news", "/metrics"):
        r = client.get(path)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", path
    assert client.get("/api/v1/status", headers={"authorization": "Bearer odlm_nope"}).status_code == 401
    assert client.get("/api/v1/status", headers={"authorization": "Basic abc"}).status_code == 401


def test_session_users_including_viewers_can_read_exports(api):
    api.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    v = TestClient(__import__("app.main", fromlist=["app"]).app, follow_redirects=False)
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    assert v.get("/api/v1/findings").status_code == 200 and v.get("/metrics").status_code == 200


def test_token_cannot_write_anything(api):
    c = bearer(make_token(api))
    assert c.post("/domains", data={"name": "x.fr"}).status_code in (303, 401, 403)  # never a successful write
    with SessionLocal() as s:
        assert s.query(Domain).count() == 2


# --- findings and news exports ---------------------------------------------------------------------


def test_findings_json_and_filters(api):
    data = api.get("/api/v1/findings").json()
    assert data["count"] == 3 and {i["domain"] for i in data["items"]} == {"exemple.fr", "autre.fr"}
    assert api.get("/api/v1/findings?domain=EXEMPLE.fr").json()["count"] == 2
    assert api.get("/api/v1/findings?status=new").json()["count"] == 1
    assert api.get("/api/v1/findings?severity=critical").json()["items"][0]["identifier"] == "b@autre.fr"
    since = (datetime.now(timezone.utc) - timedelta(days=7)).date().isoformat()
    assert api.get(f"/api/v1/findings?since={since}").json()["count"] == 2
    assert api.get("/api/v1/findings?limit=1").json()["count"] == 1
    item = api.get("/api/v1/findings?status=new").json()["items"][0]
    assert item["data_classes"] == ["Passwords", "Emails"] and "password" not in str(item).lower().replace("passwords", "")


@pytest.mark.parametrize("query", ["status=weird", "severity=urgent", "since=yesterday", "format=xml"])
def test_invalid_parameters_are_422(api, query):
    assert api.get(f"/api/v1/findings?{query}").status_code == 422


def test_csv_export_and_formula_injection_guard(api):
    r = api.get("/api/v1/findings?format=csv")
    assert r.headers["content-type"].startswith("text/csv") and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0] == exports.FINDING_FIELDS and len(rows) == 4
    cells = [c for row in rows[1:] for c in row]
    assert all(not c.startswith(("=", "+", "-", "@")) for c in cells)  # neutralised
    assert any(c.startswith("'=HYPERLINK") for c in cells) and any(c.startswith("'+cmd") for c in cells)
    assert "Passwords;Emails" in cells


def test_cell_helper_rules():
    assert exports._cell(None) == "" and exports._cell(["a", "b"]) == "a;b" and exports._cell(5) == "5"
    for bad in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"):
        assert exports._cell(bad).startswith("'")
    assert exports._cell("normal") == "normal"


def test_news_export(api):
    data = api.get("/api/v1/news").json()
    assert data["count"] == 2 and data["items"][0]["title"] == "Fuite chez Ciblex"
    assert api.get("/api/v1/news?mentions=1").json()["count"] == 1
    assert api.get("/api/v1/news?format=csv").text.splitlines()[0] == ",".join(exports.NEWS_FIELDS)


def test_ui_export_buttons_are_present(api):
    assert "/api/v1/findings?domain=exemple.fr&amp;format=csv" in api.get("/domains/1").text or "/api/v1/findings?domain=exemple.fr&format=csv" in api.get("/domains/1").text
    assert "/api/v1/news?format=csv" in api.get("/news").text


# --- status and metrics ----------------------------------------------------------------------------


def test_status_endpoint(api):
    body = bearer(make_token(api)).get("/api/v1/status").json()
    assert body["version"] == "0.1.0" and body["domains"] == 2 and body["open_findings"] == 1 and body["last_scan"]


def test_prometheus_metrics_format_and_values(api):
    r = bearer(make_token(api)).get("/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = r.text
    assert 'opendlm_info{version="0.1.0"} 1' in text
    assert 'opendlm_domains{verified="true"} 2' in text and 'opendlm_domains{verified="false"} 0' in text
    assert 'opendlm_findings{status="new",severity="high"} 1' in text
    assert 'opendlm_findings{status="resolved",severity="critical"} 1' in text
    assert "opendlm_news_items 2" in text and 'opendlm_news_source_up{source="FrenchBreaches"} 1' in text
    assert 'opendlm_news_source_up{source="Flux \\"cassé\\""} 0' in text  # label escaping
    assert "opendlm_scanner_stale 0" in text and "opendlm_scan_failures_24h 0" in text
    # every sample line is "name{labels} value" with a numeric value; every metric has HELP and TYPE
    for line in text.strip().splitlines():
        if line.startswith("#"):
            continue
        assert float(line.rsplit(" ", 1)[1]) >= 0
    assert text.count("# HELP") == text.count("# TYPE") >= 8
    assert text.endswith("\n")
