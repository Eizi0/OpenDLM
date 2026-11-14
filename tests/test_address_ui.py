import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import SessionLocal
from app.models import Domain, MonitoredAddress
from app.runtime_config import cfg


def add_domain(verified=True):
    with SessionLocal() as s:
        d = Domain(name="exemple.fr", verify_token="t", verified=verified)
        s.add(d)
        s.commit()
        return d.id


def addresses():
    with SessionLocal() as s:
        return sorted(a.address for a in s.query(MonitoredAddress))


def test_add_and_remove_addresses(logged_client):
    did = add_domain()
    r = logged_client.post(f"/domains/{did}/addresses", data={"addresses": "Direction@Exemple.fr\ncompta@exemple.fr, rh@exemple.fr"})
    assert r.status_code == 303 and "n=addresses_saved" in r.headers["location"] and "e=" not in r.headers["location"]
    assert addresses() == ["compta@exemple.fr", "direction@exemple.fr", "rh@exemple.fr"]
    page = logged_client.get(f"/domains/{did}").text
    assert "Monitored addresses" in page and "direction@exemple.fr" in page and "3 of 500" in page
    r = logged_client.post(f"/domains/{did}/addresses", data={"addresses": "direction@exemple.fr evil@autre.fr"})  # duplicate + foreign
    assert "e=addresses_invalid" in r.headers["location"] and len(addresses()) == 3
    with SessionLocal() as s:
        aid = s.query(MonitoredAddress).filter_by(address="rh@exemple.fr").one().id
    assert logged_client.post(f"/domains/{did}/addresses/{aid}/delete").status_code == 303
    assert "rh@exemple.fr" not in addresses()
    assert logged_client.post(f"/domains/{did}/addresses/{aid}/delete").status_code == 404


def test_address_limit_and_cascade(logged_client, monkeypatch):
    from app.web import dashboard

    monkeypatch.setattr(dashboard, "MAX_ADDRESSES", 3)
    did = add_domain()
    r = logged_client.post(f"/domains/{did}/addresses", data={"addresses": "a@exemple.fr b@exemple.fr c@exemple.fr d@exemple.fr e@exemple.fr"})
    assert "e=addresses_limit" in r.headers["location"] and len(addresses()) == 3
    logged_client.post(f"/domains/{did}/delete", data={"confirm": "exemple.fr"})
    assert addresses() == []  # deleted with the domain


def test_address_routes_ignore_other_domains_ids(logged_client):
    did = add_domain()
    logged_client.post(f"/domains/{did}/addresses", data={"addresses": "a@exemple.fr"})
    with SessionLocal() as s:
        aid = s.query(MonitoredAddress).one().id
    assert logged_client.post(f"/domains/999/addresses/{aid}/delete").status_code == 404
    assert addresses() == ["a@exemple.fr"]


def test_viewer_cannot_edit_addresses(logged_client):
    did = add_domain()
    logged_client.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    from app import main

    v = TestClient(main.app, follow_redirects=False)
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    assert v.post(f"/domains/{did}/addresses", data={"addresses": "a@exemple.fr"}).status_code == 403
    assert v.get(f"/domains/{did}").status_code == 200 and addresses() == []


def test_toggle_per_address_sources_and_attribution(logged_client):
    assert "Powered by LeakCheck" not in logged_client.get("/").text
    assert "n=saved" in logged_client.post("/connectors/leakcheck/toggle").headers["location"]
    assert cfg.leakcheck_enabled is True
    assert "Powered by LeakCheck" in logged_client.get("/").text  # attribution required by LeakCheck while it is on
    logged_client.post("/connectors/xposedornot/toggle")
    assert cfg.xposedornot_enabled is True
    logged_client.post("/connectors/leakcheck/toggle")
    assert cfg.leakcheck_enabled is False and cfg.source("leakcheck_enabled") == "ui"
    assert logged_client.post("/connectors/hibp/toggle").status_code == 404  # keyed connectors are not toggled


def test_sources_page_shows_a_guide_with_links_for_every_connector(logged_client):
    page = logged_client.get("/sources").text
    for name in ("Have I Been Pwned", "Hudson Rock", "LeakCheck", "XposedOrNot", "ransomware.live"):
        assert name in page
    for link in ("https://www.hudsonrock.com/free-api-key", "https://haveibeenpwned.com/API/Key", "https://my.ransomware.live",
                 "https://leakcheck.io", "https://xposedornot.com", "https://docs.leakcheck.io/public-api/lookup"):
        assert f'href="{link}"' in page, link
    assert page.count("<details") >= 5 and "Guide" in page and "Get access" in page
    assert 'rel="noopener noreferrer"' in page
    # privacy of each address source is stated before switching on
    assert "truncated SHA-256 hash" in page and "sent in clear" in page


def test_sources_guide_in_french(logged_client):
    logged_client.get("/lang/fr")
    page = logged_client.get("/sources").text
    assert "Obtenir l&#39;accès" in page or "Obtenir l'accès" in page
    assert "hachage SHA-256 tronqué" in page and "Confidentialité" in page


def test_manual_scan_works_with_only_an_address_source(logged_client, cfg_override, monkeypatch):
    monkeypatch.setattr(settings, "demo", False)
    cfg_override(hibp_api_key="", hudson_rock_key="", leakcheck_enabled=True)
    did = add_domain()
    logged_client.post(f"/domains/{did}/addresses", data={"addresses": "a@exemple.fr"})
    called = []
    from app.connectors import leakcheck

    monkeypatch.setattr(leakcheck.LeakCheckConnector, "check_address", lambda self, a: called.append(a) or [])
    from app import scan_jobs

    assert logged_client.post(f"/domains/{did}/scan").status_code == 303
    scan_jobs.wait(did)
    assert called == ["a@exemple.fr"]
    assert "Switch one on" not in logged_client.get(f"/domains/{did}").text
