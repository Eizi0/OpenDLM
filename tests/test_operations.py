from datetime import datetime, timedelta, timezone

from app.config import settings
from app.db import SessionLocal
from app.models import Domain, Finding, ScanRun


def add_domain(verified=True, name="exemple.fr"):
    with SessionLocal() as s:
        d = Domain(name=name, verify_token="t", verified=verified)
        s.add(d)
        s.commit()
        return d.id


def add_finding(domain_id, status="new"):
    with SessionLocal() as s:
        f = Finding(domain_id=domain_id, identifier="a@exemple.fr", source="HIBP", breach="B", severity="high", status=status,
                    first_seen=datetime.now(timezone.utc), data_classes=[])
        s.add(f)
        s.commit()
        return f.id


def status_of(fid):
    with SessionLocal() as s:
        return s.get(Finding, fid).status


def test_finding_status_lifecycle(logged_client):
    did = add_domain()
    fid = add_finding(did)
    for new_status in ("ack", "resolved", "new"):
        assert logged_client.post(f"/findings/{fid}/status", data={"status": new_status}).status_code == 303
        assert status_of(fid) == new_status
    assert logged_client.post(f"/findings/{fid}/status", data={"status": "known"}).status_code == 422  # « known » est réservé à la base de référence
    assert logged_client.post(f"/findings/{fid}/ack").status_code == 303 and status_of(fid) == "ack"
    assert logged_client.post("/findings/999/status", data={"status": "ack"}).status_code == 404


def test_domain_page_shows_actions_per_status(logged_client):
    did = add_domain()
    add_finding(did, "resolved")
    page = logged_client.get(f"/domains/{did}").text
    assert "Traitée" in page and "Rouvrir" in page and "Supprimer ce domaine" in page


def test_domain_deletion_requires_exact_name_and_cascades(logged_client):
    did = add_domain()
    add_finding(did)
    with SessionLocal() as s:
        s.add(ScanRun(domain_id=did, source="Démo", ok=True))
        s.commit()
    assert logged_client.post(f"/domains/{did}/delete", data={"confirm": "autre.fr"}).status_code == 422
    assert logged_client.post(f"/domains/{did}/delete", data={}).status_code == 422
    with SessionLocal() as s:
        assert s.get(Domain, did) is not None
    assert logged_client.post(f"/domains/{did}/delete", data={"confirm": " EXEMPLE.fr "}).status_code == 303
    with SessionLocal() as s:
        assert s.get(Domain, did) is None
        assert s.query(Finding).count() == 0 and s.query(ScanRun).count() == 0  # suppression en cascade


def test_dashboard_heartbeat_and_stale_warning(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "demo", True)  # un connecteur actif : le scanner « devrait » tourner
    did = add_domain()
    page = logged_client.get("/").text
    assert page.count('<span class="none"') == 60 and "Le scanner semble à l’arrêt" in page  # jamais scanné
    with SessionLocal() as s:
        s.add(ScanRun(domain_id=did, source="Démo", ok=True, new_count=1, started_at=datetime.now(timezone.utc)))
        s.commit()
    page = logged_client.get("/").text
    assert 'class="bad"' in page and "Le scanner semble à l’arrêt" not in page
    with SessionLocal() as s:
        s.query(ScanRun).update({"started_at": datetime.now(timezone.utc) - timedelta(hours=40)})
        s.commit()
    assert "Le scanner semble à l’arrêt" in logged_client.get("/").text


def test_no_stale_warning_without_connector_or_unverified_domain(logged_client, monkeypatch, cfg_override):
    monkeypatch.setattr(settings, "demo", False)
    cfg_override(hibp_api_key="")
    cfg_override(hudson_rock_key="")
    add_domain()
    assert "Le scanner semble à l’arrêt" not in logged_client.get("/").text
    monkeypatch.setattr(settings, "demo", True)
    with SessionLocal() as s:
        s.query(Domain).update({"verified": False})
        s.commit()
    assert "Le scanner semble à l’arrêt" not in logged_client.get("/").text


def test_notifications_page_never_shows_secrets(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "notify_urls", "discord://123456/SECRET-TOKEN-ABC,ntfys://user:pass@ntfy.exemple.fr/sujet")
    page = logged_client.get("/notifications").text
    assert "discord://…" in page and "ntfys://…" in page
    for secret in ("SECRET-TOKEN-ABC", "123456", "user:pass", "ntfy.exemple.fr"):
        assert secret not in page


def test_notifications_test_without_channel_and_with_channel(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "notify_urls", "")
    r = logged_client.post("/notifications/test")
    assert "error=" in r.headers["location"]
    from app import main
    sent = []
    monkeypatch.setattr(settings, "notify_urls", "json://exemple")
    monkeypatch.setattr(main.Notifier, "send", lambda self, t, b, markdown=False: sent.append(t) or True)
    r = logged_client.post("/notifications/test")
    assert "notice=" in r.headers["location"] and sent == ["[OpenDLM] Message de test"]
