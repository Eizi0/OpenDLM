from app.db import SessionLocal
from app.models import AuditEvent
from tests.conftest import STRONG


def events():
    with SessionLocal() as s:
        return [(e.username, e.action, e.outcome, e.params) for e in s.query(AuditEvent).order_by(AuditEvent.id)]


def test_setup_and_changes_are_recorded_without_form_content(logged_client):
    logged_client.post("/domains", data={"name": "exemple.fr"})
    logged_client.post("/connectors/hibp/key", data={"api_key": "super-secret-key-123"})
    rows = events()
    assert ("admin", "/setup", "ok", {}) in rows
    assert ("admin", "/domains", "ok", {}) in rows
    assert ("admin", "/connectors/{connector_id}/key", "ok", {"connector_id": "hibp"}) in rows
    with SessionLocal() as s:
        dump = repr([(e.params, e.action) for e in s.query(AuditEvent)])
    assert "super-secret-key-123" not in dump


def test_refused_change_is_marked_refused(logged_client):
    logged_client.post("/domains", data={"name": "not a domain"})
    assert events()[-1][1:3] == ("/domains", "refused")
    logged_client.post("/users/999/delete")
    assert events()[-1][1:3] == ("/users/{user_id}/delete", "refused")


def test_sign_in_events(client):
    client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    client.post("/logout")
    client.post("/login", data={"username": "admin", "password": "wrong-password-123"})
    client.post("/login", data={"username": "admin", "password": STRONG})
    rows = [r[:3] for r in events()]
    assert rows[-3:] == [("admin", "/logout", "ok"), ("admin", "/login", "refused"), ("admin", "/login", "ok")]


def test_audit_page_admin_only_and_translated(logged_client):
    logged_client.post("/domains", data={"name": "exemple.fr"})
    page = logged_client.get("/audit")
    assert page.status_code == 200 and "Domain added" in page.text
    assert "Domain added" in logged_client.get("/audit?outcome=ok&user=admin").text
    assert "Domain added" not in logged_client.get("/audit?outcome=failed").text
    logged_client.post("/users", data={"username": "lecteur", "password": STRONG, "role": "viewer"})
    logged_client.post("/logout")
    logged_client.post("/login", data={"username": "lecteur", "password": STRONG})
    assert logged_client.get("/audit").status_code == 403
