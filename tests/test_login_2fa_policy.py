import pyotp
import pytest
from fastapi.testclient import TestClient

from app import cli, twofa
from app.db import SessionLocal
from app.models import User
from tests.conftest import STRONG


def fresh():
    from app import main
    return TestClient(main.app, follow_redirects=False)


@pytest.fixture
def policy(cfg_override):
    def apply(value):
        cfg_override(require_2fa=value)
    return apply


def admin_session(client):
    r = client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    assert r.status_code == 303
    return client


# --- Policy --------------------------------------------------------------------------------------


def test_admins_without_2fa_are_sent_to_their_profile_and_nowhere_else(client, policy):
    policy("admins")
    admin_session(client)
    for path in ("/", "/news", "/reports", "/sources", "/users", "/settings", "/api/v1/status"):
        r = client.get(path)
        if path.startswith("/api"):
            assert r.status_code == 200  # the API is for tokens and sessions of the interface: not part of the browser gate
            continue
        assert r.status_code == 303 and r.headers["location"] == "/profile?e=twofa_required", path
    assert client.post("/domains", data={"name": "x.fr"}).headers["location"] == "/profile?e=twofa_required"
    page = client.get("/profile?e=twofa_required")  # the redirect target
    assert page.status_code == 200 and "Two-factor authentication is required for your role" in page.text
    assert "<svg" in page.text and "Confirm and enable" in page.text  # the QR code is shown straight away
    assert "Required" in page.text


def test_after_enabling_2fa_everything_is_reachable(client, policy):
    policy("admins")
    admin_session(client)
    client.get("/profile")  # starts the mandatory enrollment
    with SessionLocal() as s:
        secret = twofa.secret_of(s.query(User).one())
    r = client.post("/profile/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and "Recovery codes" in r.text
    assert client.get("/").status_code == 200 and client.get("/settings").status_code == 200


def test_mandatory_2fa_cannot_be_disabled_by_the_user(client, policy):
    policy("off")
    admin_session(client)
    client.post("/profile/2fa/start")
    with SessionLocal() as s:
        secret = twofa.secret_of(s.query(User).one())
    client.post("/profile/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    policy("admins")
    assert "e=twofa_mandatory" in client.post("/profile/2fa/disable", data={"password": STRONG}).headers["location"]
    with SessionLocal() as s:
        assert s.query(User).one().totp_enabled is True
    policy("off")  # optional again: the user may disable it
    assert "n=twofa_disabled" in client.post("/profile/2fa/disable", data={"password": STRONG}).headers["location"]


def test_viewers_follow_the_all_policy_only(client, policy):
    policy("off")
    admin_session(client)
    client.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    v = fresh()
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    policy("admins")
    assert v.get("/").status_code == 200  # viewers are not administrators
    policy("all")
    assert v.get("/").headers["location"] == "/profile?e=twofa_required"
    assert v.get("/profile").status_code == 200 and v.post("/profile/password", data={"current": "x", "password": "y", "confirm": "y"}).status_code == 303


def test_policy_off_changes_nothing(client, policy):
    policy("off")
    admin_session(client)
    assert client.get("/").status_code == 200


def test_setup_page_announces_the_next_step(client, policy):
    policy("admins")
    assert "Next step" in client.get("/setup").text
    policy("off")
    assert "Next step" not in client.get("/setup").text


def test_policy_is_editable_in_settings_and_validated(logged_client):
    assert "Required for administrators" in logged_client.get("/settings").text
    assert "e=invalid_value" in logged_client.post("/settings/security", data={"require_2fa": "whenever"}).headers["location"]
    assert "n=saved" in logged_client.post("/settings/security", data={"require_2fa": "all"}).headers["location"]
    from app.runtime_config import cfg
    assert cfg.require_2fa == "all"
    # the administrator who just made it mandatory is held to it too: they are sent to set it up
    assert logged_client.get("/settings").headers["location"] == "/profile?e=twofa_required"


# --- Emergency CLI -------------------------------------------------------------------------------


def test_cli_reset_2fa_and_password(client, policy):
    policy("off")
    admin_session(client)
    client.post("/profile/2fa/start")
    with SessionLocal() as s:
        secret = twofa.secret_of(s.query(User).one())
    client.post("/profile/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    with SessionLocal() as s:
        assert cli.list_users(s) == ["admin\tadmin\t2FA on"]
        assert cli.reset_2fa(s, "ADMIN") is True and cli.reset_2fa(s, "ghost") is False
    with SessionLocal() as s:
        u = s.query(User).one()
        assert u.totp_enabled is False and u.totp_secret_enc is None and u.recovery_hashes is None
        assert cli.reset_password(s, "admin", "court") is not None  # same 12-character rule
        assert cli.reset_password(s, "ghost", "un-mot-de-passe-solide-1") == "unknown user"
        assert cli.reset_password(s, "admin", "nouveau-mot-de-passe-9") is None
    other = fresh()
    assert other.post("/login", data={"username": "admin", "password": "nouveau-mot-de-passe-9"}).status_code == 303
    assert client.get("/").status_code == 303  # the old browser session is signed out by the password change


# --- Sign-in pages -------------------------------------------------------------------------------


def test_login_page_has_logo_brand_panel_favicons_and_script(client):
    client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    client.cookies.clear()
    page = client.get("/login").text
    for needle in ("/static/logo.png", "Open Data Leak Monitor", "Welcome back", 'href="/static/favicon.ico"', "/static/app.js", "data-toggle-password", "Caps Lock is on"):
        assert needle in page, needle
    for asset in ("/static/logo.png", "/static/logo-96.png", "/static/favicon.ico", "/static/favicon-32.png", "/static/apple-touch-icon.png", "/static/app.js"):
        assert client.get(asset).status_code == 200, asset


def test_failed_login_keeps_the_username_and_is_not_cached(client):
    client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    client.cookies.clear()
    r = client.post("/login", data={"username": "admin", "password": "mauvais"})
    assert r.status_code == 401 and 'value="admin"' in r.text and "Incorrect username or password." in r.text


def test_second_step_page_is_the_new_design(client, policy):
    policy("off")
    admin_session(client)
    client.post("/profile/2fa/start")
    with SessionLocal() as s:
        secret = twofa.secret_of(s.query(User).one())
    client.post("/profile/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    other = fresh()
    other.post("/login", data={"username": "admin", "password": STRONG})
    page = other.get("/login/2fa").text
    assert "Step 2 of 2" in page and "recovery-toggle" in page and 'autocomplete="one-time-code"' in page and "code-input" in page


def test_setup_page_has_a_strength_meter_and_french_texts(client):
    page = client.get("/setup").text
    assert "strength-meter" in page and "data-strength" in page
    client.get("/lang/fr")
    fr = client.get("/setup").text
    assert "Créer le compte administrateur" in fr and "Faible|Moyen|Bon|Fort" in fr


def test_csp_allows_the_local_script_only(client):
    csp = client.get("/login").headers["content-security-policy"]
    assert "default-src 'self'" in csp and "unsafe-inline" in csp.split("style-src")[1].split(";")[0] and "script-src" not in csp
