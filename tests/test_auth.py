import pytest

from app.security import LoginThrottle, hash_password, verify_password
from tests.conftest import STRONG


def test_password_hash_roundtrip_and_salt():
    h1, h2 = hash_password("abc"), hash_password("abc")
    assert h1 != h2 and verify_password("abc", h1) and not verify_password("abd", h1)
    assert not verify_password("abc", "texte-qui-n-est-pas-un-hash")


def test_throttle_blocks_then_releases():
    now = [0.0]
    t = LoginThrottle(max_failures=3, window=60, clock=lambda: now[0])
    for _ in range(3):
        assert t.retry_after("ip") == 0
        t.fail("ip")
    assert 0 < t.retry_after("ip") <= 60
    now[0] = 61
    assert t.retry_after("ip") == 0


@pytest.mark.parametrize("path", ["/", "/domains/1"])
def test_protected_pages_redirect_to_setup_when_no_user(client, path):
    r = client.get(path)
    assert r.status_code == 303 and r.headers["location"] == "/setup"


def test_setup_creates_admin_once_and_closes(client):
    assert client.get("/setup").status_code == 200
    short = client.post("/setup", data={"username": "admin", "password": "court", "confirm": "court"})
    assert short.status_code == 422 and "12 caractères" in short.text
    mismatch = client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG + "x"})
    assert mismatch.status_code == 422
    ok = client.post("/setup", data={"username": "Admin", "password": STRONG, "confirm": STRONG})
    assert ok.status_code == 303 and "opendlm_session" in ok.headers["set-cookie"]
    assert "httponly" in ok.headers["set-cookie"].lower() and "samesite=lax" in ok.headers["set-cookie"].lower()
    # Le compte existe : la page disparaît et ne permet plus de créer un second administrateur.
    assert client.get("/setup").headers["location"] == "/login"
    assert client.post("/setup", data={"username": "pirate", "password": STRONG, "confirm": STRONG}).status_code == 403


def test_login_logout_flow(logged_client):
    c = logged_client
    assert c.get("/").status_code == 200
    c.post("/logout")
    c.cookies.clear()
    assert c.get("/").headers["location"] == "/login"
    assert c.post("/login", data={"username": "admin", "password": "mauvais"}).status_code == 401
    ok = c.post("/login", data={"username": "ADMIN", "password": STRONG})
    assert ok.status_code == 303
    assert c.get("/").status_code == 200


def test_login_is_throttled(client):
    client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    client.cookies.clear()
    codes = [client.post("/login", data={"username": "admin", "password": "x"}).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    # Même le bon mot de passe est refusé pendant le blocage.
    assert client.post("/login", data={"username": "admin", "password": STRONG}).status_code == 429


def test_tampered_or_foreign_cookie_is_rejected(logged_client):
    c = logged_client
    c.cookies.set("opendlm_session", "pas-un-vrai-jeton")
    assert c.get("/").headers["location"] == "/login"


def test_cross_site_post_is_refused(logged_client):
    r = logged_client.post("/domains", data={"name": "x.fr"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_security_headers_and_open_endpoints(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/app.css").status_code == 200
