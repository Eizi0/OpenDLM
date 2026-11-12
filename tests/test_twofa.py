import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import twofa
from app.db import SessionLocal
from app.models import User
from tests.conftest import STRONG


def fresh_client():
    from app import main
    return TestClient(main.app, follow_redirects=False)


def enable_2fa(client):
    """Run the real enrollment flow; returns (secret, recovery_codes)."""
    client.post("/profile/2fa/start")
    with SessionLocal() as s:
        secret = twofa.secret_of(s.query(User).filter_by(username="admin").one())
    r = client.post("/profile/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and "Recovery codes" in r.text
    codes = [line.strip() for line in r.text.split("class=\"mono\"")[1:] and r.text.split('<div class="mono"') if "-" in line and len(line.split(">")[1].split("<")[0]) == 11]
    codes = [c.split(">")[1].split("<")[0] for c in codes]
    assert len(codes) == 10 and r.headers["cache-control"] == "no-store"
    return secret, codes


def login_with_password(c):
    return c.post("/login", data={"username": "admin", "password": STRONG})


@pytest.fixture
def enrolled(logged_client):
    secret, codes = enable_2fa(logged_client)
    return secret, codes


def test_enrollment_shows_qr_and_stores_secret_encrypted(logged_client):
    logged_client.post("/profile/2fa/start")
    page = logged_client.get("/profile").text
    assert "<svg" in page and "Confirm and enable" in page
    with SessionLocal() as s:
        u = s.query(User).filter_by(username="admin").one()
        secret = twofa.secret_of(u)
        assert secret and secret not in u.totp_secret_enc and u.totp_enabled is False
    assert secret in page  # shown to its owner during enrollment only
    assert "e=twofa_bad_code" in logged_client.post("/profile/2fa/enable", data={"code": "000000"}).headers["location"]
    with SessionLocal() as s:
        assert s.query(User).one().totp_enabled is False


def test_login_requires_the_second_factor(enrolled):
    secret, _ = enrolled
    c = fresh_client()
    r = login_with_password(c)
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"
    assert "opendlm_session" not in c.cookies  # no session before the code
    assert c.get("/").status_code == 303 and c.get("/").headers["location"] == "/login"
    assert c.get("/login/2fa").status_code == 200
    # TOTP window: use the next step so the enrollment code (already consumed) is not reused
    code = pyotp.TOTP(secret).at(time.time() + 30)
    ok = c.post("/login/2fa", data={"code": code})
    assert ok.status_code == 303 and ok.headers["location"] == "/" and c.get("/").status_code == 200


def test_wrong_code_is_refused_and_throttled(enrolled):
    c = fresh_client()
    login_with_password(c)
    codes = [c.post("/login/2fa", data={"code": "123456"}).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert "opendlm_session" not in c.cookies


def test_replayed_code_is_refused(enrolled):
    secret, _ = enrolled
    code = pyotp.TOTP(secret).at(time.time() + 30)
    a = fresh_client()
    login_with_password(a)
    assert a.post("/login/2fa", data={"code": code}).status_code == 303
    b = fresh_client()
    login_with_password(b)
    assert b.post("/login/2fa", data={"code": code}).status_code == 401  # same time step: replay


def test_recovery_code_works_once(enrolled):
    _, codes = enrolled
    a = fresh_client()
    login_with_password(a)
    assert a.post("/login/2fa", data={"code": codes[0].upper()}).status_code == 303  # case-insensitive
    b = fresh_client()
    login_with_password(b)
    assert b.post("/login/2fa", data={"code": codes[0]}).status_code == 401  # already consumed
    c = fresh_client()
    login_with_password(c)
    assert c.post("/login/2fa", data={"code": codes[1]}).status_code == 303
    with SessionLocal() as s:
        assert len(s.query(User).one().recovery_hashes) == 8
        assert codes[1] not in str(s.query(User).one().recovery_hashes)  # only hashes are stored


def test_pending_token_is_bound_and_expires(enrolled, monkeypatch):
    c = fresh_client()
    c.cookies.set("opendlm_2fa", "forged")
    assert c.get("/login/2fa").headers["location"] == "/login"
    assert c.post("/login/2fa", data={"code": "123456"}).headers["location"] == "/login"
    c.cookies.clear()
    login_with_password(c)
    token = c.cookies.get("opendlm_2fa")
    monkeypatch.setattr(twofa, "PENDING_MAX_AGE", -1)
    with SessionLocal() as s:
        assert twofa.user_from_pending(s, token) is None  # expired
    monkeypatch.setattr(twofa, "PENDING_MAX_AGE", 300)
    with SessionLocal() as s:
        u = s.query(User).one()
        u.password_hash = "x" * 10  # password changed after the first step: token no longer valid
        s.commit()
        assert twofa.user_from_pending(s, token) is None


def test_disable_requires_password_and_clears_everything(enrolled):
    c = fresh_client()
    login_with_password(c)
    _, codes = enrolled
    c.post("/login/2fa", data={"code": codes[0]})
    assert "e=password_wrong" in c.post("/profile/2fa/disable", data={"password": "nope"}).headers["location"]
    assert "n=twofa_disabled" in c.post("/profile/2fa/disable", data={"password": STRONG}).headers["location"]
    with SessionLocal() as s:
        u = s.query(User).one()
        assert u.totp_enabled is False and u.totp_secret_enc is None and u.recovery_hashes is None
    assert login_with_password(fresh_client()).headers["location"] == "/"  # plain login again


def test_regenerate_recovery_codes_invalidates_old_ones(enrolled, logged_client):
    _, codes = enrolled
    assert "e=password_wrong" in logged_client.post("/profile/2fa/recovery", data={"password": "nope"}).headers["location"]
    r = logged_client.post("/profile/2fa/recovery", data={"password": STRONG})
    assert r.status_code == 200 and "Recovery codes" in r.text
    c = fresh_client()
    login_with_password(c)
    assert c.post("/login/2fa", data={"code": codes[0]}).status_code == 401


def test_admin_can_reset_a_locked_out_users_2fa(enrolled, logged_client):
    logged_client.post("/users", data={"username": "second", "password": "un-autre-mot-de-passe-123", "role": "admin"})
    with SessionLocal() as s:
        u = s.query(User).filter_by(username="admin").one()
    other = fresh_client()
    other.post("/login", data={"username": "second", "password": "un-autre-mot-de-passe-123"})
    assert "n=twofa_reset" in other.post(f"/users/{u.id}/2fa/reset").headers["location"]
    assert login_with_password(fresh_client()).headers["location"] == "/"
    # a viewer cannot do this
    logged_client.post("/users", data={"username": "lea", "password": "un-autre-mot-de-passe-123", "role": "viewer"})
    v = fresh_client()
    v.post("/login", data={"username": "lea", "password": "un-autre-mot-de-passe-123"})
    assert v.post(f"/users/{u.id}/2fa/reset").status_code == 403


def test_users_page_shows_2fa_state(enrolled, logged_client):
    assert "Reset 2FA" in logged_client.get("/users").text


def test_totp_unit_rules():
    secret = twofa.new_secret()
    u = User(username="x", password_hash="h", totp_secret_enc=twofa.crypto.encrypt(secret))
    t0 = 1_800_000_000
    code = pyotp.TOTP(secret).at(t0)
    assert twofa.verify_code(u, code, now=t0) is True
    assert twofa.verify_code(u, code, now=t0) is False  # replay
    assert twofa.verify_code(u, pyotp.TOTP(secret).at(t0 + 30), now=t0 + 30) is True  # next step
    assert twofa.verify_code(u, pyotp.TOTP(secret).at(t0 - 30), now=t0 + 31) is False  # older than the last accepted step
    assert twofa.verify_code(u, "abcdef", now=t0) is False and twofa.verify_code(u, "12345", now=t0) is False
    assert twofa.verify_code(User(username="y", password_hash="h"), "123456") is False  # no secret
