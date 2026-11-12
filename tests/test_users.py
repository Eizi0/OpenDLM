import pytest

from app.db import SessionLocal
from app.models import Domain, User
from tests.conftest import STRONG

VIEWER_PW = "un-autre-mot-de-passe-123"


def make_user(logged_client, username="lea", password=VIEWER_PW, role="viewer"):
    r = logged_client.post("/users", data={"username": username, "password": password, "role": role})
    assert r.status_code == 303 and "n=user_created" in r.headers["location"], r.headers.get("location")


@pytest.fixture
def viewer(logged_client):
    """A second browser session signed in as a read-only viewer."""
    make_user(logged_client)
    from fastapi.testclient import TestClient
    from app import main

    c = TestClient(main.app, follow_redirects=False)
    assert c.post("/login", data={"username": "lea", "password": VIEWER_PW}).status_code == 303
    return c


def test_admin_creates_users_with_validation(logged_client):
    make_user(logged_client)
    assert "e=user_exists" in logged_client.post("/users", data={"username": "LEA", "password": VIEWER_PW, "role": "viewer"}).headers["location"]
    for bad in ({"username": "x", "password": VIEWER_PW, "role": "viewer"},
                {"username": "bob", "password": "short", "role": "viewer"},
                {"username": "bob", "password": VIEWER_PW, "role": "root"}):
        assert "e=user_invalid" in logged_client.post("/users", data=bad).headers["location"]
    with SessionLocal() as s:
        assert {u.username: u.role for u in s.query(User)} == {"admin": "admin", "lea": "viewer"}


def test_viewer_can_read_but_not_write(logged_client, viewer):
    with SessionLocal() as s:
        s.add(Domain(name="exemple.fr", verify_token="t", verified=True))
        s.commit()
    for path in ("/", "/news", "/reports", "/domains/1", "/profile"):
        assert viewer.get(path).status_code == 200, path
    for method, path, data in (("post", "/domains", {"name": "x.fr"}), ("post", "/domains/1/scan", {}),
                               ("post", "/watch-words", {"term": "Ciblex"}), ("post", "/reports/generate", {"kind": "daily"}),
                               ("post", "/findings/1/status", {"status": "ack"}), ("post", "/domains/1/delete", {"confirm": "exemple.fr"})):
        assert getattr(viewer, method)(path, data=data).status_code == 403, path
    with SessionLocal() as s:
        assert s.query(Domain).count() == 1


def test_viewer_cannot_open_admin_pages(viewer):
    for path in ("/users", "/sources", "/notifications"):
        assert viewer.get(path).status_code == 403, path
    assert viewer.post("/users", data={"username": "evil", "password": VIEWER_PW, "role": "admin"}).status_code == 403
    page = viewer.get("/").text
    assert 'href="/users"' not in page and 'href="/sources"' not in page and 'href="/profile"' in page


def test_viewer_cannot_promote_themselves(viewer):
    assert viewer.post("/users/2/role", data={"role": "admin"}).status_code == 403
    with SessionLocal() as s:
        assert s.query(User).filter_by(username="lea").one().role == "viewer"


def test_last_admin_is_protected(logged_client):
    assert "e=last_admin" in logged_client.post("/users/1/role", data={"role": "viewer"}).headers["location"]
    assert "e=own_account" in logged_client.post("/users/1/delete").headers["location"]
    make_user(logged_client, "second", role="admin")
    assert "n=user_updated" in logged_client.post("/users/1/role", data={"role": "viewer"}).headers["location"]  # now allowed: another admin exists


def test_cannot_delete_the_only_admin_from_another_admin_session(logged_client):
    make_user(logged_client, "second", role="admin")
    from fastapi.testclient import TestClient
    from app import main

    other = TestClient(main.app, follow_redirects=False)
    other.post("/login", data={"username": "second", "password": VIEWER_PW})
    assert "n=user_deleted" in other.post("/users/1/delete").headers["location"]       # admin removes the first admin
    assert "e=" in other.post("/users/2/delete").headers["location"]                    # but cannot remove themselves / the last admin


def test_password_reset_signs_the_user_out(logged_client, viewer):
    assert viewer.get("/").status_code == 200
    assert "n=user_updated" in logged_client.post("/users/2/password", data={"password": "nouveau-mot-de-passe-9"}).headers["location"]
    assert viewer.get("/").status_code == 303  # old session no longer valid
    assert "e=user_invalid" in logged_client.post("/users/2/password", data={"password": "court"}).headers["location"]


def test_delete_user_removes_access(logged_client, viewer):
    assert "n=user_deleted" in logged_client.post("/users/2/delete").headers["location"]
    assert viewer.get("/").status_code == 303
    assert logged_client.post("/users/999/delete").status_code == 404


def test_profile_password_change(viewer):
    r = viewer.post("/profile/password", data={"current": "faux", "password": "nouveau-mot-de-passe-9", "confirm": "nouveau-mot-de-passe-9"})
    assert "e=password_wrong" in r.headers["location"]
    r = viewer.post("/profile/password", data={"current": VIEWER_PW, "password": "nouveau-mot-de-passe-9", "confirm": "autre"})
    assert "e=password_mismatch" in r.headers["location"]
    r = viewer.post("/profile/password", data={"current": VIEWER_PW, "password": "court", "confirm": "court"})
    assert "e=user_invalid" in r.headers["location"]
    r = viewer.post("/profile/password", data={"current": VIEWER_PW, "password": "nouveau-mot-de-passe-9", "confirm": "nouveau-mot-de-passe-9"})
    assert "n=password_changed" in r.headers["location"]
    assert viewer.get("/profile").status_code == 200  # still signed in on this browser
    viewer.cookies.clear()
    assert viewer.post("/login", data={"username": "lea", "password": "nouveau-mot-de-passe-9"}).status_code == 303


def test_pages_render_for_admin(logged_client):
    make_user(logged_client)
    page = logged_client.get("/users")
    assert page.status_code == 200 and "lea" in page.text and "Reset password" in page.text
    assert "My profile" in logged_client.get("/profile").text
