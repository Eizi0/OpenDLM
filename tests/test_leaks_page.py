from app.db import SessionLocal
from app.models import Domain, Finding


def _seed():
    with SessionLocal() as s:
        a = Domain(name="alpha.fr", verify_token="x", verified=True)
        b = Domain(name="beta.fr", verify_token="y", verified=True)
        s.add_all([a, b])
        s.flush()
        s.add_all([
            Finding(domain_id=a.id, identifier="rh@alpha.fr", source="Demo", breach="Forum", data_classes=["Passwords"], severity="high", status="new"),
            Finding(domain_id=a.id, identifier="old@alpha.fr", source="Demo", breach="Old", data_classes=[], severity="low", status="known"),
            Finding(domain_id=b.id, identifier="ceo@beta.fr", source="Demo", breach="Stealer", data_classes=["Session cookies"], severity="critical", status="ack"),
        ])
        s.commit()
        return a.id, b.id


def test_lists_every_domain_most_urgent_first(logged_client):
    _seed()
    page = logged_client.get("/leaks").text
    assert "rh@alpha.fr" in page and "ceo@beta.fr" in page and "old@alpha.fr" in page
    assert page.index("rh@alpha.fr") < page.index("ceo@beta.fr") < page.index("old@alpha.fr")
    assert "beta.fr</a>" in page


def test_filters(logged_client):
    a, b = _seed()
    assert "ceo@beta.fr" not in logged_client.get(f"/leaks?domain={a}").text
    open_page = logged_client.get("/leaks?status=open").text
    assert "rh@alpha.fr" in open_page and "ceo@beta.fr" in open_page and "old@alpha.fr" not in open_page
    assert "rh@alpha.fr" not in logged_client.get("/leaks?severity=critical").text
    found = logged_client.get("/leaks?q=CEO").text
    assert "ceo@beta.fr" in found and "rh@alpha.fr" not in found
    assert "No leak matches" in logged_client.get("/leaks?q=nobody").text
    assert logged_client.get("/leaks?q=%25").status_code == 200  # wildcard characters are neutralised


def test_status_change_returns_to_the_filtered_list_only(logged_client):
    _seed()
    r = logged_client.post("/findings/1/status", data={"status": "ack", "back": "/leaks?status=new&page=1"})
    assert r.headers["location"].startswith("/leaks?status=new")
    r = logged_client.post("/findings/1/status", data={"status": "resolved", "back": "https://evil.example/"})
    assert r.headers["location"] == "/domains/1"
    r = logged_client.post("/findings/1/status", data={"status": "new", "back": "/leaks//evil.example"})
    assert r.headers["location"] == "/domains/1"
