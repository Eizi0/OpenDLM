import threading

from app import scan_jobs


def test_second_scan_of_same_domain_is_refused_while_running():
    release = threading.Event()
    assert scan_jobs.start(901, release.wait)
    assert scan_jobs.running_since(901) is not None
    assert not scan_jobs.start(901, lambda: None)  # manual click while running
    try:
        scan_jobs.run_locked(901, lambda: None, wait=False)
        raise AssertionError("expected Busy")
    except scan_jobs.Busy:
        pass
    release.set()
    scan_jobs.wait(901)
    assert scan_jobs.running_since(901) is None
    assert scan_jobs.start(902, lambda: None)  # other domains are independent
    scan_jobs.wait(902)


def test_scheduled_scan_waits_for_the_manual_one():
    order = []
    release = threading.Event()
    scan_jobs.start(903, lambda: (release.wait(), order.append("manual")))
    t = threading.Thread(target=lambda: scan_jobs.run_locked(903, lambda: order.append("scheduled")))
    t.start()
    release.set()
    t.join(5)
    assert order == ["manual", "scheduled"]


def test_failure_in_background_releases_the_lock():
    def boom():
        raise RuntimeError("source down")
    assert scan_jobs.start(904, boom)
    scan_jobs.wait(904)
    assert scan_jobs.start(904, lambda: None)
    scan_jobs.wait(904)


def test_manual_scan_page_flow(logged_client, monkeypatch):
    import app.web.dashboard as dash
    from app.connectors.demo import DemoConnector
    from app.db import SessionLocal
    from app.models import Domain, Finding

    with SessionLocal() as s:
        s.add(Domain(name="exemple.fr", verify_token="x", verified=True))
        s.commit()
    monkeypatch.setattr(dash, "build_connectors", lambda: [DemoConnector()])
    r = logged_client.post("/domains/1/scan")
    assert r.status_code == 303 and "n=scan_started" in r.headers["location"]
    scan_jobs.wait(1)
    with SessionLocal() as s:
        assert s.query(Finding).count() > 0
    page = logged_client.get("/domains/1?n=scan_started").text
    assert "Scan started" in page and 'http-equiv="refresh"' not in page
