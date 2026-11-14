from datetime import timedelta

from app import retention
from app.models import AuditEvent, Domain, Report, ScanRun, utcnow


def test_purge_keeps_baseline_marker_and_recent_rows(session, cfg_override):
    cfg_override(history_retention_days=30, audit_retention_days=30)
    d = Domain(name="exemple.fr", verify_token="x", verified=True)
    session.add(d)
    session.commit()
    old, recent = utcnow() - timedelta(days=100), utcnow() - timedelta(days=2)
    session.add_all([
        ScanRun(domain_id=d.id, source="HIBP", started_at=old, ok=True),          # older success
        ScanRun(domain_id=d.id, source="HIBP", started_at=old + timedelta(days=1), ok=True),  # last success: kept
        ScanRun(domain_id=d.id, source="HIBP", started_at=old, ok=False, error="down"),
        ScanRun(domain_id=d.id, source="Demo", started_at=recent, ok=True),
        Report(kind="daily", period_start=old, period_end=old, title="old", data={}, created_at=old),
        Report(kind="daily", period_start=recent, period_end=recent, title="new", data={}, created_at=recent),
        AuditEvent(action="/domains", outcome="ok", at=old),
        AuditEvent(action="/domains", outcome="ok", at=recent),
    ])
    session.commit()
    counts = retention.purge(session)
    assert counts == {"scan_runs": 2, "reports": 1, "audit_events": 1}
    hibp = session.query(ScanRun).filter_by(source="HIBP").all()
    assert len(hibp) == 1 and hibp[0].ok  # baseline marker survives, so the next scan still alerts on new leaks
    assert session.query(ScanRun).filter_by(source="Demo").count() == 1
    assert [r.title for r in session.query(Report)] == ["new"]


def test_zero_keeps_everything(session, cfg_override):
    cfg_override(history_retention_days=0, audit_retention_days=0)
    session.add(AuditEvent(action="/domains", outcome="ok", at=utcnow() - timedelta(days=5000)))
    session.commit()
    assert retention.purge(session) == {"scan_runs": 0, "reports": 0, "audit_events": 0}
    assert session.query(AuditEvent).count() == 1


def test_retention_settings_section(logged_client):
    r = logged_client.post("/settings/retention", data={"history_retention_days": "90", "audit_retention_days": "0"})
    assert "n=saved" in r.headers["location"]
    assert "e=invalid_value" in logged_client.post("/settings/retention", data={"history_retention_days": "-1", "audit_retention_days": "0"}).headers["location"]
    assert "Data retention" in logged_client.get("/settings").text
