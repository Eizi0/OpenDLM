from datetime import datetime, timedelta, timezone

import pytest

from app import reports
from app.config import settings
from app.db import SessionLocal
from app.models import Domain, Finding, NewsItem, NewsSource, Report, ScanRun
from app.notifier import Notifier
from app.scanner import run_scan
from tests.test_scanner import FakeNotifier, ScriptedConnector, hit, make_domain

NOW = datetime(2026, 11, 12, 6, 0, tzinfo=timezone.utc)


class SendSpy(Notifier):
    def __init__(self, ok=True):
        super().__init__(urls=["json://x"])
        self.calls, self.ok = [], ok

    def send(self, title, body, markdown=False):
        self.calls.append((title, body, markdown))
        return self.ok


def finding(domain, ident, status="new", when=NOW - timedelta(hours=3), severity="high", source="HIBP"):
    return Finding(domain_id=domain.id, identifier=ident, source=source, breach="Fuite B", severity=severity,
                   status=status, first_seen=when, data_classes=["Passwords"])


def test_daily_period_and_label():
    start, end, label = reports.period_for("daily", NOW)
    assert end - start == timedelta(hours=24) and label == {"type": "day", "date": "2026-11-12"}


def test_monthly_period_is_previous_calendar_month_across_dst():
    start, end, label = reports.period_for("monthly", NOW)
    assert label == {"type": "month", "year": 2026, "month": 10}
    assert start == datetime(2026, 9, 30, 22, 0, tzinfo=timezone.utc)  # 1er oct 00:00 à Paris (UTC+2)
    assert end == datetime(2026, 10, 31, 23, 0, tzinfo=timezone.utc)  # 1er nov 00:00 à Paris (UTC+1, heure d'hiver)


def test_monthly_period_in_january_rolls_back_to_december():
    _, _, label = reports.period_for("monthly", datetime(2027, 1, 5, 6, 0, tzinfo=timezone.utc))
    assert label == {"type": "month", "year": 2026, "month": 12}


def test_report_counts_only_real_new_findings_in_period(session):
    d = make_domain(session)
    session.add_all([
        finding(d, "nouvelle@exemple.fr"),                                   # dans la période
        finding(d, "acquittee@exemple.fr", status="ack"),                    # nouvelle puis acquittée : compte
        finding(d, "base@exemple.fr", status="known"),                       # base de référence : jamais comptée
        finding(d, "ancienne@exemple.fr", when=NOW - timedelta(days=3)),     # hors période
    ])
    session.commit()
    r = reports.build_report(session, "daily", NOW)
    names = [f["identifier"] for f in r.data["domains"][0]["new"]]
    assert sorted(names) == ["acquittee@exemple.fr", "nouvelle@exemple.fr"]
    assert r.data["totals"]["new_findings"] == 2 and r.data["totals"]["open"] == 2  # nouvelle + ancienne encore « new »
    assert r.data["empty"] is False and "2 new leak(s)" in reports.title_text(r)


def test_findings_sorted_by_severity(session):
    d = make_domain(session)
    session.add_all([finding(d, "b@exemple.fr", severity="low"), finding(d, "a@exemple.fr", severity="critical"), finding(d, "c@exemple.fr", severity="high")])
    session.commit()
    order = [f["severity"] for f in reports.build_report(session, "daily", NOW).data["domains"][0]["new"]]
    assert order == ["critical", "high", "low"]


def test_mentions_use_publication_date_and_ignore_unmatched(session):
    src = NewsSource(name="FB", kind="rss", enabled=True)
    session.add(src)
    session.commit()
    def item(guid, matched, published, **kw):
        return NewsItem(source_id=src.id, guid=guid, title=f"Titre {guid}", url="https://x.fr/" + guid, matched=matched,
                        published_at=published, first_seen=NOW - timedelta(hours=1), **kw)
    session.add_all([
        item("ok", ["Ciblex"], NOW - timedelta(hours=2), reliability="credible"),
        item("vieux", ["Ciblex"], NOW - timedelta(days=20)),        # historique récupéré au premier passage
        item("sans-mot", [], NOW - timedelta(hours=2)),
    ])
    session.commit()
    r = reports.build_report(session, "daily", NOW)
    assert [m["title"] for m in r.data["mentions"]] == ["Titre ok"]
    assert r.data["mentions"][0]["reliability"] == "credible" and r.data["totals"]["news"] == 2


def test_problems_listed_and_empty_flag(session):
    make_domain(session)
    r = reports.build_report(session, "daily", NOW)
    assert r.data["empty"] is True and "nothing to report" in reports.title_text(r)
    d = session.query(Domain).one()
    session.add(ScanRun(domain_id=d.id, source="Hudson Rock", ok=False, error="limite de débit atteinte", started_at=NOW - timedelta(hours=1)))
    session.commit()
    r2 = reports.build_report(session, "daily", NOW)
    assert r2.data["problems"] == [{"source": "Hudson Rock", "message": "limite de débit atteinte"}] and r2.data["empty"] is False


def test_unconfigured_source_is_not_reported_as_a_problem(session):
    make_domain(session)
    session.add(NewsSource(name="ransomware.live", kind="ransomware_live", enabled=True, last_ok=None))
    session.add(NewsSource(name="Flux cassé", kind="rss", enabled=True, last_ok=False, last_error="Réponse HTTP 503"))
    session.add(NewsSource(name="Flux coupé", kind="rss", enabled=False, last_ok=False, last_error="ancien"))
    session.commit()
    assert reports.build_report(session, "daily", NOW).data["problems"] == [{"source": "Flux cassé", "message": "Réponse HTTP 503"}]


def test_markdown_content_and_attribution(session):
    d = make_domain(session)
    session.add(finding(d, "c.martin@exemple.fr", severity="critical", source="Hudson Rock"))
    session.commit()
    md = reports.render_markdown(reports.build_report(session, "daily", NOW))
    assert md.startswith("# Daily report · 12 November 2026")
    assert "`c.martin@exemple.fr`" in md and "**Critical**" in md and "Have I Been Pwned" in md and "does not store any password" in md


def test_unknown_kind_is_rejected(session):
    with pytest.raises(ValueError):
        reports.build_report(session, "hebdo", NOW)


def test_scheduled_empty_report_respects_setting(session, cfg_override):
    make_domain(session)
    spy = SendSpy()
    cfg_override(report_send_empty=True)
    reports.run_scheduled(session, "daily", spy)
    assert len(spy.calls) == 1 and spy.calls[0][2] is True  # envoyé en Markdown : signal de vie
    cfg_override(report_send_empty=False)
    reports.run_scheduled(session, "daily", spy)
    assert len(spy.calls) == 1  # rien de plus
    assert session.query(Report).count() == 2  # mais archivé dans les deux cas


def test_sent_at_set_only_on_success(session):
    make_domain(session)
    ok, ko = SendSpy(True), SendSpy(False)
    a = reports.build_report(session, "daily", NOW)
    reports.send_report(session, a, ko)
    assert a.sent_at is None
    reports.send_report(session, a, ok)
    assert a.sent_at is not None


@pytest.mark.parametrize("threshold,expected", [("low", 2), ("high", 1), ("critical", 0)])
def test_immediate_alert_threshold(session, cfg_override, threshold, expected):
    cfg_override(alert_min_severity=threshold)
    d, spy = make_domain(session), FakeNotifier()
    sev = lambda alias, cls: hit(alias, f"B-{alias}", cls)
    c = ScriptedConnector([sev("base", ("Email addresses",))],
                          [sev("base", ("Email addresses",)), sev("low", ("Email addresses",)), sev("hi", ("Passwords",)), sev("crit", ("Stealer logs",))])
    run_scan(session, d, [c], spy)
    result = run_scan(session, d, [c], spy)
    assert len(result.new) == 3  # tout est enregistré (donc dans le rapport)
    alerted = sum(len(f) for _, f in spy.sent)
    assert alerted == {2: 3, 1: 2, 0: 1}[expected]


# --- Interface ---------------------------------------------------------------


def test_report_pages_require_login(client):
    assert client.get("/reports").status_code == 303
    assert client.post("/reports/generate", data={"kind": "daily"}).status_code == 303


def test_generate_view_and_export(logged_client):
    c = logged_client
    assert "No report yet" in c.get("/reports").text
    r = c.post("/reports/generate", data={"kind": "daily"})
    assert r.status_code == 303
    page = c.get(r.headers["location"])
    assert page.status_code == 200 and "Nothing to report" in page.text and "Download Markdown" in page.text
    rid = r.headers["location"].rsplit("/", 1)[1]
    md = c.get(f"/reports/{rid}/export.md")
    assert md.status_code == 200 and "attachment" in md.headers["content-disposition"] and md.text.startswith("# Daily report")
    html = c.get(f"/reports/{rid}/export.html")
    assert "<!doctype html>" in html.text and "Have I Been Pwned" in html.text and "attachment" in html.headers["content-disposition"]
    assert c.post("/reports/generate", data={"kind": "hebdo"}).status_code == 422
    assert c.get("/reports/9999").status_code == 404


def test_send_without_channel_explains(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "notify_urls", "")
    rid = logged_client.post("/reports/generate", data={"kind": "monthly"}).headers["location"].rsplit("/", 1)[1]
    r = logged_client.post(f"/reports/{rid}/send")
    assert r.status_code == 303 and "e=no_channel" in r.headers["location"]
    with SessionLocal() as s:
        assert s.get(Report, int(rid)).sent_at is None


def test_report_content_is_escaped(logged_client):
    with SessionLocal() as s:
        d = Domain(name="exemple.fr", verify_token="t", verified=True)
        s.add(d)
        s.commit()
        s.add(Finding(domain_id=d.id, identifier="x@exemple.fr", source="HIBP", breach="<img src=x onerror=alert(1)>",
                      severity="high", status="new", first_seen=datetime.now(timezone.utc), data_classes=[]))
        s.commit()
    rid = logged_client.post("/reports/generate", data={"kind": "daily"}).headers["location"].rsplit("/", 1)[1]
    page = logged_client.get(f"/reports/{rid}")
    assert "<img src=x" not in page.text and "&lt;img src=x" in page.text


@pytest.mark.parametrize("lang,daily,monthly", [("en", "12 November 2026", "October 2026"), ("fr", "12 novembre 2026", "octobre 2026")])
def test_daily_and_monthly_labels_share_one_format(lang, daily, monthly):
    from app import i18n

    token = i18n.set_language(lang)
    try:
        _, _, d = reports.period_for("daily", NOW)
        _, _, m = reports.period_for("monthly", NOW)
        assert reports.label_text(d) == daily and reports.label_text(m) == monthly
    finally:
        i18n.reset_language(token)
