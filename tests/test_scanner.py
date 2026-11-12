from datetime import date

import pytest

from app.connectors.base import ConnectorError, Hit
from app.connectors.demo import DemoConnector
from app.models import Domain, Finding
from app.notifier import Notifier, format_alert
from app.scanner import run_scan, severity


class FakeNotifier(Notifier):
    def __init__(self):
        super().__init__(urls=[])
        self.sent = []

    def alert(self, domain, findings):
        self.sent.append((domain, list(findings)))
        return True


class ScriptedConnector:
    name = "Script"

    def __init__(self, *rounds):
        self.rounds = list(rounds)

    def check_domain(self, domain):
        step = self.rounds.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def make_domain(session, verified=True):
    d = Domain(name="exemple.fr", verify_token="t" * 32, verified=verified)
    session.add(d)
    session.commit()
    return d


def hit(alias="a", breach="B1", classes=("Email addresses",)):
    return Hit(f"{alias}@exemple.fr", "Script", breach, date(2024, 1, 1), classes)


def test_first_scan_is_silent_baseline(session):
    d, n = make_domain(session), FakeNotifier()
    r = run_scan(session, d, [ScriptedConnector([hit("a"), hit("b")])], n)
    assert r.new == [] and r.baselined_sources == ["Script"]
    assert n.sent == []
    assert {f.status for f in session.query(Finding)} == {"known"}


def test_second_scan_alerts_only_on_new(session):
    d, n = make_domain(session), FakeNotifier()
    c = ScriptedConnector([hit("a")], [hit("a"), hit("b", "B2", ("Passwords",))], [hit("a"), hit("b", "B2", ("Passwords",))])
    run_scan(session, d, [c], n)
    r2 = run_scan(session, d, [c], n)
    assert [f.identifier for f in r2.new] == ["b@exemple.fr"]
    assert r2.new[0].severity == "high" and r2.new[0].status == "new"
    assert len(n.sent) == 1
    r3 = run_scan(session, d, [c], n)  # rien de nouveau : pas de doublon, pas d'alerte
    assert r3.new == [] and len(n.sent) == 1
    assert session.query(Finding).count() == 2


def test_failed_source_does_not_count_as_baseline(session):
    d, n = make_domain(session), FakeNotifier()
    c = ScriptedConnector(ConnectorError("429", retry_after=60), [hit("a")])
    r1 = run_scan(session, d, [c], n)
    assert r1.errors and r1.new == []
    r2 = run_scan(session, d, [c], n)  # premier succès : base de référence, toujours silencieux
    assert r2.new == [] and n.sent == []


def test_unverified_domain_is_refused(session):
    d = make_domain(session, verified=False)
    with pytest.raises(PermissionError):
        run_scan(session, d, [DemoConnector()], FakeNotifier())


def test_demo_connector_produces_an_alert_on_second_scan(session):
    d, n, demo = make_domain(session), FakeNotifier(), DemoConnector()
    run_scan(session, d, [demo], n)
    r = run_scan(session, d, [demo], n)
    assert [f.severity for f in r.new] == ["critical"]


def test_demo_connector_instance_is_shared_between_scans(monkeypatch):
    # Régression : un connecteur recréé à chaque scan remettait son compteur à zéro,
    # donc la nouvelle fuite de démonstration n'apparaissait jamais.
    from app.config import settings
    from app.connectors import build_connectors

    monkeypatch.setattr(settings, "demo", True)
    assert build_connectors()[0] is build_connectors()[0]


def test_severity_rules():
    assert severity(hit(classes=("Session cookies",))) == "critical"
    assert severity(hit(classes=("Password hashes",))) == "high"
    assert severity(hit(classes=("Email addresses",))) == "low"


def test_alert_text_has_no_secret_fields(session):
    d = make_domain(session)
    f = Finding(domain_id=d.id, identifier="x@exemple.fr", source="HIBP", breach="B", breach_date=date(2024, 5, 1),
                data_classes=["Passwords"], severity="high")
    title, body = format_alert(d.name, [f])
    assert "x@exemple.fr" in body and "High" in body and "2024-05-01" in body
    assert "1 new" in title
