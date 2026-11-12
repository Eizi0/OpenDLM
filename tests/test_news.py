import httpx
import pytest

from app import news
from app.config import settings
from app.connectors import ransomware_live
from app.feeds import FeedError
from app.models import Domain, NewsItem, NewsSource, WatchWord
from app.notifier import Notifier

URL = "http://93.184.216.34/feed.xml"


def rss(*items):
    body = "".join(
        f"<item><title>{t}</title><link>https://exemple.fr/{g}</link><guid>{g}</guid><category>credible</category><description>{d}</description></item>"
        for t, g, d in items
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>{body}</channel></rss>'.encode()


class Spy(Notifier):
    def __init__(self):
        super().__init__(urls=[])
        self.messages = []

    def send(self, title, body):
        self.messages.append((title, body))
        return True


def make_source(session, **kw):
    s = NewsSource(name=kw.pop("name", "Test"), kind="rss", url=URL, enabled=True, **kw)
    session.add(s)
    session.commit()
    return s


def client_returning(*payloads):
    queue = list(payloads)

    def handler(request):
        p = queue.pop(0)
        return p if isinstance(p, httpx.Response) else httpx.Response(200, content=p, headers={"etag": f'"{len(queue)}"'})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_first_fetch_is_a_silent_baseline_then_mentions_alert(session):
    session.add(WatchWord(term="Cabinet Lemoine"))
    src, spy = make_source(session), Spy()
    first = rss(("Fuite chez Cabinet Lemoine", "g1", "ancien"), ("Autre victime", "g2", "x"))
    r1 = news.refresh_source(session, src, spy, client_returning(first))
    assert r1.new == 2 and r1.mentions == [] and spy.messages == []  # l'historique ne déclenche rien
    assert src.baselined and src.last_ok and src.etag

    second = rss(("Fuite chez Cabinet Lemoine", "g1", "ancien"), ("Nouvelle: Cabinet Lemoine encore", "g3", "x"), ("Sans rapport", "g4", "x"))
    r2 = news.refresh_source(session, src, spy, client_returning(second))
    assert r2.new == 2 and [m.guid for m in r2.mentions] == ["g3"]
    assert len(spy.messages) == 1 and "Cabinet Lemoine" in spy.messages[0][1]
    assert session.query(NewsItem).count() == 4

    r3 = news.refresh_source(session, src, spy, client_returning(second))  # rien de nouveau
    assert r3.new == 0 and len(spy.messages) == 1


def test_followed_domains_are_watched_automatically(session):
    session.add(Domain(name="bobetdilane.fr", verify_token="t", verified=True))
    src, spy = make_source(session), Spy()
    news.refresh_source(session, src, spy, client_returning(rss(("Ancien", "g1", "x"))))
    r = news.refresh_source(session, src, spy, client_returning(rss(("Ancien", "g1", "x"), ("Piratage de bobetdilane.fr", "g2", "x"))))
    assert [m.matched for m in r.mentions] == [["bobetdilane.fr"]]


def test_not_modified_keeps_source_healthy(session):
    src = make_source(session, etag='"1"')
    r = news.refresh_source(session, src, Spy(), client_returning(httpx.Response(304)))
    assert r.not_modified and src.last_ok is True


def test_failure_is_recorded_and_does_not_baseline(session):
    src = make_source(session)
    r = news.refresh_source(session, src, Spy(), client_returning(httpx.Response(503)))
    assert "503" in r.error and src.last_ok is False and "503" in src.last_error and not src.baselined


def test_internal_url_is_refused_at_refresh(session):
    src = make_source(session)
    src.url = "http://127.0.0.1:8080/feed"
    r = news.refresh_source(session, src, Spy(), client_returning())
    assert "interne" in r.error and src.last_ok is False


def test_ransomware_live_without_key_is_skipped(session, cfg_override):
    cfg_override(ransomware_live_key="")
    src = NewsSource(name="ransomware.live", kind="ransomware_live", enabled=True, builtin=True)
    session.add(src)
    session.commit()
    r = news.refresh_source(session, src, Spy(), client_returning())
    assert "Clé API manquante" in r.skipped
    assert src.last_ok is None and src.last_error is None  # non configurée ≠ en panne : pas dans les problèmes du rapport


def test_ransomware_live_mapping_and_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, json=[
            {"victim": "ProLiant", "group": "Barracuda", "country": "US", "activity": "Technology",
             "discovered": "2026-11-12T07:22:39+00:00", "url": "https://www.ransomware.live/id/abc", "description": "texte attaquant ignoré", "claim_url": "http://x.onion"},
            {"victim": "", "group": "g"},
            "pas-un-dict",
        ])

    entries = ransomware_live.fetch_recent(httpx.Client(transport=httpx.MockTransport(handler)), "ma-cle", "ua-test")
    assert seen["x-api-key"] == "ma-cle" and seen["user-agent"] == "ua-test"
    (e,) = entries
    assert e.title == "ProLiant" and e.reliability == "claimed" and e.url == "https://www.ransomware.live/id/abc"
    assert "Barracuda" in e.excerpt and "texte attaquant" not in e.excerpt and "onion" not in e.excerpt


@pytest.mark.parametrize("response,needle", [(httpx.Response(401), "clé"), (httpx.Response(429), "débit"), (httpx.Response(200, text="pas json"), "illisible"), (httpx.Response(200, json={"a": 1}), "format")])
def test_ransomware_live_errors(response, needle):
    with pytest.raises(FeedError, match=needle):
        ransomware_live.fetch_recent(httpx.Client(transport=httpx.MockTransport(lambda r: response)), "k", "ua")


def test_foreign_link_in_ransomware_live_is_neutralised():
    payload = [{"victim": "X", "group": "g", "url": "javascript:alert(1)"}]
    (e,) = ransomware_live.fetch_recent(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))), "k", "ua")
    assert e.url == "https://www.ransomware.live/"


def test_seed_default_sources_is_idempotent(session):
    news.seed_default_sources(session)
    news.seed_default_sources(session)
    names = {s.name: s for s in session.query(NewsSource)}
    assert set(names) == {"FrenchBreaches", "ransomware.live", "CERT-FR (avis de sécurité)"}
    assert names["FrenchBreaches"].enabled and not names["CERT-FR (avis de sécurité)"].enabled
