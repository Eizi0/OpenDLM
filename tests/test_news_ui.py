from app.db import SessionLocal
from app.models import NewsItem, NewsSource, WatchWord, utcnow


def add_items(*rows):
    with SessionLocal() as s:
        src = s.query(NewsSource).filter_by(name="FrenchBreaches").one()
        for i, (title, matched, rel) in enumerate(rows):
            s.add(NewsItem(source_id=src.id, guid=f"g{i}", title=title, url=f"https://exemple.fr/{i}", excerpt="extrait",
                           published_at=utcnow(), reliability=rel, matched=matched, notified=True))
        s.commit()


def test_pages_require_login(client):
    for path in ("/news", "/sources"):
        assert client.get(path).status_code == 303


def test_news_page_lists_filters_and_escapes(logged_client):
    add_items(("Fuite Ciblex", ["Ciblex"], "credible"), ("Autre <script>alert(1)</script>", [], "confirmed"))
    page = logged_client.get("/news")
    assert page.status_code == 200 and "Fuite Ciblex" in page.text
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text  # échappé
    # L'encart des mentions récentes est indépendant des filtres : on compte les articles de la liste.
    only = logged_client.get("/news?mentions=1")
    assert only.text.count("<article") == 1 and "Autre" not in only.text
    rel = logged_client.get("/news?reliability=confirmed")
    assert rel.text.count("<article") == 1 and "Autre" in rel.text


def test_watch_words_add_dedupe_delete(logged_client):
    logged_client.post("/watch-words", data={"term": "  Cabinet   Lemoine "})
    logged_client.post("/watch-words", data={"term": "cabinet lemoine"})  # doublon, casse différente
    assert logged_client.post("/watch-words", data={"term": "ab"}).status_code == 422
    with SessionLocal() as s:
        words = s.query(WatchWord).all()
        assert [w.term for w in words] == ["Cabinet Lemoine"]
        wid = words[0].id
    logged_client.post(f"/watch-words/{wid}/delete")
    with SessionLocal() as s:
        assert s.query(WatchWord).count() == 0


def test_sources_page_and_toggle(logged_client):
    page = logged_client.get("/sources")
    assert page.status_code == 200 and "FrenchBreaches" in page.text and "API key missing" in page.text
    with SessionLocal() as s:
        cert = s.query(NewsSource).filter(NewsSource.name.like("CERT-FR%")).one()
        assert cert.enabled is False
        cid = cert.id
    logged_client.post(f"/sources/{cid}/toggle")
    with SessionLocal() as s:
        assert s.get(NewsSource, cid).enabled is True


def test_add_source_refuses_internal_and_invalid_urls(logged_client):
    for bad in ("http://127.0.0.1:8080/feed", "http://169.254.169.254/latest", "file:///etc/passwd", "ftp://93.184.216.34/x"):
        r = logged_client.post("/sources", data={"name": "Piège", "url": bad})
        assert r.status_code == 303 and "e=" in r.headers["location"]
    with SessionLocal() as s:
        assert s.query(NewsSource).filter_by(name="Piège").count() == 0


def test_add_and_delete_custom_source_but_not_builtin(logged_client):
    r = logged_client.post("/sources", data={"name": "Mon flux", "url": "http://93.184.216.34/feed.xml"})
    assert r.headers["location"] == "/sources"
    with SessionLocal() as s:
        custom = s.query(NewsSource).filter_by(name="Mon flux").one()
        builtin = s.query(NewsSource).filter_by(name="FrenchBreaches").one()
        cid, bid = custom.id, builtin.id
    assert logged_client.post(f"/sources/{bid}/delete").status_code == 403
    assert logged_client.post(f"/sources/{cid}/delete").status_code == 303
    with SessionLocal() as s:
        assert s.query(NewsSource).filter_by(name="Mon flux").count() == 0
        assert s.get(NewsSource, bid) is not None


def test_dashboard_shows_recent_mentions(logged_client):
    add_items(("Piratage Ciblex", ["Ciblex"], "credible"))
    page = logged_client.get("/")
    assert "News that concerns you" in page.text and "Piratage Ciblex" in page.text


def test_every_news_item_links_out_to_its_article(logged_client):
    add_items(("Fuite Ciblex", ["Ciblex"], "credible"))
    with SessionLocal() as s:
        src = s.query(NewsSource).filter_by(name="FrenchBreaches").one()
        s.add(NewsItem(source_id=src.id, guid="nolink", title="Sans lien", url="", excerpt="", published_at=utcnow(), matched=[], notified=True))
        s.add(NewsItem(source_id=src.id, guid="bad", title="Lien piégé", url="javascript:alert(1)", excerpt="", published_at=utcnow(), matched=[], notified=True))
        s.commit()
    page = logged_client.get("/news").text
    assert 'class="btn small readmore" href="https://exemple.fr/0"' in page and "Read the article · exemple.fr ↗" in page
    # external links open in a new tab and never leak the referrer or the opener
    assert page.count('rel="noopener noreferrer nofollow" target="_blank"') >= 2
    assert "Sans lien" in page and "Lien piégé" in page  # shown as plain titles
    assert "javascript:" not in page and page.count("Read the article") >= 1
    assert page.count('class="btn small readmore"') == 1  # only the item with a real link gets the button


def test_dashboard_mentions_link_out_too(logged_client):
    add_items(("Piratage Ciblex", ["Ciblex"], "credible"))
    page = logged_client.get("/").text
    assert 'class="ext" href="https://exemple.fr/0"' in page and "Piratage Ciblex ↗" in page


def test_read_the_article_in_french(logged_client):
    add_items(("Fuite Ciblex", ["Ciblex"], "credible"))
    logged_client.get("/lang/fr")
    assert "Lire l’article" in logged_client.get("/news").text
