import httpx
import pytest

from app import feeds
from app.feeds import FeedError, fetch, match_terms, parse_feed
from app.ssrf import UnsafeURL, check_url

PUBLIC = "http://93.184.216.34/feed.xml"  # adresse IP publique littérale : pas de DNS nécessaire

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>FrenchBreaches</title>
<item>
  <title>Ciblex</title>
  <link>https://frenchbreaches.com/alertes/ciblex-abc</link>
  <guid isPermaLink="true">https://frenchbreaches.com/alertes/ciblex-abc</guid>
  <pubDate>Thu, 12 Nov 2026 12:18:00 +0100</pubDate>
  <category>credible</category>
  <description>Fuite de donn&#233;es chez &lt;b&gt;Ciblex&lt;/b&gt;, des adresses expos&#233;es.</description>
  <content:encoded><![CDATA[<h1>Contenu long qui ne doit pas etre conserve</h1>]]></content:encoded>
</item>
<item>
  <title>Piege</title>
  <link>javascript:alert(1)</link>
  <guid>piege-1</guid>
  <category>confirmed</category>
  <description>x</description>
</item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>Entree atom</title><id>urn:uuid:1</id>
<link href="https://exemple.fr/a"/><updated>2026-11-10T08:00:00Z</updated><summary>Resume</summary></entry></feed>"""


def test_parse_rss_keeps_only_safe_metadata():
    a, b = parse_feed(RSS)
    assert (a.title, a.url, a.reliability) == ("Ciblex", "https://frenchbreaches.com/alertes/ciblex-abc", "credible")
    assert a.excerpt == "Fuite de données chez Ciblex , des adresses exposées." or "Ciblex" in a.excerpt
    assert "<" not in a.excerpt and "Contenu long" not in a.excerpt
    assert a.published_at.year == 2026 and a.published_at.utcoffset().total_seconds() == 3600
    assert b.url == "" and b.reliability == "confirmed"  # lien javascript: écarté


def test_parse_atom():
    (e,) = parse_feed(ATOM)
    assert (e.guid, e.url, e.excerpt) == ("urn:uuid:1", "https://exemple.fr/a", "Resume")
    assert e.published_at.month == 11


def test_entity_expansion_bomb_is_refused():
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
    with pytest.raises(FeedError):
        parse_feed(bomb)


def test_external_entity_is_refused():
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title></item></channel></rss>'
    with pytest.raises(FeedError):
        parse_feed(xxe)


def test_not_xml_is_a_feed_error():
    with pytest.raises(FeedError):
        parse_feed(b"<html>pas un flux")


def client_with(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_sends_conditional_headers_and_handles_304():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(304)

    r = fetch(client_with(handler), PUBLIC, 'W/"abc"', "Wed, 11 Nov 2026 10:00:00 GMT", "OpenDLM-test", False)
    assert r.not_modified and seen["if-none-match"] == 'W/"abc"' and seen["user-agent"] == "OpenDLM-test"


def test_fetch_returns_validators():
    r = fetch(client_with(lambda req: httpx.Response(200, content=RSS, headers={"etag": '"v2"'})), PUBLIC, None, None, "ua", False)
    assert r.etag == '"v2"' and r.content == RSS


def test_fetch_refuses_redirect_to_internal_network():
    def handler(request):
        if request.url.host == "93.184.216.34":
            return httpx.Response(302, headers={"location": "http://127.0.0.1:8080/secret"})
        pytest.fail("la requête vers le réseau interne ne doit jamais partir")

    with pytest.raises(FeedError, match="Internal"):
        fetch(client_with(handler), PUBLIC, None, None, "ua", False)


def test_fetch_rejects_oversized_feed(monkeypatch):
    monkeypatch.setattr(feeds, "MAX_BYTES", 1000)
    with pytest.raises(FeedError, match="too large"):
        fetch(client_with(lambda r: httpx.Response(200, content=b"x" * 5000)), PUBLIC, None, None, "ua", False)


def test_fetch_http_error_is_explicit():
    with pytest.raises(FeedError, match="500"):
        fetch(client_with(lambda r: httpx.Response(500)), PUBLIC, None, None, "ua", False)


def test_redirect_loop_is_cut():
    with pytest.raises(FeedError, match="Too many redirects"):
        fetch(client_with(lambda r: httpx.Response(302, headers={"location": PUBLIC})), PUBLIC, None, None, "ua", False)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://93.184.216.34/x", "http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/latest", "http://[::1]/", "http://user:pw@93.184.216.34/"])
def test_check_url_blocks_dangerous_targets(url):
    with pytest.raises(UnsafeURL):
        check_url(url)


def test_check_url_allows_public_and_optional_private():
    assert check_url(PUBLIC) == PUBLIC
    assert check_url("http://127.0.0.1/feed", allow_private=True)


def test_match_terms_rules():
    text = "Fuite chez Société Générale Lemoine & Associés : données exposées"
    assert match_terms(text, ["societe generale", "Lemoine", "Lemo", "ab", "autre"]) == ["societe generale", "Lemoine"]
    assert match_terms("Lemoines et fils", ["Lemoine"]) == []  # mot entier uniquement
    assert match_terms("bobetdilane.fr touché", ["bobetdilane.fr"]) == ["bobetdilane.fr"]
