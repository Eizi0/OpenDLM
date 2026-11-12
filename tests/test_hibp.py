import httpx
import pytest

from app.connectors.base import ConnectorError
from app.connectors.hibp import HibpConnector
from app.verification import check_dns_txt, normalize_domain, txt_value

CATALOG = [{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email addresses", "Password hints"]}]


def connector(handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return HibpConnector("cle-de-test", "OpenDLM-test", client)


def test_domain_search_maps_aliases_and_catalog():
    seen = {}

    def handler(request: httpx.Request):
        seen["headers"] = request.headers
        if request.url.path.endswith("/breacheddomain/exemple.fr"):
            return httpx.Response(200, json={"alice": ["Adobe"]})
        return httpx.Response(200, json=CATALOG)

    hits = connector(handler).check_domain("exemple.fr")
    assert [(h.identifier, h.breach, str(h.breach_date)) for h in hits] == [("alice@exemple.fr", "Adobe", "2013-10-04")]
    assert hits[0].data_classes == ("Email addresses", "Password hints")
    assert seen["headers"]["hibp-api-key"] == "cle-de-test" and seen["headers"]["user-agent"] == "OpenDLM-test"


def test_404_means_no_breach():
    assert connector(lambda r: httpx.Response(404)).check_domain("exemple.fr") == []


@pytest.mark.parametrize("status,needle", [(401, "API key"), (403, "not verified")])
def test_auth_errors_are_explicit(status, needle):
    with pytest.raises(ConnectorError, match=needle):
        connector(lambda r: httpx.Response(status)).check_domain("exemple.fr")


def test_rate_limit_exposes_retry_after():
    with pytest.raises(ConnectorError) as e:
        connector(lambda r: httpx.Response(429, headers={"retry-after": "42"})).check_domain("exemple.fr")
    assert e.value.retry_after == 42


def test_domain_validation():
    assert normalize_domain(" Exemple.FR. ") == "exemple.fr"
    for bad in ["localhost", "a b.fr", "http://x.fr", "-x.fr", "x..fr", ""]:
        assert normalize_domain(bad) is None


def test_dns_check_fails_closed_when_resolution_fails(monkeypatch):
    import dns.resolver

    def boom(*a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", boom)
    assert check_dns_txt("exemple.fr", "abc") is False
    assert txt_value("abc") == "opendlm-verify=abc"
