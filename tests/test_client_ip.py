from app.security import client_ip


def test_direct_connection_ignores_forwarded_header():
    # No trusted proxy configured: a client cannot pick its own address.
    assert client_ip("203.0.113.9", "1.2.3.4", trusted="") == "203.0.113.9"


def test_untrusted_peer_cannot_spoof():
    assert client_ip("203.0.113.9", "1.2.3.4", trusted="172.16.0.0/12") == "203.0.113.9"


def test_trusted_proxy_gives_real_client():
    assert client_ip("172.18.0.5", "198.51.100.7", trusted="172.16.0.0/12") == "198.51.100.7"


def test_forged_left_part_of_chain_is_ignored():
    # The client sent a fake X-Forwarded-For; the proxy appended the real address on the right.
    assert client_ip("172.18.0.5", "10.0.0.1, 198.51.100.7", trusted="172.16.0.0/12") == "198.51.100.7"


def test_chain_of_trusted_proxies():
    assert client_ip("172.18.0.5", "198.51.100.7, 172.18.0.9", trusted="172.16.0.0/12") == "198.51.100.7"


def test_invalid_entries_are_ignored():
    assert client_ip("172.18.0.5", "198.51.100.7", trusted="nonsense, 172.16.0.0/12") == "198.51.100.7"
    assert client_ip(None, None, trusted="") == "unknown"
