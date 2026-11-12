import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeURL(ValueError):
    """Refused URL: the server must not fetch just anything on a user's request."""

    def __init__(self, message: str, code: str = "unsafe") -> None:
        super().__init__(message)
        self.code = code


def check_url(url: str, allow_private: bool = False) -> str:
    """Check that a feed URL is http(s) and does not target the internal network."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("Invalid URL: http or https expected", "invalid_url")
    if parsed.username or parsed.password:
        raise UnsafeURL("Credentials in the URL are refused", "credentials")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURL("Host not found", "unresolved") from e
    if not allow_private:
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise UnsafeURL("Internal or private address refused", "private")
    return url
