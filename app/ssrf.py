import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeURL(ValueError):
    """URL refusée : le serveur ne doit pas aller chercher n'importe quoi à la demande d'un utilisateur."""


def check_url(url: str, allow_private: bool = False) -> str:
    """Vérifie qu'une URL de flux est http(s) et ne vise pas le réseau interne."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("URL invalide : http ou https attendu")
    if parsed.username or parsed.password:
        raise UnsafeURL("Identifiants dans l'URL refusés")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURL("Hôte introuvable") from e
    if not allow_private:
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise UnsafeURL("Adresse interne ou privée refusée")
    return url
