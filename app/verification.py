import re
import secrets

import dns.exception
import dns.resolver

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TXT_PREFIX = "opendlm-verify="


def normalize_domain(raw: str) -> str | None:
    name = raw.strip().lower().rstrip(".")
    return name if DOMAIN_RE.match(name) else None


def new_token() -> str:
    return secrets.token_hex(16)


def txt_value(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


def check_dns_txt(domain: str, token: str) -> bool:
    """Vrai si un enregistrement TXT du domaine contient la valeur attendue."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
    except (dns.exception.DNSException, OSError):
        return False
    expected = txt_value(token)
    for rdata in answers:
        text = b"".join(rdata.strings).decode("utf-8", "ignore")
        if text == expected:
            return True
    return False
