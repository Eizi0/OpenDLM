import logging

import apprise

from .config import settings
from .models import Finding

log = logging.getLogger("opendlm.notifier")

SEVERITY_LABEL = {"critical": "Critique", "high": "Élevée", "low": "Faible"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "low": 2}


def format_alert(domain: str, findings: list[Finding]) -> tuple[str, str]:
    """Titre et corps d'une alerte. Jamais de mot de passe, seulement des métadonnées."""
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    title = f"[OpenDLM] {len(ordered)} nouvelle(s) fuite(s) sur {domain}"
    lines = []
    for f in ordered:
        when = f" · fuite du {f.breach_date.strftime('%d/%m/%Y')}" if f.breach_date else ""
        data = f" · données : {', '.join(f.data_classes)}" if f.data_classes else ""
        lines.append(f"- {SEVERITY_LABEL.get(f.severity, f.severity)} · {f.identifier} · {f.breach} ({f.source}){when}{data}")
    return title, "\n".join(lines)


class Notifier:
    def __init__(self, urls: list[str] | None = None) -> None:
        self._urls = settings.notify_url_list if urls is None else urls

    def alert(self, domain: str, findings: list[Finding]) -> bool:
        title, body = format_alert(domain, findings)
        if not self._urls:
            log.info("Aucun canal configuré. Alerte : %s\n%s", title, body)
            return False
        ap = apprise.Apprise()
        for url in self._urls:
            ap.add(url)
        ok = ap.notify(title=title, body=body)
        if not ok:
            log.error("Échec de l'envoi de l'alerte pour %s", domain)
        return bool(ok)
