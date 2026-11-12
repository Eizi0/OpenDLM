import logging

import apprise

from . import channels
from .config import settings
from .i18n import fmt_date, t
from .labels import SEVERITY_ORDER, severity_label
from .models import Finding

log = logging.getLogger("opendlm.notifier")

__all__ = ["Notifier", "format_alert", "SEVERITY_ORDER"]


def format_alert(domain: str, findings: list[Finding]) -> tuple[str, str]:
    """Alert title and body. Never contains a password, only metadata."""
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    title = t("[OpenDLM] %(n)d new leak(s) on %(domain)s", n=len(ordered), domain=domain)
    lines = []
    for f in ordered:
        when = t(" · leaked on %(date)s", date=fmt_date(f.breach_date)) if f.breach_date else ""
        data = t(" · data: %(classes)s", classes=", ".join(f.data_classes)) if f.data_classes else ""
        lines.append(f"- {severity_label(f.severity)} · {f.identifier} · {f.breach} ({f.source}){when}{data}")
    return title, "\n".join(lines)


class Notifier:
    def __init__(self, urls: list[str] | None = None) -> None:
        self._explicit = urls

    @property
    def _urls(self) -> list[str]:
        # Resolved at send time so channels edited in the interface apply immediately.
        return self._explicit if self._explicit is not None else channels.all_urls()

    def alert(self, domain: str, findings: list[Finding]) -> bool:
        title, body = format_alert(domain, findings)
        return self.send(title, body)

    def send(self, title: str, body: str, markdown: bool = False) -> bool:
        urls = self._urls
        if not urls:
            log.info("No notification channel configured. Message: %s\n%s", title, body)
            return False
        ap = apprise.Apprise()
        for url in urls:
            ap.add(url)
        fmt = apprise.NotifyFormat.MARKDOWN if markdown else apprise.NotifyFormat.TEXT
        ok = ap.notify(title=title, body=body, body_format=fmt)
        if not ok:
            log.error("Delivery failed: %s", title)
        return bool(ok)
