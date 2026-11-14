"""Audit trail: every change made through the interface, plus sign-in events.

Recorded automatically for any successful or refused write request by a signed-in user (see the middleware
in main.py), so a new page cannot forget it. Secrets never reach the trail: only the route and its path
parameters are kept, never the form body.
"""

import logging

from sqlalchemy.orm import Session

from .db import SessionLocal
from .i18n import N_
from .models import AuditEvent

log = logging.getLogger("opendlm.audit")

# Route template -> readable label. Unknown routes are shown as the raw route.
LABELS = {
    "/setup": N_("Administrator account created"),
    "/login": N_("Sign-in"),
    "/login/2fa": N_("Sign-in, second factor"),
    "/logout": N_("Sign-out"),
    "/domains": N_("Domain added"),
    "/domains/{domain_id}/verify": N_("Domain verification"),
    "/domains/{domain_id}/scan": N_("Manual scan"),
    "/domains/{domain_id}/delete": N_("Domain deleted"),
    "/domains/{domain_id}/addresses": N_("Monitored addresses added"),
    "/domains/{domain_id}/addresses/{address_id}/delete": N_("Monitored address removed"),
    "/findings/{finding_id}/status": N_("Leak status changed"),
    "/findings/{finding_id}/ack": N_("Leak acknowledged"),
    "/watch-words": N_("Watched word added"),
    "/watch-words/{word_id}/delete": N_("Watched word removed"),
    "/reports/generate": N_("Report generated"),
    "/reports/{report_id}/send": N_("Report sent"),
    "/connectors/{connector_id}/key": N_("API key saved"),
    "/connectors/{connector_id}/key/delete": N_("API key removed"),
    "/connectors/{connector_id}/toggle": N_("Source switched on or off"),
    "/connectors/{connector_id}/test": N_("Source connection tested"),
    "/sources": N_("News feed added"),
    "/sources/{source_id}/toggle": N_("News feed switched on or off"),
    "/sources/{source_id}/refresh": N_("News feed refreshed"),
    "/sources/{source_id}/delete": N_("News feed deleted"),
    "/notifications/channels": N_("Notification channel added"),
    "/notifications/channels/{channel_id}/toggle": N_("Notification channel switched on or off"),
    "/notifications/channels/{channel_id}/delete": N_("Notification channel deleted"),
    "/notifications/channels/{channel_id}/test": N_("Notification channel tested"),
    "/notifications/test": N_("Test notification sent"),
    "/notifications/heartbeat": N_("Heartbeat URL saved"),
    "/notifications/heartbeat/delete": N_("Heartbeat URL removed"),
    "/notifications/heartbeat/test": N_("Heartbeat sent"),
    "/settings/{section}": N_("Settings changed"),
    "/settings/{section}/reset": N_("Settings reset"),
    "/users": N_("User created"),
    "/users/{user_id}/role": N_("User role changed"),
    "/users/{user_id}/password": N_("User password reset"),
    "/users/{user_id}/2fa/reset": N_("User two-factor authentication reset"),
    "/users/{user_id}/delete": N_("User deleted"),
    "/profile/2fa/start": N_("Two-factor setup started"),
    "/profile/2fa/enable": N_("Two-factor authentication enabled"),
    "/profile/2fa/recovery": N_("Recovery codes regenerated"),
    "/profile/2fa/disable": N_("Two-factor authentication disabled"),
    "/profile/password": N_("Own password changed"),
    "/tokens": N_("API token created"),
    "/tokens/{token_id}/delete": N_("API token revoked"),
}


def record(action: str, outcome: str, username: str | None = None, ip: str | None = None, params: dict | None = None,
           session: Session | None = None) -> None:
    """Store one event. Never lets an audit failure break the request it describes."""
    event = AuditEvent(action=action[:120], outcome=outcome, username=username, ip=ip,
                       params={k: str(v)[:200] for k, v in (params or {}).items()})
    try:
        if session is not None:
            session.add(event)
            session.commit()
        else:
            with SessionLocal() as own:
                own.add(event)
                own.commit()
    except Exception:
        log.exception("could not record audit event %s", action)


def outcome_of(status: int, location: str | None) -> str:
    """ok | refused (validation error shown to the user, or 4xx) | failed (5xx)."""
    if status >= 500:
        return "failed"
    if status >= 400 or (location and ("?e=" in location or "&e=" in location)):
        return "refused"
    return "ok"


# Sign-in routes record their own events (the user is not known yet when they run).
SELF_RECORDED = {"/setup", "/login", "/login/2fa", "/logout"}
