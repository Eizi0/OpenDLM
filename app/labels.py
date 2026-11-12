"""Shared display labels, translated at display time."""

from .i18n import N_, t

SEVERITY_ORDER = {"critical": 0, "high": 1, "low": 2}
_SEVERITY = {"critical": N_("Critical"), "high": N_("High"), "low": N_("Low")}
_RELIABILITY = {
    "confirmed": N_("Confirmed"),
    "credible": N_("Claimed (credible)"),
    "claimed": N_("Claim"),
    "unreliable": N_("Unreliable"),
}
RELIABILITY_CODES = tuple(_RELIABILITY)


def severity_label(code: str | None) -> str:
    return t(_SEVERITY[code]) if code in _SEVERITY else (code or "")


def reliability_label(code: str | None) -> str:
    return t(_RELIABILITY[code]) if code in _RELIABILITY else ""
