"""Sources: leak connectors (API keys) and news feeds."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import channels, news
from ..config import settings
from ..connectors import testing
from ..deps import get_session, require_admin
from ..i18n import N_, t
from ..models import NewsItem, NewsSource, utcnow
from ..notifier import Notifier
from ..runtime_config import SPECS, cfg
from ..ssrf import UnsafeURL, check_url
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_admin)])

KIND_LABEL = {"rss": N_("RSS/Atom feed"), "ransomware_live": N_("ransomware.live PRO API")}

# Leak and claim connectors configured with an API key.
CONNECTORS = {
    "hibp": {
        "key": "hibp_api_key", "name": "Have I Been Pwned",
        "desc": N_("Addresses of your domains found in known data breaches. Needs a paid API key and a domain verified on the HIBP dashboard."),
    },
    "hudson_rock": {
        "key": "hudson_rock_key", "name": "Hudson Rock (Cavalier)",
        "desc": N_("Accounts of your domains stolen by infostealer malware. Needs a key whose plan includes the search-by-domain permission."),
    },
    "ransomware_live": {
        "key": "ransomware_live_key", "name": "ransomware.live (PRO API)",
        "desc": N_("Ransomware group claims, used for the news feed. The PRO API key is free."),
    },
}

# Last connection test per connector (memory only: it is a convenience, not a record).
TEST_RESULTS: dict[str, dict] = {}


def source_status(src: NewsSource) -> tuple[str, str]:
    """(label, tone) of a news source."""
    if not src.enabled:
        return t("Disabled"), ""
    if src.kind == "ransomware_live" and not cfg.ransomware_live_key:
        return t("API key missing"), "warn"
    if src.last_ok is None:
        return t("Waiting for the first pass"), ""
    return (t("Active"), "ok") if src.last_ok else (t("Failing"), "warn")


def source_or_404(session: Session, source_id: int) -> NewsSource:
    src = session.get(NewsSource, source_id)
    if src is None:
        raise HTTPException(404, t("Unknown source"))
    return src


def connector_or_404(connector_id: str) -> dict:
    if connector_id not in CONNECTORS:
        raise HTTPException(404, t("Unknown connector"))
    return CONNECTORS[connector_id]


@router.get("/sources")
def sources_page(request: Request, session: Session = Depends(get_session)):
    rows = []
    for src in session.scalars(select(NewsSource).order_by(NewsSource.builtin.desc(), NewsSource.name)):
        label, tone = source_status(src)
        rows.append({"src": src, "status": label, "tone": tone, "kind": t(KIND_LABEL.get(src.kind, src.kind)),
                     "count": session.scalar(select(func.count(NewsItem.id)).where(NewsItem.source_id == src.id)) or 0})
    connectors = []
    for cid, spec in CONNECTORS.items():
        origin = cfg.source(spec["key"])
        connectors.append({
            "id": cid, "name": spec["name"], "desc": t(spec["desc"]), "configured": cfg.is_set(spec["key"]),
            "origin": origin, "env_var": f"OPENDLM_{spec['key'].upper()}", "test": TEST_RESULTS.get(cid),
        })
    return render(request, "sources.html", {"rows": rows, "connectors": connectors, "demo_active": settings.demo, "notify_count": len(channels.all_urls())})


@router.post("/connectors/{connector_id}/key")
def save_key(connector_id: str, api_key: str = Form(...), session: Session = Depends(get_session)):
    spec = connector_or_404(connector_id)
    try:
        cfg.save(session, {spec["key"]: api_key})
    except ValueError:
        return redirect("/sources", error="invalid_value")
    TEST_RESULTS.pop(connector_id, None)
    return redirect("/sources", notice="key_saved")


@router.post("/connectors/{connector_id}/key/delete")
def delete_key(connector_id: str, session: Session = Depends(get_session)):
    spec = connector_or_404(connector_id)
    cfg.clear(session, spec["key"])
    TEST_RESULTS.pop(connector_id, None)
    return redirect("/sources", notice="key_removed")


@router.post("/connectors/{connector_id}/test")
def test_connector(connector_id: str):
    spec = connector_or_404(connector_id)
    key = getattr(cfg, spec["key"])
    if not key:
        return redirect("/sources", error="no_key")
    ok, msgid, params = testing.check(connector_id, key, settings.user_agent)
    TEST_RESULTS[connector_id] = {"ok": ok, "msgid": msgid, "params": params, "at": utcnow()}
    return redirect("/sources", notice="conn_ok" if ok else None, error=None if ok else "conn_failed")


@router.post("/sources")
def add_source(name: str = Form(...), url: str = Form(...), session: Session = Depends(get_session)):
    name, url = " ".join(name.split()), url.strip()
    if not (2 <= len(name) <= 80):
        return redirect("/sources", error="feed_name")
    try:
        check_url(url, cfg.allow_private_feeds)
    except UnsafeURL as e:
        return redirect("/sources", error=e.code)
    if session.scalar(select(NewsSource).where(NewsSource.name == name)):
        return redirect("/sources", error="feed_taken")
    session.add(NewsSource(name=name, kind="rss", url=url[:1000], enabled=True))
    session.commit()
    return redirect("/sources")


@router.post("/sources/{source_id}/toggle")
def toggle_source(source_id: int, session: Session = Depends(get_session)):
    src = source_or_404(session, source_id)
    src.enabled = not src.enabled
    session.commit()
    return redirect("/sources")


@router.post("/sources/{source_id}/refresh")
def refresh_source_now(source_id: int, session: Session = Depends(get_session)):
    src = source_or_404(session, source_id)
    news.refresh_source(session, src, Notifier())
    return redirect("/sources")


@router.post("/sources/{source_id}/delete")
def delete_source(source_id: int, session: Session = Depends(get_session)):
    src = source_or_404(session, source_id)
    if src.builtin:
        raise HTTPException(403, t("A built-in source cannot be deleted, only disabled"))
    session.delete(src)
    session.commit()
    return redirect("/sources")
