"""Sources: news feeds and leak connectors status."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import channels, news
from ..config import settings
from ..deps import get_session, require_admin
from ..i18n import N_, t
from ..models import NewsItem, NewsSource
from ..notifier import Notifier
from ..runtime_config import cfg
from ..ssrf import UnsafeURL, check_url
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_admin)])

KIND_LABEL = {"rss": N_("RSS/Atom feed"), "ransomware_live": N_("ransomware.live PRO API")}


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


@router.get("/sources")
def sources_page(request: Request, session: Session = Depends(get_session)):
    rows = []
    for src in session.scalars(select(NewsSource).order_by(NewsSource.builtin.desc(), NewsSource.name)):
        label, tone = source_status(src)
        rows.append({"src": src, "status": label, "tone": tone, "kind": t(KIND_LABEL.get(src.kind, src.kind)),
                     "count": session.scalar(select(func.count(NewsItem.id)).where(NewsItem.source_id == src.id)) or 0})
    leak_sources = [
        {"name": "Have I Been Pwned", "ok": bool(cfg.hibp_api_key), "detail": t("API key set") if cfg.hibp_api_key else t("API key missing")},
        {"name": t("Hudson Rock (infostealer logs)"), "ok": bool(cfg.hudson_rock_key), "detail": t("API key set") if cfg.hudson_rock_key else t("API key missing")},
        {"name": t("Demo connector"), "ok": settings.demo, "detail": t("Active: fictional data") if settings.demo else t("Disabled")},
    ]
    return render(request, "sources.html", {"rows": rows, "leak_sources": leak_sources, "notify_count": len(channels.all_urls())})


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
