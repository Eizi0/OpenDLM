"""News feed and watch words."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from ..deps import get_session, require_user
from ..i18n import t
from ..labels import RELIABILITY_CODES
from ..models import NewsItem, NewsSource, WatchWord, utcnow
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_user)])
PAGE_SIZE = 30


@router.get("/news")
def news_page(
    request: Request,
    source: int | None = None,
    reliability: str | None = None,
    mentions: int = 0,
    page: int = 1,
    session: Session = Depends(get_session),
):
    page = max(page, 1)
    query = select(NewsItem).join(NewsSource)
    if source:
        query = query.where(NewsItem.source_id == source)
    if reliability in RELIABILITY_CODES:
        query = query.where(NewsItem.reliability == reliability)
    if mentions:
        # Cast to text: PostgreSQL's JSON type has no equality operator.
        query = query.where(cast(NewsItem.matched, String) != "[]")
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = session.scalars(
        query.order_by(NewsItem.published_at.desc().nulls_last(), NewsItem.id.desc()).limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)
    ).all()
    recent = session.scalars(
        select(NewsItem).where(NewsItem.first_seen > utcnow() - timedelta(days=7)).order_by(NewsItem.first_seen.desc()).limit(50)
    ).all()
    return render(
        request, "news.html",
        {
            "items": items, "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE)),
            "sources": session.scalars(select(NewsSource).order_by(NewsSource.name)).all(),
            "words": session.scalars(select(WatchWord).order_by(WatchWord.term)).all(),
            "filters": {"source": source, "reliability": reliability, "mentions": mentions},
            "recent_mentions": [i for i in recent if i.matched][:5],
        },
    )


@router.post("/watch-words")
def add_watch_word(term: str = Form(...), session: Session = Depends(get_session)):
    term = " ".join(term.split())
    if not (3 <= len(term) <= 120):
        raise HTTPException(422, t("A watched word must be 3 to 120 characters long"))
    if not session.scalar(select(WatchWord).where(func.lower(WatchWord.term) == term.lower())):
        session.add(WatchWord(term=term))
        session.commit()
    return redirect("/news")


@router.post("/watch-words/{word_id}/delete")
def delete_watch_word(word_id: int, session: Session = Depends(get_session)):
    word = session.get(WatchWord, word_id)
    if word:
        session.delete(word)
        session.commit()
    return redirect("/news")
