"""Read-only API: exports and Prometheus metrics. Accepts a bearer token or a signed-in session."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__, api_tokens, exports, health
from ..connectors import build_connectors
from ..deps import get_session
from ..labels import RELIABILITY_CODES
from ..models import Domain, Finding, ScanRun, utcnow
from ..security import SESSION_COOKIE, get_secret, user_from_token

router = APIRouter()
MAX_PARAM = 200


def api_reader(request: Request, session: Session = Depends(get_session)):
    """Bearer token (scripts, Prometheus) or an interface session. Unauthenticated: 401, never a redirect."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        token = api_tokens.authenticate(session, header[7:].strip())
        if token is not None:
            return token
        raise HTTPException(401, "Invalid API token", headers={"WWW-Authenticate": "Bearer"})
    user = user_from_token(session, request.cookies.get(SESSION_COOKIE), get_secret(session))
    if user is not None:
        return user
    raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})


def _since(raw: str | None):
    try:
        return exports.parse_since(raw)
    except ValueError as e:
        raise HTTPException(422, str(e))


def _format(fmt: str) -> str:
    if fmt not in ("json", "csv"):
        raise HTTPException(422, "format must be json or csv")
    return fmt


def _respond(rows: list[dict], fields: list[str], fmt: str, filename: str) -> Response:
    if fmt == "csv":
        return Response(
            exports.to_csv(rows, fields), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )
    return JSONResponse({"count": len(rows), "items": rows}, headers={"Content-Disposition": f'inline; filename="{filename}.json"'})


@router.get("/api/v1/status", dependencies=[Depends(api_reader)])
def status(session: Session = Depends(get_session)):
    now = utcnow()
    last_scan = session.scalar(select(func.max(ScanRun.started_at)))
    verified = bool(session.scalar(select(func.count(Domain.id)).where(Domain.verified.is_(True))))
    stale = health.scanner_stale(last_scan, now, has_work=verified and bool(build_connectors()))
    return {
        "version": __version__,
        "domains": session.scalar(select(func.count(Domain.id))) or 0,
        "open_findings": session.scalar(select(func.count(Finding.id)).where(Finding.status == "new")) or 0,
        "last_scan": exports._iso(last_scan),
        "scanner_stale": stale,
    }


@router.get("/api/v1/findings", dependencies=[Depends(api_reader)])
def findings(
    domain: str | None = None, status: str | None = None, severity: str | None = None,
    since: str | None = None, limit: int = 10_000, format: str = "json", session: Session = Depends(get_session),
):
    fmt = _format(format)
    if status and status not in ("new", "known", "ack", "resolved"):
        raise HTTPException(422, "invalid status")
    if severity and severity not in ("critical", "high", "low"):
        raise HTTPException(422, "invalid severity")
    rows = exports.findings_rows(session, (domain or "")[:MAX_PARAM] or None, status, severity, _since(since), max(1, limit))
    return _respond(rows, exports.FINDING_FIELDS, fmt, "opendlm-findings")


@router.get("/api/v1/news", dependencies=[Depends(api_reader)])
def news(
    source: int | None = None, mentions: int = 0, since: str | None = None,
    limit: int = 10_000, format: str = "json", session: Session = Depends(get_session),
):
    fmt = _format(format)
    rows = exports.news_rows(session, source, bool(mentions), _since(since), max(1, limit))
    return _respond(rows, exports.NEWS_FIELDS, fmt, "opendlm-news")


@router.get("/metrics", dependencies=[Depends(api_reader)])
def metrics(session: Session = Depends(get_session)):
    return PlainTextResponse(exports.metrics_text(session), media_type="text/plain; version=0.0.4; charset=utf-8")
