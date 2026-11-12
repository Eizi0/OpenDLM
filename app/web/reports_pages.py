"""Reports: archive, preview, export, delivery."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import channels, reports
from ..deps import get_session, require_user
from ..i18n import current_language, t
from ..models import Report
from ..notifier import Notifier
from ..runtime_config import cfg
from .common import redirect, render, templates

router = APIRouter(dependencies=[Depends(require_user)])


def report_or_404(session: Session, report_id: int) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, t("Unknown report"))
    return report


@router.get("/reports")
@router.get("/reports/{report_id}")
def reports_page(request: Request, report_id: int | None = None, session: Session = Depends(get_session)):
    archive = session.scalars(select(Report).order_by(Report.created_at.desc()).limit(60)).all()
    selected = report_or_404(session, report_id) if report_id else (archive[0] if archive else None)
    schedule = {
        "daily": cfg.report_daily, "monthly": cfg.report_monthly, "hour": cfg.report_hour,
        "timezone": cfg.timezone, "send_empty": cfg.report_send_empty,
        "channels": len(channels.all_urls()), "min_severity": cfg.alert_min_severity,
    }
    return render(request, "reports.html", {"archive": archive, "selected": selected, "schedule": schedule})


@router.post("/reports/generate")
def generate_report(kind: str = Form(...), session: Session = Depends(get_session)):
    if kind not in reports.KINDS:
        raise HTTPException(422, t("Invalid report type"))
    report = reports.build_report(session, kind)
    return redirect(f"/reports/{report.id}")


@router.post("/reports/{report_id}/send")
def send_report_now(report_id: int, session: Session = Depends(get_session)):
    report = report_or_404(session, report_id)
    if not channels.all_urls():
        return redirect(f"/reports/{report.id}", error="no_channel")
    ok = reports.send_report(session, report, Notifier())
    return redirect(f"/reports/{report.id}", notice="report_sent" if ok else None, error=None if ok else "report_failed")


def _export_name(report: Report, ext: str) -> str:
    return f"opendlm-report-{report.kind}-{report.created_at.strftime('%Y%m%d')}.{ext}"


@router.get("/reports/{report_id}/export.md")
def export_markdown(report_id: int, session: Session = Depends(get_session)):
    report = report_or_404(session, report_id)
    return PlainTextResponse(
        reports.render_markdown(report), media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_export_name(report, "md")}"'},
    )


@router.get("/reports/{report_id}/export.html")
def export_html(request: Request, report_id: int, session: Session = Depends(get_session)):
    report = report_or_404(session, report_id)
    response = templates.TemplateResponse(request, "report_doc.html", {"report": report, "d": report.data, "lang": current_language()})
    response.headers["Content-Disposition"] = f'attachment; filename="{_export_name(report, "html")}"'
    return response
