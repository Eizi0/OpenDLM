"""Notification channels."""

from fastapi import APIRouter, Depends, Request

from .. import channels
from ..deps import require_user
from ..i18n import t
from ..notifier import Notifier
from ..runtime_config import cfg
from .common import redirect, render

router = APIRouter(dependencies=[Depends(require_user)])


@router.get("/notifications")
def notifications_page(request: Request):
    masked = [channels.mask(u) for u in channels.all_urls()]
    return render(request, "notifications.html", {"channels": masked, "min_severity": cfg.alert_min_severity})


@router.post("/notifications/test")
def notifications_test():
    if not channels.all_urls():
        return redirect("/notifications", error="no_channel")
    ok = Notifier().send(t("[OpenDLM] Test message"), t("If you can read this, this channel receives OpenDLM alerts and reports."))
    return redirect("/notifications", notice="test_sent" if ok else None, error=None if ok else "test_failed")
