from app import scheduler


def hours(sched, job_id):
    job = sched.get_job(job_id)
    return job and str(job.trigger)


def test_schedule_follows_configuration_and_can_be_reapplied_live(cfg_override):
    cfg_override(scan_hour=5, report_hour=8, report_daily=True, report_monthly=True, news_interval_minutes=45, timezone="Europe/Paris")
    sched = scheduler.start()  # démarrage réel, comme dans l'application
    try:
        assert "hour='5'" in hours(sched, "daily-scan") and "hour='8'" in hours(sched, "report-daily")
        assert "day='1'" in hours(sched, "report-monthly") and "0:45:00" in hours(sched, "news")
        # Changement à chaud depuis l'interface : le planificateur tourne déjà.
        cfg_override(scan_hour=3, report_hour=10, report_daily=False, news_interval_minutes=15)
        scheduler.apply_schedule()
        assert "hour='3'" in hours(sched, "daily-scan") and "hour='10'" in hours(sched, "report-monthly")
        assert sched.get_job("report-daily") is None and "0:15:00" in hours(sched, "news")
        cfg_override(report_daily=True)
        scheduler.apply_schedule()
        assert sched.get_job("report-daily") is not None
    finally:
        sched.shutdown(wait=False)
        scheduler._scheduler = None


def test_apply_schedule_without_scheduler_is_a_noop():
    scheduler._scheduler = None
    scheduler.apply_schedule()
