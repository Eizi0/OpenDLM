from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app import health

NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)


def run(days_ago=0, hour=6, ok=True, baseline=False, new=0):
    started = (NOW - timedelta(days=days_ago)).replace(hour=hour)
    return SimpleNamespace(started_at=started, ok=ok, baseline=baseline, new_count=new)


def test_bars_cover_sixty_days_oldest_first():
    bars = health.build_bars([run(0)], NOW)
    assert len(bars) == 60 and bars[-1]["label"].startswith("2026-11-12") and bars[0]["label"].startswith("2026-09-14")


def test_priority_bad_over_warn_over_ok_over_none():
    bars = health.build_bars([
        run(0, ok=True, new=2), run(0, ok=False),   # aujourd'hui : fuite ET échec → bad
        run(1, ok=True), run(1, ok=False),          # hier : réussite + échec → partiel
        run(2, ok=True),                            # avant-hier : propre
    ], NOW)
    assert [b["cls"] for b in bars[-4:]] == ["none", "ok", "warn", "bad"]
    assert "2 new leak(s)" in bars[-1]["label"]


def test_baseline_run_is_not_a_leak_even_with_findings():
    bars = health.build_bars([run(0, baseline=True, new=0), run(1, baseline=True, new=40)], NOW)
    assert [b["cls"] for b in bars[-2:]] == ["ok", "ok"]


def test_days_follow_configured_timezone():
    # 23:30 UTC le 11 novembre = 00:30 le 12 à Paris : doit compter pour le 12.
    r = SimpleNamespace(started_at=datetime(2026, 11, 11, 23, 30, tzinfo=timezone.utc), ok=True, baseline=False, new_count=1)
    assert health.build_bars([r], NOW)[-1]["cls"] == "bad"


def test_clean_streak():
    bars = health.build_bars([run(0), run(1), run(2), run(3, new=1), run(4)], NOW)
    assert health.clean_streak(bars) == 3
    assert health.clean_streak(health.build_bars([run(0, new=1)], NOW)) == 0
    assert health.clean_streak(health.build_bars([], NOW)) == 0


def test_scanner_stale():
    assert health.scanner_stale(None, NOW, has_work=False) is False  # rien à scanner : pas d'alerte
    assert health.scanner_stale(None, NOW, has_work=True) is True
    assert health.scanner_stale(NOW - timedelta(hours=25), NOW, True) is False
    assert health.scanner_stale(NOW - timedelta(hours=27), NOW, True) is True
    assert health.scanner_stale((NOW - timedelta(hours=1)).replace(tzinfo=None), NOW, True) is False  # SQLite renvoie des dates naïves
