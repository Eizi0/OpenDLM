import os
import stat

import pytest

from app import channels, crypto
from app.config import settings
from app.db import SessionLocal
from app.models import Channel, ConfigValue
from app.notifier import Notifier
from app.runtime_config import SPECS, cfg, parse


def test_master_key_is_created_once_with_private_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path / "data"))
    monkeypatch.setattr(settings, "secret_key", "")
    crypto.reset_cache()
    first = crypto.master_key()
    path = tmp_path / "data" / "secret.key"
    assert path.exists() and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    crypto.reset_cache()
    assert crypto.master_key() == first  # relu depuis le fichier, pas régénérée
    crypto.reset_cache()


def test_environment_master_key_takes_over_the_file(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    monkeypatch.setattr(settings, "secret_key", "ma-cle-d-environnement")
    crypto.reset_cache()
    token = crypto.encrypt("secret")
    assert crypto.decrypt(token) == "secret" and not (tmp_path / "secret.key").exists()
    monkeypatch.setattr(settings, "secret_key", "autre-cle")
    crypto.reset_cache()
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(token)
    crypto.reset_cache()


def test_derived_keys_are_independent():
    assert crypto.derive("session") != crypto.derive("fernet") and len(crypto.derive("session")) == 32


@pytest.mark.parametrize("key,raw,expected", [
    ("report_hour", "7", 7), ("report_daily", "on", True), ("report_daily", "0", False),
    ("alert_min_severity", "high", "high"), ("timezone", "Europe/Paris", "Europe/Paris"), ("language", "fr", "fr"),
    ("hibp_api_key", " abc123 ", "abc123"),
])
def test_parse_valid(key, raw, expected):
    assert parse(SPECS[key], raw) == expected


@pytest.mark.parametrize("key,raw", [
    ("report_hour", "24"), ("report_hour", "x"), ("news_interval_minutes", "1"), ("alert_min_severity", "urgent"),
    ("timezone", "Mars/Olympus"), ("language", "de"), ("hibp_api_key", ""), ("hibp_api_key", "a b"), ("hibp_api_key", "x" * 600),
])
def test_parse_invalid(key, raw):
    with pytest.raises(ValueError):
        parse(SPECS[key], raw)


def test_precedence_ui_over_environment_and_clear_restores_it(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "report_hour", 9)
    assert cfg.report_hour == 9 and cfg.source("report_hour") == "default"
    monkeypatch.setenv("OPENDLM_REPORT_HOUR", "9")
    assert cfg.source("report_hour") == "env"
    with SessionLocal() as s:
        cfg.save(s, {"report_hour": "15"})
        assert cfg.report_hour == 15 and cfg.source("report_hour") == "ui"
        cfg.clear(s, "report_hour")
    assert cfg.report_hour == 9 and cfg.source("report_hour") == "env"


def test_secrets_are_encrypted_at_rest(logged_client):
    with SessionLocal() as s:
        cfg.save(s, {"hibp_api_key": "SUPER-SECRET-KEY-123", "report_hour": "8"})
        rows = {r.key: r for r in s.query(ConfigValue)}
    assert "SUPER-SECRET-KEY-123" not in rows["hibp_api_key"].value and rows["hibp_api_key"].secret is True
    assert rows["report_hour"].value == "8" and rows["report_hour"].secret is False
    assert cfg.hibp_api_key == "SUPER-SECRET-KEY-123"  # lue déchiffrée


def test_save_is_atomic_when_one_value_is_invalid(logged_client):
    with SessionLocal() as s:
        with pytest.raises(ValueError):
            cfg.save(s, {"report_hour": "6", "scan_hour": "99"})
        assert s.query(ConfigValue).count() == 0
        with pytest.raises(ValueError):
            cfg.save(s, {"inconnu": "x"})


def test_unreadable_secret_is_ignored_not_fatal(logged_client, monkeypatch):
    with SessionLocal() as s:
        s.add(ConfigValue(key="hibp_api_key", value="pas-un-chiffre-valide", secret=True))
        s.commit()
    cfg.invalidate()
    assert cfg.hibp_api_key == "" and settings.hibp_api_key == ""  # retombe sur l'environnement/défaut


def test_channels_roundtrip_encrypted_and_masked(logged_client, monkeypatch):
    monkeypatch.setattr(settings, "notify_urls", "ntfy://ntfy.sh/depuis-env")
    with SessionLocal() as s:
        ch = channels.add_channel(s, "  Alertes   SOC ", "json://exemple.fr/hook?token=TOP-SECRET")
        assert ch.name == "Alertes SOC" and "TOP-SECRET" not in ch.url_enc
        assert channels.channel_url(ch) == "json://exemple.fr/hook?token=TOP-SECRET"
        ch.enabled = False
        s.commit()
        assert channels.active_urls(s) == []
        ch.enabled = True
        s.commit()
    assert channels.all_urls() == ["json://exemple.fr/hook?token=TOP-SECRET", "ntfy://ntfy.sh/depuis-env"]
    assert channels.mask("json://exemple.fr/hook?token=TOP-SECRET") == "json://…"
    assert Notifier()._urls == channels.all_urls() and Notifier(urls=[])._urls == []


@pytest.mark.parametrize("name,url,reason", [("x", "json://a.fr", "name"), ("Bon nom", "pas-une-url", "url")])
def test_channel_validation(logged_client, name, url, reason):
    with SessionLocal() as s, pytest.raises(ValueError, match=reason):
        channels.add_channel(s, name, url)


def test_duplicate_channel_name_refused(logged_client):
    with SessionLocal() as s:
        channels.add_channel(s, "SOC", "json://a.fr/h")
        with pytest.raises(ValueError, match="duplicate"):
            channels.add_channel(s, "SOC", "json://b.fr/h")
        assert s.query(Channel).count() == 1


def test_session_signing_key_is_derived_not_stored(logged_client):
    from app import security
    assert security.get_secret() == crypto.derive("session").hex()
    with SessionLocal() as s:
        assert s.query(ConfigValue).filter(ConfigValue.key.like("%secret%")).count() == 0
