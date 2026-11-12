import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from extract_messages import extract  # noqa: E402

from app import i18n  # noqa: E402
from app.locale.fr import MESSAGES as FR  # noqa: E402

PLACEHOLDER = re.compile(r"%\((\w+)\)[0-9]*[a-z]")


def test_every_message_id_has_a_french_translation():
    missing = sorted(extract() - set(FR))
    assert not missing, "untranslated message ids:\n" + "\n".join(missing)


def test_french_catalog_has_no_stale_entries():
    stale = sorted(set(FR) - extract())
    assert not stale, "French entries no longer used in the code:\n" + "\n".join(stale)


def test_placeholders_match_between_languages():
    for msgid, fr in FR.items():
        assert sorted(PLACEHOLDER.findall(msgid)) == sorted(PLACEHOLDER.findall(fr)), msgid


def test_translation_and_fallback():
    token = i18n.set_language("fr")
    try:
        assert i18n.t("Dashboard") == "Tableau de bord"
        assert i18n.t("%(n)d new", n=3) == "3 nouvelle(s)"
        assert i18n.t("A message that has no translation") == "A message that has no translation"
    finally:
        i18n.reset_language(token)
    token = i18n.set_language("en")
    try:
        assert i18n.t("Dashboard") == "Dashboard" and i18n.t("%(n)d new", n=3) == "3 new"
    finally:
        i18n.reset_language(token)


def test_unknown_language_falls_back_to_default():
    token = i18n.set_language("de")
    try:
        assert i18n.current_language() == "en"
    finally:
        i18n.reset_language(token)


def test_date_formats_follow_language():
    from datetime import date

    for lang, expected in (("en", "2026-11-09"), ("fr", "09/11/2026")):
        token = i18n.set_language(lang)
        try:
            assert i18n.fmt_date(date(2026, 11, 9)) == expected and i18n.fmt_date("2026-11-09") == expected
        finally:
            i18n.reset_language(token)


@pytest.mark.parametrize("lang,month", [("en", "October"), ("fr", "octobre")])
def test_month_names(lang, month):
    token = i18n.set_language(lang)
    try:
        assert i18n.month_name(10) == month
    finally:
        i18n.reset_language(token)


# --- Language selection in the running app ----------------------------------------------------


def test_default_language_is_english_and_html_lang_matches(logged_client):
    page = logged_client.get("/")
    assert '<html lang="en">' in page.text and "Dashboard" in page.text and "Tableau de bord" not in page.text


def test_language_switch_sets_cookie_and_user_preference(logged_client):
    r = logged_client.get("/lang/fr", headers={"referer": "http://testserver/news"})
    assert r.status_code == 303 and r.headers["location"] == "/news" and "opendlm_lang=fr" in r.headers["set-cookie"]
    page = logged_client.get("/")
    assert '<html lang="fr">' in page.text and "Tableau de bord" in page.text and "Actus leaks" in page.text
    # The preference is stored on the user: a fresh browser (no language cookie) still gets French.
    logged_client.cookies.delete("opendlm_lang")
    assert "Tableau de bord" in logged_client.get("/").text
    logged_client.get("/lang/en")
    assert "Dashboard" in logged_client.get("/").text


def test_language_switch_never_redirects_off_site(logged_client):
    for referer in ("http://evil.example/steal", "//evil.example/x", "javascript:alert(1)"):
        r = logged_client.get("/lang/en", headers={"referer": referer})
        assert r.headers["location"] == "/"
    assert logged_client.get("/lang/xx").status_code == 404


def test_login_page_follows_language_cookie(client):
    client.post("/setup", data={"username": "admin", "password": "un-mot-de-passe-solide-123", "confirm": "un-mot-de-passe-solide-123"})
    client.cookies.clear()
    client.cookies.set("opendlm_lang", "fr")
    page = client.get("/login")
    assert "Se connecter" in page.text and '<html lang="fr">' in page.text
    wrong = client.post("/login", data={"username": "admin", "password": "mauvais"})
    assert "Nom d&#39;utilisateur ou mot de passe incorrect." in wrong.text or "mot de passe incorrect" in wrong.text


def test_instance_default_language_applies_without_preference(logged_client, cfg_override):
    cfg_override(language="fr")
    logged_client.cookies.delete("opendlm_lang")
    from app.db import SessionLocal
    from app.models import User
    with SessionLocal() as s:
        s.query(User).update({"language": None})
        s.commit()
    assert "Tableau de bord" in logged_client.get("/").text


def test_report_is_rendered_in_the_viewer_language(logged_client):
    rid = logged_client.post("/reports/generate", data={"kind": "monthly"}).headers["location"].rsplit("/", 1)[1]
    assert "Nothing to report" in logged_client.get(f"/reports/{rid}").text
    logged_client.get("/lang/fr")
    page = logged_client.get(f"/reports/{rid}")
    assert "Rien à signaler" in page.text and "Rapports" in page.text
    assert logged_client.get(f"/reports/{rid}/export.md").text.startswith("# Mensuel report") is False
    assert "Rapport" in logged_client.get(f"/reports/{rid}/export.md").text.splitlines()[0]
