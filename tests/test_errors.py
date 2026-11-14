def test_browser_gets_an_html_error_page(logged_client):
    r = logged_client.get("/domains/999", headers={"accept": "text/html"})
    assert r.status_code == 404 and "text/html" in r.headers["content-type"]
    assert "Page not found" in r.text and "Unknown domain" in r.text and "Back to the dashboard" in r.text
    r = logged_client.get("/nowhere", headers={"accept": "text/html"})
    assert r.status_code == 404 and "does not exist" in r.text


def test_missing_form_field_is_a_page_not_json(logged_client):
    r = logged_client.post("/domains", data={}, headers={"accept": "text/html"})
    assert r.status_code == 422 and "Invalid input" in r.text


def test_api_and_metrics_keep_json(logged_client):
    r = logged_client.get("/api/v1/unknown", headers={"accept": "text/html"})
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")
    r = logged_client.get("/domains/999", headers={"accept": "application/json"})
    assert r.json()["detail"]


def test_error_page_is_translated(logged_client):
    logged_client.get("/lang/fr")
    r = logged_client.get("/domains/999", headers={"accept": "text/html"})
    assert "Page introuvable" in r.text
