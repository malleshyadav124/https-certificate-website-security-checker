from webchecker import create_app


def test_home_page_includes_scan_form_and_results_dashboard():
    client = create_app().test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b'id="scan-form"' in response.data
    assert b'id="results"' in response.data
    assert b"/static/js/app.js" in response.data
    assert b"/static/css/styles.css" in response.data
