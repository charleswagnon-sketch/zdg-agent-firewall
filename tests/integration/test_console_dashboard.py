"""Integration checks for the developer console shell."""

from __future__ import annotations


def test_dashboard_shell_serves_without_admin_token(make_client):
    with make_client() as client:
        response = client.get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "ZDG-FR Developer Edition" in html
    assert "Replay governed agent runs" in html
    assert "/dashboard-assets/console.css" in html
    assert "/dashboard-assets/console.js" in html


def test_console_alias_serves_same_shell(make_client):
    with make_client() as client:
        response = client.get("/console")

    assert response.status_code == 200
    assert "ZDG-FR Developer Edition" in response.text
    assert "Pending Approvals" in response.text


def test_dashboard_assets_are_served(make_client):
    with make_client() as client:
        css_response = client.get("/dashboard-assets/console.css")
        js_response = client.get("/dashboard-assets/console.js")

    assert css_response.status_code == 200
    assert "text/css" in css_response.headers["content-type"]
    assert ".shell" in css_response.text

    assert js_response.status_code == 200
    assert "javascript" in js_response.headers["content-type"]
    assert "refreshAll" in js_response.text