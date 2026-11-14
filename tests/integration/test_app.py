import re

import pytest
from fastapi.testclient import TestClient

from app.main import create_app, instance_id


@pytest.fixture
def client(tmp_path, sign_in):
    app = create_app(tmp_path / "storage")
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        sign_in(client)
        yield client


def test_health_reports_service_live_but_model_and_competition_disabled(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "service": "team84-sentinel",
        "status": "ok",
        "phase": "deterministic_triage",
        "model_ready": False,
        "competition_use_enabled": False,
        "ui_version": "sentinel-v6",
        "authentication_required": True,
        "instance_id": instance_id(client.app.state.store.root),
        "rehearsal_enabled": False,
        "live_collection_enabled": False,
    }


def test_landing_page_and_local_stylesheet(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Roar Cyber | Team 84" in response.text
    assert 'href="/mysql"' in response.text and 'href="/live"' in response.text
    assert "scored ai" not in response.text.casefold()
    assert 'href="/static/style.css"' in response.text
    css = client.get("/static/style.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert client.get("/static/app.js").status_code == 200


@pytest.mark.parametrize(("route", "heading"), [("/mysql", "MySQL"), ("/live", "Live logs"),
                                                ("/siem", "Wazuh Tools"), ("/agents", "SIEM Agents")])
def test_beta_pages_are_linked_and_protected(client, route, heading):
    page = client.get(route)
    assert page.status_code == 200 and heading in page.text
    assert "Roar Cyber | Team 84" in page.text
    client.cookies.clear()
    for path in (route, f"/static{route}.html"):
        assert client.get(path, follow_redirects=False).headers["location"] == "/login"


def test_tool_pages_share_tab_order_and_highlight(client):
    for route, current in [("/", "Logs"), ("/live", "Live logs"), ("/mysql", "MySQL"),
                           ("/changes", "Changes"), ("/siem", "Wazuh Tools"), ("/agents", "SIEM Agents")]:
        page = client.get(route).raise_for_status().text
        nav = re.search(r'<nav class="tool-nav"[^>]*>(.*?)</nav>', page, re.S)[1]
        tabs = re.findall(r"<(?:button|a)\b([^>]*)>([^<]+)</(?:button|a)>", nav)
        assert [label for _, label in tabs] == ["Logs", "Live logs", "Network", "Timeline", "Commands", "MySQL",
                                              "Changes", "Wazuh Tools", "SIEM Agents"]
        assert [label for attrs, label in tabs if 'aria-current="page"' in attrs] == [current]


@pytest.mark.parametrize("path", ["/api/collect/linux", "/api/execute"])
def test_future_write_routes_are_absent(client, path):
    assert client.post(path, json={}, headers={"X-Sentinel-Import": "1"}).status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_cdn_backed_documentation_is_disabled(client, path):
    assert client.get(path).status_code == 404


def test_health_does_not_accept_mutation(client):
    assert client.post("/health", json={}, headers={"X-Sentinel-Import": "1"}).status_code == 405
