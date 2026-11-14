import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import create_app

HEADERS = {"X-Sentinel-Import": "1", "Content-Type": "application/octet-stream"}
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def client(tmp_path, sign_in):
    with TestClient(create_app(tmp_path / "storage"), base_url="http://127.0.0.1", client=("127.0.0.1", 50101)) as client:
        sign_in(client)
        yield client


def upload(client, records):
    response = client.post("/api/uploads?format=windows-json&filename=timeline.json", headers=HEADERS,
                           content=json.dumps(records).encode())
    assert response.status_code == 201, response.text
    return response.json()


def test_timeline_orders_utc_microseconds_unknowns_and_pages(client):
    item = upload(client, [
        {"Id": 1, "TimeCreated": "2026-11-03T15:00:00.5Z"},
        {"Id": 2, "TimeCreated": "2026-11-03T09:00:00-06:00"},
        {"Id": 3},
        {"Id": 4, "TimeCreated": "2026-11-03T15:00:01Z"},
    ])
    timeline = client.get("/api/timeline?limit=2").json()
    assert timeline["total"] == 4
    assert [e["windows_event_id"] for e in timeline["items"]] == [2, 1]
    second = client.get("/api/timeline?offset=2&limit=2").json()
    assert [e["windows_event_id"] for e in second["items"]] == [4, 3]
    assert second["items"][-1]["timestamp_utc"] is None
    assert client.get(f"/api/timeline?upload_id={item['id']}").json()["total"] == 4


def test_timeline_exact_filters_and_inclusive_time_range(client):
    upload(client, [
        {"Id": 4625, "MachineName": "host-a", "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-11-03T15:00:00Z"},
        {"Id": 4624, "MachineName": "host-b", "TimeCreated": "2026-11-03T15:00:01Z"},
        {"Id": 1, "MachineName": "host-a"},
    ])
    query = {"host": "host-a", "platform": "windows", "event_type": "auth_failure", "source": "Security",
             "start": "2026-11-03T09:00:00-06:00", "end": "2026-11-03T15:00:00Z"}
    result = client.get("/api/timeline", params=query)
    assert result.status_code == 200, result.text
    assert result.json()["total"] == 1
    assert client.get("/api/timeline?host=host").json()["total"] == 0
    assert client.get("/api/timeline?platform=linux").json()["total"] == 0
    assert client.get("/api/timeline?start=2026-11-03T15:00:00Z").json()["total"] == 2
    assert client.get("/api/timeline?host=%27%20OR%201%3D1%20--").json()["total"] == 0


@pytest.mark.parametrize("params,code", [
    ({"start": "2026-11-03T15:00:00"}, 422),
    ({"start": "12345"}, 422),
    ({"start": "not-time"}, 422),
    ({"start": "2026-11-04T00:00:00Z", "end": "2026-11-03T00:00:00Z"}, 400),
    ({"limit": 101}, 422),
    ({"platform": "other"}, 422),
])
def test_bad_timeline_filters(client, params, code):
    assert client.get("/api/timeline", params=params).status_code == code


def test_json_and_text_reports_preserve_provenance_and_no_model_claims(client):
    source = (FIXTURES / "linux_auth.txt").read_bytes()
    response = client.post("/api/uploads?format=linux-text&filename=auth.txt", content=source, headers=HEADERS)
    item = response.json()
    report = client.get(f"/api/reports/{item['id']}?format=json")
    assert report.status_code == 200
    assert report.headers["content-disposition"].startswith("attachment;")
    body = report.json()
    assert body["source"]["sha256"] == item["sha256"]
    assert len(body["events"]) == 7 and len(body["rejected"]) == 1
    assert body["events"][0]["raw_record"] == source.decode().splitlines(keepends=True)[0]
    assert body["model_version"] is None and body["model_ready"] is False
    assert body["competition_use_enabled"] is False
    assert body["parser_version"] == "exports-v2"
    text = client.get(f"/api/reports/{item['id']}?format=text")
    assert text.status_code == 200 and text.headers["content-type"].startswith("text/plain")
    assert item["sha256"] in text.text and "REJECTED" in text.text
    assert "no incident detection performed" in text.text
    assert client.get(f"/api/reports/{item['id']}?format=html").status_code == 422
    assert client.get("/api/reports/nonexistent").status_code == 404
