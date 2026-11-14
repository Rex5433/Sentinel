"""Separate trust boundaries and the owner Timeline against synthetic evidence."""

import json
from pathlib import Path
from threading import Event

from fastapi.testclient import TestClient
import pytest

from app.db import EvidenceStore
from app.main import create_app
from app.wazuh_health import WazuhSettings
from app.wazuh_receiver import INGEST_PATH, MAX_BODY, create_receiver


BIND, PEER = "192.168.56.1", "192.168.56.10"
SECRET = "synthetic-test-token-" + "a" * 32
HEADERS = {"Authorization": "Bearer " + SECRET, "Content-Type": "application/json"}
IMPORT = {"X-Sentinel-Import": "1", "Content-Type": "application/json"}
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "wazuh-alert.synthetic.json"


@pytest.fixture
def configured():
    return WazuhSettings.from_env({
        "SENTINEL_WAZUH_ENABLED": "true",
        "SENTINEL_WAZUH_ALERT_INGEST_ENABLED": "true",
        "SENTINEL_WAZUH_ALERT_INGEST_TOKEN": SECRET,
        "SENTINEL_WAZUH_MANAGER_ID": "test-manager",
    })


def fixture_alert():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def receiver(store, settings, *, peer=PEER, scheme="https"):
    return TestClient(create_receiver(store, settings, BIND, PEER), base_url=f"{scheme}://{BIND}", client=(peer, 50101))


def test_owner_timeline_merges_authenticated_wazuh_with_native_evidence(tmp_path, configured, sign_in, monkeypatch):
    store = EvidenceStore(tmp_path)
    raw = fixture_alert()
    agent_id = raw["agent"]["id"]
    raw["rule"]["description"] = "<img src=x onerror=alert(1)>"
    with receiver(store, configured) as sink:
        accepted = sink.post(INGEST_PATH, headers=HEADERS, json=raw)
        assert accepted.status_code == 201
        event_id = accepted.json()["id"]
        duplicate = sink.post(INGEST_PATH, headers=HEADERS, json=raw)
        assert duplicate.status_code == 200 and duplicate.json() == {"id": event_id, "status": "duplicate"}
        conflict = sink.post(INGEST_PATH, headers=HEADERS, json=raw | {"full_log": "different evidence"})
        assert conflict.status_code == 409
        assert sink.get("/api/wazuh/alerts").status_code == 404
    monkeypatch.setenv("SENTINEL_WAZUH_SSH_MAP", json.dumps({agent_id: {"host": "lab-native"}}))
    app = create_app(tmp_path, wazuh_settings=configured)
    app.state.live_source_health = lambda: {("lab-native", 22): ("reachable", "2026-11-11T12:01:00+00:00")}
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50102)) as client:
        for path in ("/api/wazuh/status", "/api/wazuh/alerts", f"/api/wazuh/events/{event_id}", "/api/timeline"):
            assert client.get(path).status_code == 401
        sign_in(client)
        status = client.get("/api/wazuh/status").raise_for_status().json()
        assert status["state"] == "not_configured" and status["alert_ingest_enabled"]
        assert status["delivery"]["outcome"] == "rejected_409" and SECRET not in json.dumps(status)
        assert client.post(INGEST_PATH, headers=HEADERS | IMPORT, json=raw).status_code == 404
        alert, = client.get("/api/wazuh/alerts").raise_for_status().json()["items"]
        assert alert["raw_event"] == raw and alert["ssh_status"] == "reachable"
        assert alert["rule_description"] == raw["rule"]["description"]
        native = {"Id": 4624, "MachineName": "lab-native", "TimeCreated": "2026-11-10T00:00:00Z",
                  "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing"}
        saved = client.post("/api/uploads?filename=local.json", headers=IMPORT, json=[native]).raise_for_status().json()
        assert client.post(f"/api/analysis/{saved['id']}", headers=IMPORT).status_code == 200
        assert client.get("/api/uploads").json()["total"] == 1
        page = client.get("/api/timeline", params={"limit": 1}).raise_for_status().json()
        assert page["total"] == 2 and page["items"][0]["upload_id"] == saved["id"]
        later = client.get("/api/timeline", params={"offset": 1, "limit": 1}).raise_for_status().json()
        assert later["items"] == [alert]
        detail = client.get("/api/timeline", params={"wazuh_event": event_id}).raise_for_status().json()
        assert detail["items"] == [alert]
        assert client.get("/api/timeline", params={"platform": "windows"}).json()["total"] == 1
        assert client.get("/api/timeline", params={"source_kind": "wazuh", "platform": "windows"}).status_code == 400


@pytest.mark.parametrize(("peer", "scheme", "headers", "expected"), (
    (PEER, "https", {}, 401),
    (PEER, "https", {"Authorization": "Bearer invalid"}, 401),
    ("192.168.56.99", "https", HEADERS | {"X-Forwarded-For": PEER}, 403),
    (PEER, "http", HEADERS | {"X-Forwarded-Proto": "https"}, 403),
    (PEER, "https", HEADERS | {"Host": "other.local"}, 400),
))
def test_receiver_rejects_untrusted_requests(tmp_path, configured, peer, scheme, headers, expected):
    with receiver(EvidenceStore(tmp_path), configured, peer=peer, scheme=scheme) as sink:
        assert sink.post(INGEST_PATH, headers=headers, json=fixture_alert()).status_code == expected


def test_receiver_bounds_and_validates_alerts_and_limits_retries(tmp_path, configured, monkeypatch):
    monkeypatch.setattr("app.wazuh_receiver.REQUESTS_PER_MINUTE", 4)
    store = EvidenceStore(tmp_path)
    with receiver(store, configured) as sink:
        assert sink.post(INGEST_PATH, headers=HEADERS, content=b"{").status_code == 400
        assert sink.post(INGEST_PATH, headers=HEADERS, content=b"x" * (MAX_BODY + 1)).status_code == 413
        assert sink.post(INGEST_PATH, headers=HEADERS | {"Content-Type": "text/plain"}, content=b"bad").status_code == 415
        assert sink.post(INGEST_PATH, headers=HEADERS, json=fixture_alert() | {"agent": {"id": "999"}}).status_code == 201
        assert sink.post(INGEST_PATH, headers=HEADERS, json=fixture_alert()).status_code == 429


def test_default_owner_and_demo_isolation(tmp_path, configured, sign_in):
    with receiver(EvidenceStore(tmp_path), configured) as sink:
        assert sink.post(INGEST_PATH, headers=HEADERS, json=fixture_alert()).status_code == 201
    password = None
    for env, state, count in (({}, "disabled", 0), ({"SENTINEL_WAZUH_ENABLED": "true", "SENTINEL_WAZUH_DEMO": "true"},
                                                   "connected", 1)):
        settings = WazuhSettings.from_env(env)
        app = create_app(tmp_path, wazuh_settings=settings)
        with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50102)) as client:
            if password is None:
                password = sign_in(client)
            else:
                client.post("/api/auth/login", headers=IMPORT,
                            json={"username": "test-owner", "password": password}).raise_for_status()
            status = client.get("/api/wazuh/status").raise_for_status().json()
            if not settings.demo:
                assert status["state"] == state
            assert not status["alert_ingest_enabled"]
            timeline = client.get("/api/timeline").raise_for_status().json()
            assert timeline["total"] == count
            if count:
                assert timeline["items"][0]["manager_id"] == "sentinel-demo"
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("192.168.56.99", 50103)) as peer:
        assert peer.get("/siem").status_code == 403


def test_mock_agent_transitions_enter_the_same_timeline(tmp_path, sign_in, monkeypatch):
    settings = WazuhSettings.from_env({
        "SENTINEL_WAZUH_ENABLED": "true", "SENTINEL_WAZUH_API_URL": "https://manager.test:55000",
        "SENTINEL_WAZUH_API_USERNAME": "fixture-reader", "SENTINEL_WAZUH_API_PASSWORD": "fixture-only",
    })
    sequence = iter(("active", "disconnected", "disconnected", "active"))
    observed = Event()

    class ManagerFixture:
        def fetch_agents(self):
            return [{"id": "002", "name": "fixture-linux", "status": next(sequence)}], None

    async def sample_health(tools):
        import asyncio

        for _ in range(4):
            await tools.refresh_manager()
            # Keep fixture transitions distinct on Windows' wall clock.
            await asyncio.sleep(.02)
        observed.set()

    monkeypatch.setattr("app.wazuh_tools.WazuhTools.monitor", sample_health)
    app = create_app(tmp_path, wazuh_settings=settings, wazuh_client=ManagerFixture())
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50103)) as client:
        sign_in(client)
        assert observed.wait(5)
        status = client.get("/api/wazuh/status").raise_for_status().json()
        assert status["state"] == "connected" and status["counts"]["active"] == 1
        page = client.get("/api/timeline", params={"source_kind": "wazuh"}).raise_for_status().json()
        assert [row["event_type"] for row in page["items"]] == ["agent_disconnected", "agent_recovered"]
        assert status["transitions"] == list(reversed(page["items"]))
