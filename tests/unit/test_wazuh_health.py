"""Wazuh manager contract tests using only synthetic responses and local SQLite."""

from base64 import b64encode
import json
import ssl
from urllib.parse import parse_qs, urlsplit

import pytest

from app import wazuh_health as health
from app.db import EvidenceStore
from app.wazuh_events import initialize as initialize_events, page_events


ENV = {
    "SENTINEL_WAZUH_ENABLED": "true",
    "SENTINEL_WAZUH_API_URL": "https://manager.example.test:55000",
    "SENTINEL_WAZUH_API_USERNAME": "test-reader",
    "SENTINEL_WAZUH_API_PASSWORD": "unit-test-only-password",
    "SENTINEL_WAZUH_MANAGER_ID": "mock-manager",
}


def agent(identifier="001", status="active", name="lab-linux"):
    return {"id": identifier, "status": status, "name": name, "ip": "192.0.2.40",
            "lastKeepAlive": "2026-11-11T14:00:00+02:00",
            "dateAdd": "2026-11-10T12:00:00Z", "os": {"name": "Ubuntu", "version": "24.04"}}


@pytest.fixture
def store(tmp_path):
    store = EvidenceStore(tmp_path)
    store.initialize()
    initialize_events(store)
    return store


def test_disabled_and_incomplete_settings_do_not_construct_network_client(store, monkeypatch):
    def unexpected(*args):
        pytest.fail("Disabled configuration constructed a network client.")

    monkeypatch.setattr(health, "WazuhApiClient", unexpected)
    disabled = health.WazuhSettings.from_env({"SENTINEL_WAZUH_ALERT_INGEST_ENABLED": "true"})
    assert not disabled.enabled and not disabled.alert_ingest_enabled
    invalid = ENV | {"SENTINEL_WAZUH_API_URL": "https://test:secret@manager.example.test:55000"}
    for settings, expected in [(disabled, "disabled"), (health.WazuhSettings.from_env(invalid), "not_configured")]:
        monitor = health.WazuhHealth(store, settings)
        monitor.initialize()
        monitor.refresh()
        status = monitor.status()
        assert status["state"] == expected and status["stale"]
        assert "secret" not in json.dumps(status)


def test_demo_uses_separate_source_and_no_credentials(store, monkeypatch):
    def unexpected(*args):
        pytest.fail("Demo mode constructed a network client.")

    monkeypatch.setattr(health, "WazuhApiClient", unexpected)
    settings = health.WazuhSettings.from_env(ENV | {"SENTINEL_WAZUH_DEMO": "1"})
    assert settings.demo and settings.manager_id == "sentinel-demo" and not settings.password
    monitor = health.WazuhHealth(store, settings)
    monitor.initialize()
    monitor.refresh()
    result = monitor.status()
    assert result["demo"] and result["state"] == "connected" and not result["stale"]
    assert result["counts"] == dict(active=1, disconnected=1, pending=1, never_connected=1, unknown=0)
    assert page_events(store, manager_id="sentinel-demo")["total"] == 0


def test_tls_cannot_be_disabled_and_ingest_settings_are_independent(store):
    settings = health.WazuhSettings.from_env(ENV | {
        "SENTINEL_WAZUH_VERIFY_TLS": "false",
        "SENTINEL_WAZUH_ALERT_INGEST_ENABLED": "true",
        "SENTINEL_WAZUH_ALERT_INGEST_TOKEN": "a" * 32,
    })
    assert settings.alert_ingest_enabled and settings.error
    assert settings.alert_ingest_token not in repr(settings)
    monitor = health.WazuhHealth(store, settings)
    monitor.initialize()
    assert monitor.status()["state"] == "not_configured"


def response(data):
    return {"error": 0, "data": data}


class FakeResponse:
    def __init__(self, status, data):
        self.status = status
        self.raw = json.dumps(data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read1(self, count):
        result, self.raw = self.raw[:count], self.raw[count:]
        return result


def mock_https(monkeypatch, replies):
    calls = []

    class Connection:
        def __init__(self, host, port, *, context, timeout):
            assert host == "manager.example.test" and port == 55000
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            assert 0 < timeout <= health.REQUEST_SECONDS

        def request(self, method, path, *, headers):
            calls.append((method, path, headers["Authorization"]))

        def getresponse(self):
            item = next(replies)
            if isinstance(item, Exception):
                raise item
            status, body = item
            return FakeResponse(status, body)

        def close(self):
            pass

    monkeypatch.setattr(health, "HTTPSConnection", Connection)
    return calls


def test_api_paginates_and_reauthenticates_after_401(monkeypatch):
    monkeypatch.setattr(health, "PAGE_SIZE", 2)
    calls = mock_https(monkeypatch, iter([
        (200, response({"token": "unit-test-token-1"})),
        (200, response({"affected_items": [agent(), agent("002")], "total_affected_items": 3})),
        (401, {"error": 1}),
        (200, response({"token": "unit-test-token-2"})),
        (200, response({"affected_items": [agent("003")], "total_affected_items": 3})),
        (200, response({"connection": dict(active=3, disconnected=0, never_connected=0, pending=0, total=3)})),
    ]))
    client = health.WazuhApiClient(health.WazuhSettings.from_env(ENV))
    rows, counts = client.fetch_agents()
    assert [row["id"] for row in rows] == ["001", "002", "003"]
    assert counts == dict(active=3, disconnected=0, never_connected=0, pending=0)
    expected = b64encode(b"test-reader:unit-test-only-password").decode()
    assert calls[0] == calls[3] == ("POST", "/security/user/authenticate", f"Basic {expected}")
    assert [parse_qs(urlsplit(calls[index][1]).query)["offset"] for index in (1, 2, 4)] == [["0"], ["2"], ["2"]]
    assert [calls[index][2] for index in (1, 2, 4, 5)] == [
        "Bearer unit-test-token-1", "Bearer unit-test-token-1", "Bearer unit-test-token-2", "Bearer unit-test-token-2",
    ]


@pytest.mark.parametrize(("status", "data", "message"), [
    (302, {}, "HTTP 302"),
    (200, response({"affected_items": [agent()], "total_affected_items": 2}), "partial"),
    (200, response({"affected_items": [agent(), agent()], "total_affected_items": 2}), "repeated"),
])
def test_api_rejects_redirect_and_inconsistent_roster(monkeypatch, status, data, message):
    calls = mock_https(monkeypatch, iter([(200, response({"token": "unit-token"})), (status, data)]))
    with pytest.raises(health.WazuhApiError, match=message):
        health.WazuhApiClient(health.WazuhSettings.from_env(ENV)).fetch_agents()
    assert len(calls) == 2


@pytest.mark.parametrize(("failure", "state"), [
    (TimeoutError("private upstream failure"), "timeout"),
    (ssl.SSLCertVerificationError("private TLS detail"), "tls_error"),
])
def test_transport_failures_expose_only_sanitized_diagnostics(monkeypatch, failure, state):
    calls = mock_https(monkeypatch, iter([failure]))
    with pytest.raises(health.WazuhApiError) as caught:
        health.WazuhApiClient(health.WazuhSettings.from_env(ENV)).fetch_agents()
    assert caught.value.state == state and "private" not in str(caught.value)
    assert len(calls) == 1


def test_agent_lifecycle_persists_without_false_outage_events(store):
    class MockClient:
        def fetch_agents(self):
            if isinstance(self.status, Exception):
                raise self.status
            return [agent("000"), agent(status=self.status), agent("009", "new status")], None

    client = MockClient()
    settings = health.WazuhSettings.from_env(ENV | {"SENTINEL_WAZUH_AGENT_DISCONNECT_SECONDS": "900"})
    monitor = health.WazuhHealth(store, settings, client=client)
    monitor.initialize()
    client.status = "active"
    monitor.refresh()
    initial = monitor.status()
    assert initial["state"] == "connected" and initial["counts"]["active"] == initial["counts"]["unknown"] == 1
    assert initial["disconnected_after_seconds"] == 900
    assert initial["agents"][0]["last_keepalive"] == "2026-11-11T12:00:00.000000+00:00"
    assert initial["agents"][0]["os"] == "Ubuntu 24.04"
    assert page_events(store)["total"] == 0

    client.status = health.WazuhApiError("Timed out.", state="unreachable")
    monitor.refresh()
    unavailable = monitor.status()
    assert unavailable["state"] == "unreachable" and unavailable["stale"]
    assert unavailable["observed_at"] == initial["observed_at"]
    assert unavailable["agents"] == initial["agents"] and page_events(store)["total"] == 0

    client.status = "disconnected"
    monitor = health.WazuhHealth(store, settings, client=client)
    assert monitor.status()["stale"]
    monitor.refresh()
    monitor.refresh()
    assert monitor.status()["counts"]["disconnected"] == 1
    disconnected = monitor.status()["agents"][0]["changed_at"]
    assert disconnected is not None and page_events(store)["total"] == 1

    client.status = health.WazuhApiError("Read-only access denied.", status_code=401)
    monitor.refresh()
    degraded = monitor.status()
    assert degraded["state"] == "degraded" and degraded["stale"]
    assert degraded["agents"][0]["changed_at"] == disconnected and page_events(store)["total"] == 1

    client.status = "active"
    monitor.refresh()
    monitor.refresh()
    events = page_events(store)
    assert events["total"] == 2
    assert {row["event_type"] for row in events["items"]} == {"agent_disconnected", "agent_recovered"}
