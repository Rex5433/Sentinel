"""Password workflow, privacy, lifecycle, and unchanged evidence processing."""

import json

from fastapi.testclient import TestClient
import pytest

from app import ssh_setup, ssh_collection, live_logs
from app.main import create_app
from app.password_ssh import PasswordSession


HEADERS = {"X-Sentinel-Import": "1"}
BODY = {"ssh_command": "ssh reader@lab.example.test -p 2222", "platform": "linux", "authentication": "auto"}
SECRET = "SSH-test-only-sensitive-password"


@pytest.fixture
def connected(tmp_path, sign_in, monkeypatch):
    sessions = []
    class Session:
        active = True
        def touch(self):
            assert self.active
        def close(self):
            self.active = False
        def collect(self, options):
            return b"".join((json.dumps({"__CURSOR": str(i), "__REALTIME_TIMESTAMP": "1793970000000000",
                "_HOSTNAME": "test-host", "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Failed password for reader from 192.0.2.8 port 4180 ssh2"}) + "\n").encode() for i in range(5))
    def authenticate(target, password):
        assert password == SECRET
        session = Session()
        sessions.append(session)
        return session
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda *_: b"lab.example.test ssh-ed25519 verified\n")
    monkeypatch.setattr(PasswordSession, "connect", authenticate)
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as client:
        sign_in(client)
        yield client, sessions


def test_auto_fallback_password_watch_flags_save_and_stop(connected, monkeypatch):
    client, sessions = connected
    def rejected(*args, **kwargs):
        raise ssh_collection.KeyAuthenticationRequired("Key was rejected.")
    monkeypatch.setattr(ssh_setup, "collect_output", rejected)
    result = client.post("/api/live/connect", json=BODY, headers=HEADERS).json()
    assert result["password_required"] and not sessions
    assert client.post("/api/live/password", json=BODY | {"password": SECRET}).status_code == 403
    response = client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS)
    status = response.raise_for_status().json()
    assert status["authentication"] == "password" and not status["password_required"]
    assert SECRET not in response.text
    started = client.post("/api/live/start?host=lab.example.test&port=2222", headers=HEADERS).json()["id"]
    poll = client.post(f"/api/live/{started}/poll", headers=HEADERS).raise_for_status().json()
    assert poll["parsed"] == 5 and poll["review"]["finding_count"] == 1
    client.post(f"/api/live/{started}/stop", headers=HEADERS).raise_for_status()
    assert not sessions[0].active
    client.post(f"/api/live/{started}/save", headers=HEADERS).raise_for_status()
    assert client.get("/api/live/status").json()["password_required"]
    assert client.post("/api/live/start?host=lab.example.test&port=2222", headers=HEADERS).status_code == 409
    for path in client.app.state.store.root.rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes()


@pytest.mark.parametrize("override", [{"platform": "bad"}, {"password": 42}, {"password": ""}, {"ssh_command": "ssh reader@host arbitrary-command"}])
def test_password_validation_never_echoes_secrets_or_attempts_login(connected, override):
    client, sessions = connected
    response = client.post("/api/live/password", json=BODY | {"password": SECRET} | override, headers=HEADERS)
    assert response.status_code == 400 and SECRET not in response.text
    assert not sessions


def test_password_request_is_bounded_and_requires_login(connected):
    client, sessions = connected
    response = client.post("/api/live/password", content=(SECRET * 500).encode(), headers=HEADERS | {"Content-Type": "application/json"})
    assert response.status_code == 413 and SECRET not in response.text
    assert not sessions
    client.post("/api/auth/logout", headers=HEADERS).raise_for_status()
    assert client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).status_code == 401


def test_legacy_single_pull_directs_password_users_to_live_page(connected):
    client, _ = connected
    client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).raise_for_status()
    with TestClient(create_app(client.app.state.store.root, lab_ssh=True), base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as legacy:
        legacy.cookies.update(client.cookies)
        assert not legacy.get("/api/collect/linux/status").json()["ready"]
        assert legacy.post("/api/collect/linux?host=lab.example.test&port=2222", headers=HEADERS).status_code == 409


def test_failed_password_connection_preserves_verified_settings(connected, monkeypatch):
    client, sessions = connected
    client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).raise_for_status()
    profile = client.app.state.store.root / "ssh-lab.json"
    before = profile.read_bytes()
    def denied(*args):
        raise ssh_collection.CollectionError("SSH password authentication failed.")
    monkeypatch.setattr(PasswordSession, "connect", denied)
    result = client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS)
    assert result.status_code == 400 and SECRET not in result.text
    assert profile.read_bytes() == before and sessions[0].active


@pytest.mark.parametrize("action", ["/api/live/disconnect", "/api/auth/logout"])
def test_disconnect_or_logout_closes_authenticated_transport(connected, action):
    client, sessions = connected
    client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).raise_for_status()
    assert sessions[0].active
    client.post(action, headers=HEADERS).raise_for_status()
    assert not sessions[0].active


def test_shutdown_drops_session_and_restart_requires_fresh_password(connected):
    client, sessions = connected
    with TestClient(create_app(client.app.state.store.root), base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as original:
        original.cookies.update(client.cookies)
        original.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).raise_for_status()
        assert sessions[0].active
    assert not sessions[0].active
    with TestClient(create_app(client.app.state.store.root), base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as restarted:
        restarted.cookies.update(client.cookies)
        assert restarted.get("/api/live/status").json()["password_required"]


def test_idle_watch_closes_session_and_stale_page_cannot_close_new_session(connected, monkeypatch):
    client, sessions = connected
    first = client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).json()
    second = client.post("/api/live/password", json=BODY | {"password": SECRET}, headers=HEADERS).json()
    assert not sessions[0].active and sessions[1].active
    client.post("/api/live/disconnect", params={"connection_id": first["connection_id"]}, headers=HEADERS).raise_for_status()
    assert sessions[1].active
    clock = [100.0]
    monkeypatch.setattr(live_logs, "monotonic", lambda: clock[0])
    client.post("/api/live/start?host=lab.example.test&port=2222", headers=HEADERS).raise_for_status()
    clock[0] += live_logs.IDLE_SECONDS
    assert client.get("/api/live/status").json()["password_required"]
    assert not sessions[1].active
