import json

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.auth import AuthService
from app import ssh_collection
from app.db import EvidenceStore
from app.main import create_app
from app.shared_hosting import SharedHosting
from app.shared_server import create_tls, prepare_https


PASSWORD = "Shared-fixture-only-1234"
HEADERS = {"X-Sentinel-Import": "1"}
TEAM = SharedHosting.parse("192.168.137.1", None, 8000)


def provision(path):
    store = EvidenceStore(path)
    store.initialize()
    auth = AuthService(store)
    auth.initialize()
    auth.create_owner("host-owner", PASSWORD)
    auth.create_owner("teammate-one", PASSWORD, teammate=True)
    auth.create_owner("teammate-two", PASSWORD, teammate=True)
    return auth


def login(client, name):
    return client.post("/api/auth/login", headers=HEADERS, json={"username": name, "password": PASSWORD})


def test_shared_network_session_and_permissions(tmp_path):
    auth = provision(tmp_path)
    app = create_app(tmp_path, shared=TEAM, rehearsal=True)
    with TestClient(app, base_url=TEAM.origin, client=("192.168.137.21", 5000)) as teammate:
        assert teammate.get("/siem", follow_redirects=False).status_code == 303
        assert teammate.get("/api/agents").status_code == 401
        response = login(teammate, "teammate-one").raise_for_status()
        assert response.json()["role"] == "teammate"
        assert "__Host-sentinel_team_" in response.headers["set-cookie"] and "Secure" in response.headers["set-cookie"]
        assert teammate.get("/health").json()["rehearsal_enabled"] is False
        for path in ("/", "/siem", "/agents", "/live", "/mysql", "/changes", "/api/agents"):
            teammate.get(path).raise_for_status()
        assert teammate.get("/api/wazuh/tools").json() == {"scanner_ready": False, "dashboard_url": None,
                                                          "status": {"state": "not_configured"}}
        for path in ("/api/live/connect", "/api/agents/test", "/api/wazuh/tools/connection/reconnect",
                     "/api/wazuh/tools/nmap/targets", "/api/wazuh/tools/dashboard"):
            assert teammate.post(path, headers=HEADERS, json={}).status_code == 403
        # The request reaches the scanner's validation rather than the owner guard.
        assert teammate.post("/api/wazuh/tools/nmap/start", headers=HEADERS, json={}).status_code == 422
        assert teammate.get("/health", headers={"Host": "192.168.137.1:9000"}).status_code == 403
        assert teammate.get("/health", headers={"Origin": "https://other.test"}).status_code == 403
        assert teammate.get("/api/live/status").status_code == 403
        assert teammate.post("/api/wazuh/tools/nmap/start", json={}).status_code == 403
        assert teammate.get("http://192.168.137.1:8000/health").status_code == 403
        with pytest.raises(WebSocketDisconnect), teammate.websocket_connect(
                "wss://192.168.137.1:8000/api/live/missing/stream", headers={"Origin": TEAM.origin}):
            pytest.fail("A teammate opened the owner-only live SSH socket.")

        owner = TestClient(app, base_url=TEAM.origin, client=("192.168.137.1", 5001))
        second = TestClient(app, base_url=TEAM.origin, client=("192.168.137.22", 5002))
        outside = TestClient(app, base_url=TEAM.origin, client=("192.168.138.21", 5000))
        try:
            assert outside.get("/health", headers={"X-Forwarded-For": "192.168.137.21"}).status_code == 403
            login(owner, "host-owner").raise_for_status()
            login(second, "teammate-two").raise_for_status()
            owner.post("/api/wazuh/tools/dashboard", headers=HEADERS,
                       json={"url": "https://192.168.137.1:8443"}).raise_for_status()
            assert second.get("/api/wazuh/tools").json()["dashboard_url"] == "https://192.168.137.1:8443"
            teammate.post("/api/auth/logout", headers=HEADERS).raise_for_status()
            assert teammate.get("/api/auth/me").status_code == 401
            assert owner.get("/api/auth/me").json()["role"] == "owner"
            assert second.get("/api/auth/me").json()["username"] == "teammate-two"
            auth.remove_teammate("teammate-two")
            assert second.get("/api/auth/me").status_code == 401
        finally:
            for client in (owner, second, outside):
                client.close()


@pytest.mark.parametrize("host,subnet", [("0.0.0.0", None), ("127.0.0.1", None), ("8.8.8.8", None),
                                          ("192.168.137.1", "0.0.0.0/0"), ("192.168.137.1", "192.168.138.0/24")])
def test_reject_unsafe_bind_and_network(host, subnet):
    with pytest.raises(ValueError):
        SharedHosting.parse(host, subnet, 8000)


def test_cert_reuse_and_ip_scope(tmp_path):
    cert, key, ca = create_tls(tmp_path, TEAM.host)
    leaf = x509.load_pem_x509_certificate(cert.read_bytes())
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress) == [TEAM.host]
    assert b"PRIVATE KEY" not in ca.read_bytes()
    assert create_tls(tmp_path, TEAM.host) == (cert, key, ca)
    with pytest.raises(ValueError, match="IP changed"):
        create_tls(tmp_path, SharedHosting.parse("192.168.137.2", None, 8000).host)


def test_switching_adapters_preserves_previous_certificate(tmp_path):
    _, _, old_ca = create_tls(tmp_path, TEAM.host)
    alternate = SharedHosting.parse("192.168.56.1", None, 8000)
    _, _, first_ca, _, _, _ = prepare_https(tmp_path, TEAM, {})
    _, _, next_ca, _, environment, _ = prepare_https(tmp_path, alternate, {})
    assert first_ca == old_ca and first_ca.read_bytes() != next_ca.read_bytes()
    assert next_ca.parent.name == str(alternate.host)
    assert environment["SENTINEL_SHARED_NETWORK"] == "192.168.56.0/24"
    assert prepare_https(tmp_path, alternate, {})[2] == next_ca


def test_shared_owner_can_stream_live_over_wss(tmp_path, monkeypatch):
    provision(tmp_path)
    destination = {"host": "lab.example.test", "port": 2222}
    (tmp_path / "ssh-lab.json").write_text(json.dumps(destination | {"username": "reader"}), encoding="utf-8")
    (tmp_path / "ssh-known-hosts").write_text("verified fixture", encoding="utf-8")
    record = json.dumps({"__CURSOR": "cursor-1", "__REALTIME_TIMESTAMP": "1760000000000000",
                         "_HOSTNAME": "fixture", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "SSH session opened"})
    monkeypatch.setattr(ssh_collection, "collect_live", lambda *args: (record + "\n").encode())
    with TestClient(create_app(tmp_path, shared=TEAM), base_url=TEAM.origin, client=("192.168.137.1", 5000)) as owner:
        login(owner, "host-owner").raise_for_status()
        watch = owner.post("/api/live/start", params=destination, headers=HEADERS).raise_for_status().json()
        path = f"wss://{TEAM.authority}/api/live/{watch['id']}/stream?token={watch['token']}"
        with pytest.raises(WebSocketDisconnect), owner.websocket_connect(path, headers={"Origin": "https://other.test"}):
            pytest.fail("A foreign origin opened an owner watch.")
        with owner.websocket_connect(path, headers={"Origin": TEAM.origin}) as feed:
            assert feed.receive_json()["active"]
            feed.send_text("ack")
            assert feed.receive_json()["retained"] == 1
