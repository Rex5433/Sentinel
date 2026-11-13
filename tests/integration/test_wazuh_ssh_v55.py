"""Wazuh Tools over real loopback SSH with a controlled remote command fixture."""

import json
import os
import shlex
import socket
import sqlite3
from threading import Event, Lock, Thread
from time import monotonic, sleep

import paramiko
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.wazuh_health import WazuhSettings
from app import wazuh_events
from app.db import EvidenceStore


BASE = "/api/wazuh/tools"
HEADERS = {"X-Sentinel-Import": "1"}
PASSWORD = "disposable-ssh-fixture-password"


@pytest.fixture
def vm(tmp_path):
    host_key = paramiko.RSAKey.generate(2048)
    user_key = paramiko.RSAKey.generate(2048)
    identity = tmp_path / "private.key"
    user_key.write_private_key_file(str(identity))
    state = {"auth": [], "state": "closed", "mode": None, "started": Event(), "commands": [], "host_key": host_key}
    stop = Event()
    workers = []
    lock = Lock()

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            state["auth"].append("password")
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("reader", PASSWORD) else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            state["auth"].append("key")
            return paramiko.AUTH_SUCCESSFUL if username == "reader" and key == user_key else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, channel):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            command = command.decode()
            state["commands"].append(command)
            worker = Thread(target=self.reply, args=(channel, command), daemon=True)
            worker.start()
            with lock:
                workers.append(worker)
            return True

        @staticmethod
        def reply(channel, command):
            if command.endswith("/usr/bin/nmap --version"):
                channel.sendall(b"Nmap version 7.93 ( https://nmap.org )\n")
            else:
                outer = shlex.split(command)
                assert outer[:2] == ["/bin/sh", "-c"]
                assert "-sT -Pn -n" in outer[2] and "-p 22 127.0.0.1" in outer[2]
                assert "flock -n -E 75 9" in outer[2]
                assert "kill -TERM \"$scan\"" in outer[2]
                assert outer[2].rstrip().endswith('exit "$result"')
                state["started"].set()
                if state["mode"] == "hold":
                    channel.settimeout(6)
                    assert channel.recv(1) == b""
                    channel.send_exit_status(143)
                    channel.shutdown_write()
                    return
                if state["mode"] == "disconnect":
                    channel.transport.close()
                    return
                if state["mode"] == "busy":
                    channel.send_exit_status(75)
                    channel.shutdown_write()
                    return
                body = (f'<nmaprun scanner="nmap"><host><status state="up" reason="user-set"/>'
                        f'<address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22">'
                        f'<state state="{state["state"]}"/><service name="ssh"/></port></ports></host>'
                        '<runstats><finished exit="success"/></runstats></nmaprun>')
                channel.sendall(b"<broken" if state["mode"] == "malformed" else body.encode())
            channel.send_exit_status(0)
            channel.shutdown_write()

    def serve_connection(sock):
        transport = paramiko.Transport(sock)
        transport.add_server_key(state["host_key"])
        channels = []
        try:
            transport.start_server(server=Server())
            while transport.is_active() and not stop.is_set():
                channel = transport.accept(.2)
                if channel:
                    channels.append(channel)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(.2)

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            worker = Thread(target=serve_connection, args=(connection,), daemon=True)
            worker.start()
            with lock:
                workers.append(worker)

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield {"host": "127.0.0.1", "port": listener.getsockname()[1], "username": "reader",
               "authentication": "password", "password": PASSWORD}, identity, state
    finally:
        stop.set()
        thread.join(1)
        listener.close()
        for worker in workers:
            worker.join(1)


def client_for(root):
    return TestClient(create_app(root, wazuh_settings=WazuhSettings()), base_url="http://127.0.0.1",
                      client=("127.0.0.1", 51100))


@pytest.fixture(autouse=True)
def isolated_known_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr("app.wazuh_ssh.Path.home", lambda: tmp_path)


def trust_and_save(client, form):
    path = BASE + "/connection/save"
    request = client.post(path, headers=HEADERS, json=form)
    assert request.status_code == 409
    challenge = request.json()["detail"]
    assert challenge["state"] == "approval_required"
    return client.post(path, headers=HEADERS, json=form | {"approval": challenge["approval"]}).raise_for_status().json()


def test_ssh_profile_host_key_approval_credentials_and_recovery(tmp_path, sign_in, vm):
    form, identity, remote = vm
    root = tmp_path / "store"
    connect = BASE + "/connection"
    with client_for(root) as client:
        assert client.get(BASE).status_code == 401
        owner = sign_in(client)
        assert client.post(connect + "/test", json=form).status_code == 403
        first = client.post(connect + "/test", headers=HEADERS, json=form)
        assert first.status_code == 409
        challenge = first.json()["detail"]
        assert challenge["fingerprint"] == remote["host_key"].fingerprint and challenge["key_type"] == "ssh-rsa"
        assert remote["auth"] == []
        other = form | {"host": "localhost", "approval": challenge["approval"]}
        assert client.post(connect + "/test", headers=HEADERS, json=other).status_code == 400
        assert remote["auth"] == [] and client.get(BASE).json()["profile"] is None
        approval = {"approval": challenge["approval"]}
        bad_password = client.post(connect + "/test", headers=HEADERS, json=form | approval | {"password": "wrong"})
        assert bad_password.json()["detail"]["state"] == "authentication"
        replay = client.post(connect + "/test", headers=HEADERS, json=form | approval)
        assert replay.status_code == 400
        saved = client.post(connect + "/save", headers=HEADERS, json=form).raise_for_status().json()
        assert "fingerprint" not in saved["profile"] and "host_key_type" not in saved["profile"]
        assert PASSWORD not in json.dumps(saved) and saved["credential_saved"] == (os.name == "nt")
        assert PASSWORD.encode() not in (root / "sentinel.sqlite3").read_bytes()
        assert client.post(connect + "/test", headers=HEADERS, json=form).raise_for_status().json()["version"].startswith("Nmap version 7.93")
        key_form = form | {"authentication": "key", "identity_file": str(identity)}
        assert client.post(connect + "/test", headers=HEADERS, json=key_form).raise_for_status().json()["state"] == "connected"
        assert remote["auth"][-1] == "key"
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            result = client.post(connect + "/test", headers=HEADERS, json=form | {"port": unavailable.getsockname()[1]})
        assert result.json()["detail"]["state"] in {"network", "timeout"}
        no_password = form | {"password": ""}
        assert client.post(connect + "/test", headers=HEADERS, json=no_password).raise_for_status().json()["state"] == "connected"
        assert client.get(BASE).json()["status"]["state"] == "connected"
        original = remote["host_key"]
        remote["host_key"] = paramiko.RSAKey.generate(2048)
        before = list(remote["auth"])
        assert client.post(connect + "/reconnect", headers=HEADERS).json()["status"]["state"] == "host_key"
        refused = client.post(connect + "/save", headers=HEADERS, json=no_password)
        assert refused.status_code == 502 and refused.json()["detail"]["state"] == "host_key"
        assert remote["auth"] == before
        remote["host_key"] = original
        for url in ("javascript:alert(1)", "http://localhost", "https://user:password@localhost", "https://localhost\\test"):
            assert client.post(BASE + "/dashboard", headers=HEADERS, json={"url": url}).status_code == 400
        dashboard = "https://192.0.2.1:8443/app/overview"
        client.post(BASE + "/dashboard", headers=HEADERS, json={"url": dashboard}).raise_for_status()
        assert client.get(BASE + "/agentless").status_code == 404
        assert client.get(BASE + "/indexer/alerts").status_code == 404
    with client_for(root) as restarted:
        restarted.post("/api/auth/login", headers=HEADERS, json={"username": "test-owner", "password": owner}).raise_for_status()
        assert restarted.get(BASE).json()["dashboard_url"] == dashboard
        if os.name == "nt":
            assert restarted.post(connect + "/reconnect", headers=HEADERS).raise_for_status().json()["status"]["state"] == "connected"


def test_remote_scan_allowlist_cancel_disconnect_recovery_and_timeline(tmp_path, sign_in, vm):
    connection, _, remote = vm
    path = BASE + "/nmap"
    with client_for(tmp_path / "store") as client:
        sign_in(client)
        trust_and_save(client, connection)
        for address in ("127.0.0.1/24", "-A", "224.0.0.1"):
            assert client.post(path + "/targets", headers=HEADERS, json={"name": "lab", "address": address}).status_code == 400
        client.post(path + "/targets", headers=HEADERS, json={"name": "loopback", "address": "127.0.0.1"}).raise_for_status()
        target = client.get(path).json()["targets"][0]["id"]
        form = {"target": target, "profile": "selected", "ports": "22", "authorized": True}
        for override in ({"target": "f" * 32}, {"ports": "22-200"}, {"profile": "service"}, {"authorized": False}):
            assert client.post(path + "/start", headers=HEADERS, json=form | override).status_code in {400, 422}

        def run(mode=None):
            remote["mode"] = mode
            remote["started"].clear()
            started = client.post(path + "/start", headers=HEADERS, json=form).raise_for_status().json()
            if mode == "hold":
                assert remote["started"].wait(5)
                assert client.post(path + "/start", headers=HEADERS, json=form).status_code == 400
                assert client.post(path + "/stop/" + "f" * 32, headers=HEADERS).status_code == 409
                client.post(path + "/stop/" + started["id"], headers=HEADERS).raise_for_status()
            deadline = monotonic() + 8
            while monotonic() < deadline:
                view = client.get(path).raise_for_status().json()
                if not view["active"]:
                    latest = view["history"][0]
                    assert latest["id"] == started["id"]
                    return latest
                sleep(.03)
            pytest.fail("The scan did not complete.")

        assert run()["ports"][0]["state"] == "closed"
        remote["state"] = "open"
        result = run()
        assert result["host_reason"] == "user-set" and result["ports"][0]["service"] == "ssh"
        assert result["comparison"]["new_open"] == [22]
        assert client.get("/api/timeline", params={"source_kind": "nmap", "host": "127.0.0.1"}).json()["total"] == 1
        assert run("hold")["status"] == "cancelled"
        assert run("busy")["error_kind"] == "busy"
        assert run("malformed")["status"] == "failed"
        assert run("disconnect")["error_kind"] == "network"
        assert client.get(BASE).json()["status"]["state"] == "network"
        remote["state"] = "filtered"
        assert run()["comparison"]["now_filtered"] == [22]
        assert client.get(BASE).json()["status"]["state"] == "connected"


def test_v5_settings_and_historical_timeline_are_preserved(tmp_path, sign_in):
    root = tmp_path / "legacy"
    store = EvidenceStore(root)
    store.initialize()
    wazuh_events.initialize(store)
    event = wazuh_events.normalize_alert("wazuh", {"id": "legacy", "timestamp": "2026-11-13T18:00:00Z",
                                                   "rule": {"id": "12", "level": 7}})
    wazuh_events.save_event(store, event)
    with store.connect() as db:
        db.executescript("""CREATE TABLE wazuh_connections (kind TEXT PRIMARY KEY, credential BLOB);
            INSERT INTO wazuh_connections VALUES ('manager', X'FF');
            CREATE TABLE wazuh_agentless_plans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            INSERT INTO wazuh_agentless_plans VALUES ('test', '{}');""")
    with client_for(root) as client:
        sign_in(client)
        assert client.get(BASE).json()["profile"] is None
        assert client.get("/api/wazuh/status").json()["state"] == "disabled"
        assert client.get("/api/timeline", params={"source_kind": "wazuh"}).json()["total"] == 1
    with sqlite3.connect(store.db_path) as db:
        assert db.execute("SELECT credential FROM wazuh_connections").fetchone()[0] == b"\xff"
        assert db.execute("SELECT payload FROM wazuh_agentless_plans").fetchone()[0] == "{}"


def test_known_hosts_is_read_and_each_install_keeps_its_own_trust(tmp_path, sign_in, vm):
    form, _, remote = vm
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    known = ssh / "known_hosts"
    key = remote["host_key"]
    entry = f"[{form['host']}]:{form['port']} {key.get_name()} {key.get_base64()}\n"
    different = paramiko.RSAKey.generate(2048)
    wrong = entry.replace(key.get_base64(), different.get_base64())
    known.write_text(wrong, encoding="ascii")
    with client_for(tmp_path / "host-store") as client:
        sign_in(client)
        rejected = client.post(BASE + "/connection/save", headers=HEADERS, json=form)
        assert rejected.status_code == 502 and rejected.json()["detail"]["state"] == "host_key"
        assert not remote["auth"]
        known.write_text(entry, encoding="ascii")
        result = client.post(BASE + "/connection/save", headers=HEADERS, json=form).raise_for_status().json()
        assert result["status"]["state"] == "connected"
        assert known.read_text(encoding="ascii") == entry
        # A second route to the VM has a different host-key identity.
        with client_for(tmp_path / "teammate-store") as teammate:
            sign_in(teammate)
            assert teammate.get(BASE).json()["profile"] is None
            saved = trust_and_save(teammate, form | {"host": "localhost"})
            assert saved["profile"]["host"] == "localhost"
        assert client.get(BASE).json()["profile"]["host"] == form["host"]
        known.unlink()
        assert client.post(BASE + "/connection/reconnect", headers=HEADERS).json()["status"]["state"] == "connected"


def test_old_manual_pin_migrates_without_approval(tmp_path, sign_in, vm):
    form, identity, remote = vm
    root = tmp_path / "upgrade"
    store = EvidenceStore(root)
    store.initialize()
    key = remote["host_key"]
    legacy = {name: value for name, value in form.items() if name != "password"}
    legacy.update(fingerprint=key.fingerprint, host_key_type=key.get_name(), authentication="key", identity_file=str(identity))
    with store.connect() as db:
        db.execute("CREATE TABLE wazuh_ssh_profile (id INTEGER PRIMARY KEY,settings TEXT NOT NULL,credential BLOB)")
        db.execute("INSERT INTO wazuh_ssh_profile VALUES (1,?,NULL)", (json.dumps(legacy),))
    with client_for(root) as client:
        sign_in(client)
        result = client.post(BASE + "/connection/reconnect", headers=HEADERS).raise_for_status().json()
        assert result["status"]["state"] == "connected" and "fingerprint" not in result["profile"]
    with store.connect() as db:
        assert db.execute("SELECT public_key FROM wazuh_ssh_host_keys").fetchone()[0] == key.asbytes()
