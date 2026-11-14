"""Real encrypted loopback transport, with a disposable team-authored SSH server."""

from contextlib import suppress
import json
import socket
from threading import Event, Thread
from time import monotonic

import paramiko
import pytest

from app import password_ssh, ssh_transport
from app.ssh_collection import CollectionError, COMMAND
from app.windows_live import windows_command


@pytest.fixture
def server(tmp_path):
    key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(.1)
    port = listener.getsockname()[1]
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
    state = {"passwords": [], "keys": [], "commands": [], "payload": b'{"MESSAGE":"team-authored test"}\n', "stall": False}
    stopped = Event()
    transports = []
    channels = []
    workers = []

    class Handler(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_auth_password(self, username, password):
            state["passwords"].append(password)
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("reader", "test-only-password") else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            state["keys"].append(key.asbytes())
            return paramiko.AUTH_SUCCESSFUL if username == "reader" and key.asbytes() == state.get("authorized_key") else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            state["commands"].append(command)
            if command.decode() not in {"exit 0", COMMAND, windows_command("Security")}:
                return False
            def reply():
                if state["stall"] and command != b"exit 0":
                    stopped.wait(2)
                with suppress(OSError, EOFError):
                    if command != b"exit 0" and state.get("denied"):
                        channel.sendall_stderr(b"Permission denied: fixture-private diagnostic")
                        channel.send_exit_status(1)
                        channel.close()
                        return
                    if command != b"exit 0":
                        channel.sendall(state["payload"])
                    channel.send_exit_status(0)
                    channel.close()
            # Return the exec acknowledgement before finishing the channel.
            from threading import Timer
            worker = Timer(.02, reply)
            worker.daemon = True
            worker.start()
            workers.append(worker)
            return True

    def serve():
        while not stopped.is_set():
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            transport = paramiko.Transport(sock)
            transports.append(transport)
            transport.add_server_key(key)
            with suppress(paramiko.SSHException, EOFError, OSError):
                transport.start_server(server=Handler())
                while transport.is_active() and not stopped.is_set():
                    channel = transport.accept(.1)
                    if channel is not None:
                        channels.append(channel)

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield ("127.0.0.1", "reader", port, known), state
    finally:
        stopped.set()
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(3)
        for worker in workers:
            worker.join(3)


def test_password_transport_reads_fixed_linux_and_windows_queries(server):
    target, state = server
    session = password_ssh.PasswordSession.connect(target, "test-only-password")
    try:
        assert session.transport.auth_handler.password is None
        for platform in ("linux", "windows"):
            assert session.collect({"platform": platform, "channel": "Security"}) == state["payload"]
        assert state["passwords"] == ["test-only-password"]
        assert state["commands"] == [b"exit 0", COMMAND.encode(), windows_command("Security").encode()]
    finally:
        session.close()
    assert not session.active


def test_host_mismatch_is_rejected_before_sending_password(server):
    target, state = server
    other = paramiko.RSAKey.generate(2048)
    target[3].write_text(f"[127.0.0.1]:{target[2]} {other.get_name()} {other.get_base64()}\n")
    with pytest.raises(CollectionError, match="host key"):
        password_ssh.PasswordSession.connect(target, "test-only-password")
    assert state["passwords"] == []


def test_wrong_password_has_sanitized_error(server):
    target, state = server
    with pytest.raises(CollectionError, match="authentication failed") as error:
        password_ssh.PasswordSession.connect(target, "wrong-secret")
    assert "wrong-secret" not in str(error.value)
    assert state["commands"] == []


def test_bounded_output_and_explicit_close(server, monkeypatch):
    target, state = server
    session = password_ssh.PasswordSession.connect(target, "test-only-password")
    try:
        monkeypatch.setattr(password_ssh, "MAX_BYTES", 8)
        with pytest.raises(CollectionError, match="exceeds"):
            session.collect({"platform": "linux"})
        session.close()
        with pytest.raises(CollectionError, match="expired"):
            session.touch()
        assert session.transport is None
    finally:
        session.close()


def test_active_reads_have_no_fixed_session_lifetime(server, monkeypatch):
    target, state = server
    session = password_ssh.PasswordSession.connect(target, "test-only-password")
    clock = [monotonic()]
    initial_time = clock[0]
    monkeypatch.setattr(ssh_transport, "monotonic", lambda: clock[0])
    try:
        for hours in (1, 8, 24):
            clock[0] = initial_time + hours * 60 * 60
            assert session.active
            assert session.collect({"platform": "linux"}) == state["payload"]
        assert state["passwords"] == ["test-only-password"]
        assert session.transport.auth_handler.password is None
    finally:
        session.close()


def test_idle_cleanup_closes_unused_session_and_ignores_stale_timer(server):
    target, _ = server
    session = password_ssh.PasswordSession.connect(target, "test-only-password")
    try:
        old_timer = session.timer
        assert old_timer.interval == 45
        session.touch()
        old_timer.function(*old_timer.args)
        assert session.active
        current_timer = session.timer
        current_timer.function(*current_timer.args)
        assert session.transport is None and not session.active
    finally:
        session.close()


def test_stalled_remote_command_is_bounded(server, monkeypatch):
    target, state = server
    session = password_ssh.PasswordSession.connect(target, "test-only-password")
    try:
        state["stall"] = True
        monkeypatch.setattr(password_ssh, "TIMEOUT_SECONDS", .15)
        with pytest.raises(CollectionError, match="timed out|retrieval failed"):
            session.collect({"platform": "linux"})
    finally:
        session.close()


@pytest.fixture
def identity_file(server, tmp_path):
    _, state = server
    key = paramiko.RSAKey.generate(2048)
    state["authorized_key"] = key.asbytes()
    path = tmp_path / "local key"
    key.write_private_key_file(str(path))
    return path


def test_key_transport_reuses_authenticated_connection(server, identity_file):
    target, state = server
    session = ssh_transport.SSHSession.connect(target, identity_file=identity_file)
    try:
        assert session.transport.auth_handler.private_key is None
        assert session.read(COMMAND) == state["payload"]
        assert session.read(windows_command("Security")) == state["payload"]
        assert state["keys"] == [state["authorized_key"]]
        assert state["commands"] == [COMMAND.encode(), windows_command("Security").encode()]
    finally:
        session.close()
    assert not session.active


@pytest.mark.parametrize("select_encrypted_file", [False, True])
def test_key_transport_accepts_an_agent_signer(server, tmp_path, monkeypatch, select_encrypted_file):
    target, state = server
    key = paramiko.RSAKey.generate(2048)
    state["authorized_key"] = key.asbytes()
    state["agent_closed"] = False
    identity_file = None
    if select_encrypted_file:
        identity_file = tmp_path / "encrypted-key"
        key.write_private_key_file(str(identity_file), password="fixture-passphrase")
        identity_file.with_suffix(".pub").write_text(f"{key.get_name()} {key.get_base64()} fixture\n")

    class AgentFixture:
        def get_keys(self):
            return (key,)

        def close(self):
            state["agent_closed"] = True

    monkeypatch.setattr(ssh_transport.paramiko, "Agent", AgentFixture)
    session = ssh_transport.SSHSession.connect(target, identity_file=identity_file)
    try:
        assert state["agent_closed"]
        assert session.read(COMMAND) == state["payload"]
        assert state["keys"] == [state["authorized_key"]]
    finally:
        session.close()


def test_transport_distinguishes_connect_timeout(server, monkeypatch):
    target, _ = server

    def timeout(*args, **kwargs):
        raise TimeoutError("Fixture-private network detail")

    monkeypatch.setattr(ssh_transport.socket, "create_connection", timeout)
    with pytest.raises(ssh_transport.SSHFailure) as failure:
        ssh_transport.SSHSession.connect(target)
    assert failure.value.kind == "timeout" and failure.value.retryable
    assert "Fixture-private" not in str(failure.value)


def test_channel_open_timeout_is_reconnectable(server, identity_file, monkeypatch):
    target, _ = server
    session = ssh_transport.SSHSession.connect(target, identity_file=identity_file)

    def timeout(**kwargs):
        raise paramiko.SSHException("Timeout opening channel.")

    try:
        monkeypatch.setattr(session.transport, "open_session", timeout)
        with pytest.raises(ssh_transport.SSHFailure) as failure:
            session.read(COMMAND)
        assert failure.value.kind == "timeout" and failure.value.retryable
    finally:
        session.close()


def test_live_key_connect_verifies_and_reuses_same_collector(server, identity_file, tmp_path, monkeypatch, sign_in):
    from fastapi.testclient import TestClient
    from app import ssh_setup
    from app.main import create_app

    target, state = server
    state["payload"] = (json.dumps({
        "__CURSOR": "s=journal", "__REALTIME_TIMESTAMP": "1793970000000000", "_HOSTNAME": "loopback",
        "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Failed password for reader from 192.0.2.8 port 4180 ssh2",
    }) + "\n").encode()
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda *_: target[3].read_bytes())
    body = {"ssh_command": f"ssh reader@127.0.0.1 -p {target[2]}", "platform": "linux",
            "channel": "Journal", "authentication": "key", "isolated": True,
            "identity_file": str(identity_file)}
    headers = {"X-Sentinel-Import": "1"}
    app = create_app(tmp_path / "evidence")
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as client:
        sign_in(client)
        configured = client.post("/api/live/connect", headers=headers, json=body).raise_for_status().json()
        assert configured["authentication"] == "key" and configured["session_bound"]
        assert state["commands"] == [COMMAND.encode()]
        watch = client.post(f"/api/live/start?host=127.0.0.1&port={target[2]}", headers=headers,
                            json={"connection_id": configured["connection_id"]}).raise_for_status().json()
        polled = client.post(f"/api/live/{watch['id']}/poll?token={watch['token']}", headers=headers).raise_for_status()
        assert polled.json()["parsed"] == 1
        assert state["keys"] == [state["authorized_key"]]
        assert state["commands"] == [COMMAND.encode(), COMMAND.encode()]
        client.post(f"/api/live/{watch['id']}/stop?token={watch['token']}", headers=headers).raise_for_status()
        state["denied"] = True
        denied = client.post("/api/live/connect", headers=headers, json=body)
        assert denied.status_code == 400
        assert "cannot read the selected log source" in denied.json()["detail"]
        assert "fixture-private" not in denied.text


def test_key_rejection_and_host_pin_mismatch_are_distinct(server, identity_file):
    target, state = server
    state["authorized_key"] = b"other key"
    with pytest.raises(ssh_transport.SSHKeyAuthenticationRequired) as denied:
        ssh_transport.SSHSession.connect(target, identity_file=identity_file)
    assert denied.value.kind == "authentication" and not denied.value.retryable
    previous_attempts = list(state["keys"])
    other = paramiko.RSAKey.generate(2048)
    target[3].write_text(f"[127.0.0.1]:{target[2]} {other.get_name()} {other.get_base64()}\n")
    with pytest.raises(ssh_transport.SSHFailure) as mismatch:
        ssh_transport.SSHSession.connect(target, identity_file=identity_file)
    assert mismatch.value.kind == "host_key" and not mismatch.value.retryable
    assert state["keys"] == previous_attempts
