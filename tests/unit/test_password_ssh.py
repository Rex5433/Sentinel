"""Real encrypted loopback transport, with a disposable team-authored SSH server."""

from contextlib import suppress
import socket
from threading import Event, Thread
from time import monotonic

import paramiko
import pytest

from app import password_ssh
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
    state = {"passwords": [], "commands": [], "payload": b'{"MESSAGE":"team-authored test"}\n', "stall": False}
    stopped = Event()
    transports = []
    channels = []
    workers = []

    class Handler(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            state["passwords"].append(password)
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("reader", "test-only-password") else paramiko.AUTH_FAILED

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
    monkeypatch.setattr(password_ssh, "monotonic", lambda: clock[0])
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
