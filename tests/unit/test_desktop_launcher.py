"""Desktop controls own only their child, never a PID read from disk."""
import io
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from scripts import desktop, desktop_server, launch


def test_local_environment_isolated_from_other_installations(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_STORAGE_DIR", "other-copy/storage")
    monkeypatch.setenv("SENTINEL_ENABLE_LAB_SSH", "1")
    monkeypatch.setenv("SENTINEL_SYNTHETIC_REHEARSAL", "1")
    environment = desktop.local_environment(tmp_path)
    assert environment["SENTINEL_STORAGE_DIR"] == str(tmp_path / "storage")
    assert environment["SENTINEL_ENABLE_LAB_SSH"] == environment["SENTINEL_SYNTHETIC_REHEARSAL"] == "0"
    for key in ("TMP", "TEMP", "PIP_CACHE_DIR"):
        assert Path(environment[key]).is_relative_to(tmp_path)


def test_start_has_parent_pipe_and_hidden_child_with_local_runtime(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(desktop, "ROOT", tmp_path)
    monkeypatch.setattr(desktop, "local_environment", lambda: {"SENTINEL_STORAGE_DIR": str(tmp_path / "storage")})
    monkeypatch.setattr(desktop.subprocess, "Popen", lambda args, **kwargs: calls.append((args, kwargs)) or "child")
    log = io.StringIO()
    assert desktop.start_server(Path("python.exe"), 8123, False, log) == "child"
    args, kwargs = calls[0]
    assert args == ["python.exe", "-m", "scripts.desktop_server", "--port", "8123"]
    assert kwargs["stdin"] == subprocess.PIPE
    assert kwargs["stdout"] is log and kwargs["cwd"] == tmp_path
    assert kwargs["env"]["SENTINEL_SYNTHETIC_REHEARSAL"] == "0"
    if os.name == "nt":
        assert kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW


def test_stop_requests_graceful_shutdown_before_process_termination():
    class Pipe(io.BytesIO):
        def close(self):
            self.sent = self.getvalue()
            super().close()

    pipe = Pipe()
    waits = []
    child = SimpleNamespace(poll=lambda: None, stdin=pipe, wait=lambda **kwargs: waits.append(kwargs))
    assert desktop.stop_server(child)
    assert pipe.sent == b"q" and pipe.closed
    assert waits == [{"timeout": 20}]


def test_stop_timeout_falls_back_only_on_owned_child(monkeypatch):
    stopped = []

    def wait(**kwargs):
        raise subprocess.TimeoutExpired("test-server", kwargs["timeout"])

    child = SimpleNamespace(poll=lambda: None, stdin=io.BytesIO(), wait=wait)
    monkeypatch.setattr(launch, "stop_process", lambda value: stopped.append(value))
    assert desktop.stop_server(child) is False
    assert stopped == [child]
    assert desktop.stop_server(None)
    assert desktop.stop_server(SimpleNamespace(poll=lambda: 0))


@pytest.mark.parametrize("message", [b"q", b""])
def test_parent_stop_or_crash_signals_server_exit(message):
    server = SimpleNamespace(should_exit=False)
    desktop_server.watch_parent(io.BytesIO(message), server)
    assert server.should_exit


def test_background_setup_redirects_install_and_uses_project_cache(monkeypatch, tmp_path):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1 if args[1] == "-c" and len(calls) == 2 else 0)

    monkeypatch.setattr(launch.subprocess, "run", run)
    log = io.StringIO()
    launch.ensure_environment(tmp_path, background=True, output=log)
    install = next(kwargs for args, kwargs in calls if "pip" in args)
    assert install["stdout"] is log and install["stderr"] == subprocess.STDOUT
    for _, kwargs in calls:
        assert Path(kwargs["env"]["TEMP"]).is_relative_to(tmp_path)
        if os.name == "nt":
            assert kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW


@pytest.mark.skipif(os.name != "nt", reason="Windows desktop mutex")
def test_only_one_desktop_controller_owns_folder_and_other_folder_is_independent(tmp_path):
    first = desktop.acquire_instance(tmp_path)
    second = desktop.acquire_instance(tmp_path / "other")
    try:
        assert first and second
        assert desktop.acquire_instance(tmp_path) is None
    finally:
        for kernel, handle in (first, second):
            kernel.CloseHandle(handle)
    third = desktop.acquire_instance(tmp_path)
    assert third
    third[0].CloseHandle(third[1])
