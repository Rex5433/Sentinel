"""Desktop controls own only their child, never a PID read from disk."""
import io
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from scripts import adapters, desktop, desktop_server, launch


def test_local_environment_isolated_from_other_installations(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_STORAGE_DIR", "other-copy/storage")
    monkeypatch.setenv("SENTINEL_ENABLE_LAB_SSH", "1")
    monkeypatch.setenv("SENTINEL_SYNTHETIC_REHEARSAL", "1")
    monkeypatch.setenv("SENTINEL_SHARED_HOST", "192.168.137.1")
    environment = desktop.local_environment(tmp_path)
    assert environment["SENTINEL_STORAGE_DIR"] == str(tmp_path / "storage")
    assert environment["SENTINEL_ENABLE_LAB_SSH"] == environment["SENTINEL_SYNTHETIC_REHEARSAL"] == "0"
    assert "SENTINEL_SHARED_HOST" not in environment
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


@pytest.mark.parametrize("response,index", [("", None), ("0", None), ("2", None), ("1", 0)])
def test_console_selection_requires_confirmation(monkeypatch, response, index):
    from ipaddress import IPv4Interface

    adapter = adapters.Adapter("Private Ethernet", IPv4Interface("192.168.5.93/22"))
    monkeypatch.setattr(adapters, "available", lambda: [adapter])
    monkeypatch.setattr(adapters.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(adapters, "read_choice", lambda timeout: response)
    assert adapters.choose_console() == (None if index is None else adapter)


def test_adapter_discovery_keeps_private_address_and_prefix(monkeypatch):
    source = "windows_rows" if os.name == "nt" else "unix_rows"
    monkeypatch.setattr(adapters, source, lambda: [("Ethernet", "192.168.5.93/22"), ("Public", "8.8.8.8/24"),
                                                   ("Loopback", "127.0.0.1/8"), ("Link local", "169.254.1.2/16")])
    selected, = adapters.available()
    assert selected.name == "Ethernet" and str(selected.address.network) == "192.168.4.0/22"


def test_windows_ipconfig_fallback_preserves_adapter_names(monkeypatch):
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    monkeypatch.setattr(adapters, "command", lambda *_: """
Ethernet adapter Lab:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.5.93 (Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.252.0
   Default Gateway . . . . . . . . . : 192.168.4.1

Ethernet adapter VM:

   IPv4 Address. . . . . . . . . . . : 192.168.56.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
""")
    assert adapters.windows_rows() == [("Ethernet adapter Lab", "192.168.5.93/255.255.252.0"),
                                       ("Ethernet adapter VM", "192.168.56.1/255.255.255.0")]


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
