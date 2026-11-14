import os
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import launch


def test_environment_setup_check_uses_existing_python_without_installing(monkeypatch, tmp_path):
    executable = launch.environment_python(tmp_path)
    executable.parent.mkdir(parents=True)
    executable.touch()
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(launch.subprocess, "run", run)
    assert launch.ensure_environment(tmp_path) == executable
    assert len(calls) == 1 and "pip" not in calls[0]


def test_first_setup_creates_environment_then_installs_runtime_only(monkeypatch, tmp_path):
    calls = []
    probes = 0

    def run(arguments, **kwargs):
        nonlocal probes
        calls.append(arguments)
        if arguments[1] == "-c":
            probes += 1
            return subprocess.CompletedProcess(arguments, 1 if probes == 1 else 0)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(launch.subprocess, "run", run)
    launch.ensure_environment(tmp_path)
    assert calls[0][1:3] == ["-m", "venv"]
    install = next(call for call in calls if "pip" in call)
    assert "constraints.txt" in install and install[-2:] == ["-e", "."]
    assert "[dev]" not in " ".join(install)
    assert probes == 2


def test_failed_import_check_after_install_is_not_reported_ready(monkeypatch, tmp_path):
    def run(arguments, **kwargs):
        return subprocess.CompletedProcess(arguments, 1 if arguments[1] == "-c" else 0)

    monkeypatch.setattr(launch.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="import check still fails"):
        launch.ensure_environment(tmp_path)


def test_matching_server_requires_current_instance_and_disabled_ai():
    health = {"service": "team84-sentinel", "status": "ok", "ui_version": launch.UI_VERSION,
              "instance_id": launch.expected_instance(), "model_ready": False,
              "competition_use_enabled": False}
    health["authentication_required"] = True
    assert launch.matching_server(health)
    health["rehearsal_enabled"] = True
    assert launch.matching_server(health, rehearsal=True)
    assert not launch.matching_server(health)
    for changes in ({"instance_id": "other"}, {"ui_version": "old"}, {"competition_use_enabled": True}):
        assert not launch.matching_server(health | changes, rehearsal=True)
    assert not launch.matching_server(None)


def test_live_launcher_matches_only_collection_enabled_instance(monkeypatch):
    health = {"service": "team84-sentinel", "status": "ok", "ui_version": launch.UI_VERSION,
              "instance_id": launch.expected_instance(), "model_ready": False,
              "competition_use_enabled": False, "authentication_required": True}
    monkeypatch.setenv("SENTINEL_ENABLE_LAB_SSH", "1")
    assert not launch.matching_server(health)
    assert launch.matching_server(health | {"live_collection_enabled": True})


def test_reuse_opens_ready_browser_without_starting_another_server(monkeypatch):
    opened = []
    monkeypatch.setattr(sys, "argv", ["launch.py"])
    monkeypatch.setattr(launch, "ensure_environment", lambda: Path(sys.executable))
    monkeypatch.setattr(launch, "ensure_owner", lambda executable: None)
    monkeypatch.setattr(launch, "model_testing_available", lambda executable: True)

    def choose_port(port, rehearsal):
        assert rehearsal is True
        return 8765, True

    monkeypatch.setattr(launch, "choose_port", choose_port)
    monkeypatch.setattr(launch.webbrowser, "open", lambda url: opened.append(url) or True)

    def no_new_process(*args, **kwargs):
        raise AssertionError("reused server must not start another process")

    monkeypatch.setattr(launch.subprocess, "Popen", no_new_process)
    assert launch.main() == 0
    assert opened == ["http://127.0.0.1:8765/"]


def test_legacy_unprotected_server_for_same_store_blocks_upgrade_launch(monkeypatch):
    monkeypatch.setattr(launch, "read_health", lambda port: {"service": "team84-sentinel", "instance_id": launch.expected_instance()})
    with pytest.raises(RuntimeError, match="older unprotected Sentinel"):
        launch.choose_port(8000)


def test_same_store_with_different_dashboard_mode_blocks_launch(monkeypatch):
    health = {"service": "team84-sentinel", "status": "ok", "ui_version": launch.UI_VERSION,
              "instance_id": launch.expected_instance(), "authentication_required": True,
              "model_ready": False, "competition_use_enabled": False, "rehearsal_enabled": False}
    monkeypatch.setattr(launch, "read_health", lambda port: health)
    with pytest.raises(RuntimeError, match="different Sentinel build or mode"):
        launch.choose_port(8000, rehearsal=True)


def test_launcher_runs_console_setup_only_when_owner_is_missing(monkeypatch):
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 3 if arguments[-1] == "status" else 0)

    monkeypatch.setattr(launch.subprocess, "run", run)
    launch.ensure_owner(Path(sys.executable))
    assert [call[-1] for call in calls] == ["status", "setup"]


@pytest.mark.skipif(os.name != "nt", reason="Windows batch entry point")
def test_actual_batch_entry_point_from_another_working_directory(tmp_path):
    process = subprocess.run(
        ["cmd.exe", "/d", "/c", str(launch.ROOT / "Start Sentinel.bat"), "--check"],
        cwd=tmp_path, capture_output=True, text=True, timeout=45,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    assert "PASS: Sentinel Python environment is ready." in process.stdout
