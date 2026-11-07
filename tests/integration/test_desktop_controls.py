"""Actual Tk account flow and owned server lifecycle in a disposable folder."""
import os
from pathlib import Path
import shutil
import sys
import time

import pytest

from scripts import desktop, launch

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows desktop controls")


def wait_for(window, predicate, timeout=35):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Desktop operation timed out")
        window.update()
        time.sleep(.03)
    window.update()


def test_masked_first_account_open_stop_and_parent_exit(monkeypatch, tmp_path):
    import tkinter as tk
    from app.auth import AuthService
    from app.db import EvidenceStore
    project = Path(__file__).resolve().parents[2]
    for name in ("app", "sentinel", "scripts"):
        shutil.copytree(project / name, tmp_path / name, ignore=shutil.ignore_patterns("__pycache__"))
    environment = desktop.local_environment(tmp_path)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(desktop, "ROOT", tmp_path)
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    monkeypatch.setattr(desktop, "local_environment", lambda: environment.copy())
    monkeypatch.setattr(launch, "model_testing_available", lambda exe: False)
    opened, errors = [], []
    monkeypatch.setattr(desktop.webbrowser, "open", lambda url: opened.append(url) or True)
    from tkinter import messagebox
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    def prepare(controller):
        controller.executable = Path(sys.executable)
        controller.log = (tmp_path / "server.log").open("a", encoding="utf-8")
        store = EvidenceStore(tmp_path / "storage")
        store.initialize()
        controller.owner = AuthService(store)
        controller.owner.initialize()
        return "account"

    # Environment installation has its own tests. This exercises the real UI,
    # authentication hashing, child Uvicorn and graceful stop without a browser.
    monkeypatch.setattr(desktop.Desktop, "prepare", prepare)
    window = tk.Tk()
    window.withdraw()
    controller = desktop.Desktop(window)
    try:
        wait_for(window, lambda: hasattr(controller, "account_entries"))
        for entry in controller.account_entries[1:]:
            assert entry.cget("show") != ""
        for entry, value in zip(controller.account_entries, ("beta-tester", "Test-only-long-passphrase", "Test-only-long-passphrase")):
            entry.insert(0, value)
        controller.submit()
        wait_for(window, lambda: len(opened) == 1 or bool(errors))
        assert not errors
        assert controller.owner.configured()
        port = int(opened[0].split(":")[2].rstrip("/"))
        assert launch.matching_server(launch.read_health(port), False)
        process = controller.process
        # Parent exit/crash closes the pipe even without the GUI Stop button.
        process.stdin.close()
        process.wait(timeout=20)
        assert launch.read_health(port) is None
        controller.process = None
        # Restart and explicitly stop through the GUI's shutdown path.
        controller.run(controller.connect)
        wait_for(window, lambda: len(opened) == 2 or bool(errors))
        assert not errors and controller.process.poll() is None
        process = controller.process
        controller.close()
        wait_for(window, lambda: process.poll() is not None)
        assert launch.read_health(port) is None
    finally:
        desktop.stop_server(controller.process)
        if controller.log:
            controller.log.close()
        try:
            window.destroy()
        except tk.TclError:
            pass
