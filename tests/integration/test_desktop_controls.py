"""Actual Tk account flow and owned server lifecycle in a disposable folder."""
import gc
import os
from pathlib import Path
from ipaddress import IPv4Interface
import shutil
import socket
import sys
import time

import pytest

from scripts import adapters, desktop, launch

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows desktop controls")


@pytest.fixture(autouse=True)
def collect_tk_cycles_on_main_thread():
    # The desktop starts workers. Tcl objects from earlier tests must be
    # finalized on the thread that created their interpreter.
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        gc.collect()
        if was_enabled:
            gc.enable()


def wait_for(window, predicate, timeout=35):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Desktop operation timed out")
        window.update()
        time.sleep(.03)
    window.update()


@pytest.mark.parametrize("confirm", [False, True])
def test_desktop_adapter_choice_and_timeout(monkeypatch, confirm):
    import tkinter as tk

    def prepare(controller):
        controller.adapter_options = [adapters.Adapter("Test Ethernet", IPv4Interface("192.168.5.93/22"))]
        return "adapter"

    def capture(controller):
        selected.append(controller.shared)
        return "account"

    selected = []
    monkeypatch.setattr(desktop.Desktop, "prepare", prepare)
    monkeypatch.setattr(desktop.Desktop, "prepare_account", capture)
    monkeypatch.setattr(adapters, "TIMEOUT", .5)
    window = tk.Tk()
    window.withdraw()
    controller = desktop.Desktop(window)
    try:
        wait_for(window, lambda: controller.adapter_timer is not None)
        picker, button = controller.content.winfo_children()
        assert picker.current() == 0
        assert "Test Ethernet" in picker["values"][1]
        picker.current(1)
        if confirm:
            button.invoke()
        wait_for(window, lambda: bool(selected))
        if confirm:
            assert str(selected[0].host) == "192.168.5.93" and str(selected[0].network) == "192.168.4.0/22"
        else:
            assert selected == [None]
    finally:
        window.destroy()
        del controller.status


@pytest.mark.parametrize("shared", [False, True])
def test_masked_first_account_open_stop_and_parent_exit(monkeypatch, tmp_path, shared):
    import tkinter as tk
    from app.shared_hosting import SharedHosting
    from app.shared_server import prepare_https, shared_health
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
    network = None
    if shared:
        options = adapters.available()
        if not options:
            pytest.skip("No private IPv4 adapter is available.")
        address = min(options, key=lambda adapter: (str(adapter.address.ip) != "192.168.56.1", adapter.name)).address
        with socket.socket() as probe:
            probe.bind((str(address.ip), 0))
            network = SharedHosting.parse(str(address.ip), str(address.network), probe.getsockname()[1])
    opened, errors = [], []
    monkeypatch.setattr(desktop.webbrowser, "open", lambda url: opened.append(url) or True)
    from tkinter import messagebox
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    def prepare(controller):
        controller.executable = Path(sys.executable)
        controller.log = (tmp_path / "server.log").open("a", encoding="utf-8")
        controller.shared = network
        return controller.prepare_account()

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
        wait_for(window, lambda: (controller.process is not None and not controller.busy) or bool(errors))
        assert not errors
        assert controller.owner.configured()
        if shared:
            assert not opened and controller.certificate[0].is_file()
            controller.open_dashboard()
        port = int(opened[0].split(":")[2].rstrip("/"))
        if shared:
            store = tmp_path / "storage" / "shared"
            _, _, _, _, _, opener = prepare_https(store, network, {})

            def ready():
                return shared_health(opener, network.origin, store, launch.UI_VERSION)
        else:
            def ready():
                return launch.matching_server(launch.read_health(port), False)
        assert ready()
        process = controller.process
        # Parent exit/crash closes the pipe even without the GUI Stop button.
        process.stdin.close()
        process.wait(timeout=20)
        assert not ready()
        controller.process = None
        # Restart and explicitly stop through the GUI's shutdown path.
        controller.run(controller.connect)
        wait_for(window, lambda: (controller.process is not None and not controller.busy) or bool(errors))
        assert not errors and controller.process.poll() is None
        process = controller.process
        controller.close()
        wait_for(window, lambda: process.poll() is not None)
        assert not ready()
    finally:
        desktop.stop_server(controller.process)
        if controller.log:
            controller.log.close()
        try:
            window.destroy()
        except tk.TclError:
            pass
