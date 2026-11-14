"""Native local start/stop controls without a command-prompt window."""
from hashlib import sha256
from math import ceil
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import webbrowser

from scripts import adapters, launch

ROOT = launch.ROOT


def local_environment(root=ROOT):
    scratch = root / "tmp"
    scratch.mkdir(exist_ok=True)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SENTINEL_SHARED_")}
    return dict(environment, SENTINEL_STORAGE_DIR=str(root / "storage"),
                SENTINEL_ENABLE_LAB_SSH="0", SENTINEL_SYNTHETIC_REHEARSAL="0",
                PYTHONDONTWRITEBYTECODE="1", TMP=str(scratch), TEMP=str(scratch),
                PIP_CACHE_DIR=str(scratch / "pip-cache"))


def start_server(executable, port, rehearsal, log, *, environment=None, tls=()):
    environment = local_environment() if environment is None else environment
    environment["SENTINEL_SYNTHETIC_REHEARSAL"] = "1" if rehearsal else "0"
    return subprocess.Popen([str(executable), "-m", "scripts.desktop_server", "--port", str(port), *tls],
                            cwd=ROOT, env=environment, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)


def stop_server(process):
    if process is None or process.poll() is not None:
        return True
    try:
        process.stdin.write(b"q")
        process.stdin.flush()
        process.stdin.close()
    except (OSError, ValueError):
        pass
    try:
        process.wait(timeout=20)
        return True
    except subprocess.TimeoutExpired:
        launch.stop_process(process)
        return False


def acquire_instance(root=ROOT):
    """A per-folder OS mutex; never identify/kill a process by PID file."""
    if os.name != "nt":
        raise RuntimeError("Use Start Sentinel.command on macOS or the terminal launcher on Linux.")
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    name = "Local\\SentinelDesktop-" + sha256(str(root.resolve()).casefold().encode()).hexdigest()[:24]
    handle = kernel.CreateMutexW(None, False, name)
    if not handle:
        raise OSError(ctypes.get_last_error(), "Could not reserve the local launcher")
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel.CloseHandle(handle)
        return None
    return kernel, handle


class Desktop:
    def __init__(self, window):
        import tkinter as tk
        from tkinter import ttk
        self.window, self.tk, self.ttk = window, tk, ttk
        self.messages = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.process = None
        self.url = None
        self.log = None
        self.executable = None
        self.owner = None
        self.shared = None
        self.certificate = None
        self.adapter_timer = None
        window.title("Sentinel V6 · Roar Cyber | Team 84")
        window.resizable(False, False)
        window.protocol("WM_DELETE_WINDOW", self.close)
        self.panel = ttk.Frame(window, padding=24)
        self.panel.pack(fill="both", expand=True)
        ttk.Label(self.panel, text="Sentinel", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        self.status = tk.StringVar(value="Preparing your local installation…")
        ttk.Label(self.panel, textvariable=self.status, wraplength=440).pack(anchor="w", pady=(12, 16))
        self.content = ttk.Frame(self.panel)
        self.content.pack(fill="x")
        ttk.Label(self.panel, text="Local files: " + str(ROOT), wraplength=440).pack(anchor="w", pady=(18, 0))
        self.run(self.prepare)
        window.after(100, self.drain)

    def run(self, function, *args):
        self.busy = True

        def work():
            try:
                result = function(*args)
                self.messages.put(("done", result))
            except Exception as exc:
                # Deliberately omit arguments/traceback locals: setup accepts a password.
                self.messages.put(("error", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def prepare(self):
        self.log = (ROOT / "tmp" / "desktop-launch.log").open("a", encoding="utf-8", buffering=1)
        self.executable = launch.ensure_environment(background=True, output=self.log)
        if self.cancel.is_set():
            return "closed"
        if Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
            # Reopen using the installed environment; the bootstrap Python may
            # have no application dependencies. Passwords have not been requested.
            subprocess.Popen([str(self.executable.with_name("pythonw.exe")), str(ROOT / "scripts/desktop.pyw"), "--handoff"],
                             cwd=ROOT, env=local_environment(), creationflags=subprocess.CREATE_NO_WINDOW,
                             stdout=self.log, stderr=subprocess.STDOUT, close_fds=True)
            return "restarted"
        self.adapter_options = adapters.available()
        return "adapter"

    def prepare_account(self):
        from app.auth import AuthService
        from app.db import EvidenceStore
        root = ROOT / "storage"
        store = EvidenceStore(root / "shared" if self.shared else root)
        store.initialize()
        self.owner = AuthService(store)
        self.owner.initialize()
        return "ready" if self.owner.configured() else "account"

    def save_owner(self, username, password):
        self.owner.create_owner(username, password)
        return "ready"

    def connect(self):
        rehearsal = not self.shared and launch.model_testing_available(self.executable)
        if self.shared:
            from app.shared_server import prepare_https, shared_health

            environment = local_environment()
            store = ROOT / "storage" / "shared"
            environment["SENTINEL_STORAGE_DIR"] = str(store)
            cert, key, ca, fingerprint, environment, opener = prepare_https(store, self.shared, environment)
            self.certificate = (ca, fingerprint)
            self.url = self.shared.origin + "/"
            port, reuse = self.shared.port, False
            self.process = start_server(self.executable, port, False, self.log, environment=environment,
                                        tls=("--ssl-certfile", str(cert), "--ssl-keyfile", str(key)))

            def ready():
                return shared_health(opener, self.shared.origin, store, launch.UI_VERSION)
        else:
            port, reuse = launch.choose_port(8000, rehearsal)
            self.url = f"http://127.0.0.1:{port}/"

            def ready():
                return launch.matching_server(launch.read_health(port), rehearsal)

        if not reuse:
            if not self.shared:
                self.process = start_server(self.executable, port, rehearsal, self.log)
            deadline = time.monotonic() + 30
            try:
                while self.process.poll() is None and not ready():
                    if self.cancel.is_set():
                        stop_server(self.process)
                        return "closed"
                    if self.process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("The server did not become ready. See tmp/desktop-launch.log.")
                    time.sleep(.15)
                if self.process.poll() is not None:
                    raise RuntimeError("Sentinel could not bind to this address and port. See tmp/desktop-launch.log.")
            except Exception:
                stop_server(self.process)
                raise
        if self.cancel.is_set():
            stop_server(self.process)
            return "closed"
        return "running"

    def clear(self):
        for child in self.content.winfo_children():
            child.destroy()

    def adapter_form(self):
        self.clear()
        if not self.adapter_options:
            self.select_adapter(0)
            return
        choices = ["Local only (localhost)", *(item.label for item in self.adapter_options)]
        picker = self.ttk.Combobox(self.content, values=choices, state="readonly", width=52)
        picker.current(0)
        picker.pack(fill="x")
        self.ttk.Button(self.content, text="Start Sentinel", command=lambda: self.select_adapter(picker.current())).pack(anchor="e", pady=(12, 0))
        picker.bind("<Return>", lambda event: self.select_adapter(picker.current()))
        deadline = time.monotonic() + adapters.TIMEOUT

        def tick():
            seconds = ceil(deadline - time.monotonic())
            if seconds <= 0:
                self.adapter_timer = None
                self.select_adapter(0)
            else:
                self.status.set(f"Choose a network adapter. Local only starts in {seconds} seconds.")
                self.adapter_timer = self.window.after(200, tick)

        picker.focus_set()
        tick()

    def select_adapter(self, index):
        if self.adapter_timer is not None:
            self.window.after_cancel(self.adapter_timer)
            self.adapter_timer = None
        if index > 0:
            from app.shared_hosting import SharedHosting

            adapter = self.adapter_options[index - 1].address
            self.shared = SharedHosting.parse(str(adapter.ip), str(adapter.network), 8000)
        self.clear()
        self.status.set("Preparing the Sentinel workspace…")
        self.run(self.prepare_account)

    def account_form(self):
        self.clear()
        self.status.set(f"First launch: create the {'shared workspace' if self.shared else 'local'} owner account.")
        entries = []
        for label, hidden in (("Username (lowercase, 3–32 characters)", False),
                              ("Password (15–128 characters)", True), ("Confirm password", True)):
            self.ttk.Label(self.content, text=label).pack(anchor="w", pady=(8, 2))
            row = self.ttk.Frame(self.content)
            row.pack(fill="x")
            entry = self.ttk.Entry(row, width=48, show="•" if hidden else "")
            entry.pack(side="left", fill="x", expand=True)
            if hidden:
                toggle = self.ttk.Button(row, text="👁 Show")
                toggle.configure(command=lambda field=entry, button=toggle: self.toggle_password(field, button))
                toggle.pack(side="right", padx=(6, 0))
            entries.append(entry)
        self.account_entries = entries
        self.ttk.Button(self.content, text="Create account & open Sentinel", command=self.submit).pack(anchor="e", pady=(16, 0))
        entries[0].focus_set()
        entries[-1].bind("<Return>", lambda event: self.submit())

    @staticmethod
    def toggle_password(entry, button):
        visible = bool(entry.cget("show"))
        entry.configure(show="" if visible else "•")
        button.configure(text="👁 Hide" if visible else "👁 Show")

    def submit(self):
        if self.busy:
            return
        from tkinter import messagebox
        username, password, confirmation = [entry.get() for entry in self.account_entries]
        if password != confirmation:
            messagebox.showerror("Check password", "The two passwords must match.", parent=self.window)
            return
        for entry in self.account_entries[1:]:
            entry.delete(0, "end")
        self.status.set("Creating your local account…")
        self.run(self.save_owner, username.strip(), password)

    def open_dashboard(self):
        if not webbrowser.open(self.url):
            self.status.set("Open this address in your browser: " + self.url)

    def close(self):
        if self.adapter_timer is not None:
            self.window.after_cancel(self.adapter_timer)
            self.adapter_timer = None
        if self.busy:
            self.cancel.set()
            self.status.set("Finishing the current operation, then closing. Please wait…")
            return
        if self.process is not None and self.process.poll() is None:
            self.clear()
            self.status.set("Stopping Sentinel and closing live connections…")
            self.run(lambda: "closed" if stop_server(self.process) else "forced")
        else:
            self.window.destroy()

    def drain(self):
        from tkinter import messagebox
        try:
            kind, result = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            if kind == "error":
                if self.cancel.is_set():
                    self.close()
                else:
                    self.status.set("Could not complete setup: " + result)
                    messagebox.showerror("Sentinel", result, parent=self.window)
            elif result in ("closed", "restarted", "forced"):
                if result == "forced":
                    messagebox.showwarning("Sentinel stopped", "Graceful shutdown timed out; the owned server was stopped. Check saved captures before continuing.", parent=self.window)
                self.window.destroy()
                return
            elif self.cancel.is_set():
                self.close()
            elif result == "adapter":
                self.adapter_form()
            elif result == "account":
                self.account_form()
            elif result == "ready":
                self.clear()
                self.status.set("Starting shared HTTPS…" if self.shared else "Starting the local server…")
                self.run(self.connect)
            elif result == "running":
                self.clear()
                self.status.set(("Shared HTTPS at " if self.shared else "Running locally at ") + self.url + "\nKeep this control window open or minimized.")
                if self.certificate:
                    ca, fingerprint = self.certificate
                    details = self.tk.Text(self.content, height=6, width=54, wrap="char")
                    details.insert("1.0", f"Team URL: {self.url}\nPublic trust certificate: {ca}\nSHA-256: {fingerprint}")
                    details.configure(state="disabled")
                    details.pack(fill="x", pady=(0, 10))
                    self.ttk.Label(self.content, text="Trust the public certificate before opening the dashboard.", wraplength=440).pack(anchor="w", pady=(0, 10))
                self.ttk.Button(self.content, text="Open dashboard", command=self.open_dashboard).pack(side="left")
                self.ttk.Button(self.content, text="Stop Sentinel" if self.process else "Close launcher", command=self.close).pack(side="right")
                if not self.process:
                    self.status.set("An existing local server is running. This window can reopen it; stop it from its original launcher.")
                if not self.shared:
                    self.open_dashboard()
            elif result is None:
                self.close()
        if not self.busy and self.process is not None and self.process.poll() is not None and self.url:
            self.status.set("The local server stopped. Close this window and relaunch; see tmp/desktop-launch.log if unexpected.")
        self.window.after(100, self.drain)


def main():
    os.environ.update(local_environment())
    import tkinter as tk
    from tkinter import messagebox
    window = tk.Tk()
    window.withdraw()
    mutex = acquire_instance()
    if mutex is None and "--handoff" in sys.argv:
        deadline = time.monotonic() + 10
        while mutex is None and time.monotonic() < deadline:
            time.sleep(.1)
            mutex = acquire_instance()
    if mutex is None:
        for port in range(8000, 8010):
            health = launch.read_health(port)
            if launch.matching_server(health, rehearsal=bool(health and health.get("rehearsal_enabled"))):
                webbrowser.open(f"http://127.0.0.1:{port}/")
                break
        else:
            messagebox.showinfo("Sentinel", "The launcher is already open or still preparing this folder. Use its existing control window.", parent=window)
        window.destroy()
        return
    controller = None
    try:
        controller = Desktop(window)
        window.deiconify()
        window.mainloop()
    finally:
        if controller is not None:
            stop_server(controller.process)
            if controller.log:
                controller.log.close()
        kernel, handle = mutex
        kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()
