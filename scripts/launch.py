"""One-click local launcher. Setup once, open a ready server, keep its console."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
UI_VERSION = "sentinel-v2-network-patterns"


def environment_python(root: Path = ROOT) -> Path:
    return root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_environment(root: Path = ROOT, *, background: bool = False, output=None) -> Path:
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required. Install Python, then run the launcher again.")
    scratch = root / "tmp"
    scratch.mkdir(exist_ok=True)
    install_env = dict(os.environ, PIP_CACHE_DIR=str(scratch / "pip-cache"), TMP=str(scratch),
                       TEMP=str(scratch), PYTHONDONTWRITEBYTECODE="1")
    options = {"env": install_env}
    if background and os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    if output is not None:
        options.update(stdout=output, stderr=subprocess.STDOUT)
    executable = environment_python(root)
    if not executable.is_file():
        print("First-time setup: creating the local Python environmentâ€¦", flush=True)
        # pythonw is the desktop entry point; use its console sibling without
        # creating a console so pip/venv retain normal stream handling.
        bootstrap = Path(sys.executable)
        if bootstrap.name.lower() == "pythonw.exe":
            bootstrap = bootstrap.with_name("python.exe")
        subprocess.run([str(bootstrap), "-m", "venv", str(root / ".venv")], check=True, cwd=root, **options)
    check = [str(executable), "-c", "from importlib.metadata import version; import app.main, uvicorn; "
             "assert version('fastapi') == '0.162.0'; assert version('pydantic') == '2.14.2'; "
             "assert version('uvicorn') == '0.54.0'; assert version('paramiko') == '5.1.0'; assert version('wsproto') == '1.3.2'"]
    quiet = dict(options, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    probe = subprocess.run(check, cwd=root, timeout=30, **quiet)
    if probe.returncode:
        print("First-time setup: installing pinned application dependencies (package access required)â€¦", flush=True)
        subprocess.run([str(executable), "-m", "pip", "install", "-c", "constraints.txt", "-e", "."],
                       check=True, cwd=root, **options)
        verified = subprocess.run(check, cwd=root, timeout=30, **quiet)
        if verified.returncode:
            raise RuntimeError("Dependencies were installed, but the application import check still fails. Use the README troubleshooting commands.")
    return executable


def expected_instance() -> str:
    directory = Path(os.environ.get("SENTINEL_STORAGE_DIR", str(ROOT / "storage"))).resolve()
    return sha256(str(directory).encode("utf-8")).hexdigest()[:16]


def ensure_owner(executable: Path):
    status = subprocess.run([str(executable), "-m", "app.auth", "status"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, timeout=30)
    if status.returncode == 3:
        print("First launch: create your local owner account in this console.", flush=True)
        subprocess.run([str(executable), "-m", "app.auth", "setup"], cwd=ROOT, check=True)
    elif status.returncode:
        raise RuntimeError("Could not check the local owner account. Check storage permissions.")


def read_health(port: int) -> dict | None:
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
            body = response.read(4096)
        value = json.loads(body)
        return value if isinstance(value, dict) else None
    except (OSError, URLError, ValueError):
        return None


def model_testing_available(executable: Path) -> bool:
    probe = [str(executable), "-c", "from app.rehearsal import sample_bytes, load_rehearsal_model; "
             "sample_bytes(); load_rehearsal_model()"]
    try:
        result = subprocess.run(probe, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def matching_server(health: dict | None, rehearsal: bool = False) -> bool:
    return bool(health and health.get("service") == "team84-sentinel"
                and health.get("status") == "ok"
                and health.get("ui_version") == UI_VERSION and health.get("instance_id") == expected_instance()
                and health.get("authentication_required") is True
                and health.get("rehearsal_enabled", False) is rehearsal
                and health.get("live_collection_enabled", False) is (os.environ.get("SENTINEL_ENABLE_LAB_SSH") == "1")
                and health.get("model_ready") is False and health.get("competition_use_enabled") is False)


def choose_port(start: int, rehearsal: bool = False) -> tuple[int, bool]:
    first_free = None
    for port in range(start, min(start + 10, 65536)):
        health = read_health(port)
        if (health and health.get("service") == "team84-sentinel" and health.get("instance_id") == expected_instance()
                and health.get("authentication_required") is not True):
            raise RuntimeError("An older unprotected Sentinel is still running for this evidence store. Stop its original console with Ctrl+C, then relaunch.")
        if matching_server(health, rehearsal):
            return port, True
        if health and health.get("service") == "team84-sentinel" and health.get("instance_id") == expected_instance():
            raise RuntimeError("A different Sentinel build or mode is using this evidence store. Stop its original console with Ctrl+C, then relaunch.")
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            if first_free is None:
                first_free = port
    if first_free is not None:
        return first_free, False
    raise RuntimeError("No free local port was found. Close an unused server or choose --port.")


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--deterministic-only", action="store_true", help="start with model testing disabled")
    parser.add_argument("--check", action="store_true", help="check setup and exit without starting a server")
    parser.add_argument("--smoke-test", action="store_true", help="start, check, and stop a separate test server")
    parser.add_argument("--configure-live", action="store_true", help="configure a trusted SSH source in the local console")
    parser.add_argument("--live-logs", action="store_true", help="enable lab collection and open Live logs")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    process = None
    try:
        executable = ensure_environment()
        if args.check:
            print("PASS: Sentinel Python environment is ready.")
            return 0
        settings = Path(os.environ.get("SENTINEL_STORAGE_DIR", str(ROOT / "storage"))) / "ssh-lab.json"
        if args.configure_live or (args.live_logs and not settings.is_file()):
            subprocess.run([str(executable), "-m", "scripts.configure_live_ssh"], cwd=ROOT, check=True)
        if args.live_logs or args.configure_live:
            os.environ["SENTINEL_ENABLE_LAB_SSH"] = "1"
        ensure_owner(executable)
        rehearsal = not args.deterministic_only and model_testing_available(executable)
        port, reuse = choose_port(args.port, rehearsal)
        url = f"http://127.0.0.1:{port}/" + ("live" if args.live_logs or args.configure_live else "")
        if not reuse:
            process = subprocess.Popen(
                [str(executable), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                 "--port", str(port), "--no-access-log"], cwd=ROOT,
                env=dict(os.environ, SENTINEL_SYNTHETIC_REHEARSAL="1" if rehearsal else "0"),
            )
            deadline = time.monotonic() + 30
            while not matching_server(read_health(port), rehearsal):
                if process.poll() is not None:
                    raise RuntimeError("The server could not start. Read the error above; another program may have taken the port.")
                if time.monotonic() >= deadline:
                    raise RuntimeError("The server did not become ready within 30 seconds.")
                time.sleep(0.15)
        print(f"Sentinel is ready: {url}", flush=True)
        print("Model testing is available in the main dashboard." if rehearsal else "Running deterministic analysis mode.", flush=True)
        if args.smoke_test:
            print("PASS: launcher readiness check; temporary server will stop.", flush=True)
            return 0
        if not args.no_browser:
            if not webbrowser.open(url):
                print("Open the address above in your browser.", flush=True)
        if reuse:
            print("Using the existing Sentinel server. Stop it from its original console.")
            return 0
        print("Keep this window open. Press Ctrl+C to stop Sentinel.", flush=True)
        return process.wait()
    except KeyboardInterrupt:
        print("\nStopping Sentinelâ€¦", flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Sentinel could not start: {exc}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            stop_process(process)


if __name__ == "__main__":
    raise SystemExit(main())
