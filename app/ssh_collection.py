"""One operator-initiated read-only journal export from a configured lab host."""

import json
from pathlib import Path
import re
import subprocess
from threading import Event, Timer

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 100
TIMEOUT_SECONDS = 15
COMMAND = f"journalctl --no-pager --quiet --lines={MAX_RECORDS} --output=json"
HOST = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?")
USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
WINDOWS_USERNAME = re.compile(r"(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_][A-Za-z0-9_.-]*(?:@[A-Za-z0-9.-]+)?")


class CollectionError(ValueError):
    pass


class KeyAuthenticationRequired(CollectionError):
    pass


def live_options(storage: Path) -> dict:
    try:
        with (storage / "ssh-lab.json").open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError
        data = json.loads(raw)
        platform = data.get("platform", "linux")
        channel = data.get("channel", "Security")
        identity = data.get("identity_file")
        authentication = data.get("authentication", "key")
        if platform not in {"windows", "linux"} or channel not in {"Security", "System"} or authentication not in {"key", "password"}:
            raise ValueError
        if identity is not None:
            if not isinstance(identity, str) or re.search(r'["%$\r\n]', identity):
                raise ValueError
            identity = Path(identity).expanduser().resolve()
            if not identity.is_file():
                raise ValueError
        return {"platform": platform, "channel": channel, "identity_file": identity, "authentication": authentication}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
        raise CollectionError("Configure the host, platform and SSH key on the Live logs page.") from exc


def lab_target(storage: Path) -> tuple[str, str, int, Path]:
    settings = storage / "ssh-lab.json"
    known_hosts = storage / "ssh-known-hosts"
    try:
        if any(path.resolve().parent != storage or not path.is_file() for path in (settings, known_hosts)):
            raise ValueError
        with settings.open("rb") as config:
            data = json.loads(config.read(4097))
        if known_hosts.stat().st_size == 0 or re.search(r'["%$\r\n]', known_hosts.as_posix()):
            raise ValueError
        host, username, port = data["host"], data["username"], data.get("port", 22)
        platform = live_options(storage)["platform"]
        account_pattern = WINDOWS_USERNAME if platform == "windows" else USERNAME
        if (not HOST.fullmatch(host) or not account_pattern.fullmatch(username)
                or (platform == "linux" and username == "root") or type(port) is not int or not 1 <= port <= 65535):
            raise ValueError
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise CollectionError("Configure the authorized lab host and verified host key in local SSH settings.") from exc
    return host, username, port, known_hosts


def ssh_arguments(host: str, username: str, port: int, known_hosts: Path, *,
                  command: str = COMMAND, identity_file: Path | None = None) -> list[str]:
    return [
        "ssh", "-F", "none", "-T", "-a", "-x",
        "-o", "BatchMode=yes", "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=5",
        "-o", "ClearAllForwardings=yes", "-o", "PreferredAuthentications=publickey",
        "-o", f'IdentityFile="{identity_file.as_posix()}"' if identity_file else "IdentityFile=none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no", "-o", "GlobalKnownHostsFile=none",
        "-o", f'UserKnownHostsFile="{known_hosts.as_posix()}"',
        "-o", "IdentitiesOnly=yes" if identity_file else "IdentitiesOnly=no",
        "-l", username, "-p", str(port), "--", host, command,
    ]


def collect_journal(host: str, username: str, port: int, known_hosts: Path) -> bytes:
    return collect_output(ssh_arguments(host, username, port, known_hosts))


def collect_output(args: list[str], *, allow_empty: bool = False, authentication_probe: bool = False) -> bytes:
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE if authentication_probe else subprocess.DEVNULL)
    except OSError as exc:
        raise CollectionError("Could not start the local OpenSSH client.") from exc

    expired = Event()

    def deadline():
        expired.set()
        process.kill()

    with process:
        timer = Timer(TIMEOUT_SECONDS, deadline)
        timer.start()
        try:
            data = process.stdout.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                process.kill()
                raise CollectionError("SSH log output exceeds 1 MiB. Export a smaller sample manually.")
            status = process.wait()
        finally:
            timer.cancel()
            timer.join()
            if process.poll() is None:
                process.kill()
        if expired.is_set():
            raise CollectionError("SSH log retrieval timed out. Retry or import an export manually.")
        if status:
            if authentication_probe and b"permission denied" in process.stderr.read(4096).lower():
                raise KeyAuthenticationRequired("SSH key authentication was not accepted. Enter the SSH account password to continue.")
            raise CollectionError("SSH log retrieval failed. Check the host key, key authentication, and event log permissions.")
        if not data.strip() and not allow_empty:
            raise CollectionError("The SSH account returned no journal entries.")
        return data


def collect_live(target: tuple, options: dict) -> bytes:
    if options.get("authentication") == "password":
        raise CollectionError("Reconnect with the SSH account password on the Live logs page.")
    if options["platform"] == "windows":
        from .windows_live import windows_command
        command = windows_command(options["channel"])
        return collect_output(ssh_arguments(*target, command=command, identity_file=options["identity_file"]),
                              allow_empty=True)
    if options["identity_file"] is None:
        return collect_journal(*target)
    return collect_output(ssh_arguments(*target, identity_file=options["identity_file"]))
