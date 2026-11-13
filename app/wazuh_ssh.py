"""Per-installation Wazuh SSH settings and bounded remote scan commands."""

from ipaddress import ip_address
from datetime import datetime, timezone
from base64 import b64decode
import json
import os
from pathlib import Path
import re
from secrets import token_urlsafe
from shlex import join, quote
from subprocess import SubprocessError
from threading import Lock, Timer
from time import monotonic, sleep
from urllib.parse import urlsplit
from typing import Literal

import paramiko
from pydantic import BaseModel, Field, SecretStr

from .ssh_collection import HOST, USERNAME
from .ssh_setup import trusted_host_keys
from .ssh_transport import SSHFailure, SSHSession
from .wazuh_connections import protect


DASHBOARD = "https://127.0.0.1:8443"
NMAP = "/usr/bin/nmap"
REMOTE_TIMEOUT = 100
PROFILE_FIELDS = ("host", "port", "username", "authentication", "identity_file")
VERSION_COMMAND = (
    "PATH=/usr/bin:/bin; export PATH; "
    "uid=$(id -u) && [ \"$uid\" -gt 0 ] && command -v timeout >/dev/null && command -v flock >/dev/null && "
    f"exec {NMAP} --version"
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class ConnectionInput(BaseModel):
    host: str = Field(default="127.0.0.1", max_length=253)
    port: int = Field(default=2222, ge=1, le=65535)
    username: str = Field(max_length=32)
    approval: str | None = Field(default=None, max_length=64)
    authentication: Literal["password", "key"]
    identity_file: str = Field(default="", max_length=1024)
    password: SecretStr | None = Field(default=None, max_length=2048)


class DashboardInput(BaseModel):
    url: str = Field(max_length=512)


class HostKeyApprovalRequired(Exception):
    def __init__(self, endpoint, key, approval):
        self.details = {"state": "approval_required", "host": endpoint[0], "port": endpoint[1],
                        "key_type": key.get_name(), "fingerprint": key.fingerprint, "approval": approval}


def dashboard_url(value):
    value = value.strip()
    try:
        if re.search(r"[\s\\\x00-\x1f\x7f]", value):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.port == 0
                or not re.fullmatch(r"[a-zA-Z0-9.:-]+", parsed.hostname)):
            raise ValueError
    except ValueError:
        raise ValueError("Enter an HTTPS dashboard URL without credentials.") from None
    return value


class WazuhSSH:
    def __init__(self, store):
        self.store = store
        self.password = None
        self.check = {"state": "not_configured"}
        self.lock = Lock()
        self.revision = 0
        self.pending = None

    def initialize(self):
        with self.store.connect() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS wazuh_ssh_profile (
                id INTEGER PRIMARY KEY CHECK(id=1), settings TEXT NOT NULL, credential BLOB);
                CREATE TABLE IF NOT EXISTS wazuh_ssh_host_keys (
                host TEXT NOT NULL, port INTEGER NOT NULL, key_type TEXT NOT NULL, public_key BLOB NOT NULL,
                PRIMARY KEY(host,port));
                CREATE TABLE IF NOT EXISTS wazuh_dashboard (
                id INTEGER PRIMARY KEY CHECK(id=1), url TEXT NOT NULL);""")
        profile, _ = self.saved()
        if profile:
            if profile.get("fingerprint"):
                with self.store.connect() as db:
                    db.execute("INSERT OR IGNORE INTO wazuh_ssh_host_keys VALUES (?,?,?,?)",
                               (profile["host"], profile["port"], profile["host_key_type"], profile["fingerprint"]))
            self.check = {"state": "untested"}

    def saved(self):
        with self.store.connect() as db:
            row = db.execute("SELECT settings,credential FROM wazuh_ssh_profile WHERE id=1").fetchone()
        return (json.loads(row[0]), row[1]) if row else (None, None)

    def dashboard(self):
        with self.store.connect() as db:
            row = db.execute("SELECT url FROM wazuh_dashboard WHERE id=1").fetchone()
        return row[0] if row else DASHBOARD

    def save_dashboard(self, url):
        url = dashboard_url(url)
        with self.store.connect() as db:
            db.execute("INSERT OR REPLACE INTO wazuh_dashboard VALUES (1,?)", (url,))
        return url

    def public(self):
        profile, protected = self.saved()
        public_profile = {field: profile[field] for field in PROFILE_FIELDS} if profile else None
        return {"profile": public_profile, "dashboard_url": self.dashboard(), "credential_saved": bool(protected),
                "password_available": bool(protected or self.password), "status": self.check}

    def prepare(self, form):
        host, username = form.host.strip().lower(), form.username.strip()
        try:
            if "%" in host:
                raise ValueError
            host = str(ip_address(host))
        except ValueError:
            if not HOST.fullmatch(host):
                raise ValueError("Enter the Wazuh VM's SSH hostname or IP address.") from None
        if not USERNAME.fullmatch(username) or username == "root":
            raise ValueError("Enter a non-root Linux SSH account.")
        identity = form.identity_file.strip() if form.authentication == "key" else ""
        if identity:
            if identity.startswith(("\\\\", "//")) or not all(char.isprintable() for char in identity):
                raise ValueError("Use the absolute path to a local SSH private key.")
            path = Path(identity).expanduser()
            if not path.is_absolute() or not path.is_file():
                raise ValueError("Use the absolute path to a local SSH private key.")
            identity = str(path)
        profile = {"host": host, "port": form.port, "username": username,
                   "authentication": form.authentication, "identity_file": identity}
        password = None
        if form.authentication == "password":
            password = form.password.get_secret_value() if form.password else None
            previous, protected = self.saved()
            if not password and self.is_saved(profile, previous):
                password = self.saved_password(protected)
        return profile, password

    @staticmethod
    def is_saved(profile, saved):
        return saved is not None and all(profile[field] == saved.get(field) for field in PROFILE_FIELDS)

    def saved_password(self, protected):
        return self.password or (protect(protected, decrypt=True).decode() if protected and os.name == "nt" else None)

    @staticmethod
    def remember_key(db, endpoint, key):
        db.execute("""INSERT INTO wazuh_ssh_host_keys VALUES (?,?,?,?) ON CONFLICT(host,port)
                   DO UPDATE SET key_type=excluded.key_type,public_key=excluded.public_key
                   WHERE typeof(wazuh_ssh_host_keys.public_key)='text'""",
                   (*endpoint, key.get_name(), key.asbytes()))

    def remember(self, profile, password, key, status, *, save):
        protected = protect(password.encode()) if save and password and os.name == "nt" else None
        with self.lock:
            with self.store.connect() as db:
                self.remember_key(db, (profile["host"], profile["port"]), key)
                if save:
                    db.execute("INSERT OR REPLACE INTO wazuh_ssh_profile VALUES (1,?,?)", (json.dumps(profile), protected))
            self.pending = None
            if save:
                self.password = password if not protected else None
                self.revision += 1
            if save or self.is_saved(profile, self.saved()[0]):
                self.check = status

    def report(self, revision, status):
        with self.lock:
            if revision == self.revision:
                self.check = status

    def trust(self, profile, *, interactive=False, approval=None):
        endpoint = profile["host"], profile["port"]
        with self.store.connect() as db:
            row = db.execute("SELECT key_type,public_key FROM wazuh_ssh_host_keys WHERE host=? AND port=?", endpoint).fetchone()
        if row:
            if approval:
                raise ValueError("This destination already has a verified key. Test the connection again.")
            if isinstance(row[1], str):
                return {"host_fingerprint": row[1], "host_key_type": row[0]}
            try:
                return {"trusted_keys": {row[0]: [paramiko.PKey.from_type_string(row[0], row[1])]}}
            except (ValueError, paramiko.SSHException):
                raise SSHFailure("host_key", "The saved SSH host key could not be read.") from None

        try:
            pins = trusted_host_keys(*endpoint, Path.home() / ".ssh" / "known_hosts", missing_ok=True)
            keys = {}
            for entry in pins.splitlines():
                _, key_type, data, *_ = entry.split()
                if entry.lstrip().startswith(b"@"):
                    raise ValueError("Unsupported marked known_hosts entry.")
                name = key_type.decode("ascii")
                key = paramiko.PKey.from_type_string(name, b64decode(data, validate=True))
                keys.setdefault(name, []).append(key)
        except (OSError, ValueError, SubprocessError, paramiko.SSHException):
            raise SSHFailure("host_key", "Sentinel could not verify this entry in OpenSSH known_hosts. Check the file and its host key.") from None
        if approval:
            pending = self.pending
            if pending and pending[0] == approval and pending[1] == endpoint and monotonic() < pending[3]:
                key = pending[2]
                if keys and key not in keys.get(key.get_name(), ()):
                    raise SSHFailure("host_key", "The approval does not match the key in OpenSSH known_hosts.")
                with self.store.connect() as db:
                    self.remember_key(db, endpoint, key)
                self.pending = None
                return {"trusted_keys": {key.get_name(): [key]}}
            raise ValueError("The SSH host-key approval expired or the address changed. Test the connection again.")
        if keys:
            return {"trusted_keys": keys}
        if not interactive:
            raise SSHFailure("host_key", "Test the saved connection and approve its verified host key.")
        key = SSHSession.discover_host_key(*endpoint)
        token = token_urlsafe(24)
        self.pending = (token, endpoint, key, monotonic() + 120)
        raise HostKeyApprovalRequired(endpoint, key, token)

    def connect(self, profile, password, *, trust=None):
        trust = self.trust(profile) if trust is None else trust
        if profile["authentication"] == "password" and not password:
            raise SSHFailure("authentication", "Enter the SSH password for this profile.")
        try:
            return SSHSession.connect((profile["host"], profile["username"], profile["port"], None),
                identity_file=profile["identity_file"] or None, password=password, connect_timeout=8, **trust)
        except SSHFailure as exc:
            if exc.kind == "network":
                raise SSHFailure("network", "SSH port unreachable or connection dropped. Check the VM, hotspot, and port forwarding.") from None
            raise

    def probe(self, profile, password, *, interactive=False, approval=None):
        trust = self.trust(profile, interactive=interactive, approval=approval)
        session = self.connect(profile, password, trust=trust)
        try:
            return self.version(session), session.transport.get_remote_server_key()
        finally:
            session.close()

    def version(self, session):
        try:
            data = session.read(VERSION_COMMAND, timeout=6, max_bytes=8192)
            version = next((line for line in data.decode("utf-8", "replace").splitlines()
                            if re.fullmatch(r"Nmap version [0-9][ -~]{0,100}", line)), None)
            if not version:
                raise SSHFailure("nmap_unavailable", "SSH authenticated, but the VM did not return an Nmap version.")
            return {"state": "connected", "version": version, "checked_at": utc_now()}
        except SSHFailure as exc:
            if exc.kind in {"command", "permission"}:
                raise SSHFailure("nmap_unavailable", "SSH authenticated. Check /usr/bin/nmap, timeout, flock, and the non-root account on the VM.") from None
            raise


def scan_command(args):
    # A lock on the executable's read-only descriptor limits scans across teammate accounts.
    # Closing the command's input, or sending a line, signals only this timeout supervisor.
    script = f"""PATH=/usr/bin:/bin
export PATH
uid=$(id -u) && [ "$uid" -gt 0 ] || exit 76
exec 9<{NMAP} || exit 76
flock -n -E 75 9 || exit "$?"
exec 3<&0
timeout -k 3s {REMOTE_TIMEOUT}s env -i PATH=/usr/bin:/bin LC_ALL=C {join(args)} </dev/null &
scan=$!
( IFS= read -r stop <&3; kill -TERM "$scan" 2>/dev/null ) &
watch=$!
wait "$scan"
result=$?
kill "$watch" 2>/dev/null
wait "$watch" 2>/dev/null
exit "$result"
"""
    return "/bin/sh -c " + quote(script)


def remote_scan(session, command, cancel, max_bytes):
    deadline = monotonic() + REMOTE_TIMEOUT + 10
    channel = None
    stop_deadline = None
    try:
        channel = session.transport.open_session(timeout=5)
        # Paramiko's exec request has no independent acknowledgement timeout.
        timer = Timer(5, channel.close)
        timer.daemon = True
        timer.start()
        try:
            channel.exec_command(command)
        finally:
            timer.cancel()
        data = bytearray()
        stderr_size = 0
        while monotonic() < deadline:
            if cancel.is_set() and stop_deadline is None:
                channel.shutdown_write()
                stop_deadline = monotonic() + 6
            if channel.recv_ready():
                data.extend(channel.recv(32768))
            if channel.recv_stderr_ready():
                stderr_size += len(channel.recv_stderr(32768))
            if len(data) + stderr_size > max_bytes:
                raise SSHFailure("output_limit", "The remote scan exceeded its output limit.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                status = channel.recv_exit_status()
                if status == -1:
                    raise SSHFailure("network", "The SSH scan channel closed before returning a result.")
                if stop_deadline is not None and status in {137, 143}:
                    return None
                if status == 75:
                    raise SSHFailure("busy", "The Wazuh VM is already running a Sentinel scan. Try again when it finishes.")
                if status == 76:
                    raise SSHFailure("nmap_unavailable", "The VM needs a non-root SSH account and a readable /usr/bin/nmap.")
                if status in {126, 127}:
                    raise SSHFailure("nmap_unavailable", "The VM could not run Nmap or its scan utilities.")
                if status in {124, 137}:
                    raise SSHFailure("timeout", "The remote Nmap scan timed out.")
                if status:
                    raise SSHFailure("command", "Nmap could not complete the scan. Check the VM route and target availability.")
                return bytes(data)
            if stop_deadline is not None and monotonic() >= stop_deadline:
                raise SSHFailure("network", "The VM did not confirm the stop. The scan has a remote timeout.")
            if not session.active:
                raise SSHFailure("network", "SSH disconnected during the scan. The scan has a remote timeout.")
            sleep(.04)
        raise SSHFailure("timeout", "The scan timed out while waiting for the Wazuh VM.")
    except (OSError, EOFError, paramiko.SSHException):
        raise SSHFailure("network", "The Wazuh VM disconnected or refused the scan channel.") from None
    finally:
        if channel is not None:
            channel.close()
