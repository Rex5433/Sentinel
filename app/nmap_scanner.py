"""Opt-in, single-target TCP scans with fixed arguments and local history."""

from contextlib import suppress
from ipaddress import ip_address
import json
import re
import sqlite3
from threading import Event, Lock, Thread
from time import monotonic
from typing import Literal
from uuid import uuid4
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field

from .ssh_transport import SSHFailure
from .wazuh_ssh import NMAP, remote_scan, scan_command, utc_now


COMMON_PORTS = (22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995, 3389, 8080)
MAX_OUTPUT = 512 * 1024


class ScanTarget(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(max_length=45)
    sensitive: bool = True


class ScanInput(BaseModel):
    target: str = Field(pattern=r"^[a-f0-9]{32}$")
    profile: Literal["selected", "discovery", "service"]
    ports: str = Field(default="", max_length=128)
    authorized: Literal[True]


def target_address(value):
    ip = ip_address(value.strip())
    if "%" in value or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved and not ip.is_loopback or (
        ip.version == 4 and str(ip) == "255.255.255.255"
    ):
        raise ValueError("Enter one routable or loopback IP address.")
    if getattr(ip, "ipv4_mapped", None):
        return target_address(str(ip.ipv4_mapped))
    return str(ip)


def scan_ports(form, target):
    if target["sensitive"] and form.profile != "selected":
        raise ValueError("Sensitive hosts support only explicitly selected TCP ports.")
    if form.profile == "discovery":
        return COMMON_PORTS
    values = [value.strip() for value in form.ports.split(",")]
    limit = 4 if target["sensitive"] else 8 if form.profile == "service" else 24
    if not 1 <= len(values) <= limit or any(not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535 for value in values):
        raise ValueError(f"Enter 1–{limit} individual TCP port numbers separated by commas.")
    return tuple(sorted({int(value) for value in values}))


def scan_args(target, profile, ports, sensitive):
    argv = [NMAP, "--unprivileged", "-sT", "-Pn", "-n", "--max-retries", "1", "--max-rate", "4" if sensitive else "10",
            "--scan-delay", "250ms" if sensitive else "100ms", "--host-timeout", "90s", "-oX", "-",
            "-p", ",".join(map(str, ports))]
    if ":" in target:
        argv.append("-6")
    if profile == "service":
        argv += ["-sV", "--version-light"]
    return argv + [target]


def parse_scan(data, target, ports):
    if len(data) > MAX_OUTPUT or re.search(rb"<!ENTITY|<!DOCTYPE\s+[^>]*[\[\"']", data, re.I):
        raise ValueError("Nmap output exceeds the XML limit or contains an unsupported declaration.")
    root = ET.fromstring(data)
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or root.get("scanner") != "nmap" or finished is None:
        raise ValueError("Nmap did not return a completed scan.")
    if finished.get("exit") != "success":
        raise ValueError("Nmap reported an unsuccessful scan.")
    hosts = root.findall("host")
    if not hosts and root.find("runstats/hosts") is not None and root.find("runstats/hosts").get("up") == "0":
        raise ValueError("Nmap did not report the target. It may be unreachable or may have exceeded the host timeout.")
    if len(hosts) != 1 or not any(ip_address(row.get("addr")) == ip_address(target) for row in hosts[0].findall("address")
                                  if row.get("addrtype") in {"ipv4", "ipv6"} and row.get("addr")):
        raise ValueError("The scan did not report the selected host.")
    host = hosts[0]
    status = host.find("status")
    if status is None or status.get("state") not in {"up", "down", "unknown"}:
        raise ValueError("Nmap did not return a usable host status.")
    records = {}
    for row in host.findall("ports/port"):
        port, state, service = int(row.get("portid", "0")), row.find("state"), row.find("service")
        if row.get("protocol") != "tcp" or port not in ports or port in records or state is None:
            raise ValueError("Nmap returned ports outside the selected TCP scan.")
        records[port] = {"port": port, "protocol": "tcp", "state": state.get("state", "unknown"),
                         "service": (service.get("name") or "")[:80] if service is not None else "",
                         "version": " ".join(filter(None, [service.get("product"), service.get("version")]))[:160] if service is not None else ""}
    remaining = set(ports) - records.keys()
    extra = host.findall("ports/extraports")
    implicit = extra[0].get("state", "unknown") if len(extra) == 1 and extra[0].get("count") == str(len(remaining)) else "unknown"
    for port in remaining:
        records[port] = {"port": port, "protocol": "tcp", "state": implicit, "service": "", "version": ""}
    return status.get("state"), status.get("reason", "")[:80], [records[port] for port in sorted(records)]


def port_changes(previous, current):
    before = {row["port"]: row["state"] for row in previous}
    after = {row["port"]: row["state"] for row in current}
    return {"new_open": [port for port, state in after.items() if state == "open" and before.get(port) in {"closed", "filtered"}],
            "now_closed": [port for port, state in after.items() if state == "closed" and before.get(port) == "open"],
            "now_filtered": [port for port, state in after.items() if state == "filtered" and before.get(port) == "open"]}


class NmapScanner:
    def __init__(self, store, ssh):
        self.store = store
        self.ssh = ssh
        self.lock = Lock()
        self.active = None
        self.thread = None
        self.cancel = Event()
        self.closing = False
        self.error = None

    def initialize(self):
        with self.store.connect() as connection:
            connection.executescript("""CREATE TABLE IF NOT EXISTS nmap_targets(id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE, sensitive INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS nmap_runs(id TEXT PRIMARY KEY, stamp TEXT NOT NULL, address TEXT NOT NULL,
                    payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS nmap_observations(id TEXT PRIMARY KEY REFERENCES nmap_runs(id) ON DELETE CASCADE,
                    stamp TEXT NOT NULL, address TEXT NOT NULL, payload TEXT NOT NULL);""")

    def status(self):
        with self.lock:
            # A finished scan must appear in history before the active scan disappears.
            with self.store.connect() as connection:
                targets = [dict(row) for row in connection.execute("SELECT * FROM nmap_targets ORDER BY name,id")]
                history = [json.loads(row[0]) for row in connection.execute(
                    "SELECT payload FROM nmap_runs ORDER BY stamp DESC LIMIT 20")]
            active = dict(self.active) if self.active else None
            return {"targets": targets, "history": history, "active": active, "error": self.error}

    def add(self, form):
        name, address = form.name.strip(), target_address(form.address)
        if not name or not all(char.isprintable() for char in name):
            raise ValueError("Enter a valid target display name.")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT COUNT(*) FROM nmap_targets").fetchone()[0] >= 32:
                raise ValueError("Up to 32 authorized scan targets are supported.")
            if connection.execute("SELECT 1 FROM nmap_targets WHERE address=?", (address,)).fetchone():
                raise ValueError("This address is already an authorized target.")
            connection.execute("INSERT INTO nmap_targets VALUES (?,?,?,?)", (uuid4().hex, name, address, form.sensitive))

    def remove(self, id):
        with self.store.connect() as connection:
            return bool(connection.execute("DELETE FROM nmap_targets WHERE id=?", (id,)).rowcount)

    def start(self, form):
        with self.lock:
            if self.active or self.closing:
                raise ValueError("Wait for the current scan to finish.")
            with self.store.connect() as connection:
                row = connection.execute("SELECT * FROM nmap_targets WHERE id=?", (form.target,)).fetchone()
            if not row:
                raise ValueError("Select a saved authorized target.")
            target = dict(row)
            ports = scan_ports(form, target)
            profile, protected = self.ssh.saved()
            if not profile:
                raise ValueError("Save the Wazuh VM SSH connection before scanning.")
            password = self.ssh.saved_password(protected) if profile["authentication"] == "password" else None
            if profile["authentication"] == "password" and not password:
                raise ValueError("Enter and save the SSH password for this Sentinel session.")
            run = {"id": uuid4().hex, "address": target["address"], "target": target["name"], "timestamp": utc_now(),
                   "profile": form.profile, "requested_ports": list(ports), "status": "connecting"}
            self.cancel.clear()
            self.error = None
            self.active = run.copy()
            self.thread = Thread(target=self._run,
                                  args=(run, profile, password, self.ssh.revision, ports, target["sensitive"]), daemon=True)
            self.thread.start()
            return run

    def stop(self, run_id=None):
        with self.lock:
            if not self.active or (run_id is not None and run_id != self.active["id"]):
                return False
            self.cancel.set()
            self.active["status"] = "stopping"
            return True

    def close(self):
        with self.lock:
            self.closing = True
        self.stop()
        if self.thread:
            self.thread.join(16)

    def _run(self, run, profile, password, revision, ports, sensitive):
        started = monotonic()
        try:
            if self.cancel.is_set():
                run.update(status="cancelled", error="Stopped before launching Nmap.")
                return
            session = self.ssh.connect(profile, password)
            try:
                run["scanner_host"] = session.transport.get_remote_server_key().fingerprint
                self.ssh.report(revision, self.ssh.version(session))
                with self.lock:
                    if self.cancel.is_set():
                        run.update(status="cancelled", error="Stopped before launching Nmap.")
                        return
                    self.active["status"] = "running"
                command = scan_command(scan_args(run["address"], run["profile"], ports, sensitive))
                output = remote_scan(session, command, self.cancel, MAX_OUTPUT)
                if output is None:
                    run.update(status="cancelled", error="The Wazuh VM confirmed the scan stopped.")
                else:
                    state, reason, records = parse_scan(output, run["address"], ports)
                    run.update(status="completed", host_state=state, host_reason=reason, ports=records)
            finally:
                session.close()
        except (ValueError, OSError, ET.ParseError) as exc:
            run.update(status="failed", error=str(exc) if isinstance(exc, ValueError) else "Nmap could not complete a usable scan.")
            if isinstance(exc, SSHFailure):
                run["error_kind"] = exc.kind
                if exc.kind in {"host_key", "authentication", "network", "nmap_unavailable"}:
                    self.ssh.report(revision, {"state": exc.kind, "message": str(exc)})
        finally:
            with self.lock:
                run["duration_ms"] = round((monotonic() - started) * 1000)
                try:
                    self._save(run)
                except (sqlite3.Error, OSError):
                    self.error = "The scan ended but Sentinel could not save its history."
                finally:
                    self.active = None

    def _save(self, run):
        with self.store.connect() as connection:
            if run["status"] == "completed":
                previous = (json.loads(row[0]) for row in connection.execute(
                    "SELECT payload FROM nmap_runs WHERE address=? ORDER BY stamp DESC", (run["address"],)))
                base = next((row for row in previous if row["status"] == "completed" and row["profile"] == run["profile"]
                             and row["requested_ports"] == run["requested_ports"]
                             and row.get("scanner_host") == run["scanner_host"]), None)
                run["comparison"] = port_changes(base["ports"], run["ports"]) if base else None
                if base:
                    run["comparison_timestamp"] = base["timestamp"]
            connection.execute("INSERT INTO nmap_runs VALUES (?,?,?,?)",
                               (run["id"], run["timestamp"], run["address"], json.dumps(run)))
            if run.get("comparison") and any(run["comparison"].values()):
                observation = {"id": run["id"], "source": "nmap", "event_type": "port_state_change",
                               "timestamp": run["timestamp"], "host": run["address"], "target": run["target"],
                               "changes": run["comparison"], "baseline": run["comparison_timestamp"]}
                connection.execute("INSERT INTO nmap_observations VALUES (?,?,?,?)",
                                   (run["id"], run["timestamp"], run["address"], json.dumps(observation)))
            connection.execute("DELETE FROM nmap_runs WHERE id IN (SELECT id FROM nmap_runs ORDER BY stamp DESC LIMIT -1 OFFSET 100)")
