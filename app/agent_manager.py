"""Owner-initiated, read-only monitoring with one managed SSH session per host."""

import asyncio
from base64 import b64decode, b64encode
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import sqlite3
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Literal
from uuid import uuid4

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, ValidationError
from starlette.concurrency import run_in_threadpool

from .agent_collectors import CollectorUnavailable, DEFAULT_MODULES, collection_plan
from .agent_store import AgentStore, parse_records, utc_now
from .agent_capture import AgentCapture
from .db import StorageFull
from .live_bookmark import BookmarkGap
from .ssh_collection import CollectionError, HOST, USERNAME, WINDOWS_USERNAME
from .ssh_setup import trusted_host_keys
from .ssh_transport import SSHFailure, SSHSession


CONCURRENCY = 3
TEST_TTL = 300
CYCLE_SECONDS = 45
PROBE_SECONDS = 45
WINDOWS_PLATFORM = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + b64encode(
    "[Environment]::OSVersion.Platform.ToString()".encode("utf-16-le")).decode("ascii")


def setting(name, default, minimum, maximum):
    try:
        value = int(os.environ.get("SENTINEL_AGENT_" + name, str(default)))
    except ValueError:
        return default
    return value if minimum <= value <= maximum else default


class AgentInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)
    authentication: Literal["key", "password", "auto"] = "key"
    identity_file: str = Field(default="", max_length=1024)
    platform: Literal["auto", "windows", "linux"] = "auto"
    role: str = Field(default="", max_length=160)
    interval_seconds: int = Field(default=60, ge=15, le=3600)
    modules: list[str] = Field(default_factory=list, max_length=12)
    auto_modules: dict[Literal["windows", "linux"], list[str]] | None = None
    integrity_paths: list[str] = Field(default_factory=list, max_length=12)
    enabled: bool = False
    password: SecretStr | None = Field(default=None, max_length=1024)
    agent_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class SaveInput(BaseModel):
    test_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class ActionInput(BaseModel):
    action: Literal["connect", "disconnect", "reconnect", "collect", "reset_gap", "purge"]
    password: SecretStr | None = Field(default=None, max_length=1024)
    stream_id: str | None = Field(default=None, max_length=100)


@dataclass
class Tested:
    profile: dict
    pins: bytes
    streams: list
    password: str | None = field(repr=False)
    expires: float = field(default_factory=lambda: monotonic() + TEST_TTL)


@dataclass
class Worker:
    profile: dict
    pins: bytes
    password: str | None = field(repr=False)
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    stopped: bool = False
    task: asyncio.Task | None = None
    session: SSHSession | None = field(default=None, repr=False)
    failures: int = 0
    offset: int = 0


async def body(request, model):
    # Keep credential values out of framework validation responses.
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Send a JSON object.")
    data = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(data) + len(chunk) > 16384:
                    raise HTTPException(413, "The SSH settings exceed the request limit.")
                data.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "The SSH settings request timed out.") from None
    try:
        return model.model_validate_json(data)
    except (ValidationError, ValueError, RecursionError):
        raise HTTPException(422, "Check the SSH settings and required fields.") from None


def validate_profile(values):
    for key in ("host", "name", "role", "username", "identity_file"):
        values[key] = values[key].strip()
        if not all(char.isprintable() for char in values[key]):
            raise ValueError("SSH settings must use printable text.")
    if not values["name"] or not HOST.fullmatch(values["host"]) or not WINDOWS_USERNAME.fullmatch(values["username"]):
        raise ValueError("Enter a display name, hostname or IPv4 address, and SSH username.")
    values["host"] = values["host"].lower()
    identity = values["identity_file"]
    if identity and values["authentication"] in {"key", "auto"}:
        path = Path(identity).expanduser().resolve()
        if not path.is_file():
            raise ValueError("The private-key path does not point to a local file.")
        values["identity_file"] = str(path)
    if values["authentication"] == "password":
        values["identity_file"] = ""
    return values


class AgentManager:
    def __init__(self, store, *, connect=None, trust=None):
        self.store = store
        self.evidence = AgentStore(store)
        self.capture = AgentCapture(store)
        self.import_lock = asyncio.Lock()
        self.connect = connect or SSHSession.connect
        self.trust = trust or trusted_host_keys
        self.slots = asyncio.Semaphore(setting("CONCURRENCY", CONCURRENCY, 1, 8))
        self.connect_timeout = setting("CONNECT_TIMEOUT", 5, 2, 15)
        self.command_timeout = setting("COMMAND_TIMEOUT", 15, 3, 30)
        self.keepalive = setting("KEEPALIVE", 15, 5, 60)
        self.retry_max = setting("RETRY_MAX", 300, 15, 900)
        self.cycle_seconds = setting("CYCLE_BUDGET", CYCLE_SECONDS, 15, 90)
        self.output_bytes = setting("OUTPUT_BYTES", 1024 * 1024, 64 * 1024, 1024 * 1024)
        self.mutation = asyncio.Lock()
        self.workers: dict[str, Worker] = {}
        self.pending: dict[str, Tested] = {}
        self.generation = 0
        self.lease = None

    def initialize(self):
        self.evidence.initialize()
        self.capture.initialize()
        path = self.store.root / "ssh-agents.lock"
        if path.is_symlink():
            return
        try:
            handle = path.open("a+b")
        except OSError:
            return
        try:
            if os.name == "nt":
                import msvcrt
                # Windows blocks reads of the locked range. Keep the lease beyond the file contents.
                handle.seek(1024 * 1024)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lease = handle
        except OSError:
            handle.close()

    def release(self):
        if self.lease:
            self.lease.close()
            self.lease = None

    def open_session(self, profile, pins, password):
        # Existing OpenSSH trust is copied into a temporary pin file, with no key material copied.
        with TemporaryDirectory(prefix="managed-ssh-", dir=self.store.root) as directory:
            path = Path(directory) / "known_hosts"
            path.write_bytes(pins)
            target = (profile["host"], profile["username"], profile["port"], path)
            identity = Path(profile["identity_file"]) if profile["identity_file"] else None
            limits = {"connect_timeout": self.connect_timeout, "keepalive": self.keepalive}
            if profile["authentication"] == "password":
                return self.connect(target, password=password, **limits)
            try:
                return self.connect(target, identity_file=identity, **limits)
            except SSHFailure as exc:
                if exc.kind != "authentication" or profile["authentication"] != "auto":
                    raise
                if not password:
                    raise SSHFailure("password_required", "SSH key sign-in failed. Enter the account password to continue.") from None
            return self.connect(target, password=password, **limits)

    def probe(self, values, password, previous):
        if previous:
            old, pins, _ = previous
            if (values["host"], values["port"]) != (old["host"], old["port"]):
                raise ValueError("Add a new host to change the enrolled SSH address or port.")
        else:
            pins = self.trust(values["host"], values["port"], Path.home() / ".ssh" / "known_hosts")
        if not pins or len(pins) > 65536:
            raise ValueError("The enrolled host key list is empty or too large.")
        fingerprints = sorted({"SHA256:" + b64encode(sha256(b64decode(row.split()[2], validate=True)).digest()).decode().rstrip("=")
                               for row in pins.splitlines() if len(row.split()) >= 3 and not row.startswith(b"@")})
        if not fingerprints:
            raise ValueError("Verify the host key in OpenSSH before enrolling the host.")
        if values["authentication"] == "password" and not password:
            raise ValueError("Enter the SSH account password for this test.")
        session = self.open_session(values, pins, password)
        try:
            platform = values["platform"]
            if platform == "auto":
                try:
                    answer = session.read("uname -s", timeout=4).strip()
                except SSHFailure as exc:
                    if exc.retryable:
                        raise
                    answer = b""
                if answer == b"Linux":
                    platform = "linux"
                elif session.read(WINDOWS_PLATFORM, timeout=5).strip() == b"Win32NT":
                    platform = "windows"
                else:
                    raise ValueError("The operating system could not be detected. Select Windows or Linux.")
            if previous and previous[0]["platform"] != platform:
                raise ValueError("Add a new host to change the enrolled operating system.")
            if platform == "linux" and (not USERNAME.fullmatch(values["username"]) or values["username"] == "root"):
                raise ValueError("Use a non-root Linux SSH account.")
            values["platform"] = platform
            auto_choices = values.pop("auto_modules", None) or {}
            choices = auto_choices.get(platform, values["modules"])
            if platform in auto_choices and not choices:
                raise ValueError("Select at least one collector for the detected operating system.")
            values["modules"] = list(dict.fromkeys(choices or DEFAULT_MODULES[platform]))
            plans = collection_plan(platform, values["modules"], values["integrity_paths"])
            results = []
            deadline = monotonic() + PROBE_SECONDS
            for stream in plans:
                detail = {"id": stream.id, "label": stream.label, "status": "error", "error": None}
                remaining = deadline - monotonic()
                if remaining <= 0:
                    detail["error"] = "The connection test reached its collection budget."
                else:
                    try:
                        page = stream.parse(session.read(stream.command(), timeout=min(self.command_timeout, 8, remaining),
                                                         max_bytes=self.output_bytes))
                        if page.records:
                            parsed = self._test_parse(values, stream, page)
                            if not parsed:
                                raise ValueError("The collector returned invalid event records.")
                        detail["status"] = "snapshot" if page.snapshot is not None else "ready" if page.records else "empty"
                    except CollectorUnavailable as exc:
                        detail.update(collector_error(exc))
                    except (CollectionError, ValueError) as exc:
                        detail["error"] = str(exc)[:400]
                        detail["error_kind"] = getattr(exc, "kind", "collector")
                results.append(detail)
            if not any(row["status"] in {"ready", "empty", "snapshot"} for row in results):
                failure = next((row["error"] for row in results if row["error"]), "No selected collectors are available.")
                raise ValueError(failure)
            return Tested(values, pins, results, password), fingerprints
        finally:
            session.close()

    @staticmethod
    def _test_parse(values, stream, page):
        result = parse_records(b"".join(page.records.values()), "ssh-test", values["id"], stream.source_format)
        return not result.rejected and len(result.events) == len(page.records)

    def start(self, profile, pins, password=None):
        id = profile["id"]
        if id not in self.workers and profile["enabled"]:
            worker = Worker(profile, pins, password)
            self.workers[id] = worker
            worker.task = asyncio.create_task(self.run(worker))

    async def stop(self, id):
        worker = self.workers.get(id)
        password = worker.password if worker else None
        if worker:
            worker.stopped = True
            worker.wake.set()
            if worker.session:
                await run_in_threadpool(worker.session.close)
            await worker.task
            self.workers.pop(id, None)
        return password

    async def close(self):
        self.generation += 1
        self.pending.clear()
        await asyncio.gather(*(self.stop(id) for id in list(self.workers)))

    async def restore(self):
        if not self.lease:
            return
        for row in await run_in_threadpool(self.evidence.list):
            if row["enabled"] and row["id"] not in self.workers:
                found = await run_in_threadpool(self.evidence.get, row["id"])
                if found:
                    self.start(found[0], found[1])

    async def run(self, worker):
        id = worker.profile["id"]
        try:
            delay = random.uniform(0, 2)
            while not worker.stopped:
                try:
                    await asyncio.wait_for(worker.wake.wait(), timeout=delay)
                except TimeoutError:
                    pass
                worker.wake.clear()
                if worker.stopped:
                    break
                async with self.slots:
                    if worker.stopped:
                        break
                    try:
                        delay = await self.cycle(worker)
                    except SSHFailure as exc:
                        if worker.session:
                            await run_in_threadpool(worker.session.close)
                            worker.session = None
                        worker.failures += 1
                        status = "retrying" if exc.retryable else "waiting_for_password" if exc.kind == "password_required" else "blocked"
                        await run_in_threadpool(self.evidence.set_health, id, status,
                                                str(exc), error_kind=exc.kind)
                        delay = min(self.retry_max, 5 * 2 ** min(8, worker.failures - 1) * random.uniform(.8, 1.2)) if exc.retryable else None
                    except (OSError, sqlite3.Error, ValueError):
                        with suppress(OSError, sqlite3.Error):
                            await run_in_threadpool(self.evidence.set_health, id, "partial",
                                                    "Local collection processing failed. Review the latest committed checkpoint.",
                                                    error_kind="processing")
                        delay = worker.profile["interval_seconds"]
                await self.save_live(worker.profile)
        finally:
            if worker.session:
                await run_in_threadpool(worker.session.close)
            worker.password = None

    async def save_live(self, profile, *, force=False, stop=False):
        id = profile["id"]
        try:
            if await run_in_threadpool(self.capture.status, id) is None:
                return None
            async with self.import_lock:
                upload_id = await run_in_threadpool(self.capture.flush, profile, force=force)
                if stop:
                    # A retry may first finish an older cutoff. Flush newer retained records too.
                    upload_id = await run_in_threadpool(self.capture.flush, profile, force=True) or upload_id
                    await run_in_threadpool(self.capture.stop, id)
                return upload_id
        except (OSError, sqlite3.Error, ValueError) as exc:
            message = str(exc) if isinstance(exc, StorageFull) else "Live capture could not save its next batch. Check local storage."
            with suppress(OSError, sqlite3.Error):
                await run_in_threadpool(self.capture.set_error, id, message)
            if force:
                raise ValueError(message) from None
            return None

    async def cycle(self, worker):
        profile = worker.profile
        id = profile["id"]
        if profile["authentication"] == "password" and not worker.password:
            await run_in_threadpool(self.evidence.set_health, id, "waiting_for_password",
                                    "Enter the SSH password to resume this host.")
            return None
        if not worker.session or not worker.session.active:
            await run_in_threadpool(self.evidence.set_health, id, "connecting")
            if worker.session:
                await run_in_threadpool(worker.session.close)
            worker.session = await run_in_threadpool(self.open_session, profile, worker.pins, worker.password)
            if worker.stopped:
                return 0
        plans = collection_plan(profile["platform"], profile["modules"], profile["integrity_paths"])
        state = await run_in_threadpool(self.evidence.streams, id)
        deadline = monotonic() + self.cycle_seconds
        inserted = 0
        succeeded = False
        try:
            for _ in plans:
                if worker.stopped or deadline - monotonic() < 1:
                    break
                stream = plans[worker.offset % len(plans)]
                worker.offset = (worker.offset + 1) % len(plans)
                position, previous = state.get(stream.id, (None, {}))
                if previous.get("status") == "gap" or not due(stream, previous):
                    continue
                detail = {"id": stream.id, "label": stream.label, "status": "ready", "error": None,
                          "observed_at": utc_now(), "backlog": False, "snapshot": previous.get("snapshot")}
                try:
                    raw = await run_in_threadpool(worker.session.read, stream.command(position),
                                                  timeout=min(self.command_timeout, deadline - monotonic()),
                                                  max_bytes=self.output_bytes)
                    if worker.stopped:
                        break
                    page = stream.parse(raw, position)
                    detail["status"] = "snapshot" if page.snapshot is not None else "ready" if page.records else "empty"
                    detail["backlog"] = page.more
                    if page.snapshot is not None:
                        detail.update(snapshot_details(stream, previous, page.snapshot))
                    changed = bool(detail.get("changes") and detail["changes"] != previous.get("changes"))
                    inserted += await run_in_threadpool(self.evidence.page, profile, stream, page, detail, emit_change=changed)
                    succeeded = True
                    state[stream.id] = (page.bookmark, detail)
                except BookmarkGap as exc:
                    detail.update(status="gap", error=str(exc)[:400], error_kind="gap")
                    state[stream.id] = (position, detail)
                    await run_in_threadpool(self.evidence.stream_status, id, stream.id, position, detail)
                except (CollectionError, ValueError) as exc:
                    if isinstance(exc, SSHFailure) and (exc.retryable or exc.kind in {"authentication", "host_key"}):
                        raise
                    detail.update(collector_error(exc))
                    state[stream.id] = (position, detail)
                    await run_in_threadpool(self.evidence.stream_status, id, stream.id, position, detail)
        finally:
            if inserted or await run_in_threadpool(self.evidence.review_pending, id):
                await run_in_threadpool(self.evidence.analyze, profile)
        if worker.stopped:
            return 0
        selected = [state[plan.id][1] for plan in plans if plan.id in state]
        errors = [row for row in selected if row["status"] in {"gap", "error"}]
        worker.failures = 0
        if succeeded:
            await run_in_threadpool(self.evidence.set_health, id, "partial" if errors else "connected",
                                    errors[0]["error"] if errors else None, error_kind="collector" if errors else None,
                                    last_success_at=utc_now())
        elif errors:
            await run_in_threadpool(self.evidence.set_health, id, "partial", errors[0]["error"], error_kind="collector")
        elif selected and all(row["status"] == "absent" for row in selected):
            await run_in_threadpool(self.evidence.set_health, id, "partial", "No selected log sources are present.",
                                    error_kind="unavailable")
        return (5 if any(row.get("backlog") for row in selected) else profile["interval_seconds"]) * random.uniform(.9, 1.1)


def collector_error(exc):
    kind = getattr(exc, "kind", "collector")
    return {"status": "absent" if kind == "optional_absent" else "error", "error": str(exc)[:400], "error_kind": kind}


def due(stream, detail):
    if stream.minimum_interval and detail.get("observed_at"):
        from datetime import datetime, timezone
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(detail["observed_at"])).total_seconds()
        return age >= stream.minimum_interval
    return True


def snapshot_details(stream, prior, snapshot):
    details = {"snapshot": snapshot}
    if stream.module not in {"integrity", "network"}:
        return details
    if stream.module == "network" and stream.id not in {"tcp", "udp", "sockets"}:
        return details
    baseline = prior.get("baseline") or (snapshot if not snapshot.get("limited") else None)
    details["baseline"] = baseline
    if baseline and not snapshot.get("limited"):
        if stream.module == "integrity":
            earlier = {row["path"]: row for row in baseline["rows"] if row.get("status") == "ok"}
            current = {row["path"]: row for row in snapshot["rows"] if row.get("status") == "ok"}
            changes = [{"path": path, "before": earlier[path], "after": current[path]}
                       for path in sorted(earlier.keys() & current.keys()) if earlier[path] != current[path]]
            details["unavailable_paths"] = sum(row.get("status") != "ok" for row in snapshot["rows"])
            details["baseline"] = baseline | {"rows": list((current | earlier).values())}
        else:
            earlier = listener_endpoints(stream, baseline)
            current = listener_endpoints(stream, snapshot)
            changes = [{"endpoint": address} for address in sorted(current - earlier)]
        details["changed_rows"] = len(changes)
        details["changes"] = changes
    return details


def listener_endpoints(stream, snapshot):
    result = set()
    for row in snapshot["rows"]:
        if stream.id == "sockets":
            protocol, state = row.get("protocol"), str(row.get("state", "")).upper()
            if (protocol, state) in {("tcp", "LISTEN"), ("udp", "UNCONN")}:
                result.add(f"{protocol} {row.get('local_endpoint')}")
        elif stream.id == "udp" or str(row.get("State", "")).lower() == "listen":
            if row.get("LocalAddress") and type(row.get("LocalPort")) is int:
                result.add(f"{stream.id} {row['LocalAddress']}:{row['LocalPort']}")
    return result
