"""Bounded, browser-driven lab journal review over the existing SSH pull."""

from dataclasses import dataclass, field, replace
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from hmac import compare_digest
from ipaddress import ip_address
from pathlib import Path
from math import ceil
import subprocess
import sqlite3
from time import monotonic
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, StringConstraints
from starlette.concurrency import run_in_threadpool

from sentinel.detection.linux_review import linux_findings
from sentinel.detection.rules import baseline_findings
from sentinel.features import extract_features
from sentinel.ingest import ParseInputError, parse_linux
from sentinel.ingest.windows_jsonl import parse_windows_jsonl
from sentinel.detection.windows_review import windows_findings, field as windows_field
from sentinel.ingest.common import load_json

from . import ssh_collection
from .analysis import analysis_summary, run_analysis
from .db import StorageFull
from .windows_live import windows_records
from .ssh_setup import parse_connection, save_profile
from .live_archive import LiveArchive


POLL_SECONDS = 5
IDLE_SECONDS = 45
STOPPED_SECONDS = 5 * 60
RETAIN_SECONDS = 60 * 60
BUFFER_RECORDS = 10_000
BUFFER_BYTES = 16 * 1024 * 1024
AUTOSAVE_SECONDS = 15 * 60
RETRY_LIMIT = 3


class LiveConnection(BaseModel):
    ssh_command: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
    platform: Literal["windows", "linux"] = "windows"
    channel: Literal["Security", "System"] = "Security"
    identity_file: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1024)] = ""
    authentication: Literal["auto", "key", "password"] = "auto"


class WatchSettings(BaseModel):
    autosave: bool = False


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def journal_records(data: bytes) -> tuple[dict[str, bytes], int]:
    lines = data.splitlines(keepends=True)
    if len(data) > ssh_collection.MAX_BYTES or len(lines) > ssh_collection.MAX_RECORDS:
        raise ssh_collection.CollectionError("The SSH response exceeded the journal batch limits.")
    records = {}
    skipped = 0
    for line in lines:
        try:
            value = load_json(line.decode("utf-8"))
        except (ValueError, RecursionError):
            value = None
        cursor = value.get("__CURSOR") if isinstance(value, dict) else None
        if not isinstance(cursor, str) or not cursor or len(cursor) > 512 or not line.endswith(b"\n"):
            skipped += 1
            continue
        records.setdefault(cursor, line)
    return records, skipped


def parse_buffer(data: bytes, source: str, watch_id: str, platform: str):
    if platform == "windows":
        return parse_windows_jsonl(data, source_file=source, upload_id=watch_id)
    return parse_linux(data, file_format="journal-json", source_file=source, upload_id=watch_id)


def review_buffer(data: bytes, source: str, watch_id: str, platform: str = "linux") -> dict:
    if not data:
        return {"events": [], "findings": [], "finding_count": 0, "flagged": {}, "rejected": 0,
                "process_creation_events": 0, "process_creation_with_command_line": 0}
    result = parse_buffer(data, source, watch_id, platform)
    extraction = extract_features(result.events)
    findings = baseline_findings(extraction)
    findings.extend(windows_findings(extraction)[0] if platform == "windows" else linux_findings(result.events))
    findings.sort(key=lambda entry: (
        entry["finding"]["timestamp_utc"] or "", entry["finding"]["triage_priority"],
    ), reverse=True)
    flagged = {}
    priority = {"context": 0, "lead": 1, "warning": 2, "critical": 3}
    for entry in findings:
        severity = entry.get("severity", "warning")
        for event_id in entry["finding"]["evidence_event_ids"]:
            if event_id not in flagged or priority[severity] > priority[flagged[event_id]]:
                flagged[event_id] = severity
    process_events = [event for event in result.events if getattr(event, "windows_event_id", None) == 4688]
    return {
        "events": [event.model_dump(mode="json") for event in result.events],
        "findings": findings[:50],
        "finding_count": len(findings),
        "flagged": flagged,
        "rejected": len(result.rejected),
        "process_creation_events": len(process_events),
        "process_creation_with_command_line": sum(bool(windows_field(event.raw_record, "CommandLine")) for event in process_events),
    }


@dataclass
class Watch:
    id: str
    target: tuple[str, str, int, Path]
    started: float
    last_poll: float
    options: dict = field(default_factory=lambda: {"platform": "linux", "channel": "Security", "identity_file": None})
    session: object | None = field(default=None, repr=False)
    token: str = field(default_factory=lambda: uuid4().hex, repr=False)
    owner_connected: bool = False
    autosave: bool = False
    archive: object | None = field(default=None, repr=False)
    archive_saved: int = 0
    archive_error: str | None = None
    last_autosave: float = 0
    last_autosave_id: str | None = None
    next_poll: float = 0.0
    stopped: str | None = None
    stopped_at: float | None = None
    checked_at: str | None = None
    pulls: int = 0
    attempts: int = 0
    new_last_pull: int = 0
    received: int = 0
    duration_ms: int | None = None
    error: str | None = None
    errors: int = 0
    cursor: str | None = None
    gap: bool = False
    skipped: int = 0
    evicted: int = 0
    age_evicted: int = 0
    capacity_evicted: int = 0
    revision: int = 0
    archived: str | None = None
    saved_revision: int = -1
    records: dict[str, bytes] = field(default_factory=dict)
    arrived: dict[str, float] = field(default_factory=dict)
    added: dict[str, bytes] = field(default_factory=dict, repr=False)
    review: dict = field(default_factory=lambda: {
        "events": [], "findings": [], "finding_count": 0, "flagged": {}, "rejected": 0,
    })

    def stop(self, reason: str):
        self.stopped = reason
        self.stopped_at = monotonic()
        if self.session:
            self.session.close()

    @property
    def source(self) -> str:
        if self.options["platform"] == "windows":
            return f"ssh-live-windows-{self.target[0]}-{self.target[2]}-{self.options['channel']}.jsonl"
        return f"ssh-live-{self.target[0]}-{self.target[2]}.jsonl"

    def retain(self, batch: dict[str, bytes], skipped: int):
        self.skipped += skipped
        self.gap |= bool(skipped or (self.cursor is not None and self.cursor not in batch))
        cursors = list(batch)
        fresh = cursors[cursors.index(self.cursor) + 1:] if self.cursor in batch else cursors
        additions = {cursor: batch[cursor] for cursor in fresh if cursor not in self.records}
        self.added = additions
        if additions:
            self.records.update(additions)
            self.arrived.update(dict.fromkeys(additions, monotonic()))
            self.cursor = cursors[-1]
            self.revision += 1
        self.trim()
        return len(additions)

    def trim(self):
        cutoff = monotonic() - RETAIN_SECONDS
        expired = [cursor for cursor in self.records if self.arrived.get(cursor, self.started) <= cutoff]
        for cursor in expired:
            self.records.pop(cursor)
            self.arrived.pop(cursor, None)
        self.age_evicted += len(expired)
        size = sum(map(len, self.records.values()))
        removed = 0
        while len(self.records) > BUFFER_RECORDS or size > BUFFER_BYTES:
            cursor = next(iter(self.records))
            size -= len(self.records.pop(cursor))
            self.arrived.pop(cursor, None)
            removed += 1
        self.capacity_evicted += removed
        self.evicted += len(expired) + removed
        if expired or removed:
            self.revision += 1

    def view(self, revision: int | None = None) -> dict:
        return {
            "id": self.id,
            "platform": self.options["platform"],
            "channel": self.options["channel"] if self.options["platform"] == "windows" else None,
            "active": self.stopped is None,
            "stopped": self.stopped,
            "checked_at": self.checked_at,
            "pulls": self.pulls,
            "attempts": self.attempts,
            "new_last_pull": self.new_last_pull,
            "received": self.received,
            "duration_ms": self.duration_ms,
            "next_poll_ms": max(0, ceil((self.next_poll - monotonic()) * 1000)),
            "error": self.error,
            "possible_gap": self.gap,
            "skipped": self.skipped,
            "evicted": self.evicted,
            "age_evicted": self.age_evicted,
            "capacity_evicted": self.capacity_evicted,
            "retained_seconds": RETAIN_SECONDS,
            "buffer_records": BUFFER_RECORDS,
            "buffer_bytes": BUFFER_BYTES,
            "retained": len(self.records),
            "parsed": len(self.review["events"]),
            "rejected": self.review["rejected"],
            "revision": self.revision,
            "archived": self.archived,
            "saved_revision": self.saved_revision,
            "autosave": self.autosave,
            "archive_saved": self.archive_saved,
            "archive_error": self.archive_error,
            "last_autosave_id": self.last_autosave_id,
            "review": self.review if revision != self.revision else None,
        }


def register_live_logs(application, store, *, enabled: bool):
    watch: Watch | None = None
    connection = None
    connection_id = None
    generation = 0
    guards = set()
    finalizers = set()

    async def archive_flush(item, *, sealed_only=False):
        if not item.archive:
            return
        try:
            saved = await run_in_threadpool(item.archive.save, sealed_only=sealed_only)
            state = await run_in_threadpool(item.archive.status)
            item.archive_saved = state["saved_chunks"]
            item.last_autosave_id = state["last_upload_id"]
            for entry in saved:
                await run_in_threadpool(run_analysis, store, entry)
            item.archive_error = None
        except (StorageFull, OSError, ValueError, sqlite3.Error) as exc:
            with suppress(OSError, ValueError):
                state = await run_in_threadpool(item.archive.status)
                item.archive_saved = state["saved_chunks"]
                item.last_autosave_id = state["last_upload_id"]
            item.archive_error = str(exc)
            item.stop("Automatic saving could not finish. Unsaved staged data was retained locally. Review storage before restarting.")

    async def finish_watch(item, reason):
        if not item.stopped:
            item.stop(reason)
        if item.archive:
            async with application.state.import_lock:
                await archive_flush(item)

    async def close_sessions():
        nonlocal connection, connection_id, generation
        generation += 1
        if watch and not watch.stopped:
            await finish_watch(watch, "SSH connection closed.")
        elif watch and watch.archive:
            await finish_watch(watch, watch.stopped or "SSH connection closed.")
        if connection:
            connection.close()
            connection = None
        connection_id = None
        for task in list(guards):
            task.cancel()
        if guards:
            await asyncio.gather(*list(guards), return_exceptions=True)
        if finalizers:
            await asyncio.gather(*list(finalizers), return_exceptions=True)

    application.state.close_live_sessions = close_sessions

    def configured():
        return enabled or (store.root / "ssh-lab.json").is_file()

    def expire_watch(now: float):
        nonlocal watch
        if not watch:
            return
        if not watch.stopped and not watch.owner_connected and now - watch.last_poll >= IDLE_SECONDS:
            watch.stop("Session expired. Start a new watch to resume.")
        if watch.stopped_at is not None and now - watch.stopped_at >= STOPPED_SECONDS:
            watch = None

    async def guard_watch(item):
        try:
            while not item.stopped:
                await asyncio.sleep(min(5, IDLE_SECONDS))
                if not item.owner_connected and monotonic() - item.last_poll >= IDLE_SECONDS:
                    await finish_watch(item, "Live page stopped responding. SSH watch closed.")
            if item.archive:
                await finish_watch(item, item.stopped)
        except asyncio.CancelledError:
            pass

    def current(watch_id: str) -> Watch:
        if not configured():
            raise HTTPException(404, "Live logs are disabled.")
        expire_watch(monotonic())
        if watch is None or watch.id != watch_id:
            raise HTTPException(404, "Live session is unavailable. Start a new watch.")
        return watch

    @application.get("/api/live/status")
    async def status():
        expire_watch(monotonic())
        if not configured():
            return {"enabled": False}
        try:
            host, username, port, _ = await run_in_threadpool(ssh_collection.lab_target, store.root)
            options = await run_in_threadpool(ssh_collection.live_options, store.root)
        except ssh_collection.CollectionError as exc:
            return {"enabled": True, "ready": False, "detail": str(exc)}
        return {"enabled": True, "ready": True, "host": host, "port": port,
                "username": username, "identity_file": str(options["identity_file"]) if options["identity_file"] else "",
                "platform": options["platform"], "channel": options["channel"],
                "authentication": options["authentication"],
                "password_required": options["authentication"] == "password" and not (connection and connection.active),
                "connection_id": connection_id if connection and connection.active else None,
                "poll_seconds": POLL_SECONDS, "retained_seconds": RETAIN_SECONDS}

    async def connect_source(body: LiveConnection, password=None):
        nonlocal connection, connection_id
        expire_watch(monotonic())
        if watch is not None and not watch.stopped:
            raise HTTPException(409, "Stop the current watch before changing its connection.")
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or connection is in progress. Try again shortly.")
        async with application.state.import_lock:
            started_generation = generation
            try:
                values = parse_connection(body.ssh_command)
                values.update(platform=body.platform, channel=body.channel)
                if body.identity_file:
                    values["identity_file"] = body.identity_file
                args = (store.root, values, Path.home() / ".ssh" / "known_hosts")
                session = await run_in_threadpool(save_profile, *args, password=password) if password is not None else await run_in_threadpool(save_profile, *args)
                if started_generation != generation:
                    if session:
                        session.close()
                    raise HTTPException(409, "Connection canceled. Select Connect to try again.")
                if connection:
                    connection.close()
                connection = session
                connection_id = uuid4().hex if session else None
            except ssh_collection.KeyAuthenticationRequired:
                if body.authentication == "auto":
                    return {"password_required": True, "detail": "SSH key authentication was not accepted. Enter the SSH account password."}
                raise HTTPException(400, "SSH key authentication was not accepted.") from None
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                raise HTTPException(400, str(exc)) from exc
        return await status()

    @application.post("/api/live/connect")
    async def connect(body: LiveConnection):
        if body.authentication == "password":
            return {"password_required": True, "detail": "Enter the SSH account password."}
        return await connect_source(body)

    @application.post("/api/live/password")
    async def password_connect(request: Request):
        # Parse manually so validation responses never echo credential input.
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Password connection requires JSON.")
        raw = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > 8192:
                        raise HTTPException(413, "Connection request is too large.")
                    raw.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Connection request timed out.") from None
        try:
            data = load_json(raw.decode("utf-8"))
            password = data.pop("password")
            if not isinstance(password, str) or not 1 <= len(password) <= 1024 or "\x00" in password:
                raise ValueError()
            password.encode("utf-8")
            settings = LiveConnection.model_validate(data)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise HTTPException(400, "Invalid SSH connection details or password.") from None
        return await connect_source(settings, password)

    @application.post("/api/live/disconnect", status_code=204)
    async def disconnect(connection_id: Annotated[str | None, Query(max_length=32)] = None):
        if connection_id is None or connection_id == (await status()).get("connection_id"):
            await close_sessions()

    @application.post("/api/live/start", status_code=201)
    async def start(host: Annotated[str | None, Query(max_length=253)] = None,
                    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
                    settings: WatchSettings | None = None):
        nonlocal watch
        if not configured():
            raise HTTPException(404, "Live logs are disabled.")
        try:
            target = await run_in_threadpool(ssh_collection.lab_target, store.root)
            options = await run_in_threadpool(ssh_collection.live_options, store.root)
        except ssh_collection.CollectionError as exc:
            raise HTTPException(503, str(exc)) from exc
        if (host, port) != (target[0], target[2]):
            raise HTTPException(409, "The configured SSH destination changed. Reload before starting.")
        now = monotonic()
        expire_watch(now)
        if watch is not None and not watch.stopped:
            raise HTTPException(409, "A live session is already running in this Sentinel instance.")
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or collection is still finishing. Try again shortly.")
        session = None
        if options["authentication"] == "password":
            if not connection or not connection.active:
                raise HTTPException(409, "Select Connect and enter the SSH password again before starting.")
            session = connection
            session.touch()
        watch = Watch(uuid4().hex, target, now, now, options=options, session=session)
        watch.autosave = bool(settings and settings.autosave)
        watch.last_autosave = now
        if watch.autosave:
            try:
                watch.archive = await run_in_threadpool(LiveArchive, store, watch.id, watch.source, options["platform"])
            except (OSError, ValueError) as exc:
                watch.stop("Could not prepare local automatic saving.")
                raise HTTPException(409, str(exc)) from exc
        task = asyncio.create_task(guard_watch(watch))
        guards.add(task)
        task.add_done_callback(guards.discard)
        return watch.view() | {"token": watch.token}

    async def pull(watch_id: str, revision=None, *, owner=False):
        nonlocal watch
        item = current(watch_id)
        if item.stopped:
            return item.view(revision)
        if item.owner_connected and not owner:
            raise HTTPException(409, "The live page already owns this watch.")
        now = monotonic()
        if now < item.next_poll:
            raise HTTPException(429, "Wait at least five seconds between live pulls.",
                                headers={"Retry-After": str(max(1, ceil(item.next_poll - now)))})
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or collection is in progress.")
        async with application.state.import_lock:
            item.last_poll = now
            item.next_poll = now + POLL_SECONDS
            item.attempts += 1
            item.new_last_pull = 0
            try:
                target = await run_in_threadpool(ssh_collection.lab_target, store.root)
                options = await run_in_threadpool(ssh_collection.live_options, store.root)
                if target != item.target or options != item.options:
                    item.stop("The configured SSH destination changed. Reload before starting again.")
                    return item.view(revision)
                if item.stopped:
                    return item.view(revision)
                data = await run_in_threadpool(item.session.collect, options) if item.session else await run_in_threadpool(ssh_collection.collect_live, target, options)
                if item.stopped:
                    return item.view(revision)
                if options["platform"] == "windows":
                    batch, skipped = await run_in_threadpool(windows_records, data, options["channel"])
                else:
                    batch, skipped = await run_in_threadpool(journal_records, data)
                if item.stopped:
                    return item.view(revision)
                if not batch and (skipped or options["platform"] == "linux"):
                    item.skipped += skipped
                    item.gap = True
                    raise ssh_collection.CollectionError("The pull contained no complete records with usable identifiers.")
                updated = replace(item, records=item.records.copy(), arrived=item.arrived.copy())
                updated.new_last_pull = updated.retain(batch, skipped)
                updated.received += updated.new_last_pull
                if updated.archive:
                    try:
                        await run_in_threadpool(updated.archive.append, updated.added)
                        due = now - updated.last_autosave >= AUTOSAVE_SECONDS
                        await archive_flush(updated, sealed_only=not due)
                        if due:
                            updated.last_autosave = now
                    except (OSError, ValueError, StorageFull) as exc:
                        updated.archive_error = str(exc)
                        updated.stop("Automatic saving failed. Check local storage; staged data was retained.")
                updated.added = {}
                if item.revision != updated.revision:
                    updated.review = await run_in_threadpool(review_buffer, b"".join(updated.records.values()),
                                                             updated.source, updated.id, options["platform"])
                if item.stopped:
                    return item.view(revision)
                # Keep the owning socket and idle guard attached to this watch.
                item.__dict__.update(updated.__dict__)
                item.checked_at = utc_now()
                item.pulls += 1
                item.duration_ms = round((monotonic() - now) * 1000)
                item.error = None
                item.errors = 0
            except (ssh_collection.CollectionError, ParseInputError) as exc:
                if not item.stopped:
                    item.error = str(exc)
                    item.errors += 1
                    if item.errors >= RETRY_LIMIT:
                        item.stop("Watch stopped after three unsuccessful pulls.")
        return item.view(revision)

    @application.post("/api/live/{watch_id}/poll")
    async def poll(watch_id: str, revision: Annotated[int | None, Query(ge=0)] = None):
        return await pull(watch_id, revision)

    @application.websocket("/api/live/{watch_id}/stream")
    async def stream(websocket: WebSocket, watch_id: str, token: str = ""):
        try:
            local = websocket.client is not None and ip_address(websocket.client.host).is_loopback
        except ValueError:
            local = False
        scheme = "https" if websocket.url.scheme == "wss" else "http"
        expected_origin = f"{scheme}://{websocket.headers.get('host', '')}"
        user = await run_in_threadpool(application.state.auth.current_user,
                                      websocket.cookies.get(application.state.session_cookie_name)) if local else None
        if not user or websocket.headers.get("origin") != expected_origin:
            await websocket.close(code=1008)
            return
        try:
            item = current(watch_id)
        except HTTPException:
            await websocket.close(code=1008)
            return
        if item.stopped or item.owner_connected or not compare_digest(token.encode(), item.token.encode()):
            await websocket.close(code=1008)
            return
        item.owner_connected = True
        try:
            await websocket.accept()
            # The initial status establishes ownership before any read starts.
            await websocket.send_json(item.view())
            if await asyncio.wait_for(websocket.receive_text(), timeout=15) != "ack":
                return
            revision = -1
            while not item.stopped:
                if not await run_in_threadpool(application.state.auth.current_user,
                                              websocket.cookies.get(application.state.session_cookie_name)):
                    item.stop("Local sign-in expired. Sign in again and reconnect.")
                    await websocket.send_json(item.view(item.revision))
                    break
                wait = max(0, item.next_poll - monotonic())
                if wait:
                    await asyncio.sleep(wait + .025)
                try:
                    view = await pull(watch_id, revision, owner=True)
                except HTTPException as exc:
                    if exc.status_code not in {409, 429}:
                        break
                    item.next_poll = max(item.next_poll, monotonic() + POLL_SECONDS)
                    view = item.view() | {"error": exc.detail}
                item = current(watch_id)
                async with asyncio.timeout(15):
                    await websocket.send_json(view)
                    if await websocket.receive_text() != "ack":
                        break
                revision = item.revision
        except (WebSocketDisconnect, TimeoutError, RuntimeError, KeyError, HTTPException):
            pass
        finally:
            item.owner_connected = False
            item.stop(item.stopped or "Live page closed or disconnected. SSH watch stopped.")
            cleanup = asyncio.create_task(finish_watch(item, item.stopped))
            finalizers.add(cleanup)
            cleanup.add_done_callback(finalizers.discard)
            with suppress(asyncio.CancelledError):
                await asyncio.shield(cleanup)
            with suppress(RuntimeError, WebSocketDisconnect):
                await websocket.close()

    @application.post("/api/live/{watch_id}/stop")
    async def stop(watch_id: str, token: Annotated[str | None, Query(max_length=32)] = None):
        item = current(watch_id)
        if token is not None and not compare_digest(token.encode(), item.token.encode()):
            raise HTTPException(409, "This page does not own the live watch.")
        await finish_watch(item, "Watch stopped.")
        return item.view()

    @application.post("/api/live/{watch_id}/save")
    async def save(watch_id: str):
        item = current(watch_id)
        if not item.review["events"]:
            raise HTTPException(400, "The watch has no parsed events to save.")
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or collection is in progress. Try again shortly.")
        async with application.state.import_lock:
            if item.archived is not None and item.saved_revision == item.revision:
                saved = await run_in_threadpool(store.get, item.archived)
                if saved is None:
                    raise HTTPException(404, "The saved copy is no longer in the log library.")
                if (await run_in_threadpool(analysis_summary, store, saved))["status"] == "current":
                    return {"upload_id": item.archived, "saved_revision": item.saved_revision}
            else:
                raw = b"".join(item.records.values())
                source = f"{item.source.removesuffix('.jsonl')[:185]}-snapshot-{item.id[:8]}-r{item.revision}.jsonl"
                result = await run_in_threadpool(parse_buffer, raw, source, uuid4().hex, item.options["platform"])
                try:
                    saved = await run_in_threadpool(store.save, raw, result)
                except StorageFull as exc:
                    raise HTTPException(409, str(exc)) from exc
                item.archived = saved["id"]
                item.saved_revision = item.revision
            await run_in_threadpool(run_analysis, store, saved)
            return {"upload_id": item.archived, "saved_revision": item.saved_revision}
