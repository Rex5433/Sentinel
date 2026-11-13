"""Bounded, browser-driven lab journal review over the existing SSH pull."""

from dataclasses import dataclass, field, replace
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from ipaddress import ip_address
from pathlib import Path
from math import ceil
import subprocess
import sqlite3
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, StringConstraints
from starlette.concurrency import run_in_threadpool

from sentinel.ingest import ParseInputError
from .event_activity import parse_linux, parse_windows_jsonl
from sentinel.detection.windows_review import field as windows_field
from sentinel.ingest.common import load_json

from . import ssh_collection
from .analysis import analysis_summary, run_analysis
from .db import StorageFull
from .windows_live import CHANNELS_PER_PULL, MULTI_CHANNELS, SINGLE_CHANNELS, windows_batch, windows_records
from .ssh_setup import parse_connection, save_profile
from .live_archive import LiveArchive
from .live_bookmark import BookmarkGap, after_anchor, bookmark_scope, position_for, read_bookmark, write_bookmark
from .log_review import review_events, event_flags
from .log_context import with_live_context


POLL_SECONDS = 5
IDLE_SECONDS = 45
STOPPED_SECONDS = 5 * 60
RETAIN_SECONDS = 60 * 60
BUFFER_RECORDS = 10_000
BUFFER_BYTES = 16 * 1024 * 1024
AUTOSAVE_SECONDS = 15 * 60
RETRY_LIMIT = 3
MAX_WATCHES = 8
MAX_PREPARED = 16
SourceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class LiveConnection(BaseModel):
    ssh_command: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
    platform: Literal["windows", "linux"] = "windows"
    channel: Literal["Security", "System", "Application", "TaskScheduler", "Changes", "All", "Journal"] = "Security"
    identity_file: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1024)] = ""
    authentication: Literal["auto", "key", "password"] = "auto"
    isolated: bool = False


class WatchSettings(BaseModel):
    autosave: bool = False
    connection_id: SourceId | None = None
    resume: bool = False
    restart_from_latest: bool = False
    background: bool = False


@dataclass
class PreparedSource:
    directory: TemporaryDirectory
    target: tuple[str, str, int, Path]
    options: dict
    session: object | None
    expires: float

    def close(self):
        if self.session:
            self.session.close()
        self.directory.cleanup()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def journal_records(data: bytes, *, anchored: bool = False) -> tuple[dict[str, bytes], int]:
    lines = data.splitlines(keepends=True)
    if len(data) > ssh_collection.MAX_BYTES or len(lines) > ssh_collection.MAX_RECORDS + int(anchored):
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
        if anchored and cursor in records:
            skipped += 1
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
    review = review_events(result.events, platform)
    findings = review.findings
    findings.sort(key=lambda entry: (
        entry["finding"]["timestamp_utc"] or "", entry["finding"]["triage_priority"],
    ), reverse=True)
    flagged = event_flags(findings)
    process_events = [event for event in result.events if getattr(event, "windows_event_id", None) == 4688]
    return {
        "events": [event.model_dump(mode="json") for event in result.events],
        "findings": findings[:50],
        "windows_reviewed_event_ids": review.windows_reviewed_event_ids,
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
    connection_id: str | None = field(default=None, repr=False)
    pull_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    finalizer: asyncio.Task | None = field(default=None, repr=False)
    token: str = field(default_factory=lambda: uuid4().hex, repr=False)
    owner_connected: bool = False
    background_owner: str | None = field(default=None, repr=False)
    autosave: bool = False
    archive: object | None = field(default=None, repr=False)
    archive_saved: int = 0
    archive_error: str | None = None
    bookmark_scope: str | None = None
    bookmark: str | None = None
    bookmark_lost: bool = False
    full_resume_page: bool = False
    ssh_observation: tuple[float, str, str] | None = field(default=None, repr=False)
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
    channel_cursors: dict[str, str] = field(default_factory=dict)
    coverage: dict | None = None
    channel_status: dict[str, dict] = field(default_factory=dict)
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
        if self.stopped:
            return
        self.stopped = reason
        self.stopped_at = monotonic()
        if self.session:
            self.session.close()

    @property
    def source(self) -> str:
        host, _, port, _ = self.target
        if self.options["platform"] == "windows":
            return f"ssh-live-windows-{host[:200]}-{port}-{self.options['channel']}.jsonl"
        name = "-changes" if self.options["channel"] == "Changes" else ""
        return f"ssh-live-{host[:200]}-{port}{name}.jsonl"

    def retain(self, batch: dict[str, bytes], skipped: int):
        self.skipped += skipped
        additions, gap = self.new_records(batch, self.cursor)
        self.gap |= bool(skipped or gap)
        if batch:
            self.cursor = next(reversed(batch))
        return self.retain_additions(additions)

    def new_records(self, batch: dict[str, bytes], cursor: str | None):
        cursors = list(batch)
        fresh = cursors[cursors.index(cursor) + 1:] if cursor in batch else cursors
        return {key: batch[key] for key in fresh if key not in self.records}, cursor is not None and cursor not in batch

    def retain_windows(self, batch):
        additions = {}
        self.skipped += batch.skipped
        self.gap |= bool(batch.skipped or batch.coverage["discovery_errors"] or not batch.coverage["total_channels"])
        if batch.coverage["next_offset"] == 0:
            # Keep only channels observed in recent passes, even if the remote catalog changes.
            recent_pulls = max(1, ceil(batch.coverage["total_channels"] / CHANNELS_PER_PULL))
            self.channel_status = {name: value for name, value in self.channel_status.items()
                                   if self.pulls - value["pull"] < recent_pulls}
            self.channel_cursors = {name: cursor for name, cursor in self.channel_cursors.items()
                                    if name in self.channel_status}
        for status in batch.coverage["channels"]:
            channel = status["channel"]
            records = batch.records.get(channel, {})
            fresh, missing = self.new_records(records, self.channel_cursors.get(channel))
            gap = bool(missing or status["dropped"] or status["status"] == "unavailable")
            self.gap |= gap
            additions.update(fresh)
            if records:
                self.channel_cursors[channel] = next(reversed(records))
            self.channel_status[channel] = status | {"gap": gap, "pull": self.pulls + 1}
        self.coverage = batch.coverage
        return self.retain_additions(additions)

    def retain_additions(self, additions):
        self.added = additions
        if additions:
            self.records.update(additions)
            self.arrived.update(dict.fromkeys(additions, monotonic()))
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
            "channel": self.options["channel"] if self.options["platform"] == "windows" else
            ("Changes" if self.options["channel"] == "Changes" else "Journal"),
            "coverage": self.coverage | {
                "observed_channels": len(self.channel_status),
                "unavailable_channels": sum(value["status"] == "unavailable" for value in self.channel_status.values()),
                "capped_channels": sum(value["capped"] or value["dropped"] > 0 for value in self.channel_status.values()),
                "channels": [self.channel_status[value["channel"]] for value in self.coverage["channels"]],
            } if self.coverage else None,
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
            "resume_enabled": self.bookmark_scope is not None,
            "bookmark_ready": self.bookmark is not None,
            "bookmark_lost": self.bookmark_lost,
            "full_resume_page": self.full_resume_page,
            "review": self.review if revision != self.revision else None,
        }


def register_live_logs(application, store, *, enabled: bool):
    watches: dict[str, Watch] = {}
    sources: dict[str, PreparedSource] = {}
    connection = None
    connection_id = None
    generation = 0
    pending_sources = 0
    setup_lock = asyncio.Lock()
    guards = set()

    async def context_view(item, revision=None):
        original = item.review
        archived = item.archived if item.saved_revision == item.revision else None
        review = await run_in_threadpool(with_live_context, store, original, archived)
        if original is not item.review or archived != (item.archived if item.saved_revision == item.revision else None):
            return item.view()
        changed = review != original
        item.review = review
        return item.view(None if changed else revision)

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

    async def flush_closed_watch(item):
        async with application.state.import_lock:
            await archive_flush(item)

    async def finish_watch(item, reason, *, retry=False):
        item.stop(reason)
        source = sources.get(item.connection_id)
        if source:
            source.expires = item.stopped_at + STOPPED_SECONDS
        if item.archive and (item.finalizer is None or (retry and item.finalizer.done() and item.archive_error)):
            item.finalizer = asyncio.create_task(flush_closed_watch(item))
        if item.finalizer:
            await asyncio.shield(item.finalizer)

    async def close_sessions():
        nonlocal connection, connection_id, generation
        generation += 1
        closing = list(watches.values())
        for item in closing:
            item.stop("SSH connection closed.")
        for source in sources.values():
            source.close()
        sources.clear()
        if connection:
            connection.close()
            connection = None
        connection_id = None
        active_guards = list(guards)
        for task in active_guards:
            task.cancel()
        await asyncio.gather(*active_guards, return_exceptions=True)
        await asyncio.gather(*(finish_watch(item, "SSH connection closed.") for item in closing))
        for item in closing:
            watches.pop(item.id, None)

    application.state.close_live_sessions = close_sessions

    def source_health():
        # A successful read or transport failure from an existing watch only.
        latest = {}
        now = monotonic()
        for item in watches.values():
            if item.stopped or not item.ssh_observation:
                continue
            measured, _, _ = item.ssh_observation
            host, _, port, _ = item.target
            key = host.lower(), port
            if now - measured <= IDLE_SECONDS and (key not in latest or measured > latest[key][0]):
                latest[key] = item.ssh_observation
        return {key: (value[1], value[2]) for key, value in latest.items()}

    application.state.live_source_health = source_health

    def configured():
        return enabled or (store.root / "ssh-lab.json").is_file()

    def active_watch(source_id):
        return next((item for item in watches.values() if item.connection_id == source_id and not item.stopped), None)

    def expire(now: float):
        stopped = []
        active_sources = set()
        for item in watches.values():
            if not item.stopped and not item.background_owner and not item.owner_connected and now - item.last_poll >= IDLE_SECONDS:
                item.stop("Session expired. Start a new watch to resume.")
            if item.stopped:
                if (not item.archive or (item.finalizer and item.finalizer.done())) and not item.pull_lock.locked():
                    stopped.append(item)
            else:
                active_sources.add(item.connection_id)
        stopped.sort(key=lambda item: item.stopped_at, reverse=True)
        for index, item in enumerate(stopped):
            if index >= MAX_WATCHES or now - item.stopped_at >= STOPPED_SECONDS:
                watches.pop(item.id, None)
        for source_id, source in list(sources.items()):
            if source_id not in active_sources and now >= source.expires:
                sources.pop(source_id).close()

    async def guard_watch(item):
        try:
            while not item.stopped:
                await asyncio.sleep(min(5, IDLE_SECONDS))
                if not item.owner_connected and monotonic() - item.last_poll >= IDLE_SECONDS:
                    await finish_watch(item, "Live page stopped responding. SSH watch closed.")
            await finish_watch(item, item.stopped)
            expire(monotonic())
        except asyncio.CancelledError:
            pass

    def current(watch_id: str) -> Watch:
        expire(monotonic())
        item = watches.get(watch_id)
        if item is None:
            raise HTTPException(404, "Live session is unavailable. Start a new watch.")
        return item

    def owned(item, token):
        if (item.connection_id is not None or token is not None) and not compare_digest((token or "").encode(), item.token.encode()):
            raise HTTPException(409, "This page does not own the live watch.")

    def ready_payload(target, options, source_id, session):
        host, username, port, _ = target
        return {"enabled": True, "ready": True, "host": host, "port": port,
                "username": username, "identity_file": str(options["identity_file"]) if options["identity_file"] else "",
                "platform": options["platform"], "channel": options["channel"],
                "authentication": options["authentication"],
                "session_bound": session is not None,
                "password_required": options["authentication"] == "password" and not (session and session.active),
                "connection_id": source_id,
                "poll_seconds": POLL_SECONDS, "retained_seconds": RETAIN_SECONDS}

    @application.get("/api/live/status")
    async def status():
        expire(monotonic())
        if not configured():
            return {"enabled": False}
        try:
            target = await run_in_threadpool(ssh_collection.lab_target, store.root)
            options = await run_in_threadpool(ssh_collection.live_options, store.root)
        except ssh_collection.CollectionError as exc:
            return {"enabled": True, "ready": False, "detail": str(exc)}
        return ready_payload(target, options, connection_id if connection and connection.active else None, connection)

    async def connect_source(body: LiveConnection, password=None):
        nonlocal pending_sources
        expire(monotonic())
        if not body.isolated:
            if active_watch(None):
                raise HTTPException(409, "Stop the current watch before changing its connection.")
            if setup_lock.locked():
                raise HTTPException(409, "Another SSH sign-in is in progress. Try again shortly.")
            async with setup_lock:
                return await prepare_source(body, password)
        if len(sources) + pending_sources >= MAX_PREPARED:
            raise HTTPException(409, "Too many live sources are open. Close an unused Live logs tab.")
        pending_sources += 1
        try:
            return await prepare_source(body, password)
        finally:
            pending_sources -= 1

    async def prepare_source(body, password):
        nonlocal connection, connection_id
        started_generation = generation
        directory = None
        session = None
        try:
            values = parse_connection(body.ssh_command)
            values.update(platform=body.platform, channel=body.channel)
            if body.identity_file:
                values["identity_file"] = body.identity_file
            if body.isolated:
                directory = TemporaryDirectory(prefix="live-source-", dir=store.root, ignore_cleanup_errors=True)
            root = Path(directory.name).resolve() if directory else store.root
            session = await run_in_threadpool(save_profile, root, values, Path.home() / ".ssh" / "known_hosts",
                                              password=password, reuse_key_session=body.authentication == "key")
            target = await run_in_threadpool(ssh_collection.lab_target, root)
            options = await run_in_threadpool(ssh_collection.live_options, root)
            if started_generation != generation:
                raise HTTPException(409, "Connection canceled. Select Connect to try again.")
            if directory:
                source_id = uuid4().hex
                sources[source_id] = PreparedSource(directory, target, options, session, monotonic() + STOPPED_SECONDS)
                directory = None
                view = ready_payload(target, options, source_id, session)
                session = None
                return view
            if connection:
                connection.close()
            connection = session
            connection_id = uuid4().hex if session else None
            view = ready_payload(target, options, connection_id, session)
            session = None
            return view
        except ssh_collection.KeyAuthenticationRequired as exc:
            if body.authentication == "auto":
                return {"password_required": True, "detail": "SSH key authentication was not accepted. Enter the SSH account password."}
            raise HTTPException(400, str(exc)) from None
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            raise HTTPException(400, str(exc)) from exc
        finally:
            if session:
                session.close()
            if directory:
                directory.cleanup()

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
        if connection_id in sources:
            item = active_watch(connection_id)
            source = sources.pop(connection_id)
            if item:
                item.stop("Live tab disconnected.")
            source.close()
            if item:
                await finish_watch(item, item.stopped)
        else:
            await disconnect_legacy(connection_id)

    async def disconnect_legacy(source_id):
        nonlocal connection, connection_id
        if source_id is not None and source_id != connection_id:
            return
        item = active_watch(None)
        if connection:
            connection.close()
        connection, connection_id = None, None
        if item:
            await finish_watch(item, "SSH connection closed.")

    @application.post("/api/live/start", status_code=201)
    async def start(request: Request, host: Annotated[str | None, Query(max_length=253)] = None,
                    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
                    settings: WatchSettings | None = None):
        now = monotonic()
        expire(now)
        source_id = settings.connection_id if settings else None
        if source_id:
            source = sources.get(source_id)
            if source is None:
                raise HTTPException(409, "This tab's verified connection expired. Select Connect again.")
            target, options, prepared_session = source.target, source.options, source.session
        else:
            if not configured():
                raise HTTPException(404, "Live logs are disabled.")
            if setup_lock.locked():
                raise HTTPException(409, "Wait for SSH sign-in to finish.")
            started_generation = generation
            try:
                target = await run_in_threadpool(ssh_collection.lab_target, store.root)
                options = await run_in_threadpool(ssh_collection.live_options, store.root)
            except ssh_collection.CollectionError as exc:
                raise HTTPException(503, str(exc)) from exc
            if started_generation != generation or setup_lock.locked():
                raise HTTPException(409, "The SSH connection changed. Reload before starting.")
            prepared_session = connection
        if (host, port) != (target[0], target[2]):
            raise HTTPException(409, "The configured SSH destination changed. Reload before starting.")
        scope = None
        if settings and settings.restart_from_latest and not settings.resume:
            raise HTTPException(400, "Starting a new bookmark requires Save and resume.")
        if settings and settings.resume:
            if not source_id or not settings.autosave or options["channel"] not in (
                ssh_collection.LINUX_EMPTY_OK if options["platform"] == "linux" else
                SINGLE_CHANNELS
            ):
                raise HTTPException(400, "Save and resume requires automatic saving and a supported capture source.")
            scope = await run_in_threadpool(bookmark_scope, target, options)
            if sources.get(source_id) is not source:
                raise HTTPException(409, "This tab's verified connection closed. Select Connect again.")
            if any(item.bookmark_scope == scope and not item.stopped for item in watches.values()):
                raise HTTPException(409, "This host, account and capture source already have a bookmark watch.")
        if active_watch(source_id):
            raise HTTPException(409, "A live watch is already running for this connection.")
        if sum(not item.stopped for item in watches.values()) >= MAX_WATCHES:
            raise HTTPException(409, f"Up to {MAX_WATCHES} live watches can run at once. Stop one before starting another.")
        session = None
        if options["authentication"] == "password" or prepared_session is not None:
            if not prepared_session or not prepared_session.active:
                if options["authentication"] == "password":
                    raise HTTPException(409, "Select Connect and enter the SSH password again before starting.")
                raise HTTPException(409, "The verified SSH key session closed. Select Connect again before starting.")
            session = prepared_session
            try:
                session.touch()
            except ssh_collection.CollectionError as exc:
                raise HTTPException(409, str(exc)) from None
        watch = Watch(uuid4().hex, target, now, now, options=options, session=session, connection_id=source_id)
        cookie = request.cookies.get(application.state.session_cookie_name, "")
        if settings and settings.background:
            if not cookie or not source_id:
                raise HTTPException(409, "Verify an SSH connection before starting a background watch.")
            watch.background_owner = sha256(cookie.encode()).hexdigest()
        watch.autosave = bool(settings and settings.autosave)
        watch.bookmark_scope = scope
        watch.last_autosave = now
        watches[watch.id] = watch
        if watch.autosave:
            try:
                if scope:
                    for prior in list(watches.values()):
                        if prior is not watch and prior.bookmark_scope == scope and prior.archive:
                            await finish_watch(prior, "Watch closed before restarting.")
                            # A newer watch now owns the durable staging directory.
                            prior.archive = None
                async with application.state.import_lock:
                    if watch.stopped:
                        raise ValueError("The connection closed before the watch started.")
                    watch.archive = await run_in_threadpool(LiveArchive, store, scope or watch.id, watch.source, options["platform"])
                    if scope:
                        if not settings.restart_from_latest:
                            watch.bookmark = await run_in_threadpool(read_bookmark, store, scope)
                        if watch.archive.staged_records:
                            await archive_flush(watch)
                    if watch.stopped:
                        raise ValueError(watch.archive_error or "The connection closed before the watch started.")
            except (OSError, ValueError, sqlite3.Error) as exc:
                watch.stop("Could not prepare local automatic saving.")
                watches.pop(watch.id, None)
                raise HTTPException(409, str(exc)) from exc
        task = asyncio.create_task(background_watch(watch, cookie) if watch.background_owner else guard_watch(watch))
        guards.add(task)
        task.add_done_callback(guards.discard)
        return (await context_view(watch)) | {"token": watch.token}

    async def background_watch(item, cookie):
        try:
            while not item.stopped:
                if not await run_in_threadpool(application.state.auth.current_user, cookie, touch=False):
                    item.stop("Local sign-in expired. Sign in again and reconnect.")
                    break
                await asyncio.sleep(max(0, item.next_poll - monotonic()) + .025)
                if item.stopped:
                    break
                try:
                    await pull(item.id, item.revision, owner=True)
                except HTTPException as exc:
                    if exc.status_code not in {409, 429}:
                        break
                    item.next_poll = max(item.next_poll, monotonic() + POLL_SECONDS)
        finally:
            if not item.stopped:
                item.stop("Background watch closed.")
            await finish_watch(item, item.stopped)
            expire(monotonic())

    def owner_key(request):
        return sha256(request.cookies.get(application.state.session_cookie_name, "").encode()).hexdigest()

    def require_background_owner(item, request):
        if item.background_owner and item.background_owner != owner_key(request):
            raise HTTPException(404, "Background watch is unavailable for this sign-in.")

    @application.get("/api/live/background")
    async def background_watches(request: Request):
        expire(monotonic())
        owner = owner_key(request)
        return {"items": [{"id": item.id, "token": item.token, "host": item.target[0], "port": item.target[2],
                           "platform": item.options["platform"], "channel": item.options["channel"]}
                          for item in watches.values() if item.background_owner == owner and not item.stopped]}

    @application.get("/api/live/{watch_id}/view")
    async def watch_view(request: Request, watch_id: str, token: Annotated[str, Query(max_length=32)],
                         revision: Annotated[int | None, Query(ge=0)] = None):
        item = current(watch_id)
        if not item.background_owner:
            raise HTTPException(404, "Background watch is unavailable for this sign-in.")
        require_background_owner(item, request)
        owned(item, token)
        return await context_view(item, revision)

    async def pull(watch_id: str, revision=None, *, owner=False, token=None):
        item = current(watch_id)
        if not owner:
            owned(item, token)
        if item.stopped:
            await finish_watch(item, item.stopped)
            return await context_view(item, revision)
        if (item.owner_connected or item.background_owner) and not owner:
            raise HTTPException(409, "The live page already owns this watch.")
        now = monotonic()
        if now < item.next_poll:
            raise HTTPException(429, "Wait at least five seconds between live pulls.",
                                headers={"Retry-After": str(max(1, ceil(item.next_poll - now)))})
        if item.pull_lock.locked() or (item.connection_id is None and application.state.import_lock.locked()):
            raise HTTPException(409, "Another import or collection is in progress.")
        async with item.pull_lock:
            item.last_poll = now
            item.next_poll = now + POLL_SECONDS
            item.attempts += 1
            item.new_last_pull = 0
            try:
                target, options = item.target, item.options
                if item.connection_id is None:
                    current_target = await run_in_threadpool(ssh_collection.lab_target, store.root)
                    current_options = await run_in_threadpool(ssh_collection.live_options, store.root)
                    if current_target != target or current_options != options:
                        item.stop("The configured SSH destination changed. Reload before starting again.")
                        return await context_view(item, revision)
                if item.stopped:
                    return await context_view(item, revision)
                platform, channel = options["platform"], options["channel"]
                multi = platform == "windows" and channel in MULTI_CHANNELS
                query = options | {"offset": (item.coverage or {}).get("next_offset", 0)} if multi else options
                if item.bookmark is not None:
                    query = query | {"bookmark": item.bookmark}
                try:
                    data = await run_in_threadpool(item.session.collect, query) if item.session else await run_in_threadpool(ssh_collection.collect_live, target, query)
                except ssh_collection.CollectionError:
                    item.ssh_observation = (monotonic(), "failed", utc_now())
                    raise
                item.ssh_observation = (monotonic(), "reachable", utc_now())
                if item.stopped:
                    return await context_view(item, revision)
                updated = replace(item, records=item.records.copy(), arrived=item.arrived.copy(),
                                  channel_cursors=item.channel_cursors.copy(), channel_status=item.channel_status.copy())
                if multi:
                    windows = await run_in_threadpool(windows_batch, data, channel)
                    updated.new_last_pull = updated.retain_windows(windows)
                else:
                    anchored = item.bookmark is not None
                    if platform == "windows":
                        batch, skipped = await run_in_threadpool(windows_records, data, channel, anchored=anchored)
                    else:
                        batch, skipped = await run_in_threadpool(journal_records, data, anchored=anchored)
                    if item.bookmark_scope:
                        if skipped:
                            item.skipped += skipped
                            raise ssh_collection.CollectionError("The bookmark was held because the page contained unusable records.")
                        if anchored:
                            batch = after_anchor(platform, batch, item.bookmark)
                        updated.full_resume_page = anchored and len(batch) == ssh_collection.MAX_RECORDS
                        if batch:
                            last = next(reversed(batch))
                            updated.bookmark = position_for(platform, last, batch[last])
                        updated.new_last_pull = updated.retain_additions({
                            key: raw for key, raw in batch.items() if key not in updated.records
                        })
                    else:
                        if not batch and (skipped or (platform == "linux" and channel not in ssh_collection.LINUX_EMPTY_OK)):
                            item.skipped += skipped
                            raise ssh_collection.CollectionError("The pull contained no complete records with usable identifiers.")
                        updated.new_last_pull = updated.retain(batch, skipped)
                updated.received += updated.new_last_pull
                if item.revision != updated.revision:
                    updated.review = await run_in_threadpool(review_buffer, b"".join(updated.records.values()),
                                                             updated.source, updated.id, platform)
                if item.stopped:
                    return await context_view(item, revision)
                if updated.archive:
                    async with application.state.import_lock:
                        if item.stopped:
                            return await context_view(item, revision)
                        try:
                            await run_in_threadpool(updated.archive.append, updated.added)
                            if updated.bookmark_scope and updated.bookmark != item.bookmark:
                                await run_in_threadpool(write_bookmark, store, updated.bookmark_scope, updated.bookmark)
                            due = now - updated.last_autosave >= AUTOSAVE_SECONDS
                            await archive_flush(updated, sealed_only=not due)
                            if due:
                                updated.last_autosave = now
                        except (OSError, ValueError, StorageFull, sqlite3.Error) as exc:
                            updated.archive_error = str(exc)
                            updated.bookmark = item.bookmark
                            updated.stop("Automatic saving failed. Check local storage; staged data was retained.")
                updated.added = {}
                if item.stopped:
                    return await context_view(item, revision)
                # Keep the owning socket and idle guard attached to this watch.
                updated.owner_connected = item.owner_connected
                item.__dict__.update(updated.__dict__)
                item.checked_at = utc_now()
                item.pulls += 1
                item.duration_ms = round((monotonic() - now) * 1000)
                item.error = None
                item.errors = 0
            except BookmarkGap as exc:
                item.bookmark_lost = item.gap = True
                item.error = str(exc)
                item.stop("Watch stopped at a collection gap.")
            except (ssh_collection.CollectionError, ParseInputError) as exc:
                if not item.stopped:
                    item.gap = True
                    item.error = str(exc)
                    item.errors += 1
                    if item.errors >= RETRY_LIMIT:
                        item.stop("Watch stopped after three unsuccessful pulls.")
        return await context_view(item, revision)

    @application.post("/api/live/{watch_id}/poll")
    async def poll(watch_id: str, revision: Annotated[int | None, Query(ge=0)] = None,
                   token: Annotated[str | None, Query(max_length=32)] = None):
        return await pull(watch_id, revision, token=token)

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
        if item.stopped or item.owner_connected or item.background_owner or not compare_digest(token.encode(), item.token.encode()):
            await websocket.close(code=1008)
            return
        item.owner_connected = True
        try:
            await websocket.accept()
            # The initial status establishes ownership before any read starts.
            await websocket.send_json(await context_view(item))
            if await asyncio.wait_for(websocket.receive_text(), timeout=15) != "ack":
                return
            revision = -1
            while not item.stopped:
                if not await run_in_threadpool(application.state.auth.current_user,
                                              websocket.cookies.get(application.state.session_cookie_name)):
                    item.stop("Local sign-in expired. Sign in again and reconnect.")
                    await websocket.send_json(await context_view(item, item.revision))
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
                    view = (await context_view(item)) | {"error": exc.detail}
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
            with suppress(asyncio.CancelledError):
                await finish_watch(item, item.stopped)
            with suppress(RuntimeError, WebSocketDisconnect):
                await websocket.close()

    @application.post("/api/live/{watch_id}/stop")
    async def stop(request: Request, watch_id: str, token: Annotated[str | None, Query(max_length=32)] = None):
        item = current(watch_id)
        require_background_owner(item, request)
        owned(item, token)
        await finish_watch(item, "Watch stopped.", retry=True)
        return await context_view(item)

    @application.post("/api/live/{watch_id}/save")
    async def save(request: Request, watch_id: str, token: Annotated[str | None, Query(max_length=32)] = None):
        item = current(watch_id)
        require_background_owner(item, request)
        owned(item, token)
        async with item.pull_lock:
            return await save_snapshot(item)

    async def save_snapshot(item):
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
