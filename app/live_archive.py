"""Bounded, opt-in staging of exact live JSONL records in the evidence store.

Callers serialize append/save through the application import lock. Each append
is one already-deduplicated collector batch, at most 2,000 records / 4 MiB.
Chunks stay at most 16 MiB / 50,000 records. Staged, unsaved source bytes are
capped at 64 MiB / 128 files; a full library or staging area never evicts imports.
save() uses deterministic chunk IDs so retrying an interrupted promotion does
not create another library copy. Analysis of returned imports is caller-owned.
"""

from collections.abc import Iterable, Mapping
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from uuid import uuid4

from .event_activity import parse_linux, parse_windows_jsonl

from .db import StorageFull

APPEND_BYTES = 4 * 1024 * 1024
APPEND_RECORDS = 2_000
CHUNK_BYTES = 16 * 1024 * 1024
CHUNK_RECORDS = 50_000
STAGING_BYTES = 64 * 1024 * 1024
STAGING_FILES = 128
SEGMENT = re.compile(r"chunk-([0-9]{8})\.jsonl")


class LiveArchive:
    def __init__(self, store, watch_id: str, source: str, platform: str):
        if not isinstance(watch_id, str) or not re.fullmatch(r"[a-f0-9]{32}", watch_id):
            raise ValueError("Invalid live capture identifier.")
        if platform not in {"windows", "linux"}:
            raise ValueError("Choose a Windows or Linux live capture.")
        if (not isinstance(source, str) or not source.strip() or len(source) > 255
                or any(character in source for character in '/\\:')
                or any(ord(character) < 32 or ord(character) == 127 for character in source)):
            raise ValueError("Use a plain live capture filename.")
        self.store, self.watch_id, self.source, self.platform = store, watch_id, source, platform
        parent = store.root / "live"
        if parent.is_symlink() or parent.resolve().parent != store.root:
            raise ValueError("Live captures must stay inside the evidence store.")
        parent.mkdir(exist_ok=True, mode=0o700)
        self.root = parent / watch_id
        if self.root.is_symlink() or self.root.resolve().parent != parent:
            raise ValueError("Live captures must stay inside the evidence store.")
        self.root.mkdir(exist_ok=True, mode=0o700)
        self.pending = self._path("pending.jsonl")
        state = self._path("state.json")
        if state.exists():
            with state.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("Invalid live capture checkpoint.")
            values = json.loads(raw)
            if (not isinstance(values, dict) or values.get("version") != 1 or values.get("source") != source
                    or values.get("platform") != platform or values.get("watch_id") != watch_id
                    or type(values.get("next_sequence")) is not int or not 1 <= values["next_sequence"] <= 100_000_000):
                raise ValueError("Live capture checkpoint does not match its source.")
            self.next_sequence = values["next_sequence"]
        else:
            self.next_sequence = 1
            self._checkpoint()
        self.saved_chunks = 0
        self.last_upload_id = None
        self.error = None
        self._measure()

    def _path(self, name: str) -> Path:
        target = self.root / name
        if target.is_symlink() or target.resolve().parent != self.root:
            raise ValueError("Live capture files must stay inside their capture folder.")
        return target

    def _checkpoint(self):
        temporary = self._path(f"state-{uuid4().hex}.tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"version": 1, "watch_id": self.watch_id, "source": self.source,
                           "platform": self.platform, "next_sequence": self.next_sequence}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path("state.json"))
        finally:
            temporary.unlink(missing_ok=True)

    def _segments(self):
        return sorted(self._path(path.name) for path in self.root.iterdir() if SEGMENT.fullmatch(path.name))

    def _measure(self):
        paths = self._segments()
        if self.pending.exists():
            paths.append(self.pending)
        if len(paths) > STAGING_FILES:
            raise StorageFull("Live capture staging file limit reached. Save or review pending captures.")
        total_bytes = total_records = 0
        for path in paths:
            with path.open("rb") as stream:
                raw = stream.read(CHUNK_BYTES + 1)
            records = raw.count(b"\n")
            if len(raw) > CHUNK_BYTES or records > CHUNK_RECORDS or (raw and not raw.endswith(b"\n")):
                raise ValueError("A staged capture is incomplete or exceeds the chunk limits. Review it before continuing.")
            total_bytes += len(raw)
            total_records += records
            if path == self.pending:
                self.pending_bytes, self.pending_records = len(raw), records
        if not self.pending.exists():
            self.pending_bytes = self.pending_records = 0
        if total_bytes > STAGING_BYTES:
            raise StorageFull("Live capture staging exceeds 64 MiB. Save pending captures before continuing.")
        self.staged_bytes, self.staged_records = total_bytes, total_records

    def _seal(self):
        if not self.pending_bytes:
            return
        if self.next_sequence > 99_999_999:
            raise StorageFull("Live capture chunk sequence limit reached. Start a new watch.")
        destination = self._path(f"chunk-{self.next_sequence:08}.jsonl")
        if destination.exists():
            raise ValueError("A live capture chunk already exists; it will not be overwritten.")
        self.next_sequence += 1
        self._checkpoint()
        os.rename(self.pending, destination)
        self.pending_bytes = self.pending_records = 0

    def append(self, records: Mapping[str, bytes] | Iterable[bytes]):
        """Append one new collector batch, preserving its exact record bytes."""
        try:
            batch = []
            size = 0
            for record in records.values() if isinstance(records, Mapping) else records:
                if not isinstance(record, bytes) or not record.endswith(b"\n") or record.count(b"\n") != 1:
                    raise ValueError("Append complete, newline-terminated JSONL records.")
                batch.append(record)
                size += len(record)
                if len(batch) > min(APPEND_RECORDS, CHUNK_RECORDS) or size > min(APPEND_BYTES, CHUNK_BYTES):
                    raise ValueError("A live capture batch exceeds 2,000 records or 4 MiB.")
            if not batch:
                return
            if self.staged_bytes + size > STAGING_BYTES:
                raise StorageFull("Live capture staging is full (64 MiB). Save pending captures before continuing.")
            rotate = self.pending_bytes + size > CHUNK_BYTES or self.pending_records + len(batch) > CHUNK_RECORDS
            files = len(self._segments()) + int(bool(self.pending_bytes))
            if files + int(rotate or not self.pending_bytes) > STAGING_FILES:
                raise StorageFull("Live capture staging file limit reached. Save pending captures before continuing.")
            if rotate:
                self._seal()
            start = self.pending_bytes
            descriptor = os.open(self._path("pending.jsonl"),
                                 os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            try:
                remaining = memoryview(b"".join(batch))
                while remaining:
                    count = os.write(descriptor, remaining)
                    if count <= 0:
                        raise OSError("Could not finish writing the live capture batch.")
                    remaining = remaining[count:]
                os.fsync(descriptor)
            except OSError:
                # Roll back only this unsuccessful append; older evidence stays intact.
                os.ftruncate(descriptor, start)
                os.fsync(descriptor)
                raise
            finally:
                os.close(descriptor)
            self.pending_bytes += size
            self.pending_records += len(batch)
            self.staged_bytes += size
            self.staged_records += len(batch)
            self.error = None
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            raise

    def save(self, *, sealed_only: bool = False) -> list[dict]:
        """Promote unsaved chunks into the normal library, without duplicate retries."""
        saved = []
        try:
            if not sealed_only:
                self._seal()
            for path in self._segments():
                sequence = SEGMENT.fullmatch(path.name)[1]
                with path.open("rb") as stream:
                    raw = stream.read(CHUNK_BYTES + 1)
                if len(raw) > CHUNK_BYTES or raw.count(b"\n") > CHUNK_RECORDS or not raw.endswith(b"\n"):
                    raise ValueError("A staged capture is incomplete or exceeds its chunk limit.")
                digest = sha256(raw).hexdigest()
                upload_id = sha256(f"live-archive-v1:{self.watch_id}:{sequence}:{digest}".encode()).hexdigest()[:32]
                item = self.store.get(upload_id)
                name = f"{self.source.removesuffix('.jsonl')[:190]}-capture-{self.watch_id[:8]}-{sequence}.jsonl"
                if not name.startswith("ssh-live"):
                    name = "ssh-live-" + name
                if item is not None:
                    if item["sha256"] != digest or item["byte_count"] != len(raw) or item["filename"] != name:
                        raise ValueError("A saved capture ID conflicts with staged evidence; no files were overwritten.")
                else:
                    if self.platform == "windows":
                        parsed = parse_windows_jsonl(raw, source_file=name, upload_id=upload_id)
                    else:
                        parsed = parse_linux(raw, file_format="journal-json", source_file=name, upload_id=upload_id)
                    item = self.store.save(raw, parsed)
                path.unlink()
                self.saved_chunks += 1
                self.last_upload_id = item["id"]
                self.staged_bytes -= len(raw)
                self.staged_records -= raw.count(b"\n")
                saved.append(item)
            self.error = None
            return saved
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            raise

    def status(self) -> dict:
        return {"pending_records": self.staged_records, "pending_bytes": self.staged_bytes,
                "saved_chunks": self.saved_chunks, "last_upload_id": self.last_upload_id,
                "error": self.error, "chunk_limit_bytes": CHUNK_BYTES,
                "chunk_limit_records": CHUNK_RECORDS, "staging_limit_bytes": STAGING_BYTES,
                "sealed_chunks": len(self._segments()), "current_records": self.pending_records,
                "current_bytes": self.pending_bytes}
