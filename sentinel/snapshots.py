"""Inert snapshot validation and deterministic, evidence-referenced comparisons."""

from dataclasses import dataclass
from difflib import unified_diff
from hashlib import sha256
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Literal

from pydantic import Field, JsonValue, ValidationError

from .schemas import Contract, UtcTimestamp
from .ingest.common import ParseInputError, load_json

VERSION = "system-snapshot-v1"
COMPARE_VERSION = "snapshot-diff-v1"
MAX_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 5000
CATEGORIES = ("services", "files", "packages", "users", "firewall")


class Host(Contract):
    id: str = Field(pattern=r"^[a-f0-9]{64}$")
    name: str = Field(min_length=1, max_length=255)
    platform: Literal["windows", "linux"]


class Item(Contract):
    id: str = Field(min_length=1, max_length=1024)
    values: dict[str, JsonValue] = Field(min_length=1, max_length=32)


class Section(Contract):
    complete: bool = Field(strict=True)
    scope: str = Field(min_length=1, max_length=1024)
    notes: list[str] = Field(default_factory=list, max_length=20)
    items: list[Item] = Field(max_length=MAX_ITEMS)


class Snapshot(Contract):
    schema_version: Literal["system-snapshot-v1"]
    host: Host
    started_at_utc: UtcTimestamp
    ended_at_utc: UtcTimestamp
    collector: str = Field(min_length=1, max_length=128)
    sections: dict[str, Section] = Field(min_length=1, max_length=5)


@dataclass
class SnapshotResult:
    source_file: str
    source_sha256: str
    upload_id: str
    snapshot: Snapshot
    parser: str = "snapshot"


def _scalar(value, maximum=4096):
    return (value is None or type(value) is bool or
            type(value) is int and abs(value) <= 2**53-1 or
            isinstance(value, str) and len(value) <= maximum and "\x00" not in value)


def file_path(value, platform):
    cls = PureWindowsPath if platform == "windows" else PurePosixPath
    path = cls(value)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in value):
        raise ValueError("file identifiers must be absolute paths without traversal or controls")
    if platform == "windows" and (not re.fullmatch(r"[A-Za-z]:", path.drive) or ":" in value[2:]):
        raise ValueError("UNC paths and alternate data streams are unsupported")
    return str(path)


def validate_snapshot(value) -> Snapshot:
    snapshot = Snapshot.model_validate(value)
    if not snapshot.host.name.strip() or not snapshot.collector.strip():
        raise ValueError("blank host/collector")
    if snapshot.started_at_utc > snapshot.ended_at_utc:
        raise ValueError("snapshot times are reversed")
    if not set(snapshot.sections) <= set(CATEGORIES):
        raise ValueError("unknown snapshot category")
    if sum(len(section.items) for section in snapshot.sections.values()) > MAX_ITEMS:
        raise ValueError("snapshot exceeds item limit")
    for category, section in snapshot.sections.items():
        seen = set()
        if not section.scope.strip() or any(len(note) > 1024 for note in section.notes):
            raise ValueError("invalid scope/notes")
        for item in section.items:
            if not item.id.strip() or any(ord(c) < 32 for c in item.id):
                raise ValueError("invalid item identity")
            key = item.id.casefold() if snapshot.host.platform == "windows" else item.id
            if key in seen:
                raise ValueError("duplicate item identity")
            seen.add(key)
            for name, data in item.values.items():
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) is None:
                    raise ValueError("invalid field name")
                if category == "files" and name == "text":
                    valid = data is None or isinstance(data, str) and len(data.encode("utf-8")) <= 32768 and "\x00" not in data
                else:
                    valid = _scalar(data) or isinstance(data, list) and len(data) <= 128 and all(_scalar(entry) for entry in data)
                if not valid:
                    raise ValueError("field type/size unsupported")
            if category == "files":
                file_path(item.id, snapshot.host.platform)
                fields = item.values
                if fields.get("kind") == "regular" and fields.get("exists") is True:
                    if not isinstance(fields.get("sha256"), str) or re.fullmatch(r"[a-f0-9]{64}", fields["sha256"]) is None:
                        raise ValueError("regular files require SHA-256")
                    if type(fields.get("byte_count")) is not int or fields["byte_count"] < 0:
                        raise ValueError("regular files require size")
                    if fields.get("text") is not None:
                        raw = fields["text"].encode("utf-8")
                        if sha256(raw).hexdigest() != fields["sha256"] or len(raw) != fields["byte_count"]:
                            raise ValueError("file text does not match hash/size")
                elif fields.get("text") is not None:
                    raise ValueError("only observed regular files can include text")
    json.dumps(snapshot.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
    return snapshot


def parse_snapshot(data: bytes, *, source_file: str, upload_id: str) -> SnapshotResult:
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ParseInputError("Snapshot exceeds the 4 MiB limit or is not bytes.")
    try:
        snapshot = validate_snapshot(load_json(data.decode("utf-8-sig")))
    except (ValueError, ValidationError, UnicodeError, OverflowError, RecursionError):
        raise ParseInputError("Invalid system-snapshot-v1 document. Check identity, coverage, times, unique items, and file text/hash consistency.") from None
    return SnapshotResult(source_file, sha256(data).hexdigest(), upload_id, snapshot)


class IncompatibleSnapshots(ValueError):
    pass


def compare(before: SnapshotResult, after: SnapshotResult):
    old, new = before.snapshot, after.snapshot
    if before.upload_id == after.upload_id or old.host.id != new.host.id or old.host.platform != new.host.platform:
        raise IncompatibleSnapshots("Choose distinct snapshots of the same host identity and platform.")
    if old.ended_at_utc >= new.started_at_utc:
        raise IncompatibleSnapshots("Baseline collection must finish before current collection starts.")
    if old.collector != new.collector:
        raise IncompatibleSnapshots("Collector versions differ; use matching collectors/scopes.")
    changes, coverage = [], []
    for category in CATEGORIES:
        left, right = old.sections.get(category), new.sections.get(category)
        comparable = bool(left and right and left.complete and right.complete and left.scope == right.scope)
        coverage.append({"category": category, "comparable": comparable,
                         "reason": None if comparable else "Missing/incomplete section or unequal scope; no additions/removals inferred."})
        if not comparable:
            continue
        def index(section):
            return {(item.id.casefold() if old.host.platform == "windows" else item.id): (position, item)
                    for position, item in enumerate(section.items)}
        a, b = index(left), index(right)
        for key in sorted(a.keys() | b.keys()):
            previous, current = a.get(key), b.get(key)
            if previous is None or current is None:
                fields = [None]
            else:
                fields = sorted(previous[1].values.keys() | current[1].values.keys())
                if category == "files":
                    fields = [field for field in fields if field != "text"]
            for field in fields:
                p = previous[1].values.get(field) if previous and field else None
                c = current[1].values.get(field) if current and field else None
                if previous and current and type(p) is type(c) and p == c:
                    continue
                status = "added" if previous is None else "removed" if current is None else "unverified" if p is None or c is None else "modified"
                item_id = (current or previous)[1].id
                identity = json.dumps([COMPARE_VERSION, before.source_sha256, after.source_sha256, category, key, field, status])
                change = {"change_id": sha256(identity.encode()).hexdigest(), "category": category,
                          "item_id": item_id, "field": field, "status": status,
                          "before": p if field else previous[1].values if previous else None,
                          "after": c if field else current[1].values if current else None,
                          "before_index": previous[0] if previous else None, "after_index": current[0] if current else None}
                changes.append(change)
                if len(changes) > 20000:
                    raise IncompatibleSnapshots("Comparison exceeds 20000 differences; capture a narrower scope.")
    counts = {status: sum(c["status"] == status for c in changes) for status in ("added", "removed", "modified", "unverified")}
    return {"comparison_version": COMPARE_VERSION, "host": new.host.model_dump(),
            "baseline_id": before.upload_id, "current_id": after.upload_id,
            "baseline_sha256": before.source_sha256, "current_sha256": after.source_sha256,
            "baseline_interval": [old.started_at_utc.isoformat(), old.ended_at_utc.isoformat()],
            "current_interval": [new.started_at_utc.isoformat(), new.ended_at_utc.isoformat()],
            "coverage": coverage, "counts": counts,
            "limitations": ["Snapshot differences are observed values, not proof of an attack or an exact change time/actor.",
                            "A baseline is not inherently trusted. No change in compared fields does not establish safety.",
                            "Only complete matching scopes are compared. Unknown fields are unverified, not confirmed modifications."]}, changes


def detail(change, before, after):
    result = dict(change)
    for label, snapshot, index in (("before", before, change["before_index"]), ("after", after, change["after_index"])):
        result[label + "_evidence"] = None if index is None else {
            "upload_id": snapshot.upload_id, "source_sha256": snapshot.source_sha256,
            "json_pointer": f"/sections/{change['category']}/items/{index}",
            "item": snapshot.snapshot.sections[change["category"]].items[index].model_dump()}
    if change["category"] == "files" and change["field"] == "sha256":
        texts = [(result[label+"_evidence"] or {}).get("item", {}).get("values", {}).get("text") for label in ("before", "after")]
        if all(isinstance(text, str) for text in texts) and all(len(text.splitlines()) <= 500 for text in texts):
            result["text_diff"] = "".join(unified_diff(texts[0].splitlines(keepends=True), texts[1].splitlines(keepends=True), fromfile="baseline", tofile="current"))
        else:
            result["text_diff"] = None
            result["text_diff_note"] = "Text absent or exceeds 500 lines; hashes identify content difference without a rendered line diff."
    return result
