"""Shared bounded-input, provenance, and evidence-preserving parser helpers."""

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from io import StringIO
from ipaddress import ip_address
import json
import math
from typing import Iterator

from sentinel.schemas import EventRecord

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 100_000
PARSER_VERSION = "exports-v2"


class ParseInputError(ValueError):
    """The file cannot be safely framed/decoded within the supported contract."""


@dataclass
class RejectedRecord:
    record_index: int
    reason: str
    raw_record: object


@dataclass
class ParseResult:
    source_file: str
    source_sha256: str
    upload_id: str
    parser: str
    events: list[EventRecord] = field(default_factory=list)
    rejected: list[RejectedRecord] = field(default_factory=list)

    def provenance(self, index: int) -> dict:
        identity = f"{PARSER_VERSION}:{self.parser}:{self.source_sha256}:{index}"
        return {
            "event_id": sha256(identity.encode("utf-8")).hexdigest(),
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "upload_id": self.upload_id,
            "record_index": index,
        }

    def to_dict(self) -> dict:
        return {
            "parser_version": PARSER_VERSION,
            "parser": self.parser,
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "upload_id": self.upload_id,
            "accepted_count": len(self.events),
            "rejected_count": len(self.rejected),
            "events_with_warnings": sum(bool(e.parsing_errors) for e in self.events),
            "events": [event.model_dump(mode="json") for event in self.events],
            "rejected": [vars(record) for record in self.rejected],
        }


def prepare(data: bytes, source_file: str, upload_id: str, parser: str) -> tuple[str, ParseResult]:
    if not isinstance(data, bytes):
        raise ParseInputError("input must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise ParseInputError("input exceeds the 25 MiB limit")
    if any(not isinstance(value, str) or not value.strip() for value in (source_file, upload_id)):
        raise ParseInputError("source_file and upload_id must be nonblank strings")
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        text = data.decode(encoding)
    except UnicodeError as exc:
        raise ParseInputError("expected UTF-8 or BOM-marked UTF-16 text") from exc
    if "\x00" in text:
        raise ParseInputError("NUL-containing/binary input is unsupported")
    return text, ParseResult(source_file, sha256(data).hexdigest(), upload_id, parser)


def bounded(records: Iterator[tuple[int, object]]) -> Iterator[tuple[int, object]]:
    for count, record in enumerate(records, 1):
        if count > MAX_RECORDS:
            raise ParseInputError("input exceeds the 100000-record limit")
        yield record


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def load_json(text: str) -> object:
    value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant,
                       parse_float=_finite_float)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON nesting exceeds 64 levels")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def text_records(text: str) -> Iterator[tuple[int, str]]:
    for index, line in enumerate(text.splitlines(keepends=True), 1):
        if line.strip():
            yield index, line


def json_records(text: str) -> Iterator[tuple[int, object]]:
    if not text.strip():
        return
    try:
        records = load_json(text)
    except (ValueError, RecursionError) as exc:
        raise ParseInputError("invalid JSON document") from exc
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise ParseInputError("JSON must contain an object or an array of objects")
    yield from enumerate(records, 1)


def csv_records(text: str) -> Iterator[tuple[int, object]]:
    reader = csv.reader(StringIO(text, newline=""), strict=True)
    try:
        headers = next(reader, None)
        if headers is None:
            return
        if not all(headers) or len(set(headers)) != len(headers):
            raise ParseInputError("CSV headers must be nonempty and unique")
        if not set(headers) & {"Id", "EventID", "TimeCreated", "Timestamp", "Message"}:
            raise ParseInputError("unsupported Windows CSV headers")
        index = 0
        for row in reader:
            if not row:
                continue
            index += 1
            # A list indicates a bad-width row; preserve every cell for rejection.
            yield index, dict(zip(headers, row)) if len(row) == len(headers) else row
    except csv.Error as exc:
        raise ParseInputError("malformed CSV framing; no partial report returned") from exc


def text_value(value: object, name: str, errors: list[str]) -> str | None:
    if value is None or (isinstance(value, str) and (not value.strip() or value == "-")):
        return None
    if not isinstance(value, str):
        errors.append(f"{name}: expected text; raw value retained")
        return None
    return value


def choose(record: dict, names: tuple[str, ...], errors: list[str]) -> object:
    values = [record[name] for name in names if name in record and record[name] not in (None, "", "-")]
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        errors.append(f"{names[0]}: conflicting aliases; raw values retained")
        return None
    return values[0]


def integer(value: object, name: str, errors: list[str], maximum: int | None = None) -> int | None:
    if value in (None, "", "-"):
        return None
    if type(value) is int:
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        number = int(value)
    else:
        errors.append(f"{name}: invalid integer; raw value retained")
        return None
    if number < 0 or (maximum is not None and number > maximum):
        errors.append(f"{name}: out of range; raw value retained")
        return None
    return number


def timestamp(value: str | None, errors: list[str]) -> datetime | None:
    if value is None:
        errors.append("timestamp: missing; no time inferred")
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        errors.append("timestamp: unsupported, invalid, or timezone missing; raw value retained")
        return None


def address(value: object, errors: list[str]) -> str | None:
    value = text_value(value, "source_ip", errors)
    if value is None:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        errors.append("source_ip: invalid address; raw value retained")
        return None
