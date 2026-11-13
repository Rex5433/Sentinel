"""Read Windows event exports framed as one JSON object per line."""

from pydantic import ValidationError

from .common import ParseResult, RejectedRecord, bounded, load_json, prepare, text_records
from .windows import _event

WINDOWS_FIELDS = frozenset({"Id", "EventID", "TimeCreated", "Timestamp", "Message"})


def parse_windows_jsonl(data: bytes, *, source_file: str, upload_id: str) -> ParseResult:
    text, result = prepare(data, source_file, upload_id, "windows-jsonl")
    for index, line in bounded(text_records(text)):
        try:
            record = load_json(line)
        except (ValueError, RecursionError):
            result.rejected.append(RejectedRecord(index, "invalid Windows JSON line", line))
            continue
        if not isinstance(record, dict) or not WINDOWS_FIELDS.intersection(record):
            result.rejected.append(RejectedRecord(index, "not a supported Windows record", record))
            continue
        try:
            result.events.append(_event(record, index, result))
        except ValidationError:
            result.rejected.append(RejectedRecord(index, "record cannot satisfy event contract", record))
    return result
