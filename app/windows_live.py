"""Fixed Windows event queries for SSH and stable live batch identities."""

from base64 import b64encode
from hashlib import sha256
import json

from sentinel.commands.catalog import WINDOWS_PROJECTION
from sentinel.ingest.common import load_json

from .ssh_collection import CollectionError, MAX_BYTES, MAX_RECORDS


def windows_script(channel: str) -> str:
    if channel not in {"Security", "System"}:
        raise CollectionError("Choose the Security or System Windows event log.")
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
        "try {\n"
        f"    $events = @(Get-WinEvent -LogName '{channel}' -MaxEvents {MAX_RECORDS} -ErrorAction Stop)\n"
        "} catch {\n"
        "    if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'NoMatchingEventsFound') { throw }\n"
        "    $events = @()\n"
        "}\n"
        f"$events | Sort-Object RecordId | {WINDOWS_PROJECTION}"
    )


def windows_command(channel: str) -> str:
    encoded = b64encode(windows_script(channel).encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"


def windows_records(data: bytes, channel: str) -> tuple[dict[str, bytes], int]:
    lines = data.splitlines(keepends=True)
    if len(data) > MAX_BYTES or len(lines) > MAX_RECORDS:
        raise CollectionError("The Windows response exceeded the event batch limits.")
    records = {}
    skipped = 0
    for line in lines:
        try:
            value = load_json(line.decode("utf-8-sig"))
            record_id = value.get("RecordId")
            host, timestamp = value.get("MachineName"), value.get("TimeCreated")
            if (value.get("LogName") != channel or type(record_id) is not int or record_id < 0
                    or not isinstance(host, str) or not host
                    or not isinstance(timestamp, str) or not timestamp or not line.endswith(b"\n")):
                raise ValueError
            cursor = sha256(json.dumps([host, channel, record_id, timestamp]).encode()).hexdigest()
            if cursor in records and records[cursor] != line:
                raise ValueError
            records[cursor] = line
        except (ValueError, TypeError, AttributeError, RecursionError):
            skipped += 1
    return records, skipped
