"""Fixed Windows event queries for SSH and stable live batch identities."""

from base64 import b64encode
from dataclasses import dataclass
from gzip import compress
from hashlib import sha256
import json
import re

from sentinel.commands.catalog import WINDOWS_PROJECTION
from sentinel.ingest.common import load_json

from .ssh_collection import CollectionError, MAX_BYTES, MAX_RECORDS


TASK_SCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"
SINGLE_CHANNELS = {
    "Security": "Security", "System": "System", "Application": "Application",
    "TaskScheduler": TASK_SCHEDULER,
}
CHANNELS_PER_PULL = 8
CHANGE_IDS = {"Security": (1102, 4657, 4697, 4698, 4699, 4700, 4701, 4702, 4719), "System": (104, 7040, 7045)}
MULTI_CHANNELS = {"Changes", "All"}
MAX_CHANNELS = 100_000
PREAMBLE = (
    "$ErrorActionPreference = 'Stop'\n"
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
)


def windows_script(channel: str, offset: int = 0, *, bookmark: str | None = None) -> str:
    if channel in MULTI_CHANNELS:
        return PREAMBLE + multi_script(channel, offset)
    if channel not in SINGLE_CHANNELS:
        raise CollectionError("Choose a supported Windows event log or capture preset.")
    log = SINGLE_CHANNELS[channel]
    query = f"Get-WinEvent -LogName '{log}' -MaxEvents {MAX_RECORDS}"
    if bookmark is not None:
        if not re.fullmatch(r"[0-9]{1,19}:[a-f0-9]{64}", bookmark):
            raise CollectionError("The saved Windows event bookmark is invalid.")
        number = int(bookmark.split(":", 1)[0])
        if number > 2**63 - 1:
            raise CollectionError("The saved Windows event bookmark is out of range.")
        query = (f"Get-WinEvent -LogName '{log}' -FilterXPath '*[System[EventRecordID >= {number}]]' "
                 f"-Oldest -MaxEvents {MAX_RECORDS + 1}")
    return (
        PREAMBLE +
        "try {\n"
        f"    $events = @({query} -ErrorAction Stop)\n"
        "} catch {\n"
        "    if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'NoMatchingEventsFound') { throw }\n"
        "    $events = @()\n"
        "}\n"
        f"$events | Sort-Object RecordId | {WINDOWS_PROJECTION}"
    )


def multi_script(channel: str, offset: int) -> str:
    if type(offset) is not int or not 0 <= offset < MAX_CHANNELS:
        raise CollectionError("The Windows channel rotation is out of range.")
    if channel == "Changes":
        ids = {name: ",".join(map(str, values)) for name, values in CHANGE_IDS.items()}
        plan = (
            "$plan = @('Security', 'System', '" + TASK_SCHEDULER + "')\n"
            f"$eventIds = @{{Security=@({ids['Security']}); System=@({ids['System']})}}\n"
        )
    else:
        plan = (
            "$enabled = @(Get-WinEvent -ListLog '*' -Force -ErrorAction SilentlyContinue -ErrorVariable discovery |\n"
            "    Where-Object { $_.IsEnabled -and ($_.IsClassicLog -or $_.LogType -in @('Administrative', 'Operational')) } |\n"
            "    Select-Object -ExpandProperty LogName | Sort-Object -Unique)\n"
            f"$priority = @('Security','System','{TASK_SCHEDULER}','Application')\n"
            "$plan = @($priority | Where-Object { $_ -in $enabled }) + @($enabled | Where-Object { $_ -notin $priority })\n"
            "$eventIds = @{}\n"
        )
    # Limit each channel's output so one noisy source leaves room for the others and the coverage record.
    return f"""$discovery = @()
{plan}
$total = $plan.Count
$next = 0
$coverage = @()
if ($total -gt 0) {{
    $start = {offset} % $total
    $count = [Math]::Min({CHANNELS_PER_PULL}, $total - $start)
    $limit = [int][Math]::Floor({MAX_RECORDS} / $count)
    $byteLimit = [int][Math]::Floor({MAX_BYTES - 64 * 1024} / $count)
    $next = ($start + $count) % $total
    $since = (Get-Date).AddHours(-1)
    foreach ($log in $plan[$start..($start + $count - 1)]) {{
        $status = 'empty'
        $capped = $false
        $dropped = 0
        try {{
            $filter = @{{LogName=$log; StartTime=$since}}
            if ($eventIds.ContainsKey($log)) {{ $filter.Id = $eventIds[$log] }}
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ($limit + 1) -ErrorAction Stop)
            $capped = $events.Count -gt $limit
            if ($events.Count -gt 0) {{ $status = 'read' }}
            $lines = @($events | Select-Object -First $limit | Sort-Object RecordId | {WINDOWS_PROJECTION})
            $bytes = 0
            foreach ($line in $lines) {{
                $size = [Text.Encoding]::UTF8.GetByteCount($line) + 2
                if ($bytes + $size -gt $byteLimit) {{ $dropped++; continue }}
                $bytes += $size
                $line
            }}
        }} catch {{
            if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'NoMatchingEventsFound') {{ $status = 'unavailable' }}
        }}
        $coverage += [ordered]@{{channel=$log; status=$status; capped=$capped; dropped=$dropped}}
    }}
}}
[ordered]@{{SentinelCapture=1; channels=$coverage; total_channels=$total; next_offset=$next;
    discovery_errors=$discovery.Count}} | ConvertTo-Json -Compress -Depth 4
"""


def windows_command(channel: str, offset: int = 0, *, bookmark: str | None = None) -> str:
    script = windows_script(channel, offset, bookmark=bookmark)
    if channel in MULTI_CHANNELS:
        # Windows OpenSSH commonly dispatches through cmd.exe's 8,191-character limit.
        packed = b64encode(compress(script.encode("utf-8"), mtime=0)).decode("ascii")
        script = (
            f"$inputBytes = [Convert]::FromBase64String('{packed}')\n"
            "$stream = New-Object IO.MemoryStream(,$inputBytes)\n"
            "$gzip = New-Object IO.Compression.GZipStream($stream, [IO.Compression.CompressionMode]::Decompress)\n"
            "$reader = New-Object IO.StreamReader($gzip)\n"
            "try { & ([ScriptBlock]::Create($reader.ReadToEnd())) } finally { $reader.Dispose() }"
        )
    encoded = b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"


def windows_records(data: bytes, channel: str, *, anchored: bool = False) -> tuple[dict[str, bytes], int]:
    log = SINGLE_CHANNELS.get(channel, channel)
    records, skipped = records_by_channel(data.splitlines(keepends=True), {log}, limit=MAX_RECORDS + int(anchored))
    return records[log], skipped


@dataclass
class WindowsBatch:
    records: dict[str, dict[str, bytes]]
    skipped: int
    coverage: dict


def windows_batch(data: bytes, preset: str) -> WindowsBatch:
    lines = data.splitlines(keepends=True)
    try:
        if len(data) > MAX_BYTES or not lines or not lines[-1].endswith(b"\n"):
            raise ValueError
        info = load_json(lines.pop().decode("utf-8-sig"))
        if type(info.get("SentinelCapture")) is not int or info["SentinelCapture"] != 1:
            raise ValueError
        channels = info["channels"]
        total, offset, errors = (info[key] for key in ("total_channels", "next_offset", "discovery_errors"))
        if (not isinstance(channels, list) or len(channels) > CHANNELS_PER_PULL
                or any(type(value) is not int or not 0 <= value <= MAX_CHANNELS for value in (total, offset, errors))
                or offset >= max(total, 1) or bool(total) != bool(channels) or len(channels) > total):
            raise ValueError
        seen = set()
        coverage = []
        for entry in channels:
            name, status, capped, dropped = (entry[key] for key in ("channel", "status", "capped", "dropped"))
            if (not isinstance(name, str) or not 1 <= len(name) <= 512 or name in seen
                    or status not in ("read", "empty", "unavailable") or type(capped) is not bool
                    or type(dropped) is not int or not 0 <= dropped <= MAX_RECORDS):
                raise ValueError
            seen.add(name)
            coverage.append({"channel": name, "status": status, "capped": capped, "dropped": dropped})
        if preset == "Changes" and (seen != set(CHANGE_IDS) | {TASK_SCHEDULER} or total != len(seen) or offset):
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise CollectionError("The Windows pull did not return valid channel coverage.") from None
    records, skipped = records_by_channel(lines, {entry["channel"] for entry in coverage if entry["status"] == "read"})
    return WindowsBatch(records, skipped, {"channels": coverage, "total_channels": total, "next_offset": offset,
                                           "discovery_errors": errors})


def records_by_channel(lines: list[bytes], channels: set[str], *, limit=MAX_RECORDS) -> tuple[dict[str, dict[str, bytes]], int]:
    if sum(map(len, lines)) > MAX_BYTES or len(lines) > limit:
        raise CollectionError("The Windows response exceeded the event batch limits.")
    records = {channel: {} for channel in channels}
    skipped = 0
    for line in lines:
        try:
            value = load_json(line.decode("utf-8-sig"))
            channel = value.get("LogName")
            record_id = value.get("RecordId")
            host, timestamp = value.get("MachineName"), value.get("TimeCreated")
            if (channel not in records or type(record_id) is not int or record_id < 0
                    or not isinstance(host, str) or not host
                    or not isinstance(timestamp, str) or not timestamp or not line.endswith(b"\n")):
                raise ValueError
            cursor = sha256(json.dumps([host, channel, record_id, timestamp]).encode()).hexdigest()
            bucket = records[channel]
            if cursor in bucket and bucket[cursor] != line:
                raise ValueError
            bucket[cursor] = line
        except (ValueError, TypeError, AttributeError, RecursionError):
            skipped += 1
    return records, skipped
