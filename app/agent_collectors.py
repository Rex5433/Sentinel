"""Fixed SSH commands and bounded pages for Sentinel's managed hosts."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import re
import shlex

from sentinel.commands.catalog import WINDOWS_PROJECTION
from sentinel.ingest.common import load_json

from .live_bookmark import BookmarkGap, after_anchor, position_for
from .live_logs import journal_records
from .ssh_collection import CollectionError, MAX_BYTES, journal_command
from .windows_live import PREAMBLE, TASK_SCHEDULER, windows_records


PAGE_RECORDS = 64
SNAPSHOT_ROWS = 100
FILE_PAGE_BYTES = 16 * 1024
ANCHOR_BYTES = 64
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
AUTH_FILES = ("/var/log/auth.log", "/var/log/secure", "/var/log/messages")
DEFAULT_INTEGRITY_PATHS = ("/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config")
MAX_INTEGRITY_BYTES = 1024 * 1024

MODULES = {
    "windows": {
        "authentication": "Authentication", "accounts": "Account and privilege changes",
        "directory": "Active Directory authentication", "process": "Processes",
        "services": "Services and persistence", "system": "System and audit integrity",
        "network": "Network endpoints and firewall events",
    },
    "linux": {
        "authentication": "SSH authentication", "privilege": "Privilege and account activity",
        "process": "Processes", "services": "Services", "network": "Network endpoints and kernel firewall events",
        "audit": "Audit journal", "auth_files": "Authentication log files",
        "integrity": "Selected file integrity",
    },
}
DEFAULT_MODULES = {"windows": ("authentication", "accounts", "system"), "linux": ("authentication", "privilege")}


class CollectorUnavailable(CollectionError):
    """An individual module is absent or denied."""

    def __init__(self, message, kind="unavailable"):
        super().__init__(message)
        self.kind = kind

@dataclass(frozen=True)
class Page:
    records: dict[str, bytes]
    bookmark: str | None
    more: bool = False
    snapshot: dict | None = None


@dataclass(frozen=True)
class Stream:
    id: str
    label: str
    module: str
    kind: str
    channel: str | None = None
    argument: str = ""
    paths: tuple[str, ...] = ()
    platform: str = ""

    @property
    def source_format(self):
        return {"windows": "windows-jsonl", "journal": "linux-journal-json", "file": "linux-text"}.get(self.kind)

    @property
    def minimum_interval(self):
        return 300 if self.module == "integrity" else 60 if self.kind == "snapshot" else 0

    def command(self, bookmark=None):
        if self.kind == "windows":
            return _windows_command(_windows_events(self.channel, self.argument, bookmark))
        if self.kind == "journal":
            return journal_command(PAGE_RECORDS, self.argument, bookmark)
        if self.kind == "file":
            return _file_command(self.channel, bookmark)
        if self.platform == "windows":
            return _windows_command(_windows_snapshot(self.argument))
        return _linux_snapshot(self.argument, self.paths)

    def parse(self, raw, bookmark=None):
        if len(raw) > MAX_BYTES:
            raise CollectionError("Collector output exceeded the size limit.")
        if self.kind == "file":
            return _file_page(raw, bookmark)
        if self.kind == "snapshot":
            return Page({}, None, snapshot=_parse_snapshot(raw, self))
        return _event_page(raw, self, bookmark)


def integrity_paths(values):
    paths = tuple(values)
    if len(paths) > 8 or any(
        not isinstance(path, str) or len(path) > 256
        or not re.fullmatch(r"/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+", path)
        or any(part in {".", ".."} for part in path.split("/"))
        for path in paths
    ):
        raise CollectionError("Choose up to eight absolute Linux file paths without wildcards or traversal.")
    return tuple(dict.fromkeys(paths))


def _windows_stream(module, name, channel, ids=(), *, warning=False):
    conditions = [f"EventID={value}" for value in ids]
    if warning:
        conditions.append("(Level=1 or Level=2 or Level=3)")
    return Stream(name, f"{channel} · {MODULES['windows'][module]}", module, "windows", channel,
                  " or ".join(conditions), platform="windows")


def _snapshot_stream(platform, module, source, title, paths=()):
    return Stream(source, title, module, "snapshot", argument=source, paths=paths, platform=platform)


def _journal_stream(module, identifiers, *, audit=False):
    filters = " ".join(f"SYSLOG_IDENTIFIER={value}" for value in identifiers)
    if audit:
        filters = f"{filters} + _TRANSPORT=audit"
    return Stream(f"journal-{module}", MODULES["linux"][module], module, "journal", "journal", filters, platform="linux")


def collection_plan(platform, modules, integrity_paths=()):
    if platform not in MODULES:
        raise CollectionError("Choose Windows or Linux for the collector.")
    selected = tuple(dict.fromkeys(modules))
    if any(module not in MODULES[platform] for module in selected):
        raise CollectionError("Choose modules supported on this operating system.")
    return tuple(stream for module in selected for stream in _module_streams(platform, module, integrity_paths))


def _module_streams(platform, module, paths):
    if platform == "windows":
        security = {
            "authentication": (4624, 4625, 4634, 4648, 4672, 4740),
            "accounts": (4720, 4722, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4756, 4757),
            "directory": (4768, 4769, 4771, 4776),
            "process": (4688,),
            "services": (4657, 4697, 4698, 4699, 4700, 4701, 4702),
            "system": (1100, 1102, 4719),
        }
        if module in security:
            yield _windows_stream(module, f"security-{module}", "Security", security[module])
        if module == "system":
            yield _windows_stream(module, "system-events", "System", (104, 1074, 6005, 6006, 6008), warning=True)
            yield _windows_stream(module, "application-events", "Application", warning=True)
            yield _windows_stream(module, "defender-events", DEFENDER, (1116, 1117, 1118, 1119, 5001, 5007))
            yield _snapshot_stream(platform, module, "audit-policy", "Audit policy")
        if module == "process":
            yield _snapshot_stream(platform, module, "processes", "Running processes")
        if module == "services":
            yield _windows_stream(module, "system-services", "System", (7000, 7001, 7034, 7036, 7040, 7045))
            yield _windows_stream(module, "task-scheduler", TASK_SCHEDULER, (100, 102, 106, 129, 140, 141, 200, 201))
            yield _snapshot_stream(platform, module, "services", "Services")
            yield _snapshot_stream(platform, module, "scheduled-tasks", "Scheduled tasks")
            yield _snapshot_stream(platform, module, "startup", "Startup entries")
        if module == "network":
            yield _windows_stream(module, "security-network", "Security", (5152, 5156, 5157, 5158))
            yield _snapshot_stream(platform, module, "tcp", "TCP connections")
            yield _snapshot_stream(platform, module, "udp", "UDP endpoints")
            yield _snapshot_stream(platform, module, "interfaces", "Network interfaces")
        return

    identifiers = {
        "authentication": ("sshd", "sshd-session", "sshd-auth", "systemd-logind"),
        "privilege": ("sudo", "su", "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "passwd"),
        "services": ("systemd", "cron", "CRON", "crond", "CROND", "crontab"),
        "audit": ("audit", "auditd"),
    }
    if module in identifiers:
        yield _journal_stream(module, identifiers[module], audit=module == "audit")
    if module == "process":
        yield _snapshot_stream(platform, module, "processes", "Running processes")
    if module == "services":
        yield _snapshot_stream(platform, module, "services", "Service units")
    if module == "network":
        yield Stream("journal-firewall", "Kernel and firewall journal", module, "journal", "journal",
                     "_TRANSPORT=kernel + SYSLOG_IDENTIFIER=ufw",
                     platform="linux")
        yield _snapshot_stream(platform, module, "sockets", "TCP and UDP sockets")
        yield _snapshot_stream(platform, module, "interfaces", "Network interfaces")
    if module == "auth_files":
        for path in AUTH_FILES:
            yield Stream(f"file-{path.rsplit('/', 1)[1]}", path, module, "file", path, platform="linux")
    if module == "integrity":
        yield _snapshot_stream(platform, module, "integrity", "Selected file integrity",
                               integrity_paths(paths) if paths else DEFAULT_INTEGRITY_PATHS)


def _windows_command(script):
    encoded = b64encode(script.encode("utf-16-le")).decode("ascii")
    command = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded
    if len(command) > 8000:
        raise CollectionError("Windows collector command exceeds the OpenSSH command-line limit.")
    return command


_PS_FAILURE = r"""
    $id = ($_.FullyQualifiedErrorId -split ',')[0]
    $cause = $_.Exception
    while ($cause.InnerException) { $cause = $cause.InnerException }
    if ($_.CategoryInfo.Category -in @('PermissionDenied', 'SecurityError') -or
        $cause -is [System.UnauthorizedAccessException] -or $cause.HResult -eq -2147024891) {
        '{"SentinelCollectorError":"permission"}'
    } elseif ($id -in @('NoMatchingLogsFound','NoMatchingProvidersFound') -or
        $_.CategoryInfo.Category -in @('ObjectNotFound','ResourceUnavailable','NotInstalled')) {
        '{"SentinelCollectorError":"unavailable"}'
    } else { '{"SentinelCollectorError":"command"}' }
"""


def _windows_events(channel, conditions, bookmark):
    predicates = [f"({conditions})"] if conditions else []
    if bookmark is not None:
        if not re.fullmatch(r"[0-9]{1,19}:[a-f0-9]{64}", bookmark):
            raise CollectionError("The saved Windows bookmark is invalid.")
        record_id = int(bookmark.split(":", 1)[0])
        if record_id > 2**63 - 1:
            raise CollectionError("The saved Windows record number is out of range.")
        predicates.append(f"EventRecordID >= {record_id}")
    xpath = " and ".join(predicates)
    query = f"Get-WinEvent -LogName '{channel}' -MaxEvents {PAGE_RECORDS + int(bookmark is not None)}"
    if xpath:
        query += f" -FilterXPath '*[System[{xpath}]]'"
    if bookmark is not None:
        query += " -Oldest"
    return PREAMBLE + f"""
try {{
    try {{ $events = @({query} -ErrorAction Stop) }} catch {{
        if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'NoMatchingEventsFound') {{ throw }}
        if ((Get-WinEvent -ListLog '{channel}' -ErrorAction Stop).IsEnabled -eq $false) {{
            '{{"SentinelCollectorError":"disabled"}}'
        }}
        exit 0
    }}
    $events | Sort-Object RecordId | {WINDOWS_PROJECTION}
}} catch {{
    {_PS_FAILURE}
}}
exit 0
"""


def _json(data):
    try:
        return load_json(data.decode("utf-8-sig"))
    except (ValueError, RecursionError) as exc:
        raise CollectionError("Collector returned malformed JSON.") from exc


def _check_marker(data):
    if len(data.splitlines()) != 1 or b'"SentinelCollectorError"' not in data:
        return
    marker = _json(data)
    if not isinstance(marker, dict) or set(marker) != {"SentinelCollectorError"}:
        return
    error = marker["SentinelCollectorError"]
    if error == "permission":
        raise CollectorUnavailable("The SSH account lacks permission for this collector.", "permission")
    if error == "unavailable":
        raise CollectorUnavailable("The selected log or native utility is unavailable.")
    if error == "disabled":
        raise CollectorUnavailable("This Windows event channel is disabled.", "disabled_channel")
    raise CollectionError("The remote collection command failed.")


def _event_page(raw, stream, bookmark):
    _check_marker(raw)
    anchored = bookmark is not None
    lines = raw.split(b"\n")
    if raw and (lines[-1] or len(lines) - 1 > PAGE_RECORDS + int(anchored)):
        raise CollectionError("Collector returned a truncated or oversized event page.")
    if stream.kind == "windows":
        records, rejected = windows_records(raw, stream.channel, anchored=anchored)
    else:
        records, rejected = journal_records(raw, anchored=anchored)
    if rejected or len(records) != len(lines) - 1:
        raise CollectionError("Collector returned malformed or duplicate records. The bookmark was held.")
    ids = []
    for cursor, raw_record in records.items():
        value = _json(raw_record)
        if stream.kind == "windows":
            try:
                timestamp = datetime.fromisoformat(value["TimeCreated"])
                valid = timestamp.tzinfo is not None and type(value.get("Id")) is int and 0 <= value["Id"] <= 65535
            except (ValueError, TypeError, OverflowError):
                valid = False
            if not valid:
                raise CollectionError("Windows returned an invalid event identity or timestamp.")
            ids.append(value["RecordId"])
        else:
            timestamp = value.get("__REALTIME_TIMESTAMP")
            if (not re.fullmatch(r"[A-Za-z0-9=;]{1,512}", cursor) or not isinstance(timestamp, str)
                    or not re.fullmatch(r"[0-9]{1,18}", timestamp) or int(timestamp) > 253402300799999999):
                raise CollectionError("The journal returned an invalid cursor or timestamp.")
    if any(new <= old for old, new in zip(ids, ids[1:])):
        raise CollectionError("Windows returned an out-of-order event page.")
    platform = "windows" if stream.kind == "windows" else "linux"
    if anchored:
        records = after_anchor(platform, records, bookmark)
    if records:
        cursor = next(reversed(records))
        bookmark = position_for(platform, cursor, records[cursor])
    return Page(records, bookmark, len(records) == PAGE_RECORDS)


def _file_bookmark(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,20}:[0-9]{1,20}:[0-9]{1,19}:[a-f0-9]{64}", value):
        raise CollectionError("The saved file bookmark is invalid.")
    device, inode, offset, digest = value.split(":")
    if int(offset) > 2**63 - 1:
        raise CollectionError("The saved file offset is out of range.")
    return device, inode, int(offset), digest


def _shell(script):
    return "bash -c " + shlex.quote("export LC_ALL=C\n" + script)


def _file_command(path, bookmark):
    if path not in AUTH_FILES:
        raise CollectionError("The requested log file is outside the collector list.")
    position = _file_bookmark(bookmark) if bookmark is not None else None
    # Read through a held file descriptor so a concurrent rename cannot switch files.
    checkpoint = (
        f"""if [ "$device" != "{position[0]}" ] || [ "$inode" != "{position[1]}" ] || [ "$size" -lt {position[2]} ]; then
    printf 'sentinel-file-v1 gap\n'; exit 0
fi
start={position[2]}""" if position else f"start=$(( size > {FILE_PAGE_BYTES} ? size - {FILE_PAGE_BYTES} : 0 ))"
    )
    return _shell(f"""set -e -o pipefail
path={shlex.quote(path)}
if [ ! -x "${{path%/*}}" ]; then
    printf 'sentinel-file-v1 permission\n'; exit 0
fi
if [ ! -e "$path" ]; then
    printf 'sentinel-file-v1 absent\n'; exit 0
fi
if [ ! -f "$path" ] || [ ! -r "$path" ] || ! {{ exec 3< "$path"; }} 2>/dev/null; then
    printf 'sentinel-file-v1 permission\n'; exit 0
fi
opened=/proc/$$/fd/3
metadata=$(stat -Lc '%d %i %s' -- "$opened")
read -r device inode size <<< "$metadata"
{checkpoint}
before=$(( start < {ANCHOR_BYTES} ? start : {ANCHOR_BYTES} ))
count=$(( size - start < {FILE_PAGE_BYTES} ? size - start : {FILE_PAGE_BYTES} ))
printf 'sentinel-file-v1 %s %s %s %s\n' "$device" "$inode" "$start" "$size"
dd if="$opened" iflag=skip_bytes,count_bytes skip="$(( start - before ))" count="$before" status=none | base64 -w0
printf '\n'
dd if="$opened" iflag=skip_bytes,count_bytes skip="$start" count="$count" status=none | base64 -w0
printf '\n'
""")


def _file_page(raw, bookmark):
    if raw == b"sentinel-file-v1 gap\n":
        raise BookmarkGap("The source file rotated or was truncated. Review the gap before resetting its bookmark.")
    if raw == b"sentinel-file-v1 unavailable\n":
        raise CollectorUnavailable("The source log file is absent or unreadable by the SSH account.")
    if raw == b"sentinel-file-v1 absent\n":
        raise CollectorUnavailable("This optional log file is absent. Journal collection may still be available.",
                                   "optional_absent" if bookmark is None else "unavailable")
    if raw == b"sentinel-file-v1 permission\n":
        raise CollectorUnavailable("The SSH account cannot read this log file.", "permission")
    try:
        header, prefix, payload, end = raw.split(b"\n")
        fields = header.decode("ascii").split()
        if end or len(fields) != 5 or fields[0] != "sentinel-file-v1":
            raise ValueError()
        device, inode, start_value, size_value = fields[1:]
        if any(not re.fullmatch(r"[0-9]{1,20}", value) for value in fields[1:]):
            raise ValueError()
        start, size = int(start_value), int(size_value)
        if not 0 <= start <= size <= 2**63 - 1:
            raise ValueError()
        before = b64decode(prefix, validate=True)
        data = b64decode(payload, validate=True)
        if len(before) != min(start, ANCHOR_BYTES) or len(data) != min(size - start, FILE_PAGE_BYTES):
            raise ValueError()
    except (ValueError, UnicodeError, Base64Error) as exc:
        raise CollectionError("The source file page was incomplete or malformed.") from exc
    if bookmark:
        previous_device, previous_inode, offset, digest = _file_bookmark(bookmark)
        if (device, inode, start, sha256(before).hexdigest()) != (previous_device, previous_inode, offset, digest):
            raise BookmarkGap("The source file no longer matches its bookmark. Review rotation or truncation before resetting.")
    elif start != max(0, size - FILE_PAGE_BYTES):
        raise CollectionError("The first source file page has an invalid starting offset.")

    consumed = 0
    if start and not bookmark and not before.endswith(b"\n"):
        end_of_partial = data.find(b"\n")
        if end_of_partial < 0:
            raise CollectionError("The latest log line exceeded the file read limit.")
        consumed = end_of_partial + 1
    records = {}
    for content in data[consumed:].split(b"\n")[:-1][:PAGE_RECORDS]:
        line = content + b"\n"
        key = f"{device}:{inode}:{start + consumed}:{sha256(line).hexdigest()}"
        records[key] = line
        consumed += len(line)
    if not consumed and len(data) == FILE_PAGE_BYTES:
        raise CollectionError("A source log line exceeded the file read limit.")
    if consumed or not data:
        digest = sha256((before + data[:consumed])[-ANCHOR_BYTES:]).hexdigest()
        bookmark = f"{device}:{inode}:{start + consumed}:{digest}"
    return Page(records, bookmark, b"\n" in data[consumed:] or start + len(data) < size)


_WINDOWS_SNAPSHOTS = {
    "processes": "Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate",
    "services": "Get-CimInstance -ClassName Win32_Service | Select-Object Name,State,StartMode,StartName",
    "scheduled-tasks": "Get-ScheduledTask | Select-Object TaskName,TaskPath,@{n='State';e={ [string]$_.State }}",
    "startup": "Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name,Location,User",
    "tcp": "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,@{n='State';e={ [string]$_.State }}",
    "udp": "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess",
    "interfaces": "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength",
    "audit-policy": "auditpol.exe /get /category:* /r | ForEach-Object { [ordered]@{ line=$_ } }",
}


def _windows_snapshot(name):
    command = _WINDOWS_SNAPSHOTS[name]
    native_status = 'if ($LASTEXITCODE -ne 0) { throw "auditpol failed" }' if name == "audit-policy" else ""
    return PREAMBLE + f"""
try {{
    $rows = @({command} | Select-Object -First {SNAPSHOT_ROWS + 1})
    {native_status}
    [ordered]@{{SentinelAgentSnapshot=1; rows=@($rows | Select-Object -First {SNAPSHOT_ROWS}); limited=($rows.Count -gt {SNAPSHOT_ROWS})}} |
        ConvertTo-Json -Depth 4 -Compress
}} catch {{ {_PS_FAILURE} }}
exit 0
"""


_LINUX_SNAPSHOTS = {
    "processes": "ps -ww -eo pid=,ppid=,user=,etimes=,comm=",
    "services": "systemctl list-units --type=service --all --no-legend --no-pager --plain",
    "sockets": "ss -H -tunap",
    "interfaces": "ip -brief address",
}


def _linux_snapshot(name, paths):
    if name != "integrity":
        command = _LINUX_SNAPSHOTS[name]
        return _shell(f"set -o pipefail\n{command} | awk 'NR <= {SNAPSHOT_ROWS + 1}'")
    paths = integrity_paths(paths)
    selection = " ".join(shlex.quote(path) for path in paths)
    return _shell(f"""set -e -o pipefail
for path in {selection}; do
    if [ ! -f "$path" ] || [ ! -r "$path" ] || [ -L "$path" ]; then
        printf '%s\tunavailable\n' "$path"; continue
    fi
    before=$(stat -Lc '%d:%i:%s:%Y:%a:%u:%g' -- "$path") || {{
        printf '%s\tunavailable\n' "$path"; continue
    }}
    IFS=: read -r dev inode size modified mode uid gid <<< "$before"
    if [ "$size" -gt {MAX_INTEGRITY_BYTES} ]; then
        printf '%s\ttoo_large\n' "$path"; continue
    fi
    if ! digest=$(head -c {MAX_INTEGRITY_BYTES + 1} -- "$path" | sha256sum); then
        printf '%s\tunavailable\n' "$path"; continue
    fi
    if [ "$(stat -Lc '%d:%i:%s:%Y:%a:%u:%g' -- "$path")" != "$before" ]; then
        printf '%s\tchanged_during_read\n' "$path"; continue
    fi
    printf '%s\tok\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "${{digest%% *}}" "$size" "$modified" "$mode" "$uid" "$gid"
done
""")


def _parse_snapshot(raw, stream):
    _check_marker(raw)
    if stream.platform == "windows":
        value = _json(raw)
        if (not isinstance(value, dict) or type(value.get("SentinelAgentSnapshot")) is not int
                or value["SentinelAgentSnapshot"] != 1 or not isinstance(value.get("rows"), list)
                or type(value.get("limited")) is not bool or len(value["rows"]) > SNAPSHOT_ROWS):
            raise CollectionError("Windows returned an invalid snapshot envelope.")
        rows, limited = value["rows"], value["limited"]
        if any(
            not isinstance(row, dict) or len(row) > 20
            or any(len(key) > 80 or type(value) not in (str, int, float, bool, type(None))
                   or (isinstance(value, str) and len(value) > 4096) for key, value in row.items())
            for row in rows
        ):
            raise CollectionError("Windows returned invalid snapshot fields.")
    else:
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise CollectionError("Linux returned a non-UTF-8 snapshot.") from exc
        if len(lines) > SNAPSHOT_ROWS + 1 or any(len(line) > 4096 for line in lines):
            raise CollectionError("Linux returned an oversized snapshot.")
        limited = len(lines) > SNAPSHOT_ROWS
        rows = _linux_snapshot_rows(stream, lines[:SNAPSHOT_ROWS])
    return {"schema": 1, "kind": stream.id, "rows": rows, "limited": limited}


def _linux_snapshot_rows(stream, lines):
    if stream.id == "integrity":
        entries = {}
        for line in lines:
            path, sep, rest = line.partition("\t")
            if not sep or path not in stream.paths or path in entries:
                raise CollectionError("Linux returned an unexpected integrity path.")
            fields = rest.split("\t")
            status = fields[0]
            if len(fields) == 1 and status in {"unavailable", "too_large", "changed_during_read"}:
                entries[path] = {"path": path, "status": status}
            elif (len(fields) == 7 and status == "ok" and re.fullmatch(r"[a-f0-9]{64}", fields[1])
                  and all(re.fullmatch(r"[0-9]{1,19}", part) for part in fields[2:])):
                entries[path] = {"path": path, "status": status, "sha256": fields[1], "size": int(fields[2]),
                                 "modified_epoch": int(fields[3]), "mode": fields[4], "uid": int(fields[5]), "gid": int(fields[6])}
            else:
                raise CollectionError("Linux returned invalid integrity metadata.")
        if set(entries) != set(stream.paths):
            raise CollectionError("Linux did not report each requested integrity path.")
        return list(entries.values())
    rows = []
    for line in lines:
        if stream.id == "processes":
            parts = line.split(maxsplit=4)
            if len(parts) != 5 or any(not re.fullmatch(r"[0-9]{1,12}", parts[index]) for index in (0, 1, 3)):
                raise CollectionError("Linux returned invalid process metadata.")
            rows.append({"pid": int(parts[0]), "parent_pid": int(parts[1]), "user": parts[2],
                         "elapsed_seconds": int(parts[3]), "name": parts[4]})
        elif stream.id == "services":
            parts = line.split(maxsplit=4)
            if len(parts) < 4:
                raise CollectionError("Linux returned invalid systemd unit metadata.")
            rows.append(dict(zip(("unit", "load", "active", "state", "description"), parts)))
        elif stream.id == "interfaces":
            parts = line.split()
            if len(parts) < 2:
                raise CollectionError("Linux returned invalid interface metadata.")
            rows.append({"interface": parts[0], "state": parts[1], "addresses": " ".join(parts[2:])})
        elif stream.id == "sockets":
            parts = line.split(maxsplit=6)
            if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
                raise CollectionError("Linux returned invalid socket metadata.")
            rows.append(dict(zip(("protocol", "state", "receive_queue", "send_queue", "local_endpoint",
                                  "peer_endpoint", "process"), parts)))
    return rows
