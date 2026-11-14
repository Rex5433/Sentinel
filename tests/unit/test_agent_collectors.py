from base64 import b64decode, b64encode
from hashlib import sha256
import json
import shlex
from shutil import which
import subprocess
import sys

import pytest

from app.agent_collectors import (AUTH_FILES, DEFAULT_MODULES, FILE_PAGE_BYTES, MODULES, PAGE_RECORDS,
                                  CollectorUnavailable, collection_plan)
from app.live_bookmark import BookmarkGap
from app.ssh_collection import CollectionError
from sentinel.ingest import parse_linux
from sentinel.ingest.windows_jsonl import parse_windows_jsonl


def jsonl(*rows):
    return b"".join((json.dumps(row) + "\n").encode() for row in rows)


def windows_row(record_id, *, stamp="2026-11-11T12:00:00Z"):
    return {"Id": 4625, "RecordId": record_id, "MachineName": "fixture-windows", "LogName": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing", "TimeCreated": stamp,
            "EventData": {"TargetUserName": "fixture-user", "IpAddress": "192.0.2.7", "LogonType": "3"}}


def journal_row(record_id):
    return {"__CURSOR": f"i={record_id:x}", "__REALTIME_TIMESTAMP": str(1794398400000000 + record_id),
            "_HOSTNAME": "fixture-linux", "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for fixture-user from 192.0.2.7 port 34567 ssh2"}


def test_modules_are_dynamic_and_use_the_existing_import_contracts():
    for platform, modules in MODULES.items():
        streams = collection_plan(platform, modules)
        assert len(streams) == len({stream.id for stream in streams})
        assert all(stream.command() for stream in streams)
        assert all(len(stream.command()) < 8000 for stream in streams if platform == "windows")
        assert set(DEFAULT_MODULES[platform]) <= modules.keys()
    windows, = collection_plan("windows", ["authentication", "authentication"])
    journal, = collection_plan("linux", ["authentication"])
    fallback = collection_plan("linux", ["auth_files"])
    assert windows.source_format == "windows-jsonl"
    assert journal.source_format == "linux-journal-json"
    assert {item.source_format for item in fallback} == {"linux-text"}
    assert {item.channel for item in fallback} == set(AUTH_FILES)
    with pytest.raises(CollectionError):
        collection_plan("linux", ["directory"])
    with pytest.raises(CollectionError):
        collection_plan("anything", [])


def test_windows_page_preserves_raw_records_and_resumes_the_anchor():
    stream, = collection_plan("windows", ["authentication"])
    raw = jsonl(windows_row(3), windows_row(4))
    first = stream.parse(raw)
    assert first.bookmark.startswith("4:")
    assert b"".join(first.records.values()) == raw
    continued = stream.parse(jsonl(windows_row(4), windows_row(7)), first.bookmark)
    assert continued.bookmark.startswith("7:")
    assert b"".join(continued.records.values()) == jsonl(windows_row(7))
    normalized = parse_windows_jsonl(raw, source_file="fixture.jsonl", upload_id="fixture")
    assert len(normalized.events) == 2 and all(event.target == "fixture-user" for event in normalized.events)
    with pytest.raises(BookmarkGap):
        stream.parse(jsonl(windows_row(4, stamp="2026-11-11T13:00:00Z"), windows_row(7)), first.bookmark)
    with pytest.raises(CollectionError, match="out-of-order"):
        stream.parse(jsonl(windows_row(7), windows_row(4)))
    for invalid in (raw[:-1], raw + b"oops\n", raw + jsonl(windows_row(4))):
        with pytest.raises(CollectionError):
            stream.parse(invalid)


def test_linux_journal_returns_new_records_and_rejects_lost_or_injected_anchors():
    stream, = collection_plan("linux", ["authentication"])
    assert "SYSLOG_IDENTIFIER=sshd-session" in stream.command()
    first = stream.parse(jsonl(journal_row(1), journal_row(2)))
    assert first.bookmark == "i=2"
    rows = [journal_row(number) for number in range(2, 3 + PAGE_RECORDS)]
    continued = stream.parse(jsonl(*rows), first.bookmark)
    assert continued.more and len(continued.records) == PAGE_RECORDS
    normalized = parse_linux(b"".join(continued.records.values()), file_format="journal-json", source_file="fixture.jsonl",
                             upload_id="fixture")
    assert len(normalized.events) == PAGE_RECORDS
    assert stream.parse(jsonl(journal_row(2)), "i=2").records == {}
    assert stream.parse(b"").records == {}
    for invalid in (b"", jsonl(journal_row(3))):
        with pytest.raises(BookmarkGap):
            stream.parse(invalid, "i=2")
    with pytest.raises(CollectionError, match="invalid cursor or timestamp"):
        stream.parse(jsonl(journal_row(2) | {"__REALTIME_TIMESTAMP": "invalid"}))
    with pytest.raises(CollectionError, match="invalid"):
        stream.command("bad'; touch /tmp/should-not-run")


def _file_wire(contents, offset, *, device=12, inode=34):
    before = contents[max(0, offset - 64):offset]
    payload = contents[offset:offset + FILE_PAGE_BYTES]
    return b"\n".join([f"sentinel-file-v1 {device} {inode} {offset} {len(contents)}".encode(),
                        b64encode(before), b64encode(payload), b""])


def test_file_checkpoint_holds_partial_line_and_detects_rotation_and_rewrites():
    stream, *_ = collection_plan("linux", ["auth_files"])
    record = b"Nov 11 12:34:56 fixture sshd[123]: Failed password for sample from 192.0.2.1 port 22 ssh2"
    first = stream.parse(_file_wire(record + b"\n" + record, 0))
    assert list(first.records.values()) == [record + b"\n"]
    digest = sha256((record + b"\n")[-64:]).hexdigest()
    assert first.bookmark == f"12:34:{len(record) + 1}:{digest}"
    offset = len(record) + 1
    complete = record + b"\n" + record + b"\n"
    later = stream.parse(_file_wire(complete, offset), first.bookmark)
    assert list(later.records.values()) == [record + b"\n"]
    assert list(later.records) != list(first.records)
    with pytest.raises(BookmarkGap):
        stream.parse(_file_wire(complete, offset, inode=35), first.bookmark)
    with pytest.raises(BookmarkGap):
        stream.parse(_file_wire(complete.replace(b"password", b"passcode"), offset), first.bookmark)
    with pytest.raises(BookmarkGap):
        stream.parse(b"sentinel-file-v1 gap\n", first.bookmark)
    with pytest.raises(CollectionError):
        stream.parse(_file_wire(complete, offset)[:-3], first.bookmark)
    with pytest.raises(CollectorUnavailable):
        stream.parse(b"sentinel-file-v1 unavailable\n")
    assert "iflag=skip_bytes,count_bytes" in stream.command(first.bookmark)
    assert "/proc/$$/fd/3" in stream.command(first.bookmark)


def test_file_first_tail_drops_only_the_leading_partial_record_and_paginates():
    stream, *_ = collection_plan("linux", ["auth_files"])
    text = b"leading-partial\n" * 100 + b"complete\n" * 1800
    start = len(text) - FILE_PAGE_BYTES
    page = stream.parse(_file_wire(text, start))
    assert len(page.records) == PAGE_RECORDS and page.more
    assert all(value in {b"leading-partial\n", b"complete\n"} for value in page.records.values())
    assert all(int(key.split(":")[2]) > start for key in page.records)


def test_snapshots_capture_metadata_and_validate_selected_paths():
    stream, = collection_plan("linux", ["integrity"], ["/etc/ssh/sshd_config", "/etc/group"])
    assert stream.minimum_interval == 300
    raw = f"/etc/ssh/sshd_config\tok\t{'a' * 64}\t120\t1794398400\t640\t0\t0\n/etc/group\tunavailable\n".encode()
    page = stream.parse(raw)
    assert not page.records and page.bookmark is None
    assert page.snapshot["rows"] == [
        {"path": "/etc/ssh/sshd_config", "status": "ok", "sha256": "a" * 64, "size": 120,
         "modified_epoch": 1794398400, "mode": "640", "uid": 0, "gid": 0},
        {"path": "/etc/group", "status": "unavailable"},
    ]
    with pytest.raises(CollectionError, match="each requested"):
        stream.parse(raw.splitlines()[0])
    for bad in ("/etc/../outside", "/etc/sshd_config*", "/etc/a;id", "relative"):
        with pytest.raises(CollectionError):
            collection_plan("linux", ["integrity"], [bad])
    process, = collection_plan("linux", ["process"])
    assert process.parse(b"4 1 example 14 process name\n").snapshot["rows"] == [
        {"pid": 4, "parent_pid": 1, "user": "example", "elapsed_seconds": 14, "name": "process name"}
    ]
    assert "args=" not in process.command()


def test_linux_network_and_service_snapshots_preserve_observed_fields():
    streams = {stream.id: stream for stream in collection_plan("linux", ["network", "services"])}
    sockets = streams["sockets"].parse(b'tcp LISTEN 0 511 [::]:443 [::]:* users:(("sample",pid=3,fd=2))\n')
    assert sockets.snapshot["rows"] == [
        {"protocol": "tcp", "state": "LISTEN", "receive_queue": "0", "send_queue": "511",
         "local_endpoint": "[::]:443", "peer_endpoint": "[::]:*", "process": 'users:(("sample",pid=3,fd=2))'}
    ]
    service = streams["services"].parse(b"sample.service loaded failed failed Sample service\n")
    assert service.snapshot["rows"] == [
        {"unit": "sample.service", "load": "loaded", "active": "failed", "state": "failed", "description": "Sample service"}
    ]
    assert streams["interfaces"].parse(b"eth0 UP 192.0.2.4/24\n").snapshot["rows"][0]["addresses"] == "192.0.2.4/24"


def test_generated_linux_commands_parse_in_bash_without_running_native_utilities():
    if sys.platform == "win32":
        pytest.skip("Native Bash syntax check requires Linux")
    executable = which("bash")
    if not executable:
        pytest.skip("Bash unavailable")
    streams = collection_plan("linux", MODULES["linux"])
    for stream in streams:
        command = stream.command()
        inner = shlex.split(command)[2] if command.startswith("bash -c ") else command
        subprocess.run([executable, "-n", "-c", inner], capture_output=True, check=True, timeout=20)


PS_FIXTURE = r"""
function Get-WinEvent {
    [CmdletBinding()]
    param($LogName, $MaxEvents, $FilterXPath, [switch]$Oldest)
    if ($LogName -ne 'Security' -or $FilterXPath -notmatch 'EventID=4625') { throw 'Wrong filter' }
    if ($Oldest -and ($MaxEvents -ne 65 -or $FilterXPath -notmatch 'EventRecordID >= 3')) { throw 'Wrong checkpoint' }
    if (-not $Oldest -and $MaxEvents -ne 64) { throw 'Wrong page bound' }
    foreach ($number in @(4,3)) {
        [pscustomobject]@{
            Id=4625; RecordId=$number; LogName='Security'; ProviderName='Microsoft-Windows-Security-Auditing'
            MachineName='fixture-windows'; TimeCreated=[datetime]::Parse('2026-11-11T12:00:00Z')
        } | Add-Member ScriptMethod FormatDescription { 'Fixture authentication failure' } -PassThru |
            Add-Member ScriptMethod ToXml {
                '<Event><EventData><Data Name="TargetUserName">fixture-user</Data><Data Name="LogonType">3</Data></EventData></Event>'
            } -PassThru
    }
}
"""


@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_windows_encoded_commands_execute_on_available_powershell_versions(shell):
    executable = which(shell)
    if not executable:
        pytest.skip(f"{shell} unavailable")
    stream, = collection_plan("windows", ["authentication"])

    def execute(command, fixture):
        script = b64decode(command.split()[-1]).decode("utf-16-le")
        encoded = b64encode((fixture + script).encode("utf-16-le")).decode("ascii")
        completed = subprocess.run([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                   capture_output=True, check=True, timeout=20)
        return completed.stdout

    initial = stream.parse(execute(stream.command(), PS_FIXTURE))
    assert len(initial.records) == 2
    anchor = stream.parse(next(iter(initial.records.values()))).bookmark
    resumed = stream.parse(execute(stream.command(anchor), PS_FIXTURE), anchor)
    assert len(resumed.records) == 1 and resumed.bookmark.startswith("4:")
    denied = """
function Get-WinEvent {
    [CmdletBinding()]
    param($LogName, $MaxEvents, $FilterXPath)
    Write-Error 'Fixture access denied' -Category PermissionDenied
}
"""
    with pytest.raises(CollectorUnavailable, match="lacks permission"):
        stream.parse(execute(stream.command(), denied))
    empty = """
function Get-WinEvent {
    [CmdletBinding()]
    param($LogName, $MaxEvents, $FilterXPath, $ListLog)
    if ($ListLog) { return [pscustomobject]@{IsEnabled=$true} }
    Write-Error 'Fixture has no matching records' -ErrorId NoMatchingEventsFound
}
"""
    assert not stream.parse(execute(stream.command(), empty)).records
    with pytest.raises(CollectorUnavailable, match="channel is disabled") as disabled:
        stream.parse(execute(stream.command(), empty.replace("IsEnabled=$true", "IsEnabled=$false")))
    assert disabled.value.kind == "disabled_channel"
    processes = next(stream for stream in collection_plan("windows", ["process"]) if stream.kind == "snapshot")
    fixture = """
function Get-CimInstance {
    param($ClassName)
    if ($ClassName -ne 'Win32_Process') { throw 'Unexpected class' }
    [pscustomobject]@{ProcessId=7; ParentProcessId=4; Name='fixture'; ExecutablePath='C:\\fixture.exe'; CreationDate='2026-11-11T12:00:00Z'}
}
"""
    assert processes.parse(execute(processes.command(), fixture)).snapshot["rows"][0]["ParentProcessId"] == 4


def test_linux_file_absence_is_optional_until_a_checkpoint_exists():
    stream = collection_plan("linux", ["auth_files"])[0]
    with pytest.raises(CollectorUnavailable) as missing:
        stream.parse(b"sentinel-file-v1 absent\n")
    assert missing.value.kind == "optional_absent"
    with pytest.raises(CollectorUnavailable) as disappeared:
        stream.parse(b"sentinel-file-v1 absent\n", "known-position")
    assert disappeared.value.kind == "unavailable"
    with pytest.raises(CollectorUnavailable) as denied:
        stream.parse(b"sentinel-file-v1 permission\n")
    assert denied.value.kind == "permission"
