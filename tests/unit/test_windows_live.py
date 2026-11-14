from base64 import b64decode, b64encode
import json
from shutil import which
import subprocess

import pytest

from app.windows_live import TASK_SCHEDULER, windows_batch, windows_command, windows_records, windows_script
from sentinel.ingest.windows_jsonl import parse_windows_jsonl


def test_remote_command_is_fixed_and_encoded():
    command = windows_command("Security")
    script = b64decode(command.split()[-1]).decode("utf-16-le")
    assert script == windows_script("Security")
    assert "Get-WinEvent -LogName 'Security' -MaxEvents 100 -ErrorAction Stop" in script
    assert "Sort-Object RecordId" in script and "LogFileCleared" in script
    assert "FormatDescription" in script and "UnnamedEventData" in script
    with pytest.raises(ValueError):
        windows_command("Security'; Remove-Item")


@pytest.mark.parametrize("shell", ("powershell", "pwsh"))
@pytest.mark.parametrize("anchored", (False, True))
def test_windows_live_script_projects_ordered_events_in_both_shells(shell, anchored):
    executable = which(shell)
    if not executable:
        pytest.skip(f"{shell} unavailable")
    fixture = """
function Get-WinEvent {
    [CmdletBinding()]
    param($LogName, $MaxEvents, $FilterXPath, [switch]$Oldest)
    if ($LogName -ne 'System') { throw 'Wrong scope' }
    if ($Oldest) {
        if ($FilterXPath -ne '*[System[EventRecordID >= 1]]' -or $MaxEvents -ne 101) { throw 'Wrong bookmark' }
    } elseif ($MaxEvents -ne 100) { throw 'Wrong limit' }
    foreach ($number in @(2,1)) {
        [pscustomobject]@{
            Id=7045; RecordId=$number; LogName='System'; ProviderName='Service Control Manager'
            MachineName='lab-win'; TimeCreated=[datetime]::Parse('2026-11-06T12:00:00Z')
        } | Add-Member ScriptMethod FormatDescription { 'Sentinel SYSTEM visibility test' } -PassThru |
            Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="ServiceName">sample</Data><Data>unnamed test value</Data></EventData></Event>' } -PassThru
    }
}
"""
    source = fixture + windows_script("System", bookmark=f"1:{'a' * 64}" if anchored else None)
    encoded = b64encode(source.encode("utf-16-le")).decode()
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, check=True, timeout=20)
    records, skipped = windows_records(result.stdout, "System")
    assert skipped == 0 and len(records) == 2
    parsed = parse_windows_jsonl(b"".join(records.values()), source_file="live.jsonl", upload_id="lab")
    assert [row.raw_record["RecordId"] for row in parsed.events] == [1, 2]
    assert all(row.message == "Sentinel SYSTEM visibility test" for row in parsed.events)
    assert all(row.raw_record["UnnamedEventData"] == ["unnamed test value"] for row in parsed.events)


def test_journal_bookmark_is_quoted_and_injection_is_rejected():
    from shlex import split
    from app.ssh_collection import linux_command

    command = linux_command("Changes", "s=ab;i=2")
    script = split(command)[2]
    assert "--no-tail" in script and "head -n 101" in script and "--cursor='s=ab;i=2'" in script
    assert "SYSLOG_IDENTIFIER=CROND" in command
    with pytest.raises(ValueError, match="cursor"):
        linux_command("Journal", "cursor'; touch file; #")


def test_cursor_changes_when_record_number_is_reused_after_log_clear():
    first = {"RecordId": 1, "LogName": "Security", "MachineName": "lab-win", "TimeCreated": "2026-11-06T12:00:00Z"}
    second = first | {"TimeCreated": "2026-11-06T12:01:00Z"}
    raw = b"".join((json.dumps(row) + "\n").encode() for row in (first, second))
    assert len(windows_records(raw, "Security")[0]) == 2
    assert windows_records(raw, "System") == ({}, 2)


MULTI_FIXTURE = r"""
function Get-WinEvent {
    [CmdletBinding()]
    param($ListLog, [switch]$Force, $FilterHashtable, $MaxEvents)
    if ($ListLog) {
        foreach ($name in @('Security','System','Application','Microsoft-Windows-TaskScheduler/Operational','a','b','c','d','e','trace','disabled')) {
            [pscustomobject]@{
                LogName=$name; IsEnabled=$name -ne 'disabled'; IsClassicLog=$name -eq 'System'
                LogType=if ($name -eq 'trace') { 'Analytical' } else { 'Operational' }
            }
        }
        return
    }
    $log = $FilterHashtable.LogName
    if ($log -eq 'System') { Write-Error -Message 'Denied by fixture' -ErrorId TestAccessDenied }
    if ($log -notin @('Security', 'e')) { Write-Error -Message 'Quiet channel' -ErrorId NoMatchingEventsFound }
    $id = if ($FilterHashtable.ContainsKey('Id')) {
        if ($FilterHashtable.Id -notcontains 4702 -or $FilterHashtable.Id -contains 4624) { throw 'Wrong change filter' }
        4702
    } else { 4624 }
    foreach ($number in ($MaxEvents..1)) {
        [pscustomobject]@{
            Id=$id; RecordId=$number; LogName=$log; ProviderName='Microsoft-Windows-Security-Auditing'
            MachineName='lab-win'; TimeCreated=[datetime]::Parse('2026-11-10T12:00:00Z')
        } | Add-Member ScriptMethod FormatDescription { 'Fixture event' } -PassThru |
            Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="Example">fixture</Data></EventData></Event>' } -PassThru
    }
}
"""


@pytest.mark.parametrize("shell", ("powershell", "pwsh"))
@pytest.mark.parametrize(("preset", "offset", "expected_id"), (("All", 0, 4624), ("All", 8, 4624), ("Changes", 0, 4702)))
def test_wide_capture_executes_as_encoded_read_with_coverage(shell, preset, offset, expected_id):
    executable = which(shell)
    if not executable:
        pytest.skip(f"{shell} unavailable")
    command = windows_command(preset, offset)
    assert len(command) < 8_000
    bootstrap = b64decode(command.split()[-1]).decode("utf-16-le")
    encoded = b64encode((MULTI_FIXTURE + bootstrap).encode("utf-16-le")).decode()
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, check=True, timeout=20)
    batch = windows_batch(result.stdout, preset)
    assert batch.skipped == 0
    entries = {status["channel"]: status for status in batch.coverage["channels"]}
    assert "trace" not in entries and "disabled" not in entries
    if offset:
        assert list(entries) == ["e"] and batch.coverage["next_offset"] == 0
        log = "e"
    else:
        assert entries["System"]["status"] == "unavailable"
        assert entries[TASK_SCHEDULER]["status"] == "empty"
        assert batch.coverage["next_offset"] == (8 if preset == "All" else 0)
        log = "Security"
    assert entries[log]["capped"]
    ids = [json.loads(row) for row in batch.records[log].values()]
    assert ids and all(row["Id"] == expected_id for row in ids)
    assert [row["RecordId"] for row in ids] == sorted(row["RecordId"] for row in ids)


def test_wide_capture_rejects_invalid_coverage_and_excludes_unread_channels():
    header = {"SentinelCapture": 1, "total_channels": 2, "next_offset": 0, "discovery_errors": 0,
              "channels": [{"channel": "System", "status": "unavailable", "capped": False, "dropped": 0},
                           {"channel": "Security", "status": "read", "capped": True, "dropped": 1}]}
    raw = json.dumps({"RecordId": 1, "LogName": "System", "MachineName": "lab-win",
                      "TimeCreated": "2026-11-10T12:00:00Z"}) + "\n"
    batch = windows_batch((raw + json.dumps(header) + "\n").encode(), "All")
    assert batch.records == {"Security": {}} and batch.skipped == 1
    for invalid in (b"", (json.dumps(header) + "\n").encode(), (json.dumps(header | {"next_offset": 100}) + "\n").encode()):
        with pytest.raises(ValueError, match="channel coverage"):
            windows_batch(invalid, "Changes")
