from base64 import b64decode, b64encode
import json
from shutil import which
import subprocess

import pytest

from app.windows_live import windows_command, windows_records, windows_script
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
def test_windows_live_script_projects_ordered_events_in_both_shells(shell):
    executable = which(shell)
    if not executable:
        pytest.skip(f"{shell} unavailable")
    fixture = """
function Get-WinEvent {
    [CmdletBinding()]
    param($LogName, $MaxEvents)
    if ($LogName -ne 'System' -or $MaxEvents -ne 100) { throw 'Wrong scope' }
    foreach ($number in @(2,1)) {
        [pscustomobject]@{
            Id=7045; RecordId=$number; LogName='System'; ProviderName='Service Control Manager'
            MachineName='lab-win'; TimeCreated=[datetime]::Parse('2026-11-06T12:00:00Z')
        } | Add-Member ScriptMethod FormatDescription { 'Sentinel SYSTEM visibility test' } -PassThru |
            Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="ServiceName">sample</Data><Data>unnamed test value</Data></EventData></Event>' } -PassThru
    }
}
"""
    source = fixture + windows_script("System")
    encoded = b64encode(source.encode("utf-16-le")).decode()
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, check=True, timeout=20)
    records, skipped = windows_records(result.stdout, "System")
    assert skipped == 0 and len(records) == 2
    parsed = parse_windows_jsonl(b"".join(records.values()), source_file="live.jsonl", upload_id="lab")
    assert [row.raw_record["RecordId"] for row in parsed.events] == [1, 2]
    assert all(row.message == "Sentinel SYSTEM visibility test" for row in parsed.events)
    assert all(row.raw_record["UnnamedEventData"] == ["unnamed test value"] for row in parsed.events)


def test_cursor_changes_when_record_number_is_reused_after_log_clear():
    first = {"RecordId": 1, "LogName": "Security", "MachineName": "lab-win", "TimeCreated": "2026-11-06T12:00:00Z"}
    second = first | {"TimeCreated": "2026-11-06T12:01:00Z"}
    raw = b"".join((json.dumps(row) + "\n").encode() for row in (first, second))
    assert len(windows_records(raw, "Security")[0]) == 2
    assert windows_records(raw, "System") == ({}, 2)
