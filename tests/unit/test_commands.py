from base64 import b64encode
import json
from shutil import which
import subprocess

import pytest

from sentinel.commands.catalog import CATEGORIES, REVIEW, catalog_hash, commands, command_ids
from sentinel.ingest.windows_jsonl import parse_windows_jsonl


def test_reference_has_complete_source_review_for_each_platform_and_category():
    entries = commands()
    assert len(entries) == 21 and len({entry["id"] for entry in entries}) == 21
    for platform in ("windows", "linux"):
        assert {entry["category"] for entry in commands(platform=platform)} == set(CATEGORIES)
    for entry in entries:
        assert entry["read_only"] and entry["execution"] == "copy_only"
        assert entry["reference"].startswith("https://")
        assert all(entry[field] for field in ("purpose", "permissions", "assumptions", "limitations", "command"))
        assert entry["review"]["status"] == "source_reviewed_team_review_pending"
    assert len(catalog_hash()) == 64


def test_reference_search_and_results_never_change_static_commands():
    before = catalog_hash()
    entry = commands(platform="linux", category="network", q="TCP")[0]
    assert entry["id"] == "linux-network" and entry["command"] == "ss -tn"
    assert commands(q="no-such-entry") == []
    entry["review"]["status"] = "modified-copy"
    assert REVIEW["status"] == "source_reviewed_team_review_pending"
    assert catalog_hash() == before
    assert command_ids("authentication", "windows") == ["windows-auth"]


def test_collection_commands_keep_fixed_scope_and_document_format():
    windows = commands(category="log_collection", platform="windows")
    linux = commands(category="log_collection", platform="linux")
    assert len(windows) == 5 and len(linux) == 5
    for row in windows:
        assert row["output_format"] == "windows-jsonl"
        limit = 25 if row["id"] == "windows-security-jsonl" else 100
        assert f"-MaxEvents {limit} -ErrorAction Stop" in row["command"]
    journals = [row for row in linux if row["output_format"] == "linux-journal-json"]
    assert len(journals) == 4
    assert all("--lines=100" in row["command"] and "--output=json" in row["command"] for row in journals)
    text = commands(category="log_collection", q="legacy")[0]
    assert text["output_format"] == "linux-text"
    assert "tail -n 100 -- /var/log/auth.log" in text["command"]


@pytest.fixture(params=("powershell", "pwsh"))
def powershell(request):
    executable = which(request.param)
    if not executable:
        pytest.skip(f"{request.param} is not installed")
    return executable


def run_powershell(powershell, script, **kwargs):
    encoded = b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, timeout=30, **kwargs)


def test_all_windows_catalog_commands_parse_on_available_shell(powershell):
    entries = [{"id": entry["id"], "command": entry["command"]} for entry in commands(platform="windows")]
    script = r"""
$ErrorActionPreference = 'Stop'
$entries = ConvertFrom-Json ([Console]::In.ReadToEnd())
foreach ($entry in $entries) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($entry.command, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "$($entry.id): $($errors[0].Message)" }
}
"""
    run_powershell(powershell, script, input=json.dumps(entries).encode("ascii"), check=True)


@pytest.mark.parametrize(("command_id", "channel", "ids", "limit", "sample", "provider"), [
    ("windows-security-jsonl", "Security", "", 25, "4688,1102", None),
    ("windows-logon-jsonl", "Security", "4624,4625,4634,4647,4648", 100, "4625", None),
    ("windows-process-task-jsonl", "Security", "1102,4688,4697,4698,4699,4700,4701,4702", 100, "4688,1102", None),
    ("windows-account-jsonl", "Security", "4672,4720,4722,4725,4726,4728,4729,4732,4733,4738,4740,4756,4757", 100,
     "4720", None),
    ("windows-service-jsonl", "System", "7036,7040,7045", 100, "7045", "Service Control Manager"),
])
def test_windows_collection_projection_round_trips_synthetic_powershell_output(
    powershell, command_id, channel, ids, limit, sample, provider,
):
    provider_value = f"'{provider}'" if provider else "$null"
    expected = (f"$channel='{channel}'\n$ids='{ids}'\n$limit={limit}\n"
                f"$sample=@({sample})\n$provider={provider_value}\n")
    fixture = r"""
function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, $MaxEvents)
    if ($FilterHashtable.LogName -ne $channel -or ($FilterHashtable.Id -join ',') -ne $ids -or
        $MaxEvents -ne $limit -or $FilterHashtable.ProviderName -ne $provider -or
        $FilterHashtable.StartTime -isnot [datetime]) {
        throw 'Unexpected event filter'
    }
    foreach ($id in $sample) {
        $payload = if ($id -eq 1102) {
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>operator</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName></LogFileCleared></UserData></Event>'
        } else {
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="SubjectUserName">operator</Data><Data Name="CommandLine">echo &quot;sample&quot;</Data></EventData></Event>'
        }
        [pscustomobject]@{
            Id = $id; TimeCreated = [datetime]::Parse('2026-11-06T12:00:00Z'); MachineName = 'win-lab'
            LogName = $channel; ProviderName = $(if ($id -eq 1102) {'Microsoft-Windows-Eventlog'}
                elseif ($provider) {$provider} else {'Microsoft-Windows-Security-Auditing'})
            RecordId = $id; Payload = $payload
        } | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Payload } -PassThru
    }
}
"""
    export = next(row for row in commands(category="log_collection") if row["id"] == command_id)
    result = run_powershell(powershell, expected + fixture + export["command"], check=True)
    parsed = parse_windows_jsonl(result.stdout, source_file="synthetic.jsonl", upload_id="a" * 32)
    assert not parsed.rejected
    assert [event.windows_event_id for event in parsed.events] == [int(id_) for id_ in sample.split(",")]
    assert all(event.host == "win-lab" and event.channel == channel for event in parsed.events)
    if sample == "4688,1102":
        process, audit_clear = parsed.events
        assert process.raw_record["EventData"]["CommandLine"] == 'echo "sample"'
        assert audit_clear.actor == "operator" and audit_clear.raw_record["EventData"]["SubjectDomainName"] == "LAB"


@pytest.mark.parametrize("error_id", ("NoMatchingEventsFound", "AccessDenied"))
def test_windows_event_queries_distinguish_empty_results_from_errors(powershell, error_id):
    fixture = """
function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, $MaxEvents)
    Write-Error 'Synthetic event-log status' -ErrorId '%s'
}
""" % error_id
    export = next(row for row in commands(category="log_collection") if row["id"] == "windows-security-jsonl")
    result = run_powershell(powershell, fixture + export["command"])
    if error_id == "NoMatchingEventsFound":
        assert result.returncode == 0 and b"No matching events" in result.stdout + result.stderr
    else:
        assert result.returncode != 0 and b"Synthetic event-log status" in result.stderr
