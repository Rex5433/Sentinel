"""Operational review with authored records. Private samples stay outside fixtures."""

import json

from fastapi.testclient import TestClient
import pytest

from app.agent_collectors import collection_plan
from app.event_activity import parse_linux, parse_windows_jsonl
from app.log_context import with_live_context
from app.log_review import event_flags, review_events
from app.main import create_app


HEADERS = {"X-Sentinel-Import": "1"}
SECURITY = "Microsoft-Windows-Security-Auditing"
DEFENDER = "Microsoft-Windows-Windows Defender"


def journal(message, index, service="kernel", host="example-linux"):
    return {"MESSAGE": message, "SYSLOG_IDENTIFIER": service, "_HOSTNAME": host,
            "__REALTIME_TIMESTAMP": str(1794398400000000 + index * 1_000_000), "__CURSOR": f"s=ab;i={index:x}"}


def windows(code, index, fields, *, channel="Security", provider=SECURITY, host="example-windows"):
    return {"Id": code, "RecordId": index + 1, "LogName": channel, "ProviderName": provider, "MachineName": host,
            "TimeCreated": f"2026-11-11T12:00:{index:02d}Z", "EventData": fields}


def parsed(rows, platform):
    data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    kw = {"source_file": "authored.jsonl", "upload_id": "test"}
    result = (parse_linux(data, file_format="journal-json", **kw) if platform == "linux"
              else parse_windows_jsonl(data, **kw))
    assert not result.rejected
    return result.events


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_inbound_port_sweep_needs_distinct_ports_within_scope(platform):
    def probe(index, port, *, outbound=False, source="192.0.2.17", host="target", response=False):
        if platform == "windows":
            return windows(5157, index, {"Direction": "%%14593" if outbound else "%%14592",
                                        "SourceAddress": source, "DestAddress": "192.0.2.19",
                                        "DestPort": port, "Protocol": "6"}, host=host)
        interfaces = "IN= OUT=eth0" if outbound else "IN=eth0 OUT="
        flags = "SYN ACK" if response else "SYN"
        return journal(f"[UFW BLOCK] {interfaces} SRC={source} DST=192.0.2.19 PROTO=TCP SPT=40000 DPT={port} {flags}",
                       index, host=host)

    scan = [probe(i, i + 1) for i in range(12)]
    events = parsed(scan, platform)
    assert all(event.source_ip == "192.0.2.17" for event in events)
    findings = review_events(events, platform).findings
    assert [row["title"] for row in findings] == ["Possible inbound port scan"]
    assert set(event_flags(findings).values()) == {"warning"}
    assert len(event_flags(findings)) == 12
    for rows in (scan[:11], [probe(i, 22) for i in range(12)],
                 [probe(i, i + 1, outbound=True) for i in range(12)],
                 [probe(i, i + 1, source=f"192.0.2.{20 + i}") for i in range(12)],
                 [probe(i, i + 1, host=f"target-{i % 2}") for i in range(12)]):
        assert not review_events(parsed(rows, platform), platform).findings
    if platform == "linux":
        assert not review_events(parsed([probe(i, i + 1, response=True) for i in range(12)], platform), platform).findings
        stale = [probe(i * 7, i + 1) for i in range(12)]
        assert not review_events(parsed(stale, platform), platform).findings


def test_windows_defender_distinguishes_detection_action_and_settings():
    rows = [windows(code, i, fields, channel=DEFENDER + "/Operational", provider=DEFENDER)
            for i, (code, fields) in enumerate(((5007, {}), (1116, {"Severity Name": "Severe"}),
                                                (1117, {"Action Name": "Quarantine"})))]
    rows.append(windows(1116, 3, {"Severity Name": "Severe"}, channel="Application", provider="Unrelated"))
    events = parsed(rows, "windows")
    assert [row.event_type for row in events] == ["defender_settings_changed", "defender_detection", "defender_action", None]
    flags = event_flags(review_events(events, "windows").findings)
    assert flags == {events[1].event_id: "critical", events[2].event_id: "context"}


def test_linux_blue_team_role_coexists_with_flags_and_host_override(tmp_path, sign_in):
    events = parsed([
        journal("blueteam : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-size=1M", 0, "sudo"),
        journal("pam_unix(sudo:session): session opened for user root(uid=0) by blueteam(uid=1004)", 1, "sudo"),
        journal("pam_unix(sudo:session): session closed for user root", 2, "sudo"),
        journal("Disconnected from user blueteam 192.0.2.17 port 50000", 3, "sshd-session"),
        journal("Invalid user blueteam from 192.0.2.17 port 50001", 4, "sshd-auth"),
        journal("Connection closed by 192.0.2.17 port 50001", 5, "sshd-session"),
        journal("blueteam : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/journalctl -n 20", 6, "sudo", "other-host"),
    ], "linux")
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 52301)) as client:
        sign_in(client)
        body = {"platform": "linux", "account": "blueteam", "category": "blue-team"}
        assert client.post("/api/accounts", headers=HEADERS, json=body).status_code == 422
        client.post("/api/accounts", headers=HEADERS, json=body | {"all_hosts": True}).raise_for_status()
        client.post("/api/accounts", headers=HEADERS, json=body | {"host": "other-host", "category": "user"}).raise_for_status()
        findings = review_events(events, "linux").findings
        review = with_live_context(client.app.state.store, {"findings": findings, "events": [e.model_dump(mode="json") for e in events]})
        assert set(review["blue_team_events"]) == {events[i].event_id for i in (0, 1, 3, 4)}
        assert review["blue_team_events"][events[4].event_id]["role"] == "target"
        assert set(review["user_account_events"]) == {events[6].event_id}
        assert event_flags(findings) == {events[0].event_id: "warning"}


def test_network_collectors_use_passive_native_reads():
    from base64 import b64decode
    from shlex import split

    windows_stream = collection_plan("windows", ["network"])[0]
    script = b64decode(windows_stream.command().split()[-1]).decode("utf-16-le")
    assert all(value in script for value in ("Get-WinEvent", "EventID=5152", "EventID=5157"))
    assert all(value not in script for value in ("Remove-Item", "Set-MpPreference", "Clear-EventLog", "auditpol /set"))
    linux_stream = collection_plan("linux", ["network"])[0]
    script = split(linux_stream.command("s=ab;i=2"))[2]
    assert all(value in script for value in ("journalctl", "_TRANSPORT=kernel", "--no-tail", "head -n 65"))
    assert all(value not in script for value in ("sudo", "--vacuum", "nmap", "iptables"))


def test_linux_privileged_editor_and_root_shell_require_separate_review():
    commands = ["/usr/bin/nano /etc/ssh/sshd_config", "/usr/bin/su",
                "/usr/bin/nl -ba /etc/ssh/sshd_config", "/usr/bin/nano /home/operator/notes.txt",
                "/usr/bin/env -i PATH=/usr/bin /usr/bin/bash --noprofile --norc ./check-config"]
    events = parsed([journal(f"blueteam : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={command}", i, "sudo")
                     for i, command in enumerate(commands)], "linux")
    findings = review_events(events, "linux").findings
    assert event_flags(findings) == {events[0].event_id: "warning", events[1].event_id: "context"}
