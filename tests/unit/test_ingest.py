"""Parser behavior on original project fixtures and malformed variants."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest

from sentinel.ingest import ParseInputError, parse_linux, parse_windows
from sentinel.ingest import common

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def windows(data, fmt="json", upload_id="synthetic-upload"):
    return parse_windows(data, file_format=fmt, source_file="synthetic-export", upload_id=upload_id)


def linux(data, fmt="text"):
    return parse_linux(data, file_format=fmt, source_file="synthetic-export", upload_id="synthetic-upload")


def test_windows_json_activity_accounts_and_evidence():
    data = (FIXTURES / "windows_events.json").read_bytes()
    result = windows(data)
    assert not result.rejected
    assert [e.event_type for e in result.events] == [
        "auth_failure", "auth_success", "account_created", "service_installed", "service_state_change"
    ]
    failed, success, account, service, state = result.events
    assert failed.timestamp_utc == datetime(2026, 11, 3, 15, tzinfo=timezone.utc)
    assert failed.original_timestamp == "2026-11-03T09:00:00-06:00"
    assert failed.actor == "demo-user"
    assert str(success.source_ip) == "2001:db8::20"
    assert account.actor == "demo-admin" and account.target == "demo-new-user"
    assert service.target == "demo-service"
    assert service.host is None
    assert state.raw_record["EventData"]["param2"] == "running"
    assert failed.message == "  Synthetic unsuccessful login example.  "
    assert failed.raw_record == json.loads(data)[0]
    assert failed.attributes["windows_record_id"] == 101
    assert failed.source_sha256 == sha256(data).hexdigest()
    assert failed.record_index == 1 and state.record_index == 5
    assert all(not e.parsing_errors for e in result.events)
    assert json.loads(json.dumps(result.to_dict()))["accepted_count"] == 5


def test_windows_csv_bom_multiline_and_quoted_fields():
    text = (FIXTURES / "windows_events.csv").read_text()
    result = windows(text.encode("utf-8-sig"), "csv")
    assert len(result.events) == 2 and not result.rejected
    assert result.events[0].message == "Synthetic example, with a comma"
    assert result.events[1].message == "Synthetic multiline\nmessage"
    assert result.events[1].record_index == 2
    assert result.events[0].raw_record["Id"] == "4625"


def test_utf16_and_original_byte_hash():
    data = '{"EventID":4625,"Message":"Synthetic"}'.encode("utf-16")
    event = windows(data).events[0]
    assert event.windows_event_id == 4625
    assert event.source_sha256 == sha256(data).hexdigest()


def test_stable_ids_respect_format_content_and_record_position():
    data = b'[{"Id":4625},{"Id":4625}]'
    first, second = windows(data), windows(data, upload_id="another-upload")
    assert [e.event_id for e in first.events] == [e.event_id for e in second.events]
    assert first.events[0].event_id != first.events[1].event_id
    assert first.events[0].event_id != windows(data + b" ").events[0].event_id
    assert second.events[0].upload_id == "another-upload"


def test_windows_malformed_rows_and_unknown_facts_are_retained():
    data = json.dumps([
        42,
        {},
        {"Id": True, "TimeCreated": "2026-11-03T09:00:00", "MachineName": None,
         "IpAddress": "999.0.0.1", "EventData": [], "Message": ["not", "text"]},
        {"Id": 1234, "Message": "Synthetic unknown event"},
    ]).encode()
    result = windows(data)
    assert [r.record_index for r in result.rejected] == [1, 2]
    assert result.rejected[0].raw_record == 42
    event = result.events[0]
    assert event.timestamp_utc is None and event.original_timestamp == "2026-11-03T09:00:00"
    assert event.host is None and event.source_ip is None and event.message is None
    assert event.windows_event_id is None and event.raw_record["Id"] is True
    assert any("EventData" in e for e in event.parsing_errors)
    assert result.events[1].event_type is None


@pytest.mark.parametrize("changes", [
    {"ProviderName": "Other-Provider"}, {"LogName": "Other-Channel"}, {"ProviderName": None}
])
def test_windows_event_codes_require_provider_and_channel(changes):
    record = {"Id": 4625, "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing"}
    assert windows(json.dumps(record | changes).encode()).events[0].event_type is None


def test_conflicting_windows_aliases_and_details_stay_unknown():
    record = {"Id": 4624, "EventID": 4625, "Computer": "one", "MachineName": "two",
              "TargetUserName": "one", "EventData": {"TargetUserName": "two"}}
    event = windows(json.dumps(record).encode()).events[0]
    assert event.windows_event_id is None and event.host is None and event.target is None
    assert sum("conflicting" in error for error in event.parsing_errors) == 3


def test_bad_width_csv_row_is_rejected_and_next_record_survives():
    result = windows(b'Id,Message\n4625,too,many\n4624,Synthetic\n', "csv")
    assert len(result.rejected) == 1 and result.rejected[0].raw_record == ["4625", "too", "many"]
    assert result.events[0].windows_event_id == 4624 and result.events[0].record_index == 2


@pytest.mark.parametrize("data,fmt", [
    (b'{"Id":4625', "json"),
    (b'{"Id":4625,"Id":4624}', "json"),
    (b'{"Id":4625,"value":NaN}', "json"),
    (b'{"Id":4625,"value":1e999}', "json"),
    (b'42', "json"),
    (b'Id,Id\n4624,4625', "csv"),
    (b'Other,Unknown\nfoo,bar', "csv"),
    (b'Id,Message\n4625,"unterminated', "csv"),
])
def test_bad_file_framing_fails_without_a_partial_report(data, fmt):
    with pytest.raises(ParseInputError):
        windows(data, fmt)


def test_linux_text_auth_sudo_session_service_and_raw_lines():
    data = (FIXTURES / "linux_auth.txt").read_bytes()
    result = linux(data)
    assert len(result.events) == 7 and len(result.rejected) == 1
    failed, success, sudo, session, service, legacy, unknown = result.events
    assert failed.timestamp_utc == datetime(2026, 11, 3, 15, tzinfo=timezone.utc)
    assert failed.actor == "demo-user" and failed.process_id == 100
    assert failed.event_type == "auth_failure" and success.event_type == "auth_success"
    assert str(success.source_ip) == "2001:db8::20"
    assert sudo.actor == "demo-user" and sudo.target == "root"
    assert sudo.attributes["command_text"] == "/usr/bin/id"
    assert session.event_type == "session_open" and session.actor == "demo-user"
    assert service.event_type == "service_activity" and service.target is None
    assert legacy.timestamp_utc is None and legacy.original_timestamp == "Nov  3 09:00:05"
    assert "year/timezone" in legacy.parsing_errors[0]
    assert unknown.event_type is None and unknown.message is not None
    assert failed.raw_record == data.decode().splitlines(keepends=True)[0]
    assert result.rejected[0].record_index == 7
    assert unknown.record_index == 8


def test_linux_journal_fields_timestamp_precision_and_binary_message():
    result = linux((FIXTURES / "linux_journal.jsonl").read_bytes(), "journal-json")
    assert len(result.events) == 3 and not result.rejected
    first, service, binary = result.events
    assert first.timestamp_utc == datetime(2026, 11, 3, 15, 0, 0, 123456, tzinfo=timezone.utc)
    assert first.original_timestamp == "1793718000123456"
    assert first.service == "sshd" and first.process_id == 200
    assert not first.parsing_errors
    assert first.raw_record["__CURSOR"] == "synthetic-cursor-only"
    assert service.target == "demo.service"
    assert service.attributes["emitter_systemd_unit"] == "init.scope"
    assert binary.message is None and binary.raw_record["MESSAGE"] == [65, 66]
    assert binary.timestamp_utc is None and binary.parsing_errors


def test_journal_recovers_after_malformed_lines_and_preserves_line_numbers():
    data = b'\nnot-json\n{"MESSAGE":"Synthetic"}\n[]\n{"MESSAGE":"one","MESSAGE":"two"}\n'
    result = linux(data, "journal-json")
    assert [r.record_index for r in result.rejected] == [2, 4, 5]
    assert result.rejected[0].raw_record == "not-json\n"
    assert result.events[0].record_index == 3


@pytest.mark.parametrize("stamp", ["-1", "9" * 20, "not-time", None, ["1", "2"]])
def test_bad_journal_timestamps_do_not_drop_evidence(stamp):
    record = {"__REALTIME_TIMESTAMP": stamp, "MESSAGE": "Synthetic"}
    event = linux(json.dumps(record).encode(), "journal-json").events[0]
    assert event.timestamp_utc is None and event.raw_record == record
    assert event.parsing_errors


def test_journal_missing_fields_and_multiple_values_remain_unknown():
    record = {"MESSAGE": "Synthetic", "SYSLOG_IDENTIFIER": ["sshd", "sudo"], "_PID": True}
    event = linux(json.dumps(record).encode(), "journal-json").events[0]
    assert event.host is None and event.service is None and event.process_id is None


def test_sudo_does_not_extract_user_metadata_from_command_contents():
    data = b'2026-11-03T15:00:00Z host sudo: demo : TTY=pts/0 ; COMMAND=echo hello ; USER=root\n'
    event = linux(data).events[0]
    assert event.event_type is None and event.actor is None and event.target is None


def test_unknown_program_does_not_become_ssh_event_from_quoted_message():
    data = b'2026-11-03T15:00:00Z host demo: Failed password for demo from 192.0.2.1 port 5\n'
    assert linux(data).events[0].event_type is None


def test_unknown_timezone_and_invalid_ip_preserve_original_evidence():
    data = b'2026-11-03T15:00:00 host sshd: Failed password for demo from bad-ip port 5\r\n'
    event = linux(data).events[0]
    assert event.timestamp_utc is None and event.source_ip is None
    assert event.raw_record.endswith("\r\n")
    assert len(event.parsing_errors) == 2


@pytest.mark.parametrize("parse", [windows, linux])
def test_empty_input_returns_empty_report(parse):
    assert parse(b'').to_dict()["accepted_count"] == 0
    assert not parse(b'').rejected


@pytest.mark.parametrize("data", [b'\xff', b'\x00binary', 'not-bytes'])
def test_invalid_encoding_and_binary_input(data):
    with pytest.raises(ParseInputError):
        linux(data)


def test_format_identity_size_and_record_limits(monkeypatch):
    with pytest.raises(ParseInputError):
        windows(b'{}', "evtx")
    with pytest.raises(ParseInputError):
        linux(b'', "pcap")
    with pytest.raises(ParseInputError):
        windows(b'{}', upload_id=" ")
    monkeypatch.setattr(common, "MAX_INPUT_BYTES", 8)
    with pytest.raises(ParseInputError, match="25 MiB"):
        windows(b'{"Id":4625}')
    monkeypatch.setattr(common, "MAX_INPUT_BYTES", 1024)
    monkeypatch.setattr(common, "MAX_RECORDS", 1)
    with pytest.raises(ParseInputError, match="record limit"):
        windows(b'[{"Id":1},{"Id":2}]')


def test_deep_json_is_rejected():
    with pytest.raises(ParseInputError):
        windows(b'{"Id":1,"value":' + b'[' * 70 + b'0' + b']' * 70 + b'}')


def test_fixture_hash_manifest():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for fixture in manifest["files"]:
        assert sha256((FIXTURES / fixture["path"]).read_bytes()).hexdigest() == fixture["sha256"]
