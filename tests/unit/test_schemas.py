from datetime import timedelta
import json

import pytest
from pydantic import ValidationError

from sentinel.schemas import EventRecord, Finding, LinuxEventRecord, WindowsEventRecord


def test_event_normalizes_time_preserves_evidence_and_round_trips(event_data):
    event = EventRecord.model_validate(event_data)
    assert event.timestamp_utc.utcoffset() == timedelta(0)
    assert event.timestamp_utc.hour == 15
    assert event.original_timestamp == event_data["original_timestamp"]
    assert event.message == event_data["message"]
    assert event.raw_record == event_data["raw_record"]
    assert EventRecord.model_validate_json(event.model_dump_json()) == event


def test_missing_observed_facts_remain_unknown():
    event = EventRecord(
        event_id="synthetic-1", platform="linux", source="auth.log", upload_id="upload-1"
    )
    assert event.timestamp_utc is None
    assert event.host is None
    assert event.actor is None
    assert event.event_type is None
    assert event.raw_record is None
    assert event.attributes == {}


@pytest.mark.parametrize("field", ["event_id", "platform", "source", "upload_id"])
def test_required_event_identity(event_data, field):
    del event_data[field]
    with pytest.raises(ValidationError):
        EventRecord.model_validate(event_data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "   "),
        ("platform", "macos"),
        ("timestamp_utc", "2026-11-02T09:00:00"),
        ("timestamp_utc", "not-a-date"),
        ("timestamp_utc", 1793631600),
        ("timestamp_utc", "1793631600"),
        ("timestamp_utc", True),
        ("source_ip", "999.0.0.1"),
        ("source_ip", 123),
        ("source_sha256", "not-a-hash"),
        ("record_index", 0),
        ("record_index", True),
        ("attributes", {"invalid": object()}),
        ("typo_field", "reject"),
    ],
)
def test_malformed_event_is_rejected(event_data, field, value):
    event_data[field] = value
    with pytest.raises(ValidationError):
        EventRecord.model_validate(event_data)


def test_platform_specific_contracts_and_ipv6(event_data):
    windows = dict(event_data, platform="windows", windows_event_id=4625, channel="Security")
    assert WindowsEventRecord.model_validate(windows).windows_event_id == 4625
    linux = LinuxEventRecord.model_validate(
        dict(event_data, service="sshd", process_id=42, source_ip="2001:db8::20")
    )
    assert linux.service == "sshd"
    assert str(linux.source_ip) == "2001:db8::20"
    with pytest.raises(ValidationError):
        LinuxEventRecord.model_validate(windows)
    with pytest.raises(ValidationError):
        WindowsEventRecord.model_validate(event_data)


@pytest.mark.parametrize("code", [-1, 65536, "4625", True])
def test_invalid_windows_event_code(event_data, code):
    with pytest.raises(ValidationError):
        WindowsEventRecord.model_validate(dict(event_data, platform="windows", windows_event_id=code))


@pytest.mark.parametrize("pid", [-1, "42", True])
def test_invalid_linux_process_id(event_data, pid):
    with pytest.raises(ValidationError):
        LinuxEventRecord.model_validate(dict(event_data, process_id=pid))


def test_mutable_event_defaults_are_independent(event_data):
    first, second = EventRecord(**event_data), EventRecord(**event_data)
    first.attributes["service"] = "ssh"
    first.parsing_errors.append("synthetic error")
    assert second.attributes == {}
    assert second.parsing_errors == []


def test_finding_round_trip_and_model_provenance(finding_data):
    finding = Finding(**finding_data)
    assert Finding.model_validate_json(finding.model_dump_json()) == finding
    assert finding.confidence is None
    assert finding.model_version is None
    finding_data.update(method="model", model_version="synthetic-contract-only", confidence=0.5)
    assert Finding(**finding_data).model_version == "synthetic-contract-only"


@pytest.mark.parametrize(
    "changes",
    [
        {"triage_priority": -1},
        {"triage_priority": 101},
        {"triage_priority": True},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"evidence_event_ids": []},
        {"evidence_event_ids": [" "]},
        {"activity_class": "confirmed-compromise"},
        {"method": "model"},
        {"model_version": "unrelated-version"},
        {"explanation": ""},
        {"timestamp_utc": "2026-11-02T15:00:00"},
    ],
)
def test_invalid_finding_is_rejected(finding_data, changes):
    with pytest.raises(ValidationError):
        Finding.model_validate(finding_data | changes)


def test_finding_requires_evidence(finding_data):
    del finding_data["evidence_event_ids"]
    with pytest.raises(ValidationError):
        Finding(**finding_data)


def test_contract_json_schema_is_exportable():
    for contract in (EventRecord, WindowsEventRecord, LinuxEventRecord, Finding):
        assert json.loads(json.dumps(contract.model_json_schema()))["type"] == "object"
