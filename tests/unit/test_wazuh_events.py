import json
from pathlib import Path

import pytest

from app import wazuh_events as events
from app.db import EvidenceStore


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "wazuh-alert.synthetic.json"


@pytest.fixture
def raw():
    return events.decode_alert(FIXTURE.read_bytes())


@pytest.fixture
def store(tmp_path):
    result = EvidenceStore(tmp_path)
    result.initialize()
    events.initialize(result)
    return result


def test_nested_wazuh_alert_preserves_evidence_and_converts_timestamp(raw):
    raw["rule"]["description"] = "<img src=x onerror=alert(1)>"
    result = events.normalize_alert("lab-manager", raw)
    assert result["timestamp"] == "2026-11-11T12:00:00.125000+00:00"
    assert result["source_event_id"] == "synthetic-wazuh-001"
    assert result["manager_id"] == "lab-manager"
    assert result["agent_id"] == "003" and result["agent_name"] == "lab-linux-01"
    assert result["agent_ip"] == "192.0.2.33"
    assert result["rule_id"] == "100001" and result["rule_level"] == 10
    assert result["rule_groups"] == ["authentication_failed", "synthetic_lab"]
    assert result["message"] == raw["rule"]["description"]
    assert result["raw_event"] == raw


def test_optional_fields_and_content_identity():
    raw = {"timestamp": "2026-11-11T12:00:00Z", "rule": {"id": 100000, "level": 16}}
    alert = events.normalize_alert("lab-manager", raw)
    assert alert["source_event_id"] is None
    assert alert["agent_id"] is None and alert["agent_name"] is None and alert["agent_ip"] is None
    assert alert["rule_id"] == "100000" and alert["rule_groups"] == []
    reordered = events.decode_alert(json.dumps(dict(reversed(list(raw.items())))).encode())
    assert events.normalize_alert("lab-manager", reordered)["id"] == alert["id"]
    assert events.normalize_alert("other-manager", raw)["id"] != alert["id"]


@pytest.mark.parametrize("body", [
    b"[]", b'{"id":', b'{"id":"first","id":"second"}', b'{"rule":{"level":1,"level":2}}',
    b'{"number":NaN}', b'{"number":1e999}', b'{"data":"\xff"}',
])
def test_decode_rejects_ambiguous_or_malformed_json(body):
    with pytest.raises(events.EventValidationError):
        events.decode_alert(body)


@pytest.mark.parametrize("change", [
    {"timestamp": "2026-11-11T12:00:00"}, {"timestamp": "2026-11-11T12:00:00+0099"},
    {"rule": {"id": "100001", "level": True}}, {"rule": {"id": "100001", "level": 17}},
    {"rule": {"id": "100001", "level": 10, "groups": "synthetic"}}, {"agent": []},
])
def test_normalize_rejects_malformed_required_fields(raw, change):
    with pytest.raises(events.EventValidationError):
        events.normalize_alert("lab-manager", raw | change)


def test_limits_apply_to_wire_and_normalized_objects(raw):
    with pytest.raises(events.EventTooLarge):
        events.decode_alert(b" " * (events.MAX_ALERT_BYTES + 1))
    with pytest.raises(events.EventTooLarge):
        events.normalize_alert("lab-manager", raw | {"full_log": "a" * events.MAX_ALERT_BYTES})


def test_persistent_deduplication_conflict_and_manager_scope(store, raw):
    first = events.normalize_alert("lab-manager", raw)
    assert events.save_event(store, first)
    reopened = EvidenceStore(store.root)
    assert not events.save_event(reopened, events.normalize_alert("lab-manager", raw))
    with pytest.raises(events.EventConflict):
        events.save_event(reopened, events.normalize_alert("lab-manager", raw | {"full_log": "changed"}))
    assert events.read_event(reopened, first["id"], manager_id="lab-manager") == first
    assert events.read_event(reopened, first["id"], manager_id="other-manager") is None
    assert events.save_event(reopened, events.normalize_alert("other-manager", raw))
    assert events.page_events(reopened, manager_id="lab-manager")["items"] == [first]


def test_out_of_order_delivery_and_bounded_retention(store, raw, monkeypatch):
    monkeypatch.setattr(events, "MAX_ALERTS", 2)
    transition = events.normalize_transition(
        "lab-manager", agent_id="003", agent_name="lab-linux-01",
        timestamp="2026-11-11T12:00:00Z", previous_status="active", status="disconnected",
    )
    assert events.save_event(store, transition)
    newest, oldest, middle = [
        events.normalize_alert("lab-manager", raw | {"id": str(hour), "timestamp": f"2026-11-11T{hour}:00:00Z"})
        for hour in (14, 12, 13)
    ]
    for event in (newest, oldest):
        assert events.save_event(store, event)
    assert events.page_events(store, event_type=events.ALERT)["items"] == [newest, oldest]
    assert events.save_event(store, middle)
    assert events.page_events(store, event_type=events.ALERT)["items"] == [middle, oldest]
    assert events.read_event(store, newest["id"]) is None
    assert not events.save_event(store, newest)
    assert events.read_event(store, transition["id"]) == transition


def test_transition_and_receipt_share_caller_transaction(store):
    event = events.normalize_transition(
        "lab-manager", agent_id="003", agent_name=None, ip="any",
        timestamp="2026-11-11T12:00:00Z", previous_status="disconnected", status="active",
    )
    assert event["event_type"] == "agent_recovered" and event["agent_ip"] is None
    with pytest.raises(RuntimeError):
        with store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assert events.record_event(connection, event)
            raise RuntimeError("fixture simulates failure committing agent state")
    assert events.read_event(store, event["id"]) is None
    assert events.save_event(store, event)
    assert not events.save_event(store, event)
