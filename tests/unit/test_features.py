from datetime import datetime, timedelta, timezone
import math

import pytest

import sentinel.features as features
from sentinel.features import FEATURE_ORDER, extract_features, schema_hash
from sentinel.schemas import EventRecord

BASE = datetime(2026, 11, 3, 15, tzinfo=timezone.utc)


def event(index=0, **changes):
    return EventRecord.model_validate({
        "event_id": f"synthetic-{index}", "upload_id": "synthetic-upload", "platform": "windows",
        "source": "Security", "source_sha256": "a" * 64, "host": "synthetic-host",
        "timestamp_utc": BASE + timedelta(seconds=index), "event_type": "auth_failure",
        "actor": "demo-user", "source_ip": "192.0.2.20", "target": "sshd", **changes,
    })


def test_golden_feature_vector_counts_ratios_and_quality():
    records = [
        event(0, actor="alice", source_ip="192.0.2.1"),
        event(1, actor="bob", source_ip="192.0.2.2"),
        event(2, event_type="auth_success", actor="alice", source_ip="192.0.2.1"),
        event(3, event_type="session_open", actor="alice", source_ip=None, target="login"),
        event(4, event_type="sudo_command", actor="alice", source_ip=None, target="root"),
        event(5, event_type="service_installed", actor=None, source_ip=None, target="demo"),
        event(6, timestamp_utc=BASE + timedelta(seconds=90), event_type=None, actor=None,
              source_ip=None, target=None, parsing_errors=["Synthetic warning only"]),
    ]
    result = extract_features(records)
    window = result.windows[0]
    assert window.vector == [7, 2, 1, 1, 0, 1, 0, 1, 0, 0, 1, 2, 2, 4, 90, 2/7, 1, 0]
    assert window.quality == {"missing_actor_count": 2, "missing_source_ip_count": 4,
                              "warning_event_count": 1, "missing_source_hash_count": 0}
    assert window.event_ids == [e.event_id for e in records]
    assert window.feature_schema_sha256 == schema_hash()
    assert result.coverage["used_records"] == 7 and result.coverage["excluded_records"] == 0
    assert all(math.isfinite(value) for value in window.vector)
    assert len(FEATURE_ORDER) == 18


def test_fixed_window_boundary_is_exclusive_and_does_not_create_empty_buckets():
    records = [event(0), event(1, timestamp_utc=BASE + timedelta(seconds=299, microseconds=999999)),
               event(2, timestamp_utc=BASE + timedelta(seconds=300)), event(3, timestamp_utc=BASE + timedelta(hours=1))]
    windows = extract_features(records).windows
    assert [len(window.event_ids) for window in windows] == [2, 1, 1]
    assert windows[0].start_utc == BASE and windows[0].end_utc == BASE + timedelta(minutes=5)
    assert windows[1].start_utc == windows[0].end_utc


def test_platform_host_and_imports_never_merge():
    records = [event(0), event(1, host="other-host"), event(2, platform="linux"),
               event(3, upload_id="other-import")]
    result = extract_features(records)
    assert len(result.windows) == 4
    assert all(window.feature_values()["event_count"] == 1 for window in result.windows)
    linux = next(window for window in result.windows if window.platform == "linux")
    assert linux.feature_values()["is_linux"] == 1 and linux.feature_values()["is_windows"] == 0


def test_missing_host_time_and_extreme_window_report_exclusions():
    result = extract_features([event(0, host=None), event(1, timestamp_utc=None),
                               event(2, timestamp_utc=datetime.max.replace(tzinfo=timezone.utc))])
    assert result.windows == []
    assert result.coverage["excluded_records"] == 3
    assert result.coverage["exclusion_counts"] == {"missing_host": 1, "missing_timestamp": 1, "window_out_of_range": 1}


def test_pre_epoch_times_floor_to_the_previous_utc_bucket():
    stamp = datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    window = extract_features([event(0, timestamp_utc=stamp)]).windows[0]
    assert window.start_utc == datetime(1969, 12, 31, 23, 55, tzinfo=timezone.utc)
    assert window.end_utc == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_output_is_deterministic_for_reordered_input_and_ties():
    records = [event(1, timestamp_utc=BASE), event(0, timestamp_utc=BASE), event(2)]
    one, two = extract_features(records), extract_features(reversed(records))
    assert [w.model_dump(mode="json") for w in one.windows] == [w.model_dump(mode="json") for w in two.windows]


def test_duplicate_identity_counts_once_but_conflicts_are_refused():
    record = event()
    result = extract_features([record, record])
    assert result.coverage["duplicate_records"] == 1 and result.coverage["used_records"] == 1
    with pytest.raises(ValueError, match="Conflicting duplicate"):
        extract_features([record, record.model_copy(update={"message": "Conflicting evidence"})])


def test_literal_identifiers_messages_and_quality_do_not_enter_vector():
    first = event()
    changed = event(host="different-host", actor="another-account", source_ip="2001:db8::2",
                    source="other-file", message="arbitrary text", parsing_errors=["warning"],
                    timestamp_utc=BASE + timedelta(minutes=5))
    one, two = extract_features([first]).windows[0], extract_features([changed]).windows[0]
    assert one.vector == two.vector
    assert one.window_id != two.window_id
    assert one.quality != two.quality


def test_unknown_actor_ip_and_hash_are_not_invented():
    window = extract_features([event(actor=None, source_ip=None, source_sha256=None)]).windows[0]
    assert window.feature_values()["distinct_actor_count"] == 0
    assert window.feature_values()["distinct_source_ip_count"] == 0
    assert window.source_sha256 is None and window.quality["missing_source_hash_count"] == 1


def test_conflicting_hashes_and_record_cap_are_refused(monkeypatch):
    with pytest.raises(ValueError, match="Conflicting source"):
        extract_features([event(0), event(1, source_sha256="b" * 64)])
    monkeypatch.setattr(features, "MAX_EVENTS", 1)
    with pytest.raises(ValueError, match="record limit"):
        extract_features([event(0), event(1)])


def test_feature_contract_hash_changes_when_window_policy_changes(monkeypatch):
    before = schema_hash()
    monkeypatch.setattr(features, "WINDOW_SECONDS", 600)
    assert schema_hash() != before


def test_empty_input_is_not_a_normal_classification():
    result = extract_features([])
    assert result.windows == [] and result.coverage["used_records"] == 0
