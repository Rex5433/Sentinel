from datetime import datetime, timedelta, timezone

import pytest

from sentinel.features import extract_features
from sentinel.detection.rules import baseline_findings
from sentinel.schemas import EventRecord, Finding

BASE = datetime(2026, 11, 3, 15, tzinfo=timezone.utc)


def record(index, **changes):
    return EventRecord.model_validate({"event_id": f"event-{index}", "upload_id": "synthetic-import",
        "source": "synthetic", "platform": "linux", "host": "synthetic-host",
        "event_type": "auth_failure", "timestamp_utc": BASE + timedelta(seconds=index),
        "actor": "demo-user", "source_ip": "192.0.2.20", **changes})


def test_threshold_finding_has_real_evidence_and_explicit_limits():
    events = [record(i) for i in range(5)]
    found = baseline_findings(extract_features(events))
    finding = Finding.model_validate(found[0]["finding"])
    assert finding.triage_priority == 60 and finding.activity_class == "authentication_burst"
    assert set(finding.evidence_event_ids) == {e.event_id for e in events}
    assert finding.method == "deterministic" and finding.model_version is None and finding.confidence is None
    assert any("ground-truth" in text for text in finding.limitations)


def test_matched_later_success_increases_priority_without_claiming_compromise():
    events = [record(i) for i in range(5)] + [record(10, event_type="auth_success")]
    finding = baseline_findings(extract_features(events))[0]["finding"]
    assert finding["triage_priority"] == 75 and finding["timestamp_utc"] == "2026-11-03T15:00:10Z"
    assert set(finding["evidence_event_ids"]) == {e.event_id for e in events}
    assert "same recorded account and source IP" in finding["explanation"]


@pytest.mark.parametrize("changes", [
    {"actor": "different-user"}, {"source_ip": "192.0.2.21"},
    {"actor": None}, {"source_ip": None},
    {"timestamp_utc": BASE - timedelta(seconds=1)},
    {"timestamp_utc": BASE + timedelta(seconds=4)},
])
def test_success_does_not_link_without_matching_identity_and_strict_time(changes):
    events = [record(i) for i in range(5)] + [record(10, event_type="auth_success", **changes)]
    found = baseline_findings(extract_features(events))
    assert found[0]["finding"]["triage_priority"] == 60
    assert len(found[0]["finding"]["evidence_event_ids"]) == 5


def test_fixed_windows_and_import_boundaries_can_split_a_burst():
    events = [record(i) for i in range(3)] + [record(i + 300) for i in range(3)]
    assert baseline_findings(extract_features(events)) == []
    events = [record(i) for i in range(3)] + [record(i + 3, upload_id="separate-import") for i in range(3)]
    assert baseline_findings(extract_features(events)) == []


def test_subthreshold_or_success_only_yields_no_baseline_pattern_not_safe():
    assert baseline_findings(extract_features([record(i) for i in range(4)])) == []
    assert baseline_findings(extract_features([record(i, event_type="auth_success") for i in range(6)])) == []


def test_duplicates_cannot_inflate_a_single_failure_into_a_burst():
    event = record(0)
    assert baseline_findings(extract_features([event] * 6)) == []
