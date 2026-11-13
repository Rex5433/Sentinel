"""Short failure bursts: boundaries, context and non-attribution regressions."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from app.live_logs import review_buffer
from sentinel.detection.auth_review import auth_findings
from sentinel.detection.rules import baseline_findings
from sentinel.features import extract_features
from sentinel.ingest.windows_jsonl import parse_windows_jsonl

BASE = datetime(2026, 11, 10, 16, 54, 45, tzinfo=timezone.utc)


def row(index, seconds=0, *, user="NOUSER", ip="-", host="lab-win", code=4625, **fields):
    return {"Id": code, "TimeCreated": (BASE + timedelta(seconds=seconds)).isoformat(),
            "MachineName": host, "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing",
            "RecordId": index, "EventData": {"TargetUserName": user, "TargetDomainName": "LAB",
                "IpAddress": ip, "ProcessName": r"C:\Windows\System32\OpenSSH\sshd.exe",
                "Status": "0xc000006d", "SubStatus": "0xc0000064", **fields}}


def raw(rows):
    return b"".join((json.dumps(r) + "\n").encode() for r in rows)


def parsed(rows, upload="auth-test"):
    return parse_windows_jsonl(raw(rows), source_file="synthetic.jsonl", upload_id=upload).events


def review(rows):
    extraction = extract_features(parsed(rows))
    baseline = baseline_findings(extraction)
    return baseline + auth_findings(extraction, baseline)


def test_short_burst_crosses_five_minute_boundary_and_cites_only_failures():
    rows = [row(1, 0), row(2, 16), row(3, 30), row(4, 31, user="blueteam", code=4624)]
    entry, = review(rows)
    assert entry["title"] == "Short burst of failed sign-ins"
    assert entry["severity"] == "warning" and entry["finding"]["confidence"] is None
    assert len(entry["related_window_ids"]) == 2
    assert set(entry["finding"]["evidence_event_ids"]) == {e.event_id for e in parsed(rows)[:3]}
    assert any("Client IP is absent" in limit for limit in entry["finding"]["limitations"])
    assert any("NOUSER" in limit for limit in entry["finding"]["limitations"])


@pytest.mark.parametrize("seconds,expected", [([0], 0), ([0, 1], 0), ([0, 30, 60], 1),
                         ([0, 30, 60.000001], 0), ([0, 120, 240], 0)])
def test_typo_and_rolling_time_boundaries(seconds, expected):
    assert len(review([row(i + 1, value) for i, value in enumerate(seconds)])) == expected


@pytest.mark.parametrize("change", [{"user": "other"}, {"ip": "192.0.2.9"}, {"host": "other-host"}])
def test_unrelated_account_source_or_host_does_not_complete_burst(change):
    assert review([row(1, 0), row(2, 1), row(3, 2, **change)]) == []


def test_domain_and_import_scopes_stay_separate():
    assert review([row(1), row(2), row(3, TargetDomainName="OTHER")]) == []
    events = parsed([row(1), row(2)]) + parsed([row(3)], upload="other-import")
    assert auth_findings(extract_features(events)) == []


def test_known_account_failures_are_still_reviewed_without_linking_later_success():
    rows = [row(i, i, user="blueteam", ip="192.0.2.7") for i in range(3)]
    rows.append(row(9, 4, user="blueteam", ip="192.0.2.7", code=4624))
    found, = review(rows)
    assert len(found["finding"]["evidence_event_ids"]) == 3
    assert found["finding"]["triage_priority"] == 55


def test_five_failure_baseline_is_preserved_without_redundant_short_alert():
    rows = [row(i, i, ip="192.0.2.7") for i in range(5)]
    extraction = extract_features(parsed(rows))
    baseline = baseline_findings(extraction)
    assert len(baseline) == 1
    assert auth_findings(extraction, baseline) == []


def test_duplicate_native_records_and_normalized_events_do_not_inflate_burst():
    assert review([row(1), row(1), row(1)]) == []
    assert review([row(1), row(1), row(2)]) == []
    event, = parsed([row(1)])
    assert auth_findings(extract_features([event] * 4)) == []


def test_native_record_ids_reused_after_clear_are_distinct_when_times_differ():
    assert len(review([row(1, 0), row(1, 10), row(1, 20)])) == 1


def test_windows_identity_case_differences_and_overlapping_windows_do_not_hide_or_duplicate_burst():
    found, = review([row(1, 0, user="BlueTeam"), row(2, 10, user="blueteam"),
                    row(3, 20, user="BLUETEAM", host="LAB-WIN"), row(4, 30, user="blueteam")])
    assert len(found["finding"]["evidence_event_ids"]) == 4


def test_success_only_and_unsupported_provider_do_not_create_failure_alerts():
    assert review([row(i, code=4624) for i in range(5)]) == []
    rows = [row(i) | {"ProviderName": "Not-Windows-Security"} for i in range(3)]
    assert review(rows) == []


def test_unknown_timestamp_or_host_cannot_complete_timed_burst():
    for missing in ({"TimeCreated": None}, {"MachineName": None}):
        assert review([row(1), row(2), row(3) | missing]) == []


def test_unsorted_input_and_separate_episodes_return_exact_nonoverlapping_evidence():
    rows = [row(i + 1, value) for i, value in enumerate([0, 5, 10, 120, 125, 130])]
    found = review(list(reversed(rows)))
    assert len(found) == 2
    assert [len(f["finding"]["evidence_event_ids"]) for f in found] == [3, 3]
    assert not set(found[0]["finding"]["evidence_event_ids"]) & set(found[1]["finding"]["evidence_event_ids"])


def test_import_and_live_windows_use_identical_short_review():
    rows = [row(i + 1, i * 10) for i in range(3)]
    live = review_buffer(raw(rows), "synthetic.jsonl", "auth-test", "windows")
    assert live["finding_count"] == 1 and len(live["flagged"]) == 3
    assert live["findings"][0]["finding"]["finding_id"] == review(rows)[0]["finding"]["finding_id"]


def test_linux_journal_equivalent_is_reviewed_below_five_failures():
    rows = [{"__CURSOR": f"test-{i}", "__REALTIME_TIMESTAMP": str(int((BASE + timedelta(seconds=i * 10)).timestamp() * 1e6)),
             "_HOSTNAME": "lab-linux", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE":
             "Failed password for invalid user sample from 192.0.2.8 port 4444 ssh2"} for i in range(3)]
    live = review_buffer(raw(rows), "synthetic.jsonl", "auth-test", "linux")
    assert live["finding_count"] == 1 and len(live["flagged"]) == 3
