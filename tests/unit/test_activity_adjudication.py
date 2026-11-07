"""Check post-CNN corrections, review safeguards and actor correlation."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.detection.activity_adjudication import adjudicate, rotating_auth_hits
from sentinel.detection.verification import COVERAGE


def member(kind, identifier="record", ip="192.0.2.1", actor="operator"):
    return SimpleNamespace(event_type=kind, event_id=identifier, source_ip=ip, actor=actor)


def decision(*reasons, hits=(), prior=4):
    return dict(reasons=reasons, rule_hits=hits, derived_prior_windows=prior, requires_review=bool(reasons))


@pytest.mark.parametrize("prediction", (0, 1, 3))
def test_current_account_event_overrides_wrong_pivot_prediction(prediction):
    result = adjudicate(prediction, object(), [member("account_created")], decision("account_created", hits=("account_created",)))
    assert result["cnn_class"] == prediction and result["activity_class"] == 2
    assert result["activity_evidence_ids"] == ["record"] and result["requires_review"]


def test_only_uncorroborated_clean_cnn_alert_is_lower_priority_and_all_reviews_stay_visible():
    members = [member("auth_success")]
    clean = adjudicate(3, object(), members, decision("model_flag"))
    assert clean["activity_class"] == 0 and clean["review_priority"] == "lower"
    assert clean["requires_review"]
    assert adjudicate(3, object(), members, decision("model_flag", "uncertain_model"))["review_priority"] == "standard"
    assert adjudicate(3, object(), members, decision("model_flag", "coverage_gap"))["activity_class"] is None
    assert adjudicate(3, object(), members, decision("model_flag", prior=3))["requires_review"]


def test_mixed_activity_stays_unassessed_and_reviewed():
    members = [member("auth_failure", "failure"), member("account_created", "account")]
    result = adjudicate(1, object(), members, decision("account_created", "five_window_authentication", hits=("five_window_authentication",)))
    assert result["activity_class"] is None and result["activity_basis"] == "mixed_observed_activity"
    assert result["requires_review"] and set(result["activity_evidence_ids"]) == {"failure", "account"}


def test_weak_authentication_stays_a_cnn_decision_and_rotating_review_is_separate():
    result = adjudicate(0, object(), [member("auth_failure")], decision(), rotating=("a", "b", "c"))
    assert result["activity_class"] == 0 and result["requires_review"]
    assert result["rotating_ip_evidence_ids"] == ["a", "b", "c"]


def timeline(slot, ip, *, host="host-a", source="import-a", complete=True, actor="operator"):
    start = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(minutes=5*slot)
    window = SimpleNamespace(upload_id=source, platform="windows", host=host, start_utc=start, window_id=f"w{slot}")
    coverage = dict.fromkeys(COVERAGE, 0)
    coverage["collection_complete"] = complete
    return window, [member("auth_failure", f"e{slot}", ip, actor)] if ip else [], coverage


def test_rotating_ip_hits_after_three_distinct_windows_and_preserves_references():
    rows = [timeline(i, f"192.0.2.{i+1}" if i in (0, 2, 4) else None) for i in range(5)]
    assert not rotating_auth_hits(rows[:-1])
    assert rotating_auth_hits(rows) == {"w4":["e0", "e2", "e4"]}


@pytest.mark.parametrize("boundary", ("host", "source", "actor", "complete", "gap", "same_ip", "expiry"))
def test_rotation_does_not_pool_unrelated_or_incomplete_failures(boundary):
    rows = [timeline(0, "192.0.2.1"), timeline(1, "192.0.2.2")]
    if boundary == "gap":
        rows.append(timeline(3, "192.0.2.3"))
    elif boundary == "same_ip":
        rows.append(timeline(2, "192.0.2.2"))
    elif boundary == "expiry":
        rows.extend(timeline(i, None) for i in range(2, 12))
        rows.append(timeline(12, "192.0.2.3"))
    else:
        rows.append(timeline(2, "192.0.2.3", **{boundary:False if boundary == "complete" else "other"}))
    assert not rotating_auth_hits(rows)
