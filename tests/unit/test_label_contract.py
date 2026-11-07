"""Hand-authored schema examples, not a generated training dataset."""
from copy import deepcopy

import pytest
from pydantic import ValidationError

from sentinel.features import FEATURE_VERSION, schema_hash
from training.experiment_data import CLASSES
from training.label_contract import CLASS_ORDER, LABEL_VERSION, WindowAnnotation, conflicting_contexts


def record(activity="account_or_privilege_change"):
    return dict(label_version=LABEL_VERSION, feature_version=FEATURE_VERSION,
                feature_schema_sha256=schema_hash(), window_id="a" * 64, source_sha256="b" * 64,
                causal_window_ids=["a" * 64], origin="team_generated_synthetic",
                scenario_group="schema-test-only", split="review_only",
                observed_categories=[activity], observable_activity=activity, label_status="supported",
                evidence_event_ids=["event-1"], activity_evidence_refs=["scenario:account-created"],
                rationale="Account creation is observed regardless of approval.",
                review_status="reviewed", reviewer="test-reviewer",
                authorization=dict(status="authorized", basis="scenario_manifest",
                                   evidence_refs=["scenario:approved-provisioning"], rationale="Declared synthetic approval."))


def test_category_order_and_feature_contract_remain_original():
    assert CLASS_ORDER == CLASSES
    assert len(CLASS_ORDER) == 4


@pytest.mark.parametrize("activity", CLASS_ORDER)
def test_authorization_changes_do_not_change_training_target(activity):
    approved = record(activity)
    unapproved = deepcopy(approved)
    unapproved["authorization"].update(status="simulated_unapproved", evidence_refs=["scenario:unapproved"])
    assert WindowAnnotation(**approved).training_target() == WindowAnnotation(**unapproved).training_target()


def test_normal_observations_can_have_unapproved_security_context():
    data = record("normal_or_unremarkable")
    data["authorization"].update(status="simulated_unapproved", evidence_refs=["scenario:stolen-valid-credential"])
    assert WindowAnnotation(**data).training_target() == 0


@pytest.mark.parametrize("status", ["mixed_activity", "insufficient_evidence", "feature_unobservable"])
def test_ambiguous_labels_are_masked_not_mapped_to_normal(status):
    data = record()
    data.update(label_status=status, observable_activity=None,
                observed_categories=["authentication_burst", "account_or_privilege_change"] if status == "mixed_activity" else [])
    assert WindowAnnotation(**data).training_target() is None
    data["observable_activity"] = "normal_or_unremarkable"
    with pytest.raises(ValidationError):
        WindowAnnotation(**data)


def test_pending_review_has_no_training_target():
    data = record()
    data.update(review_status="pending", reviewer=None)
    assert WindowAnnotation(**data).training_target() is None


@pytest.mark.parametrize("change", [
    {"label_version": "legacy"}, {"feature_schema_sha256": "0" * 64},
    {"observable_activity": "network_activity_anomaly"}, {"observable_activity": None},
    {"observed_categories": ["normal_or_unremarkable", "account_or_privilege_change"]},
    {"observed_categories": []}, {"causal_window_ids": ["c" * 64]},
    {"causal_window_ids": ["a" * 64, "a" * 64]}, {"reviewer": None},
    {"evidence_event_ids": []}, {"activity_evidence_refs": []},
    {"label_status": "mixed_activity", "observable_activity": None},
    {"authorization": {"status": "confirmed_unapproved", "basis": "scenario_manifest", "evidence_refs": ["scenario"], "rationale": "Not field evidence."}},
    {"authorization": {"status": "authorized", "basis": "unavailable", "evidence_refs": [], "rationale": "Missing."}},
])
def test_invalid_claims_and_contract_drift_are_rejected(change):
    with pytest.raises(ValidationError):
        WindowAnnotation(**(record() | change))


def test_unknown_authorization_does_not_prevent_supported_activity_review():
    data = record()
    data["authorization"] = dict(status="unknown", basis="unavailable", evidence_refs=[], rationale="No approval evidence.")
    assert WindowAnnotation(**data).training_target() == 2


def test_synthetic_context_cannot_be_promoted_to_confirmed_field_incident():
    data = record()
    data["authorization"] = dict(status="confirmed_unapproved", basis="human_review", reviewer="test-reviewer",
                                 evidence_refs=["report"], rationale="Invalid claim for synthetic origin.")
    with pytest.raises(ValidationError):
        WindowAnnotation(**data)
    data["origin"] = "team_collected"
    assert WindowAnnotation(**data).training_target() == 2


def test_same_causal_inputs_with_conflicting_targets_are_quarantined():
    one = WindowAnnotation(**record())
    two_data = record("process_or_service_anomaly")
    two_data.update(window_id="c" * 64, causal_window_ids=["c" * 64])
    two = WindowAnnotation(**two_data)
    vector = [[0.0] * 18]  # Shape-only collision probe, not real telemetry/features.
    assert conflicting_contexts([(one, vector), (two, vector)]) == [["a" * 64, "c" * 64]]
    assert conflicting_contexts([(one, vector), (two, [[0] * 18])]) == [["a" * 64, "c" * 64]]
    assert conflicting_contexts([(one, vector), (one, vector)]) == []
    changed_history = [[0.0] * 17 + [1.0]]
    assert conflicting_contexts([(one, vector), (two, changed_history)]) == []


@pytest.mark.parametrize("vectors", [[], [[0.0] * 17], [[float("nan")] * 18], [[float("inf")] * 18], [[True] * 18], [["0"] * 18]])
def test_collision_check_rejects_malformed_context(vectors):
    with pytest.raises(ValueError):
        conflicting_contexts([(WindowAnnotation(**record()), vectors)])
