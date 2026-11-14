"""Check queue grouping and scope-safe team confirmations."""
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.detection.offline_review import review_capture
from sentinel.detection.review_queue import TeamConfirmation, build_review_queue
from training.adjudication_holdout import SEEDS, plan
from training.fresh_scenarios import emit


def row(slot, *, source="capture-a", host="server-a", history=True):
    timestamp = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(minutes=5 * slot)
    return dict(source=source, host=host, platform="windows", start_utc=timestamp.isoformat(),
                window_id=f"{slot + 1:064x}", prediction=0, vector=[1, 0] + [0] * 16,
                event_ids=[f"event-{slot}"], combined=dict(
                    reasons=["short_history", "causal_context_incomplete"] if history else ["uncertain_model"], rule_hits=[]),
                post=dict(requires_review=True, activity_class=None, activity_basis="coverage_unassessed",
                          review_priority="standard", activity_evidence_ids=[], same_ip_evidence_ids=[], rotating_ip_evidence_ids=[]))


def test_grouping_preserves_evidence_and_stops_at_findings_gaps_and_host_boundaries():
    rows = [row(0), row(1), row(2, history=False), row(3), row(5), row(6, host="server-b"), row(7, source="capture-b")]
    rows[2]["combined"]["evidence_ids"] = ["earlier-window-evidence"]
    queue = build_review_queue(rows, {})
    assert queue["reviewed_windows"] == 7 and queue["active_items"] == 6
    assert queue["coverage_notices"] == 5
    assert [w["evidence_ids"] for w in queue["items"][0]["windows"]] == [["event-0"], ["event-1"]]
    assert queue["items"][1]["kind"] == "finding"
    assert queue["items"][1]["windows"][0]["evidence_ids"] == ["event-2", "earlier-window-evidence"]


def account_row():
    change = row(8)
    change["combined"] = dict(reasons=["account_created", "model_flag"], rule_hits=["account_created"])
    change["post"].update(activity_class=2, activity_basis="explicit_current_event", activity_evidence_ids=["account"])
    return change


def confirmation(change, **updates):
    value = dict(capture_sha256="a" * 64, window_id=change["window_id"], evidence_ids=["account"],
                 reviewer="team-operator", reference="change-ticket-12")
    return TeamConfirmation(**(value | updates))


def test_confirmed_work_leaves_active_queue_but_remains_in_audit():
    change = account_row()
    queue = build_review_queue([change], {"capture-a": "a" * 64}, [confirmation(change)])
    assert queue["confirmed_items"] == 1 and queue["active_items"] == 0
    assert queue["reviewed_windows"] == 1 and change["post"]["requires_review"]
    assert queue["items"][0]["confirmation"]["reference"] == "change-ticket-12"


@pytest.mark.parametrize("problem", ("digest", "evidence", "window", "failures", "coverage", "rotation", "uncertain"))
def test_confirmation_fails_closed_on_wrong_scope_or_additional_signals(problem):
    change = account_row()
    update = {}
    if problem == "digest":
        update["capture_sha256"] = "b" * 64
    elif problem == "evidence":
        update["evidence_ids"] = ["other"]
    elif problem == "window":
        update["window_id"] = "f" * 64
    elif problem == "failures":
        change["vector"][1] = 1
    elif problem == "rotation":
        change["post"]["rotating_ip_evidence_ids"] = ["failure"]
    else:
        change["combined"]["reasons"].append("coverage_gap" if problem == "coverage" else "uncertain_model")
    queue = build_review_queue([change], {"capture-a": "a" * 64}, [confirmation(change, **update)])
    assert queue["confirmed_items"] == 0 and queue["active_items"] == 1
    assert len(queue["unmatched_confirmations"]) == 1


@pytest.mark.parametrize("fmt", ("windows-json", "windows-csv", "linux-text", "linux-journal-json"))
def test_raw_capture_confirmation_does_not_carry_over_to_another_import(fmt):
    episode = plan("maintenance_with_quiet_afterward", SEEDS[0], fmt.split("-")[0])
    raw, _ = emit(episode, fmt)

    def score(vectors):
        return [[.99, .01, 0., 0.] for _ in vectors]

    first = review_capture(raw, fmt, "capture-a", "synthetic.raw", score, collection_complete=True)
    change = next(r for r in first["rows"] if r["post"]["activity_class"] == 2)
    approval = confirmation(change, capture_sha256=first["source_sha256"], evidence_ids=change["post"]["activity_evidence_ids"])
    same = review_capture(raw, fmt, "capture-a", "synthetic.raw", score, collection_complete=True, confirmations=[approval])
    replay = review_capture(raw, fmt, "capture-b", "synthetic.raw", score, collection_complete=True, confirmations=[approval])
    unknown = review_capture(raw, fmt, "capture-a", "synthetic.raw", score, confirmations=[approval])
    assert same["queue"]["confirmed_items"] == 1 and same["rows"] == first["rows"]
    assert replay["queue"]["confirmed_items"] == unknown["queue"]["confirmed_items"] == 0
    assert replay["queue"]["unmatched_confirmations"] == [approval.window_id]


def test_capture_gap_stays_visible_and_splits_cnn_inputs():
    episode = plan("capture_gap", SEEDS[0], "windows")
    raw, _ = emit(episode, "windows-json")
    lengths = []

    def score(vectors):
        lengths.append(len(vectors))
        return [[.99, .01, 0., 0.] for _ in vectors]

    result = review_capture(raw, "windows-json", "gap-a", "synthetic.raw", score, collection_complete=True)
    assert lengths == [9, 18]
    gap = next(row for row in result["rows"] if row.get("gap_end_utc"))
    assert gap["post"]["requires_review"] and gap["prediction"] is None
