"""Auditable queue view over review-preserving activity decisions."""
from datetime import datetime, timedelta

from pydantic import Field

from sentinel.features import WINDOW_SECONDS, canonical_hash
from sentinel.schemas import Contract, Sha256, Text

VERSION = "review-queue-v1"
_HISTORY_ONLY = {"short_history", "causal_context_incomplete"}
_TEAM_RULE = {2: "account_created", 3: "service_change"}


class TeamConfirmation(Contract):
    """An authorized caller's review of exact records in a specific capture."""

    capture_sha256: Sha256
    window_id: Sha256
    evidence_ids: list[Text] = Field(min_length=1)
    reviewer: Text
    reference: Text


def review_id(row):
    return canonical_hash([row["source"], row["platform"], row.get("host"), row.get("start_utc"), row.get("window_id")])


def _confirmed(row, source_hash, confirmation):
    if confirmation is None or confirmation.capture_sha256 != source_hash:
        return False
    post = row["post"]
    rule = _TEAM_RULE.get(post["activity_class"])
    reasons = set(row["combined"]["reasons"])
    return (rule is not None and post["activity_basis"] == "explicit_current_event"
            and reasons in ({rule}, {rule, "model_flag"})
            and set(row["combined"]["rule_hits"]) == {rule}
            and row["vector"][1] == 0
            and not post["same_ip_evidence_ids"] and not post["rotating_ip_evidence_ids"]
            and sorted(confirmation.evidence_ids) == sorted(post["activity_evidence_ids"]))


def _window_entry(row):
    post = row["post"]
    evidence = row.get("event_ids", row.get("evidence_preview_ids", []))
    decision = row["combined"]
    verifier_evidence = decision.get("evidence_ids", decision.get("evidence_preview_ids", []))
    return dict(review_id=review_id(row), window_id=row.get("window_id"), start_utc=row.get("start_utc"),
                gap_end_utc=row.get("gap_end_utc"), cnn_class=row["prediction"],
                activity_class=post["activity_class"], activity_basis=post["activity_basis"],
                reasons=decision["reasons"], priority=post["review_priority"],
                activity_evidence_ids=post["activity_evidence_ids"],
                evidence_ids=list(dict.fromkeys([*evidence, *verifier_evidence, *post["activity_evidence_ids"],
                    *post["same_ip_evidence_ids"], *post["rotating_ip_evidence_ids"]])))


def build_review_queue(rows, source_hashes, confirmations=()):
    """Group adjacent history notices and retain explicitly confirmed work in the audit lane.

    Only supply confirmations from the trusted operator channel. Raw logs,
    model outputs and display names provide evidence, never authorization.
    """
    approved = {}
    for confirmation in confirmations:
        if confirmation.window_id in approved:
            raise ValueError("Duplicate team confirmation for one window")
        approved[confirmation.window_id] = confirmation

    entries, used, seen = [], set(), set()
    previous_notice = None
    ordered = sorted(rows, key=lambda row: (
        row["source"], row["platform"], row.get("host") or "", row.get("start_utc") or ""
    ))
    for row in ordered:
        if not row["post"]["requires_review"]:
            continue
        window = _window_entry(row)
        if window["review_id"] in seen:
            raise ValueError("Duplicate reviewed interval")
        seen.add(window["review_id"])
        identity = (row["source"], row["platform"], row.get("host"))
        confirmation = approved.get(row.get("window_id"))
        kind = "finding"
        if _confirmed(row, source_hashes.get(row["source"]), confirmation):
            kind = "confirmed_team_activity"
            used.add(confirmation.window_id)
        elif (row.get("window_id") and row.get("start_utc") and set(window["reasons"]) == _HISTORY_ONLY
                and not row["combined"]["rule_hits"] and not row["post"]["same_ip_evidence_ids"]
                and not row["post"]["rotating_ip_evidence_ids"]):
            kind = "coverage_notice"

        if kind == "coverage_notice":
            now = datetime.fromisoformat(window["start_utc"])
            if (previous_notice is not None and previous_notice[0] == identity
                    and now - previous_notice[1] == timedelta(seconds=WINDOW_SECONDS)):
                entries[-1]["windows"].append(window)
                previous_notice = (identity, now)
                continue
            previous_notice = (identity, now)
        else:
            previous_notice = None
        item = dict(kind=kind, source=identity[0], platform=identity[1], host=identity[2],
                    capture_sha256=source_hashes.get(identity[0]), windows=[window])
        if kind == "confirmed_team_activity":
            item["confirmation"] = confirmation.model_dump(mode="json")
        entries.append(item)

    for item in entries:
        item["item_id"] = canonical_hash([VERSION, item["kind"], *[window["review_id"] for window in item["windows"]]])
    return dict(version=VERSION, reviewed_windows=len(seen),
                active_items=sum(item["kind"] != "confirmed_team_activity" for item in entries),
                coverage_notices=sum(item["kind"] == "coverage_notice" for item in entries),
                confirmed_items=len(used), unmatched_confirmations=sorted(approved.keys() - used), items=entries)
