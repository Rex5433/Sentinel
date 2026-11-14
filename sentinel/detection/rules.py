"""Initial lab baseline: authentication bursts, never automatic malicious labels."""

from collections import defaultdict
from bisect import bisect_left

from sentinel.features import Extraction, canonical_hash
from sentinel.schemas import Finding

BASELINE_VERSION = "auth-burst-v1"
FAILURE_THRESHOLD = 5


def baseline_policy() -> dict:
    return {"version": BASELINE_VERSION, "failure_threshold": FAILURE_THRESHOLD,
            "scope": "single host/platform/import, one fixed feature window",
            "burst_priority": 60, "matched_success_priority": 75,
            "matched_success": "at least five strictly earlier failures for the same non-null actor and source IP",
            "meaning": "experimental review priority, not compromise probability or ground truth",
            "no_match": "no supported pattern, never a normal/safe classification"}


def policy_hash() -> str:
    return canonical_hash(baseline_policy())


def baseline_findings(extraction: Extraction) -> list[dict]:
    results = []
    for window in extraction.windows:
        members = extraction.members[window.window_id]
        failures = [event for event in members if event.event_type == "auth_failure"]
        if len(failures) < FAILURE_THRESHOLD:
            continue
        by_pair = defaultdict(list)
        for event in failures:
            if event.actor is not None and event.source_ip is not None:
                by_pair[(event.actor, str(event.source_ip))].append(event.timestamp_utc)
        matched = None
        for event in members:
            if event.event_type != "auth_success" or event.actor is None or event.source_ip is None:
                continue
            prior = by_pair.get((event.actor, str(event.source_ip)), [])
            if bisect_left(prior, event.timestamp_utc) >= FAILURE_THRESHOLD:
                matched = event
                break
        evidence = [event.event_id for event in failures]
        explanation = (
            f"Observed {len(failures)} authentication failures in one 300-second host window "
            f"(experimental threshold: {FAILURE_THRESHOLD})."
        )
        if matched is not None:
            evidence.append(matched.event_id)
            explanation += " A later success has the same recorded account and source IP as at least five earlier failures."
        finding = Finding(
            finding_id=canonical_hash([policy_hash(), window.window_id]),
            timestamp_utc=max(failures[-1].timestamp_utc, matched.timestamp_utc) if matched else failures[-1].timestamp_utc,
            activity_class="authentication_burst", triage_priority=75 if matched else 60,
            evidence_event_ids=evidence, explanation=explanation, method="deterministic",
            confidence=None, model_version=None,
            limitations=["Experimental lab baseline; thresholds have not been evaluated on team lab sessions.",
                         "Failed logins can be benign. Matching account/IP does not prove a person or compromise.",
                         "Fixed windows can split bursts at boundaries; no correlation across imports or hosts.",
                         "No model ran. Rule results must not be used as training ground-truth labels."],
        )
        results.append({"finding": finding.model_dump(mode="json"), "window_id": window.window_id,
                        "baseline_version": BASELINE_VERSION, "baseline_policy_sha256": policy_hash(),
                        "feature_version": window.feature_version,
                        "feature_schema_sha256": window.feature_schema_sha256})
    return sorted(results, key=lambda item: (-item["finding"]["triage_priority"], item["finding"]["timestamp_utc"], item["finding"]["finding_id"]))
