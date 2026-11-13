"""Offline evidence corrections and review decisions for the frozen CNN."""
from collections import defaultdict
from datetime import timedelta

from sentinel.detection.slow_auth_review import LOOKBACK, MIN_WINDOWS, slow_auth_hits
from sentinel.detection.verification import COVERAGE
from sentinel.features import WINDOW_SECONDS

VERSION = "activity-adjudication-v2"
_INCOMPLETE = {
    "invalid_features", "feature_contract", "collection_unknown", "coverage_unknown",
    "coverage_gap", "evidence_missing", "verification_arguments_invalid", "causal_input_unassessed",
    "causal_context_incomplete", "correlation_context_invalid", "short_history", "history_unknown",
    "model_unavailable", "scores_unavailable", "prediction_inconsistent",
}


def rotating_auth_hits(observations):
    """Find current failures linked by actor across three windows and three IPs."""
    states, hits = {}, {}
    for window, members, coverage in observations:
        identity = (window.upload_id, window.platform, window.host)
        if coverage.get("collection_complete") is not True or any(
            type(coverage.get(key)) is not int or coverage[key] != 0 for key in COVERAGE
        ):
            states.pop(identity, None)
            continue
        now = window.start_utc
        previous, history = states.get(identity, (None, {}))
        if previous is None or now - previous != timedelta(seconds=WINDOW_SECONDS):
            history = {}
        cutoff = now - LOOKBACK
        history = {actor: [entry for entry in past if entry[0] > cutoff]
                   for actor, past in history.items() if past[-1][0] > cutoff}
        current = defaultdict(list)
        for event in members:
            if event.event_type == "auth_failure" and event.actor and event.source_ip is not None:
                current[event.actor].append((event.source_ip, event.event_id))
        evidence = []
        for actor, failures in current.items():
            past = history.setdefault(actor, [])
            past.append((now, failures))
            addresses = {address for _, events in past for address, _ in events}
            if len(past) >= MIN_WINDOWS and len(addresses) >= 3:
                evidence.extend(event_id for _, events in past for _, event_id in events)
        if evidence:
            hits[window.window_id] = list(dict.fromkeys(evidence))
        states[identity] = (now, history)
    return hits


def adjudicate(prediction, window, members, decision, *, same_ip=(), rotating=()):
    """Keep the CNN prediction and adjudicate observable activity independently of review."""
    reasons = set(decision["reasons"])
    complete = (window is not None and decision.get("derived_prior_windows") == 4
                and not reasons.intersection(_INCOMPLETE))
    activity = None
    basis = "coverage_unassessed"
    evidence = []
    failures = []
    if complete:
        accounts = [event.event_id for event in members if event.event_type == "account_created"]
        services = [event.event_id for event in members if event.event_type in (
            "service_installed", "service_state_change", "service_activity")]
        failures = [event.event_id for event in members if event.event_type == "auth_failure"]
        distributed = bool(failures) and "five_window_authentication" in decision["rule_hits"]
        candidates = ([2] if accounts else []) + ([3] if services else [])
        if len(failures) >= 5 or distributed:
            candidates.append(1)
        if len(candidates) > 1:
            basis = "mixed_observed_activity"
            evidence = accounts + services + failures
        elif accounts or services or len(failures) >= 5:
            activity = candidates[0]
            basis = "explicit_current_event"
            evidence = accounts + services + (failures if activity == 1 else [])
        elif distributed and prediction in (2, 3):
            activity = 1
            basis = "corroborated_distributed_authentication"
            evidence = failures
        elif prediction in (2, 3) or (prediction == 1 and not failures):
            activity = 0
            basis = "no_matching_current_event"
        else:
            activity = prediction
            basis = "cnn_activity"

    # Preserve low-score, coverage and corroborated reviews, plus all new correlation leads.
    lower_priority = (activity == 0 and basis == "no_matching_current_event" and not failures
                      and reasons == {"model_flag"} and not same_ip and not rotating)
    requires_review = bool(decision["requires_review"] or same_ip or rotating)
    return dict(version=VERSION, cnn_class=prediction, activity_class=activity, activity_basis=basis,
                activity_evidence_ids=evidence, requires_review=requires_review,
                review_priority="lower" if lower_priority else "standard" if requires_review else None,
                same_ip_evidence_ids=list(same_ip),
                rotating_ip_evidence_ids=list(rotating))


def postprocess(rows, extraction):
    """Apply the layer to parser-backed rows with v2 decisions and no label inputs."""
    windows = {window.window_id: window for window in extraction.windows} if extraction else {}
    by_window = {row["window_id"]: row for row in rows if row.get("window_id")}
    observations = [(window, extraction.members[key], by_window[key]["coverage"])
                    for key, window in windows.items()]
    same_ip = slow_auth_hits(observations)
    rotating = rotating_auth_hits(observations)
    return [adjudicate(row["prediction"], windows.get(row.get("window_id")),
                       extraction.members[row["window_id"]] if row.get("window_id") in windows else (),
                       row["combined"], same_ip=same_ip.get(row.get("window_id"), ()),
                       rotating=rotating.get(row.get("window_id"), ())) for row in rows]
