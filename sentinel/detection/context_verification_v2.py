"""Experimental causal verification v2; preserves frozen v1 per-window checks.

Offline, stateless per call, current plus four prior consecutive windows in each
platform/host/session. No labels, training, network calls or infrastructure writes.
"""
from datetime import datetime, timedelta, timezone

from sentinel.detection.verification import verify

VERSION = "context-verification-v2"
HISTORY = 5
FAILURES = 5
_ARGUMENTS = frozenset(("vector", "model_class", "probabilities", "coverage", "history_windows",
                        "feature_version", "feature_schema_sha256", "evidence_ids"))
_INPUT_GAPS = frozenset(("invalid_features", "feature_contract", "collection_unknown", "coverage_unknown",
                         "coverage_gap", "evidence_missing", "verification_arguments_invalid"))


def _review(result, code, message, *, alert=False):
    result["requires_review"] = True
    if alert:
        result["disposition"] = "alert"
        result["rule_hits"].append(code)
    elif result["disposition"] == "no_alert_observed":
        result["disposition"] = "manual_review"
    result["reasons"].append(dict(code=code, message=message))


def _base(row):
    raw = row.get("verification") if isinstance(row, dict) else None
    arguments = {key:value for key,value in raw.items() if key in _ARGUMENTS} if isinstance(raw,dict) else {}
    arguments.setdefault("vector",None)
    arguments.setdefault("model_class",None)
    try:
        result = verify(**arguments)
    except (TypeError, ValueError, OverflowError):
        # A malformed numeric input must not prevent preservation of a valid CNN flag.
        result = verify(vector=None, model_class=arguments["model_class"],
                        feature_version=arguments.get("feature_version"),
                        feature_schema_sha256=arguments.get("feature_schema_sha256"))
        _review(result,"verification_arguments_invalid","Malformed verification arguments; input context is unassessed.")
    if not isinstance(raw,dict) or set(raw)-_ARGUMENTS:
        _review(result,"verification_arguments_invalid","Missing or unsupported verification arguments; manual review required.")
    result["base_version"] = result["version"]
    result["version"] = VERSION
    return result,arguments


def verify_series(rows):
    """Verify ordered source rows; input dictionaries are never changed.

    Identity/time failures clear correlation state. Missing/invalid feature rows
    are never converted into zero-event observations. The caller must supply the
    causal prefix; a claimed history_windows=4 cannot prove missing input history.
    """
    states,output = {},[]
    for row in rows:
        result,arguments = _base(row)
        result["temporal_policy"] = dict(version=VERSION, maximum_windows=HISTORY, failure_threshold=FAILURES)
        try:
            identity = tuple(row[key] for key in ("platform","host","session_id"))
            if identity[0] not in ("windows","linux") or any(not isinstance(value,str) or not value.strip() for value in identity):
                raise ValueError("Invalid identity")
            original = datetime.fromisoformat(row["start_utc"]) if isinstance(row["start_utc"],str) else None
            if original is None or original.utcoffset() is None:
                raise ValueError("Time must have an explicit timezone")
            start = original.astimezone(timezone.utc)
            if start.second or start.microsecond or start.minute%5:
                raise ValueError("Time must be explicit and UTC bucket-aligned")
            state = states.get(identity,dict(observations=[],failures=[],last=None))
            if state["last"] is not None and start <= state["last"]:
                raise ValueError("Out-of-order or repeated window")
            if state["last"] is not None and start-state["last"] != timedelta(seconds=300):
                state = dict(observations=[],failures=[],last=None)
            codes = {r["code"] for r in result["reasons"]}
            vector = arguments["vector"]
            usable = not {"invalid_features","feature_contract"}.intersection(codes)
            if usable and tuple(vector[-2:]) != ((1,0) if identity[0]=="windows" else (0,1)):
                raise ValueError("Platform and feature bits disagree")
            gap = bool(codes.intersection(_INPUT_GAPS))
            observation = dict(time=start,gap=gap,evidence=list(result["evidence_ids"]))
            state["observations"] = (state["observations"]+[observation])[-HISTORY:]
            if usable:
                state["failures"] = (state["failures"]+[dict(count=vector[1],evidence=list(result["evidence_ids"]))])[-HISTORY:]
            else:
                state["failures"] = []
            prior = len(state["failures"])-1 if usable else 0
            result["derived_prior_windows"] = prior
            if prior < HISTORY-1:
                _review(result,"causal_context_incomplete","Fewer than four contiguous usable preceding feature windows in this source/host; context remains unassessed.")
            previous_gaps = [w for w in state["observations"][:-1] if w["gap"]]
            if previous_gaps:
                _review(result,"causal_input_unassessed","Prior parser/schema/evidence gaps remain inside the CNN's current five-window input.")
                result["evidence_ids"] = list(dict.fromkeys(result["evidence_ids"]+[e for w in previous_gaps for e in w["evidence"]]))
                result["unassessed_prior_starts"] = [w["time"].isoformat() for w in previous_gaps]
            failures = state["failures"]
            count = sum(w["count"] for w in failures)
            if count >= FAILURES and sum(w["count"]>0 for w in failures) >= 2:
                _review(result,"five_window_authentication",f"{int(count)} observed failures across {len(failures)} consecutive windows; may be benign retries.",alert=True)
                result["evidence_ids"] = list(dict.fromkeys(result["evidence_ids"]+[e for w in failures for e in w["evidence"]]))
            state["last"] = start
            states[identity] = state
        except (KeyError,TypeError,ValueError,OverflowError):
            # Identity/time is not trustworthy enough to attribute this boundary.
            # Clear state, rather than mixing counts or silently keeping stale history.
            states.clear()
            result["derived_prior_windows"] = 0
            _review(result,"correlation_context_invalid","Invalid identity, time, order or platform; correlation reset for manual review.")
        output.append(result)
    return output
