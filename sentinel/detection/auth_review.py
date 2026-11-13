"""Short rolling authentication review, separate from frozen ML/baseline inputs."""
from collections import defaultdict
from datetime import timedelta

from sentinel.features import canonical_hash
from sentinel.schemas import Finding

VERSION = "short-auth-review-v1"
THRESHOLD = 3
SECONDS = 60


def policy():
    return {"version": VERSION, "failure_threshold": THRESHOLD, "rolling_seconds": SECONDS,
            "boundary": "inclusive at 60 seconds", "priority": 55,
            "scope": "same import, platform, host, source hash, reported account/domain and source IP",
            "missing_identity": "unknown account/IP grouped only within that host/import; attribution unavailable",
            "success_linking": False, "roster_suppression": False,
            "duplicate_alerts": "omit episodes whose failures are all covered by existing baseline findings",
            "meaning": "review repeated authentication failures; not confirmed malicious activity"}


def policy_hash():
    return canonical_hash(policy())


def _episodes(events):
    """Union overlapping qualifying rolling windows; no fixed-time bucket edges."""
    left = 0
    start = end = None
    for right, (event, _) in enumerate(events):
        while event.timestamp_utc - events[left][0].timestamp_utc > timedelta(seconds=SECONDS):
            left += 1
        if right - left + 1 < THRESHOLD:
            continue
        if end is not None and left > end:
            yield events[start:end + 1]
            start = end = None
        start = left if start is None else start
        end = right
    if end is not None:
        yield events[start:end + 1]


def auth_findings(extraction, existing=()):
    covered = {event_id for entry in existing for event_id in entry["finding"]["evidence_event_ids"]}
    groups = defaultdict(list)
    seen_native = set()
    for window in extraction.windows:
        for event in extraction.members[window.window_id]:
            if event.event_type != "auth_failure":
                continue
            raw = event.raw_record if isinstance(event.raw_record, dict) else {}
            host = event.host.casefold() if event.platform == "windows" else event.host
            native = raw.get("RecordId") if event.platform == "windows" else raw.get("__CURSOR")
            if isinstance(native, (str, int)) and str(native):
                native_key = (event.upload_id, event.platform, host, event.source,
                              str(native), event.timestamp_utc)
                if native_key in seen_native:
                    continue
                seen_native.add(native_key)
            account = event.actor.casefold() if event.actor and event.platform == "windows" else event.actor
            domain = None
            if event.platform == "windows" and isinstance(event.raw_record, dict):
                from sentinel.detection.windows_review import field
                domain = field(event.raw_record, "TargetDomainName").casefold() or None
            scope = (event.upload_id, event.platform, host, event.source_sha256,
                     account, domain, str(event.source_ip) if event.source_ip else None)
            groups[scope].append((event, window.window_id))
    results = []
    for scope, candidates in groups.items():
        candidates.sort(key=lambda row: (row[0].timestamp_utc, row[0].event_id))
        for episode in _episodes(candidates):
            evidence = [event.event_id for event, _ in episode]
            if set(evidence) <= covered:
                continue
            first, last = episode[0][0], episode[-1][0]
            account = first.actor or "unavailable"
            address = str(first.source_ip) if first.source_ip else "unavailable"
            explanation = (f"Observed {len(episode)} failed sign-ins in an episode containing at least "
                           f"{THRESHOLD} failures within {SECONDS} seconds on this host. "
                           f"Reported account: {account}; source IP: {address}. "
                           "Check whether these were authorized connection mistakes or unsolicited attempts.")
            limitations = ["Repeated failures can be typing mistakes, automation errors or probing; intent is unconfirmed.",
                           "A known Blue Team account is a context label and does not suppress this warning.",
                           "No success is attributed to these attempts; no cross-import or cross-host correlation.",
                           "Only timestamped, host-attributed, deduplicated parsed failures are eligible.",
                           "Rule priority is not a probability. No model ran."]
            if first.source_ip is None:
                limitations.append("Client IP is absent. These failures cannot be attributed to one remote source.")
            if first.actor is None or (first.platform == "windows" and first.actor.casefold() == "nouser"):
                limitations.append("The reported account is absent or NOUSER; the original attempted username is not established.")
            finding = Finding(finding_id=canonical_hash([policy_hash(), scope, evidence]),
                              timestamp_utc=last.timestamp_utc, activity_class="authentication_burst",
                              triage_priority=55, evidence_event_ids=evidence, explanation=explanation,
                              method="deterministic", confidence=None, model_version=None, limitations=limitations)
            results.append({"finding": finding.model_dump(mode="json"), "window_id": episode[-1][1],
                            "related_window_ids": list(dict.fromkeys(window for _, window in episode)),
                            "title": "Short burst of failed sign-ins", "severity": "warning",
                            "auth_review_version": VERSION, "auth_review_policy_sha256": policy_hash(),
                            "episode_start_utc": first.timestamp_utc.isoformat(),
                            "episode_end_utc": last.timestamp_utc.isoformat(),
                            "feature_version": extraction.windows[0].feature_version})
    return sorted(results, key=lambda row: (row["finding"]["timestamp_utc"], row["finding"]["finding_id"]))
