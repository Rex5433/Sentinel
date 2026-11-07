"""Experimental evidence-backed review of low-rate authentication failures."""
from collections import defaultdict
from datetime import timedelta

from sentinel.detection.verification import COVERAGE
from sentinel.features import WINDOW_SECONDS

VERSION = "slow-auth-review-v1"
LOOKBACK = timedelta(minutes=60)
MIN_WINDOWS = 3


def slow_auth_hits(observations):
    """Return current-window evidence for recurring actor and source-IP pairs.

    Each item is a parsed feature window, its member events, and explicit coverage.
    Histories are local to a source, platform and host, with reset on gaps.
    """
    states = {}
    hits = {}
    for window, members, coverage in observations:
        identity = (window.upload_id, window.platform, window.host)
        now = window.start_utc
        complete = coverage.get("collection_complete") is True and all(
            type(coverage.get(key)) is int and coverage[key] == 0 for key in COVERAGE
        )
        if not complete:
            states.pop(identity, None)
            continue
        previous, history = states.get(identity, (None, {}))
        if previous is None or now - previous != timedelta(seconds=WINDOW_SECONDS):
            history = {}
        active = defaultdict(list)
        for event in members:
            if event.event_type == "auth_failure" and event.actor and event.source_ip is not None:
                active[(event.actor, event.source_ip)].append(event.event_id)
        cutoff = now - LOOKBACK
        history = {key: [item for item in past if item[0] > cutoff]
                   for key, past in history.items() if past[-1][0] > cutoff}
        evidence = []
        for key, current in active.items():
            past = history.setdefault(key, [])
            past.append((now, current))
            if len(past) >= MIN_WINDOWS:
                evidence.extend(event_id for _, ids in past for event_id in ids)
        if evidence:
            hits[window.window_id] = list(dict.fromkeys(evidence))
        states[identity] = (now, history)
    return hits
