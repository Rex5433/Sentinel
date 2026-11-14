"""Evidence-backed sign-in success following a burst of matching failures."""

from collections import defaultdict, deque
from datetime import timedelta

from sentinel.features import canonical_hash
from sentinel.schemas import Finding

from .auth_review import SECONDS, THRESHOLD
from .windows_review import SECURITY_PROVIDER, field

VERSION = "sign-in-after-failures-v1"
FOLLOWUP = timedelta(minutes=10)


def identity(event):
    if event.event_type not in {"auth_success", "auth_failure"} or not event.actor or event.source_ip is None:
        return None
    if event.source_ip.is_loopback or event.source_ip.is_unspecified or event.actor.casefold() in {"nouser", "unknown", "-"}:
        return None
    if event.platform == "linux":
        if event.service in {"sshd", "sshd-session"}:
            return event.actor, "ssh"
        return None
    code = 4624 if event.event_type == "auth_success" else 4625
    if (event.windows_event_id != code or (event.channel or "").casefold() != "security"
            or (event.provider or "").casefold() != SECURITY_PROVIDER):
        return None
    domain = field(event.raw_record, "TargetDomainName").casefold()
    logon = field(event.raw_record, "LogonType", numeric=True)
    if domain and logon in {"3", "8", "10"}:
        return event.actor.casefold(), domain, logon
    return None


def auth_transitions(extraction):
    groups = defaultdict(list)
    for window in extraction.windows:
        for event in extraction.members[window.window_id]:
            account = identity(event)
            if account:
                scope = (event.upload_id, event.platform, event.host.casefold() if event.platform == "windows" else event.host,
                         event.source_sha256, str(event.source_ip), account)
                groups[scope].append((event, window.window_id))
    for rows in groups.values():
        failures = deque(maxlen=THRESHOLD)
        seen = set()
        for event, window_id in sorted(rows, key=lambda row: (row[0].timestamp_utc, row[0].record_index)):
            native = event.raw_record.get("RecordId" if event.platform == "windows" else "__CURSOR") if isinstance(event.raw_record, dict) else None
            dedup = (event.timestamp_utc, event.event_type, str(native) if native is not None else canonical_hash(event.raw_record))
            if dedup in seen:
                continue
            seen.add(dedup)
            if event.event_type == "auth_failure":
                failures.append(event)
                continue
            if (len(failures) == THRESHOLD
                    and failures[-1].timestamp_utc - failures[0].timestamp_utc <= timedelta(seconds=SECONDS)
                    and timedelta() < event.timestamp_utc - failures[-1].timestamp_utc <= FOLLOWUP):
                evidence = [row.event_id for row in failures] + [event.event_id]
                finding = Finding(
                    finding_id=canonical_hash([VERSION, evidence]), timestamp_utc=event.timestamp_utc,
                    activity_class="authentication_burst", triage_priority=75, evidence_event_ids=evidence,
                    explanation=f"A successful sign-in for {event.actor} from {event.source_ip} followed "
                    f"{THRESHOLD} failures within {SECONDS} seconds for the same account, host and source IP. "
                    "Compare this with expected sign-in activity.",
                    method="deterministic",
                    limitations=["A legitimate retry can produce this sequence. Verify the account operator and authorization.",
                                 "Correlation uses the evidence available in this capture or live buffer."],
                )
                yield {"finding": finding.model_dump(mode="json"), "window_id": window_id,
                       "rule_version": VERSION, "title": "Successful sign-in after repeated failures", "severity": "warning"}
            failures.clear()
