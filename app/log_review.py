"""One deterministic review path for saved imports and current live buffers."""
from dataclasses import dataclass

from sentinel.features import extract_features, Extraction
from sentinel.detection.rules import baseline_findings
from sentinel.detection.auth_review import auth_findings
from sentinel.detection.auth_transition import auth_transitions
from sentinel.detection.windows_review import windows_findings, observation
from sentinel.detection.windows_configuration import configuration_findings, configuration_title
from sentinel.detection.linux_review import linux_findings
from .endpoint_review import endpoint_findings
from .event_activity import enrich


def windows_checked(event):
    if configuration_title(event):
        return True
    seen = observation(event)
    return bool(seen and (event.windows_event_id != 1102 or seen.source_present))


@dataclass
class LogReview:
    extraction: Extraction
    findings: list
    windows_reviewed_count: int
    windows_reviewed_event_ids: list


def review_events(events, platform):
    events = [enrich(event) for event in events]
    extraction = extract_features(events)
    findings = baseline_findings(extraction)
    findings.extend(auth_findings(extraction, findings))
    findings.extend(auth_transitions(extraction))
    if platform == "windows":
        native, _ = windows_findings(extraction)
        native.extend(configuration_findings(extraction, native))
        checked = [event.event_id for event in events if windows_checked(event)]
        count = len(checked)
    else:
        native, count, checked = linux_findings(events), 0, []
    findings.extend(native)
    findings.extend(endpoint_findings(events))
    return LogReview(extraction, findings, count, checked)


def event_flags(findings):
    flags = {}
    priority = {"context": 0, "lead": 1, "warning": 2, "critical": 3}
    for entry in findings:
        severity = entry.get("severity", "warning")
        for event_id in entry["finding"]["evidence_event_ids"]:
            if event_id not in flags or priority[severity] > priority[flags[event_id]]:
                flags[event_id] = severity
    return flags
