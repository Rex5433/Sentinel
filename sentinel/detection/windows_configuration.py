"""Review Windows configuration evidence using recorded channel and provider."""

import re

from sentinel.features import canonical_hash
from sentinel.schemas import Finding, WindowsEventRecord

from .windows_review import AUDIT_PROVIDER, SECURITY_PROVIDER, TOKEN, USER_BINARY, field, path, task_targets

VERSION = "windows-configuration-review-v1"
TASK_CHANNEL = "microsoft-windows-taskscheduler/operational"
TITLES = {
    ("security", SECURITY_PROVIDER): {
        4657: "Registry value changed", 4697: "Service installed",
        4698: "Scheduled task created", 4699: "Scheduled task deleted",
        4700: "Scheduled task enabled", 4701: "Scheduled task disabled",
        4702: "Scheduled task updated", 4719: "Audit policy changed",
    },
    ("system", "service control manager"): {
        7040: "Service startup type changed", 7045: "Service installed",
    },
    ("system", AUDIT_PROVIDER): {104: "Windows event log cleared"},
    (TASK_CHANNEL, "microsoft-windows-taskscheduler"): {
        100: "Scheduled task started", 102: "Scheduled task completed",
        106: "Scheduled task registered", 140: "Scheduled task updated",
        141: "Scheduled task deleted", 142: "Scheduled task disabled",
        200: "Scheduled action started", 201: "Scheduled action completed",
    },
}
ROUTINE_RUNS = {100, 102, 200, 201}
RUN_KEY = re.compile(r"\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?$", re.I)
WRITABLE_BINARY = re.compile(r"^(?:[a-z]:\\(?:users\\public|windows\\temp)\\|%temp%\\).+\.(?:exe|com|scr)$")


def configuration_title(event):
    if (not isinstance(event, WindowsEventRecord) or not event.channel or not event.provider
            or not event.host or event.timestamp_utc is None
            or any(error.startswith(("LogName:", "ProviderName:", "EventID:")) for error in event.parsing_errors)):
        return None
    return TITLES.get((event.channel.casefold(), event.provider.casefold()), {}).get(event.windows_event_id)


def writable_binary(value):
    return bool(USER_BINARY.fullmatch(value) or WRITABLE_BINARY.fullmatch(value))


def command_image(value):
    first = TOKEN.match(value)
    return path(first[0]) if first else ""


def suspicious_target(event):
    raw = event.raw_record
    code = event.windows_event_id
    if code in {4697, 7045}:
        image = command_image(field(raw, "ServiceFileName") or field(raw, "ImagePath"))
        if writable_binary(image):
            return "Service targets a user-writable executable", "The installed service's recorded executable is in a user profile or temporary location."
    if code in {4698, 4702, 200}:
        content = field(raw, {4698: "TaskContent", 4702: "TaskContentNew", 200: "ActionName"}[code])
        if any(writable_binary(target) for target in task_targets(content)):
            return "Scheduled task targets a user-writable executable", "The recorded task action points to an executable in a user profile or temporary location."
    if code == 4657 and RUN_KEY.search(field(raw, "ObjectName")):
        if writable_binary(command_image(field(raw, "NewValue"))):
            return "Sign-in auto-start targets a user-writable executable", "The changed Run or RunOnce value names an executable in a user profile or temporary location."
    return None


def configuration_findings(extraction, existing):
    cited = {event_id for entry in existing for event_id in entry["finding"]["evidence_event_ids"]}
    findings = []
    for window in extraction.windows:
        for event in extraction.members[window.window_id]:
            title = configuration_title(event)
            if not title or event.event_id in cited:
                continue
            signal = suspicious_target(event)
            if signal:
                title, explanation = signal
                severity, priority = "warning", 70
            elif event.windows_event_id == 104:
                explanation = "The Windows Event Log service recorded a log clear. Review the affected channel and preserve any forwarded copy."
                severity, priority = "critical", 90
            elif event.windows_event_id in ROUTINE_RUNS:
                continue
            else:
                explanation = "The source recorded this change. Compare it with the expected configuration and authorized work."
                severity, priority = "context", 35
            finding = Finding(
                finding_id=canonical_hash([VERSION, title, event.event_id]),
                timestamp_utc=event.timestamp_utc, activity_class="process_or_service_anomaly",
                triage_priority=priority, evidence_event_ids=[event.event_id],
                explanation=explanation, method="deterministic",
                limitations=["The recorded change alone does not establish who authorized it."],
            )
            findings.append({"finding": finding.model_dump(mode="json"), "window_id": window.window_id,
                             "rule_version": VERSION, "title": title,
                             "severity": severity, "source_metadata_complete": True})
    return findings
