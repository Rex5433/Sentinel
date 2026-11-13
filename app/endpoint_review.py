"""Correlate passive firewall evidence and surface Defender's reported actions."""

from collections import defaultdict, deque
from datetime import timedelta

from sentinel.detection.network_review import POLICY
from sentinel.detection.linux_review import basename, words
from sentinel.features import canonical_hash
from sentinel.schemas import Finding, UtcTimestamp

from .event_activity import firewall_fields, ip, windows_field

SCAN = POLICY["port_sweep"]
VERSION = "endpoint-review-v1"
SECURITY_FILES = {"/etc/ssh/sshd_config", "/etc/sudoers", "/etc/pam.conf", "/etc/audit/auditd.conf"}
SECURITY_DIRECTORIES = ("/etc/ssh/sshd_config.d/", "/etc/sudoers.d/", "/etc/pam.d/", "/etc/audit/rules.d/")
EDITORS = {"nano", "vi", "vim", "nvim", "emacs", "sudoedit"}


class EndpointFinding(Finding):
    timestamp_utc: UtcTimestamp | None


def finding(event, title, explanation, severity, *, members=(), network=False):
    data = EndpointFinding(
        finding_id=canonical_hash([VERSION, title, event.event_id]),
        timestamp_utc=event.timestamp_utc,
        activity_class="network_activity_anomaly" if network else "process_or_service_anomaly",
        triage_priority={"critical": 90, "warning": 70, "context": 35}[severity],
        evidence_event_ids=[row.event_id for row in members] or [event.event_id],
        explanation=explanation, method="deterministic",
        limitations=["Verify authorization and outcome in the source records."],
    )
    return {"finding": data.model_dump(mode="json"), "window_id": None, "rule_version": VERSION,
            "title": title, "severity": severity, "platform": event.platform,
            "source_record_index": event.record_index, "original_timestamp": event.original_timestamp}


def inbound_probe(event):
    if event.platform == "windows" and event.event_type in {
        "network_connection_allowed", "network_connection_blocked", "network_packet_blocked",
    }:
        if str(windows_field(event, "Direction")).strip().casefold() not in {"%%14592", "inbound"}:
            return None
        protocol = {"6": "TCP", "17": "UDP"}.get(str(windows_field(event, "Protocol")))
        source, dest, port = (windows_field(event, field) for field in ("SourceAddress", "DestAddress", "DestPort"))
    elif event.platform == "linux" and event.event_type in {"network_packet_allowed", "network_packet_blocked", "firewall_observation"}:
        logged = firewall_fields((event.message or "").strip())
        if not logged:
            return None
        _, fields = logged
        if not fields.get("IN") or fields.get("OUT") != "":
            return None
        protocol = fields.get("PROTO")
        if protocol == "TCP" and ("SYN" not in fields or {"ACK", "RST", "FIN"} & fields.keys()):
            return None
        source, dest, port = (fields.get(field) for field in ("SRC", "DST", "DPT"))
    else:
        return None
    source, dest = ip(source), ip(dest)
    port = str(port)
    if (protocol not in {"TCP", "UDP"} or not source or not dest or source.version != dest.version
            or source == dest or source.is_loopback or dest.is_loopback or source.is_unspecified
            or dest.is_unspecified or source.is_multicast or dest.is_multicast
            or str(dest) == "255.255.255.255"
            or not port.isascii() or not port.isdecimal() or len(port) > 5 or not 0 < int(port) <= 65535):
        return None
    return str(source), str(dest), protocol, int(port)


def scan_findings(events):
    groups = defaultdict(list)
    for event in events:
        if event.host and event.timestamp_utc and (probe := inbound_probe(event)):
            source, dest, protocol, port = probe
            groups[event.upload_id, event.host.casefold(), source, dest, protocol].append((event, port))
    span = timedelta(seconds=SCAN["seconds"])
    for (_, _, source, dest, protocol), rows in groups.items():
        active, ports = deque(), defaultdict(int)
        next_review = None
        for event, port in sorted(rows, key=lambda row: row[0].timestamp_utc):
            stamp = event.timestamp_utc
            while active and stamp - active[0][0].timestamp_utc > span:
                _, expired = active.popleft()
                ports[expired] -= 1
                if not ports[expired]:
                    del ports[expired]
            active.append((event, port))
            ports[port] += 1
            if len(ports) >= SCAN["distinct_ports"] and (next_review is None or stamp >= next_review):
                evidence = {dest_port: row for row, dest_port in active}
                yield finding(event, "Possible inbound port scan",
                              f"Firewall telemetry recorded {len(ports)} distinct {protocol} destination ports from {source} "
                              f"to {dest} within {SCAN['seconds']} seconds. Check for an authorized scanner or inventory job.",
                              "warning", members=evidence.values(), network=True)
                next_review = stamp + span


def endpoint_findings(events):
    for event in events:
        kind = event.event_type
        if kind == "defender_detection":
            high = str(windows_field(event, "Severity Name")).casefold() in {"high", "severe"}
            yield finding(event, "Defender reported a threat detection",
                          "Defender recorded a malware or potentially unwanted software detection. Review the reported path, process, and detection source.",
                          "critical" if high else "warning")
        elif kind == "defender_action":
            action = windows_field(event, "Action Name")
            description = f"Defender recorded the action “{action}”." if isinstance(action, str) and action.strip() else "Defender recorded an action."
            yield finding(event, "Defender reported a protection action",
                          f"{description} Check its status in the original Defender record.", "context")
        elif kind in {"defender_action_failed", "defender_protection_disabled"}:
            title = "Defender reported a failed protection action" if kind == "defender_action_failed" else "Defender real-time protection disabled"
            yield finding(event, title, "Defender recorded this state. Verify it against the endpoint policy and expected maintenance.", "warning")
        elif kind == "sudo_command" and event.target == "root":
            command = words(event.attributes.get("command_text"))
            if not command:
                continue
            executable, arguments = basename(command[0]), command[1:]
            if executable == "journalctl" and any(
                value.partition("=")[0] in {"--vacuum-time", "--vacuum-size", "--vacuum-files"} for value in arguments
            ):
                yield finding(event, "Sudo requested journal cleanup",
                              "Sudo recorded a journal vacuum request as root. Verify the maintenance window and check whether retained logs changed.",
                              "warning")
            elif executable in EDITORS and any(path in SECURITY_FILES or path.startswith(SECURITY_DIRECTORIES)
                                                for path in arguments):
                yield finding(event, "Privileged editor opened a security configuration path",
                              "Sudo recorded a root editor targeting SSH, privilege, PAM, or audit configuration. Check the file for changes and verify authorization.",
                              "warning")
            elif executable == "su" and arguments in ([], ["-"], ["root"], ["-", "root"], ["--login"], ["--login", "root"]):
                yield finding(event, "Sudo requested a root shell",
                              "Sudo recorded a request to switch to root. Correlate the request with session records and the operator's maintenance activity.",
                              "context")
    yield from scan_findings(events)
