"""Operational activity labels layered on the frozen import parsers."""

from ipaddress import ip_address
import re

from sentinel.ingest import parse_linux as parse_linux_base, parse_windows as parse_windows_base
from sentinel.ingest.windows_jsonl import parse_windows_jsonl as parse_windows_jsonl_base

SECURITY = "microsoft-windows-security-auditing"
DEFENDER = "microsoft-windows-windows defender"
WINDOWS_ACTIVITY = {
    ("security", SECURITY): {
        4648: "explicit_credentials", 4688: "process_started", 4717: "system_access_granted",
        4718: "system_access_removed", 4719: "audit_policy_changed", 4733: "group_member_removed",
        4738: "account_changed", 4776: "credential_validation", 4798: "group_membership_read",
        5152: "network_packet_blocked", 5156: "network_connection_allowed",
        5157: "network_connection_blocked", 5158: "network_port_bound",
    },
    ("security", "microsoft-windows-eventlog"): {1100: "event_logging_stopped", 1102: "audit_log_cleared"},
    (DEFENDER + "/operational", DEFENDER): {
        1116: "defender_detection", 1117: "defender_action", 1118: "defender_action_failed",
        1119: "defender_action_failed", 5001: "defender_protection_disabled", 5007: "defender_settings_changed",
    },
    ("system", "schannel"): {36874: "tls_handshake_failed"},
    ("system", "service control manager"): {7000: "service_start_failed", 7034: "service_stopped_unexpectedly",
                                            7040: "service_startup_changed"},
    ("system", "eventlog"): {6005: "event_logging_started", 6006: "event_logging_stopped"},
    ("system", "user32"): {1074: "shutdown_requested"},
    ("system", "microsoft-windows-winrm"): {10149: "remote_management_listening"},
    ("application", "microsoft-windows-winlogon"): {6004: "sign_in_notification_failed"},
    ("application", "microsoft-windows-perflib"): {1008: "performance_counter_failed"},
    ("microsoft-windows-taskscheduler/operational", "microsoft-windows-taskscheduler"): {
        100: "task_started", 102: "task_completed", 106: "task_registered", 107: "task_triggered",
        129: "task_process_started", 140: "task_updated", 141: "task_deleted", 142: "task_disabled",
        200: "task_action_started", 201: "task_action_completed",
    },
    ("microsoft-windows-crypto-dpapi/operational", "microsoft-windows-crypto-dpapi"): {12289: "dpapi_key_found"},
    ("microsoft-windows-kernel-io/operational", "microsoft-windows-kernel-io"): {
        1: "volume_mount_requested", 2: "volume_mounted",
    },
    ("microsoft-windows-known folders api service", "microsoft-windows-knownfolders"): {1002: "folder_check_failed"},
    ("microsoft-windows-appxdeployment/operational", "microsoft-windows-appxdeployment"): {325: "appx_registration_checked"},
    ("microsoft-windows-powershell/operational", "microsoft-windows-powershell"): {
        40961: "powershell_starting", 40962: "powershell_ready", 53504: "powershell_ipc_started",
        4103: "powershell_module_logged", 4104: "powershell_script_logged",
    },
    ("microsoft-windows-bits-client/operational", "microsoft-windows-bits-client"): {306: "bits_job_list_loaded"},
    ("microsoft-windows-devicesetupmanager/admin", "microsoft-windows-devicesetupmanager"): {
        100: "device_manager_started", 101: "device_manager_stopped", 112: "device_serviced",
    },
    ("microsoft-windows-devicesetupmanager/operational", "microsoft-windows-devicesetupmanager"): {300: "device_ready"},
    ("microsoft-windows-kernel-pnp/configuration", "microsoft-windows-kernel-pnp"): {
        400: "device_configured", 410: "device_started", 420: "device_removed",
    },
    ("microsoft-windows-ntlm/operational", "microsoft-windows-ntlm"): {4022: "remote_ntlm_authentication"},
    ("microsoft-windows-ntfs/operational", "microsoft-windows-ntfs"): {146: "ntfs_latency_report"},
    ("microsoft-windows-printservice/admin", "microsoft-windows-printservice"): {823: "default_printer_changed"},
}

SSH_DISCONNECT = re.compile(r"^Disconnected from (?:(?:invalid )?user (?P<user>\S+) )?(?P<ip>\S+) port \d+(?:\s|$)")
SSH_OPEN = re.compile(r"^Connection from (?P<ip>\S+) port \d+(?:\s|$)")
SSH_RECEIVED = re.compile(r"^Received disconnect from (?P<ip>\S+) port \d+:")
SSH_CLOSED = re.compile(r"^Connection closed by (?:(?:invalid )?user (?P<user>\S+) )?(?P<ip>\S+) port \d+(?:\s|$)")
SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+(?:\s|$)")
SSH_PAM_FAILURE = re.compile(r"^error: PAM: Authentication failure for (?:illegal user )?(?P<user>\S+) from (?P<ip>\S+)$")
SSH_SIGN_IN = re.compile(r"^(?P<outcome>Failed|Accepted) (?:password|publickey|keyboard-interactive(?:/pam)?) "
                         r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+(?:\s|$)")
SUDO_INITIATOR = re.compile(r"^pam_unix\(sudo:session\): session opened for user \S+ by (?P<user>[^\s(]+)(?:\(uid=\d+\)|\s|$)")
FIREWALL = re.compile(r"^(?:\[\s*\d+(?:\.\d+)?\]\s*)?\[UFW (BLOCK|ALLOW|LIMIT BLOCK|AUDIT)\]\s+")


def ip(value):
    try:
        parsed = ip_address(str(value))
    except ValueError:
        return None
    return getattr(parsed, "ipv4_mapped", None) or parsed


def windows_source(event):
    return (event.channel or "").casefold(), (event.provider or "").casefold()


def windows_field(event, field):
    raw = event.raw_record
    nested = raw.get("EventData")
    flat_value = raw.get(field)
    nested_value = nested.get(field) if isinstance(nested, dict) else None
    if flat_value is not None and nested_value is not None and str(flat_value) != str(nested_value):
        return None
    return nested_value if flat_value is None else flat_value


def firewall_fields(message):
    match = FIREWALL.match(message)
    if not match:
        return None
    fields = {}
    for token in message[match.end():].split():
        name, separator, value = token.partition("=")
        if separator:
            if name in fields:
                return None
            fields[name] = value
        else:
            fields[name] = True
    return match[1], fields


def describe_linux(event):
    message, service = (event.message or "").strip(), (event.service or "").casefold()
    if not service and isinstance(event.raw_record, dict) and event.raw_record.get("_TRANSPORT") == "kernel":
        service = "kernel"
    if service == "sudo" and event.event_type == "session_open" and (match := SUDO_INITIATOR.match(message)):
        return {"actor": match["user"], "target": event.actor, "event_type": "sudo_session_open"}
    if event.event_type:
        return {}
    if service in {"sshd", "sshd-session", "sshd-auth"}:
        if match := SSH_SIGN_IN.match(message):
            address = ip(match["ip"])
            return {"event_type": "auth_success" if match["outcome"] == "Accepted" else "auth_failure",
                    "actor": match["user"], "target": service, "source_ip": str(address) if address else None}
        for expression, activity in ((SSH_DISCONNECT, "ssh_disconnected"), (SSH_RECEIVED, "ssh_disconnected"),
                                     (SSH_CLOSED, "ssh_disconnected"),
                                     (SSH_OPEN, "ssh_connection"), (SSH_INVALID, "ssh_invalid_account"),
                                     (SSH_PAM_FAILURE, "ssh_pam_failure")):
            if match := expression.match(message):
                address = ip(match["ip"])
                return {"event_type": activity, "actor": match.groupdict().get("user"),
                        "source_ip": str(address) if address else None}
    if service in {"kernel", "ufw"} and (logged := firewall_fields(message)):
        action, fields = logged
        address = ip(fields.get("SRC"))
        return {"event_type": "network_packet_blocked" if "BLOCK" in action else
                "network_packet_allowed" if action == "ALLOW" else "firewall_observation",
                "source_ip": str(address) if address else None}
    if service in {"audit", "auditd", "kernel"} and re.match(r"^(?:audit:\s+)?type=\w+\s+(?:msg=)?audit\(", message):
        return {"event_type": "linux_audit"}
    if service == "kernel":
        return {"event_type": "kernel_activity"}
    if service == "mqtt_modbus":
        return {"event_type": "industrial_protocol_activity"}
    if service == "systemd" and re.match(r"^(?:Finished|Reloaded|Failed to|Reached target) ", message):
        return {"event_type": "service_activity"}
    if service in {"useradd", "userdel", "usermod", "groupadd", "groupmod", "groupdel", "passwd"}:
        return {"event_type": "account_management"}
    if service in {"cron", "crond", "crontab"}:
        return {"event_type": "scheduled_job_activity"}
    return {}


def enrich(event):
    if event.platform == "linux":
        fields = describe_linux(event)
    elif not event.event_type and not any(error.startswith(("EventID:", "EventData:")) for error in event.parsing_errors):
        kind = WINDOWS_ACTIVITY.get(windows_source(event), {}).get(event.windows_event_id)
        fields = {"event_type": kind} if kind else {}
        if kind in {"network_packet_blocked", "network_connection_allowed", "network_connection_blocked"}:
            address = ip(windows_field(event, "SourceAddress"))
            if address:
                fields["source_ip"] = str(address)
    else:
        fields = {}
    if not fields:
        return event
    fields["parsing_errors"] = [error for error in event.parsing_errors if not error.startswith("event_type:")]
    return event.model_copy(update=fields)


def _enriched(result):
    result.events = [enrich(event) for event in result.events]
    return result


def parse_linux(*args, **kwargs):
    return _enriched(parse_linux_base(*args, **kwargs))


def parse_windows(*args, **kwargs):
    return _enriched(parse_windows_base(*args, **kwargs))


def parse_windows_jsonl(*args, **kwargs):
    return _enriched(parse_windows_jsonl_base(*args, **kwargs))
