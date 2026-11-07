"""Full-match grammar. Unsupported words are never silently discarded."""

from dataclasses import dataclass
from ipaddress import ip_address
import re

VERSION = "investigation-intents-v1"
EXAMPLES = (
    "show failed logins", "show successful logins", "show failed SSH logins",
    "show successful SSH logins", "show account creations", "show sudo activity",
    "show service activity", "find Windows 4625 events",
    'show activity for account "demo-user"', 'show events from IP "192.0.2.20"',
)
HELP = {
    "version": VERSION, "examples": EXAMPLES,
    "host_suffix": 'Append: on host "exact-host-name"',
    "matching": "Keywords ignore case; quoted host/account values match exactly and preserve case/spaces. IPs are normalized.",
    "limitations": "Ten fixed request forms. No arbitrary questions, shell commands, time phrases, or inferred threat verdicts. Use timeline time filters separately.",
}


@dataclass(frozen=True)
class Intent:
    name: str
    filters: dict
    category: str | None


def route(query: str) -> Intent | None:
    if not isinstance(query, str) or not 1 <= len(query) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in query):
        return None
    text = query.strip()
    host = None
    suffix = re.search(r' on host "([^"\r\n]{1,255})"$', text, re.IGNORECASE)
    if suffix:
        host, text = suffix[1], text[:suffix.start()]
    filters = {"host": host} if host is not None else {}
    fixed = {
        "show failed logins": ("failed_logins", {"event_type": "auth_failure"}, "authentication"),
        "show successful logins": ("successful_logins", {"event_type": "auth_success"}, "authentication"),
        "show failed ssh logins": ("failed_ssh_logins", {"event_type": "auth_failure", "platform": "linux", "services": ["sshd", "sshd-session"]}, "authentication"),
        "show successful ssh logins": ("successful_ssh_logins", {"event_type": "auth_success", "platform": "linux", "services": ["sshd", "sshd-session"]}, "authentication"),
        "show account creations": ("account_creations", {"event_type": "account_created"}, "users"),
        "show sudo activity": ("sudo_activity", {"event_type": "sudo_command", "platform": "linux"}, "users"),
        "show service activity": ("service_activity", {"event_types": ["service_installed", "service_state_change", "service_activity"]}, "services"),
    }
    if text.lower() in fixed:
        name, values, category = fixed[text.lower()]
        return Intent(name, {**filters, **values}, category)
    match = re.fullmatch(r"find Windows ([0-9]{1,5}) events", text, re.IGNORECASE)
    if match and int(match[1]) <= 65535:
        code = int(match[1])
        category = {4624: "authentication", 4625: "authentication", 4720: "users",
                    4697: "services", 7036: "services"}.get(code)
        return Intent("windows_event_id", {**filters, "platform": "windows", "windows_event_id": code}, category)
    match = re.fullmatch(r'show activity for account "([^"\r\n]{1,255})"', text, re.IGNORECASE)
    if match:
        return Intent("account_activity", {**filters, "actor": match[1]}, "users")
    match = re.fullmatch(r'show events from IP "([^"\r\n]{1,255})"', text, re.IGNORECASE)
    if match:
        try:
            value = str(ip_address(match[1]))
        except ValueError:
            return None
        return Intent("source_ip_activity", {**filters, "source_ip": value}, "network")
    return None
