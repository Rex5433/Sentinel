"""Read-only Windows evidence rules for dashboard imports."""
from dataclasses import dataclass
from datetime import timedelta
import ntpath
import re
from xml.etree import ElementTree

from sentinel.features import canonical_hash
from sentinel.schemas import Finding, WindowsEventRecord

VERSION = "windows-process-review-v4"
SECURITY_PROVIDER = "microsoft-windows-security-auditing"
AUDIT_PROVIDER = "microsoft-windows-eventlog"
EVENT_CODES = {4688, 4648, 4698, 1102}
OFFICE = {"winword", "excel", "powerpnt"}
POWERSHELL = {"powershell", "pwsh"}
TOKEN = re.compile(r'"[^"]*"|[^\s"]+')
USER_BINARY = re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\(?:local|roaming|locallow)\\.+\.(?:exe|com|scr)$")
ENCODED = re.compile(r"[a-z0-9+/]{16,}={0,2}", re.I)

# Bind argument checks to the recorded executable. Reasons describe attempts
# where a process-start record alone cannot establish an outcome.
COMMAND_RULES = (
    ({"rundll32"}, r'^(?:"(?:[^"]*\\)?comsvcs\.dll"|(?:[^"]*\\)?comsvcs\.dll)\s*,\s*minidump\b',
     "Process memory dump", "The command invoked the COM services memory-dump entry point.", "critical"),
    (POWERSHELL, r"^(?:(?:-command|-c)\s+)?[\"']?set-mppreference\b.*\s-disablerealtimemonitoring\s+(?:\$true|1)\b",
     "Defender real-time protection disable attempt", "PowerShell requested that Defender real-time monitoring be disabled.", "critical"),
    ({"vssadmin"}, r"^delete\s+shadows(?:\s|$)",
     "Shadow copy deletion attempt", "The command requested deletion of volume shadow copies.", "critical"),
    ({"bcdedit"}, r"^/set\s+(?:\{[^}]+\}\s+)?recoveryenabled\s+(?:no|off|0)(?:\s|$)",
     "Boot recovery disable attempt", "The boot configuration command requested disabling recovery.", "critical"),
    ({"wevtutil"}, r'^(?:cl|clear-log)\s+"?security"?(?:\s|$)',
     "Security log clearing attempt", "The process requested that the Windows Security log be cleared.", "critical"),
    ({"wmic"}, r'^/node:[^\s]+\s+process\s+call\s+create(?:\s|$)',
     "Remote process creation attempt", "WMI requested process creation on a specified remote node.", "warning"),
)

LINKED_COMMAND_RULES = (
    ({"whoami"}, r"^/priv(?:\s|$)", "Privilege discovery"),
    ({"nltest"}, r"^/dclist:(?:\S+)", "Domain controller discovery"),
    ({"net", "net1"}, r"^group\s+\S.*\s/domain(?:\s|$)", "Domain group discovery"),
    ({"7z", "7za", "7zz"}, r"^a(?=\s).*\s-p\S+", "Password-protected archive staging"),
    ({"curl"}, r"(?:^|\s)(?:-T|--upload-file)\s+\S+.*https?://", "File upload attempt"),
    ({"net", "net1"}, r'^use\s+"?\\\\[^\\\s]+\\(?:admin|[a-z])\$(?:["\s]|$)', "Administrative share access attempt"),
)


def field(record, key, *, numeric=False):
    nested = record.get("EventData")
    values = [record.get(key), nested.get(key) if isinstance(nested, dict) else None]
    present = [v for v in values if v not in (None, "", "-")]
    if numeric:
        present = [str(value) if type(value) is int else value for value in present]
    if not present or any(not isinstance(v, str) or len(v) > 64_000 for v in present):
        return ""
    return present[0].strip() if len(set(present)) == 1 else ""


def path(value):
    return ntpath.normcase(ntpath.normpath(value.strip('"'))) if value else ""


def executable(value):
    return ntpath.basename(path(value)).removesuffix(".exe")


def is_temp_binary(value):
    return bool(USER_BINARY.fullmatch(value) and "\\appdata\\local\\temp\\" in value)


def encoded_invocation(arguments):
    tokens = TOKEN.findall(arguments)
    for token, value in zip(tokens, tokens[1:]):
        switch = token.strip('"').casefold()
        if switch in {"-file", "-f", "-command", "-c"}:
            break
        if switch in {"-enc", "-encodedcommand", "-ec"}:
            return ENCODED.fullmatch(value.strip('"')) is not None
    return False


def cmd_shell_arguments(arguments):
    wrapper = re.match(r"^((?:/(?:s|d|q)\s+)*)/[ck]\s+", arguments, re.I)
    if wrapper:
        command = arguments[wrapper.end():]
        if "/s" in wrapper[1].casefold().split() and command.startswith('"') and command.endswith('"'):
            command = command[1:-1].lstrip()
        image = TOKEN.match(command)
        if image and executable(image[0]) in POWERSHELL:
            tail = command[image.end():].strip()
            if not re.search(r"[&|<>^()]", tail):
                return tail
    return None


def task_targets(content):
    if not content.startswith("<"):
        match = TOKEN.match(content)
        return [path(match[0])] if match else []
    if re.search(r"<!\s*(?:doctype|entity)\b", content, re.I):
        return []
    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, ValueError):
        return []
    return [path(child.text.strip()) for element in root.iter() if element.tag.split("}")[-1] == "Exec"
            for child in element if child.tag.split("}")[-1] == "Command" and child.text]


@dataclass(frozen=True)
class Observation:
    event: WindowsEventRecord
    image: str
    parent: str
    arguments: str
    subject: str
    source_present: bool
    task_paths: tuple[str, ...] = ()


def observation(event):
    if (not isinstance(event, WindowsEventRecord) or event.windows_event_id not in EVENT_CODES
            or not event.host or event.timestamp_utc is None or not isinstance(event.raw_record, dict)):
        return None
    provider = AUDIT_PROVIDER if event.windows_event_id == 1102 else SECURITY_PROVIDER
    if ((event.channel and event.channel.casefold() != "security")
            or (event.provider and event.provider.casefold() != provider)
            or any(error.startswith(("LogName:", "ProviderName:", "EventID:")) for error in event.parsing_errors)):
        return None
    raw = event.raw_record
    code = event.windows_event_id
    image = path(field(raw, "NewProcessName" if code == 4688 else "ProcessName"))
    command = field(raw, "CommandLine")
    first = TOKEN.match(command)
    arguments = command[first.end():].strip() if first else ""
    task_paths = ()
    source_present = bool(event.channel and event.provider)
    if code == 4688 and (not image or not first or executable(first[0]) != executable(image)):
        return None
    if code == 4648 and not (image and field(raw, "TargetUserName") and field(raw, "TargetServerName")):
        return None
    if code == 4698:
        task_paths = tuple(target for target in task_targets(field(raw, "TaskContent")) if target)
        if not task_paths:
            return None
    if code == 1102 and not source_present and (event.message or "").strip().casefold() not in (
        "the audit log was cleared.", "the audit log was cleared",
    ):
        return None
    name = field(raw, "SubjectUserName")
    domain = field(raw, "SubjectDomainName")
    subject = field(raw, "SubjectUserSid") or (f"{domain}\\{name}" if domain and name else name)
    return Observation(event, image, path(field(raw, "ParentProcessName")), arguments, subject.casefold(),
                       source_present, task_paths)


def previous(entries, key, current, minutes, *, creator=False):
    prior = entries.get(key)
    if prior is None or not timedelta(0) < current.event.timestamp_utc - prior.event.timestamp_utc <= timedelta(minutes=minutes):
        return None
    if creator:
        child_pid = field(current.event.raw_record, "ProcessId", numeric=True)
        parent_pid = field(prior.event.raw_record, "NewProcessId", numeric=True)
        if child_pid and parent_pid:
            try:
                same_pid = int(child_pid, 16 if child_pid.lower().startswith("0x") else 10) == int(
                    parent_pid, 16 if parent_pid.lower().startswith("0x") else 10)
            except ValueError:
                return None
            if not same_pid:
                return None
    return prior


def finding(window, current, title, explanation, severity="warning", related=None):
    evidence = [current] if related is None else [related, current]
    limitations = ["Review against authorized change records and original evidence. A process start alone gives no execution outcome."]
    if any(not item.source_present for item in evidence):
        limitations.append("The export omits the Windows channel or provider for at least one cited record.")
    if related:
        limitations.append("Related records were linked by their recorded fields and time. Review the linkage in the original events.")
    result = Finding(
        finding_id=canonical_hash([VERSION, title, current.event.event_id]),
        timestamp_utc=current.event.timestamp_utc, activity_class="process_or_service_anomaly",
        triage_priority={"critical": 90, "warning": 70, "context": 35}[severity],
        evidence_event_ids=[item.event.event_id for item in evidence], explanation=explanation,
        method="deterministic", limitations=limitations,
    )
    return {"finding": result.model_dump(mode="json"), "window_id": window.window_id, "rule_version": VERSION,
            "title": title, "severity": severity, "source_metadata_complete": all(item.source_present for item in evidence)}


def windows_findings(extraction):
    """Review targeted behavior and short, same-source process relationships."""
    results = []
    attachments, downloads, launched, autoruns, log_clears = {}, {}, {}, {}, {}
    reviewed_count = 0
    for window in extraction.windows:
        for event in extraction.members[window.window_id]:
            current = observation(event)
            if current is None:
                continue
            scope = (event.upload_id, event.host.casefold(), current.subject) if current.subject else None
            if event.windows_event_id == 1102:
                clear = previous(log_clears, scope, current, 2)
                if current.source_present or clear:
                    reviewed_count += 1
                    results.append(finding(window, current, "Security audit log cleared",
                                           "An audit-log-cleared record was observed.", "critical", clear))
                continue
            reviewed_count += 1
            image, arguments = executable(current.image), current.arguments.casefold()
            image_key, parent_key = (scope, current.image), (scope, current.parent)
            if event.windows_event_id == 4648:
                prior = previous(launched, image_key, current, 20, creator=True)
                if prior:
                    results.append(finding(window, current, "Explicit credentials from a recently downloaded process",
                                           "The recorded process attempted to use explicit credentials after a linked download and launch.",
                                           related=prior))
                continue
            if event.windows_event_id == 4698:
                for target in current.task_paths:
                    prior = previous(autoruns, (scope, target), current, 10)
                    if prior or is_temp_binary(target):
                        results.append(finding(window, current, "Scheduled task launches a user-writable executable",
                                               "A new task targets a temporary executable or the same file as a recent Run-key write.",
                                               related=prior))
                        break
                else:
                    if any(USER_BINARY.fullmatch(target) for target in current.task_paths):
                        results.append(finding(window, current, "Scheduled task targets a user profile executable",
                                               "The record describes a task targeting an AppData executable. Verify the source, file, and authorization.",
                                               "warning" if current.source_present else "context"))
                continue

            if scope and image in OFFICE:
                attachments.pop(image_key, None)
                if executable(current.parent) in {"outlook", "olk"} and re.search(r'\.(?:docm|xlsm|pptm)"?(?:\s|$)', arguments):
                    attachments[image_key] = current

            office_parent = executable(current.parent) in OFFICE
            shell_args = (current.arguments if image in POWERSHELL else
                          cmd_shell_arguments(current.arguments) if image == "cmd" and office_parent else None)
            if shell_args is not None and encoded_invocation(shell_args):
                related = previous(attachments, parent_key, current, 2, creator=True) if office_parent else None
                results.append(finding(window, current, "Office launched an encoded shell" if office_parent else "Encoded PowerShell launch",
                                       "The recorded command passed an encoded payload to PowerShell.", related=related))

            if image == "certutil" and "-urlcache" in arguments.split():
                args = TOKEN.findall(current.arguments)
                target = path(args[-1])
                if USER_BINARY.fullmatch(target) and any(arg.strip('"').casefold().startswith(("http://", "https://")) for arg in args[:-1]):
                    if scope:
                        downloads[(scope, target)] = current
                    results.append(finding(window, current, "Executable download into a user profile",
                                           "Certutil was invoked with a remote URL and a user-writable executable destination."))
            launched.pop(image_key, None)
            prior = previous(downloads, image_key, current, 5)
            if prior:
                launched[image_key] = current
                results.append(finding(window, current, "Recently downloaded executable launched",
                                       "The executable path matches the destination of an earlier download on this host.", related=prior))

            if image == "reg" and re.match(r'^add\s+"?(?:hkcu|hklm|hkey_current_user|hkey_local_machine)\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?(?:"|\s|$)', arguments):
                data = re.search(r'(?:^|\s)/d\s+("[^"]+"|\S+)', arguments)
                target = path(data[1]) if data else ""
                if USER_BINARY.fullmatch(target):
                    if scope:
                        autoruns[(scope, target)] = current
                    results.append(finding(window, current, "Run-key write for a user-writable executable",
                                           "The registry command targeted a sign-in auto-start key and a user profile executable."))

            for tools, pattern, title, reason, severity in COMMAND_RULES:
                if image in tools and re.search(pattern, arguments, re.DOTALL):
                    if image == "wevtutil" and scope:
                        log_clears[scope] = current
                    results.append(finding(window, current, title, reason, severity))
                    break

            origin = previous(launched, parent_key, current, 20, creator=True)
            if origin:
                for tools, pattern, title in LINKED_COMMAND_RULES:
                    if image in tools and re.search(pattern, current.arguments if image == "curl" else arguments):
                        results.append(finding(window, current, title,
                                               "The recorded command ran under a process linked to the earlier executable download.",
                                               related=origin))
                        break
    return results, reviewed_count
