"""Evidence rules for Linux syslog and journal records, including undated exports."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import PurePosixPath
import re
import shlex
from urllib.parse import urlsplit

from sentinel.features import canonical_hash
from sentinel.schemas import Finding, LinuxEventRecord, UtcTimestamp

VERSION = "linux-evidence-review-v6"
SHELLS = {"bash", "dash", "sh", "zsh"}
LEGACY_TIME = re.compile(r"([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
COMMAND = re.compile(r"^root\s*:\s*TTY=(\S+)\s*:\s*COMMAND=(.+)$")
SUDO_DENIED = re.compile(r"^\s*(\S+)\s*:\s*user NOT in sudoers\s*;.*;\s*USER=root\s*;\s*COMMAND=(\S+)")
SUDO_AUTH = re.compile(r"^pam_unix\(sudo:auth\): authentication failure;.*\buser=(\S+)")
SUDO_AUDIT_COMMAND = re.compile(
    r"\S+\s*:\s*TTY=[^;]+;\s*PWD=[^;]+;\s*USER=root\s*;\s*"
    r"COMMAND=/(?:usr/)?(?:bin/systemctl\s+((?:--no-block\s+)?stop\s+auditd(?:\.service)?)"
    r"|s?bin/auditctl\s+-e\s*0)"
)
ACCOUNT = re.compile(r"^new user: name=([^,\s]+), UID=\d+, GID=\d+, home=(/[^,\s]+), shell=(/\S+)$")
TEMP = ("/dev/shm/", "/tmp/", "/var/tmp/")
UFW_ALLOW = re.compile(r"^(?:\[\s*\d+(?:\.\d+)?\]\s+)?\[UFW ALLOW\]\s+(.+)$")
FLOW_FIELDS = {"IN", "OUT", "SRC", "DST", "PROTO", "SPT", "DPT"}
NATIVE_AUDIT = re.compile(r"^(?:audit:\s+)?type=(SYSCALL|EXECVE|SOCKADDR|1300|1309|1306)\s+(?:msg=)?audit\((\d+\.\d+:\d+)\):\s+(.+)$")
AUDIT_FIELDS = re.compile(r'(?<!\S)([A-Za-z]\w*(?:\[\d+\])?)=("[^"]*"|[^\s"]+)(?=\s|$)')
AUDIT_TYPES = {"1300": "SYSCALL", "1309": "EXECVE", "1306": "SOCKADDR"}
CONNECT_SYSCALLS = {"c000003e": "42", "c00000b7": "203"}
HIDDEN_SYSTEM_BINARY = re.compile(r"/usr/local/(?:s?bin)/\.[^./\s][^/\s]*")


class LinuxEvidenceFinding(Finding):
    timestamp_utc: UtcTimestamp | None


@dataclass(frozen=True)
class Connection:
    event: LinuxEventRecord
    companion: LinuxEventRecord
    pid: int
    image: str
    uid: int
    address: IPv4Address | IPv6Address
    port: int
    succeeded: bool


def basename(value):
    return PurePosixPath(value).name


def words(value):
    if not value or len(value) > 16_000:
        return []
    try:
        return shlex.split(value)
    except ValueError:
        return []


def exec_record(message):
    """Read a projected single-record audit event with its executable and argv."""
    if not message.startswith("EXECVE "):
        return None
    fields = {}
    for token in words(message.removeprefix("EXECVE ")):
        key, separator, value = token.partition("=")
        if not separator or key in fields:
            return None
        fields[key] = value
    image = basename(fields.get("exe", ""))
    if not image or not fields.get("uid", "").isdecimal() or basename(fields.get("a0", "")) not in {image, *SHELLS}:
        return None
    if basename(fields["a0"]) != image and image not in SHELLS:
        return None
    arguments = [fields[f"a{i}"] for i in range(1, len(fields)) if f"a{i}" in fields]
    if len(arguments) + 1 != sum(bool(re.fullmatch(r"a\d+", key)) for key in fields):
        return None
    parent = fields.get("ppid", "")
    return image, fields["uid"], int(parent) if parent.isdecimal() and len(parent) <= 10 else None, arguments


def nearby(prior, current, minutes):
    if prior is None:
        return None
    if prior.timestamp_utc is not None and current.timestamp_utc is not None:
        delta = current.timestamp_utc - prior.timestamp_utc
        return prior if timedelta() <= delta <= timedelta(minutes=minutes) else None
    if prior.timestamp_utc is not None or current.timestamp_utc is not None:
        return None
    left = LEGACY_TIME.fullmatch(prior.original_timestamp or "")
    right = LEGACY_TIME.fullmatch(current.original_timestamp or "")
    if not left or not right or left.group(1, 2) != right.group(1, 2):
        return None
    lh, lm, ls = map(int, left.group(3, 4, 5))
    rh, rm, rs = map(int, right.group(3, 4, 5))
    if not (lh < 24 and rh < 24 and lm < 60 and rm < 60 and ls < 60 and rs < 60):
        return None
    seconds = (rh - lh) * 3600 + (rm - lm) * 60 + rs - ls
    return prior if 0 <= seconds <= minutes * 60 else None


def audit_string(value):
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        return None
    try:
        result = bytes.fromhex(value).decode("utf-8")
    except UnicodeError:
        return None
    return None if "\x00" in result else result


def audit_connection(syscall, fields, event, companion):
    number = CONNECT_SYSCALLS.get(syscall.get("arch", "").casefold())
    success, exit_code = syscall.get("success"), syscall.get("exit", "")
    if (number is None or syscall.get("syscall") != number or
            not ((success == "yes" and exit_code == "0") or
                 (success == "no" and re.fullmatch(r"-[1-9][0-9]{0,9}", exit_code)))):
        return None
    image = audit_string(syscall.get("exe", ""))
    pid = syscall.get("pid", "")
    uid = syscall.get("euid", syscall.get("uid", ""))
    if (not image or not image.startswith("/") or not re.fullmatch(r"[0-9]{1,10}", pid)
            or int(pid) == 0 or not re.fullmatch(r"[0-9]{1,10}", uid)):
        return None
    saddr = fields.get("saddr", "")
    if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{56}", saddr):
        return None
    raw = bytes.fromhex(saddr)
    family = int.from_bytes(raw[:2], "little")
    if family == 2 and len(raw) == 16:
        address = ip_address(raw[4:8])
    elif family == 10 and len(raw) == 28:
        address = ip_address(raw[8:24])
    else:
        return None
    port = int.from_bytes(raw[2:4], "big")
    if not port or address.is_unspecified:
        return None
    return Connection(event, companion, int(pid), image, int(uid), address, port, success == "yes")


def native_evidence(events):
    """Join complete native audit pairs without changing the original records."""
    pairs = defaultdict(list)
    for event in events:
        if not isinstance(event, LinuxEventRecord) or not event.host or not event.message or len(event.message) > 16_000:
            continue
        if (event.service or "").casefold() not in {"audit", "auditd", "kernel"}:
            continue
        match = NATIVE_AUDIT.fullmatch(event.message.strip())
        if match:
            scope = (event.upload_id, event.host, match[2])
            pairs[scope].append((AUDIT_TYPES.get(match[1], match[1]), event, match[3]))

    executions, connections = {}, {}
    for parts in pairs.values():
        kinds = {part[0] for part in parts}
        if len(parts) != 2 or "SYSCALL" not in kinds or len(kinds) != 2 or not nearby(parts[0][1], parts[1][1], 1):
            continue
        system, other = sorted(parts, key=lambda part: part[0] != "SYSCALL")
        companion, anchor = parts[0][1], parts[1][1]
        syscall_fields, argument_fields = AUDIT_FIELDS.findall(system[2]), AUDIT_FIELDS.findall(other[2])
        syscall, arguments = dict(syscall_fields), dict(argument_fields)
        if len(syscall) != len(syscall_fields) or len(arguments) != len(argument_fields):
            continue
        if other[0] == "SOCKADDR":
            if connection := audit_connection(syscall, arguments, anchor, companion):
                connections[anchor.event_id] = connection
            continue
        pid, parent, uid = (syscall.get(key, "") for key in ("pid", "ppid", "uid"))
        count = arguments.get("argc", "")
        if (syscall.get("success") != "yes" or not all(re.fullmatch(r"[0-9]{1,10}", field) for field in (pid, parent, uid))
                or int(pid) == 0 or not re.fullmatch(r"[0-9]{1,3}", count) or not 1 <= int(count) <= 128):
            continue
        if set(arguments) != {"argc", *(f"a{i}" for i in range(int(count)))}:
            continue
        image_path = audit_string(syscall.get("exe", ""))
        argv = [audit_string(arguments[f"a{i}"]) for i in range(int(count))]
        if not image_path or not image_path.startswith("/") or any(value is None for value in argv):
            continue
        image, invoked = basename(image_path), basename(argv[0])
        if invoked != image and not (image in SHELLS and invoked in SHELLS):
            continue
        executions[anchor.event_id] = ((image, uid, int(parent), argv[1:]), int(pid), companion)
    return executions, connections


def download_address(url):
    try:
        return ip_address(urlsplit(url).hostname or "")
    except ValueError:
        return None


def outbound_attempt(message):
    """Read an outbound initial TCP SYN from an allowed firewall record."""
    match = UFW_ALLOW.fullmatch(message)
    if not match:
        return None
    fields, flags = {}, set()
    for token in match[1].split():
        key, separator, value = token.partition("=")
        if not separator:
            flags.add(key)
        elif key in FLOW_FIELDS:
            if key in fields:
                return None
            fields[key] = value
    if (set(fields) != FLOW_FIELDS or fields["IN"] or not fields["OUT"] or fields["PROTO"] != "TCP"
            or "SYN" not in flags or flags.intersection({"ACK", "FIN", "RST"})):
        return None
    ports = (fields["SPT"], fields["DPT"])
    if any(not (port.isascii() and port.isdecimal() and len(port) <= 5 and 0 < int(port) <= 65535) for port in ports):
        return None
    try:
        source, dest = ip_address(fields["SRC"]), ip_address(fields["DST"])
    except ValueError:
        return None
    if source.version != dest.version or source == dest:
        return None
    return (source, dest, int(ports[1])), int(ports[0])


def recorded_second(event):
    if event.timestamp_utc is not None:
        return event.timestamp_utc.replace(microsecond=0)
    stamp = LEGACY_TIME.fullmatch(event.original_timestamp or "")
    return (stamp[1], *(int(part) for part in stamp.groups()[1:])) if stamp else None


def matching_firewall(events, connections):
    """Return only one-to-one matches on the same host, endpoint and recorded second."""
    sockets, packets = defaultdict(list), defaultdict(list)
    for entry in connections.values():
        event = entry.event
        second = recorded_second(event)
        if second is not None and second == recorded_second(entry.companion):
            sockets[event.upload_id, event.host, entry.address, entry.port, second].append(entry)
    if not sockets:
        return {}
    for event in events:
        if isinstance(event, LinuxEventRecord) and (event.service or "").casefold() == "kernel":
            attempt = outbound_attempt((event.message or "").strip())
            if attempt:
                (_, address, port), _ = attempt
                key = event.upload_id, event.host, address, port, recorded_second(event)
                if key in sockets:
                    packets[key].append(event)
    return {entries[0].event.event_id: packets[key][0]
            for key, entries in sockets.items() if len(entries) == 1 and len(packets[key]) == 1}


def finding(event, title, reason, severity, related, *, network=False):
    cited = list(dict.fromkeys([*(prior.event_id for prior in related if prior), event.event_id]))
    limits = ["Rule evidence requires verification of authorization and outcome."]
    if event.timestamp_utc is None:
        limits.append("The export omits an absolute timestamp. Related records use file order and the recorded local time.")
    if severity == "lead":
        limits.append("Firewall records give connection attempts. Process identity, completed connections, and application protocol remain unverified.")
    data = LinuxEvidenceFinding(
        finding_id=canonical_hash([VERSION, title, event.event_id]),
        timestamp_utc=event.timestamp_utc,
        activity_class="network_activity_anomaly" if network or severity == "lead" else "process_or_service_anomaly",
        triage_priority={"critical": 90, "warning": 70, "lead": 45}[severity], evidence_event_ids=cited,
        explanation=reason, method="deterministic", limitations=limits,
    )
    return {"finding": data.model_dump(mode="json"), "window_id": None, "rule_version": VERSION,
            "title": title, "severity": severity, "platform": "linux",
            "source_record_index": event.record_index, "original_timestamp": event.original_timestamp}


def linux_findings(events):
    findings = []
    context = {}
    native, connections = native_evidence(events)
    firewall_matches = matching_firewall(events, connections)
    cited_firewall = set()
    lead_attempts = {}
    for event in events:
        if not isinstance(event, LinuxEventRecord) or not event.host or not event.message:
            continue
        scope = event.upload_id, event.host
        service = (event.service or "").casefold()
        message = event.message.strip()
        native_process = native.get(event.event_id)
        if native_process:
            process, pid, _ = native_process
            event = event.model_copy(update={"process_id": pid})
        else:
            process = exec_record(message) if service in {"audit", "auditd"} else None

        def remember(kind, key=None):
            context[scope, kind, key] = event

        def recent(kind, key=None, minutes=10):
            return nearby(context.get((scope, kind, key)), event, minutes)

        def flag(title, reason, *related, severity="warning", network=False):
            evidence = []
            for item in (*related, event):
                if item is None:
                    continue
                if part := native.get(item.event_id):
                    evidence.append(part[2])
                if connection := connections.get(item.event_id):
                    evidence.append(connection.companion)
                if item is not event:
                    evidence.append(item)
            entry = finding(event, title, reason, severity, evidence, network=network)
            findings.append(entry)
            return entry

        if connection := connections.get(event.event_id):
            download = recent("download-address", connection.address, minutes=60)
            started = recent("linked-service-start", minutes=60)
            if (connection.succeeded and download and started and nearby(download, started, 60)
                    and connection.uid == 0 and HIDDEN_SYSTEM_BINARY.fullmatch(connection.image)):
                firewall = firewall_matches.get(event.event_id)
                reason = (f"Audit reports a successful connect() by {connection.image} (PID {connection.pid}, UID 0) "
                          f"to {connection.address} on port {connection.port}. The same host recorded an earlier flagged "
                          "download to that address and a linked service start.")
                if firewall:
                    reason += " An outbound firewall record matches the endpoint and recorded second."
                    cited_firewall.add(firewall.event_id)
                flag("Hidden root executable connected to a linked address", reason, download, started, firewall, network=True)
        elif process:
            image, uid, parent, args = process
            command = args[1] if image in SHELLS and len(args) >= 2 and args[0] == "-c" else ""
            shell_origin = recent("remote-script", (uid, parent))
            root_origin = recent("root-shell", parent, minutes=45) if uid == "0" else None
            if re.match(r"^(?:/\S+/)?(?:curl|wget)\s+[^|]*https?://[^|]+\|\s*(?:/\S+/)?(?:ba|da|z)?sh(?:\s|$)", command):
                flag("Remote script piped into a shell", "Audit recorded a shell invocation that streams a remote response into another shell.", severity="critical")
                if event.process_id is not None:
                    remember("remote-script", (uid, event.process_id))
            elif shell_origin and image in {"curl", "wget"} and any(a.startswith(TEMP) for a in args) and (urls := [a for a in args if a.startswith(("http://", "https://"))]):
                flag("Linked download into a temporary directory", "A child of the flagged shell requested a remote download to temporary storage.", shell_origin)
                if len(urls) == 1 and (dest := download_address(urls[0])) is not None:
                    remember("download-address", dest)
            elif shell_origin and re.match(r"^(?:id|whoami)(?:\s|;|$)", command):
                flag("Host discovery from a flagged shell", "The linked shell invoked identity discovery.", shell_origin)
            elif uid == "0" and image in SHELLS and "-i" in args and (elevation := recent("pkexec", parent, minutes=2)):
                flag("Root shell after pkexec", "An interactive UID-0 shell records the flagged pkexec process as its parent.", elevation, severity="critical")
                if event.process_id is not None:
                    remember("root-shell", event.process_id)
                    remember("root-chain")
            elif uid == "0" and re.search(r"\bssh-(?:ed25519|rsa)\s+\S+.*>>\s*/root/\.ssh/authorized_keys(?:\s|$)", command):
                flag("Root SSH key append attempt", "Audit recorded a command appending an SSH key to root's authorized keys.", severity="critical")
                remember("root-key")
            elif image == "chattr" and "+i" in args and "/root/.ssh/authorized_keys" in args:
                flag("Root SSH key file made immutable attempt", "The command requested the immutable attribute on root's authorized keys.", severity="critical")
            elif root_origin and image == "cp" and len(args) == 2 and args[0].startswith(TEMP) and args[1].startswith("/usr/local/bin/."):
                flag("Hidden binary copied into a system path", "The linked root shell requested a copy from temporary storage into a hidden system executable path.", root_origin)
                remember("hidden-bin", args[1])
            elif root_origin and image == "tee" and len(args) == 1 and re.fullmatch(r"/etc/systemd/system/[\w.@-]+\.service", args[0]):
                flag("Systemd unit write attempt", "The linked root shell opened a system service definition for writing.", root_origin)
                remember("unit-write", basename(args[0]))
            elif image in {"iptables", "ip6tables"} and set(args) & {"-F", "--flush"}:
                flag("Firewall rules flush attempt", "The recorded command requested a firewall chain flush.", severity="critical")
            elif image == "systemctl" and args in (["stop", "auditd"], ["stop", "auditd.service"]):
                flag("Audit service stop attempt", "The recorded command requested stopping auditd.", severity="critical")
                remember("audit-stop")
            elif image == "auditctl" and uid == "0" and args in (["-e", "0"], ["-e0"]):
                flag("Kernel auditing disable attempt", "Audit recorded a root command requesting that kernel auditing be disabled.", severity="critical")
            elif root_origin and image == "rm" and any(a.startswith("/var/log/") for a in args):
                flag("Log deletion attempt", "The linked root shell invoked removal of a path under /var/log.", root_origin, severity="critical")

        elif service == "sudo" and (audit_command := SUDO_AUDIT_COMMAND.fullmatch(message)):
            if audit_command[1]:
                flag("Audit service stop attempt", "Sudo recorded a request to stop auditd as root.", severity="critical")
                remember("audit-stop")
            else:
                flag("Kernel auditing disable attempt", "Sudo recorded a root command requesting that kernel auditing be disabled.", severity="critical")
        elif service == "sudo" and (denied := SUDO_DENIED.match(message)) and basename(denied[2]) in SHELLS:
            flag("Sudo denied a root shell request", "Sudo reported a policy denial for an attempt to run a shell as root.")
            remember("sudo-denied", denied[1])
        elif service == "sudo" and (failure := SUDO_AUTH.match(message)) and (denial := recent("sudo-denied", failure[1], minutes=2)):
            flag("Authentication failure after denied root shell request", "The same account appears in a nearby denied shell request and sudo authentication failure.", denial)
        elif service == "pkexec" and re.fullmatch(r"\S+: Executing command \[USER=root\] \[TTY=unknown\] \[CWD=(?:/dev/shm|/tmp)(?:/[^]]*)?\] \[COMMAND=/(?:usr/)?bin/(?:bash|dash|sh)\]", message):
            flag("Noninteractive pkexec request for a root shell", "The event records pkexec requesting a root shell from temporary storage.")
            if event.process_id is not None:
                remember("pkexec", event.process_id)
        elif service == "useradd" and (account := ACCOUNT.fullmatch(message)) and not account[2].startswith("/home/") and basename(account[3]) in SHELLS:
            remember("account", account[1])
        elif service == "passwd" and (changed := re.fullmatch(r"pam_unix\(passwd:chauthtok\): password changed for (\S+)", message)):
            remember("password", changed[1])
        elif service == "usermod" and (group := re.fullmatch(r"add '([^']+)' to group '(?:sudo|wheel)'", message)):
            user = group[1]
            created = recent("account", user)
            if created and recent("root-chain"):
                flag("New interactive account granted administrator group", "A recent non-home interactive account was granted an administrator group after the linked root shell.", created,
                     recent("password", user), severity="critical")
        elif service == "systemd":
            started = re.fullmatch(r"Started ([\w.@-]+\.service)\.", message)
            if started and (write := recent("unit-write", started[1])):
                flag("Service started after linked unit write", "The reported service name matches a recently written unit from the linked shell.", write)
                remember("linked-service-start")
            elif re.fullmatch(r"Stopping (?:Security Auditing Service|auditd(?:\.service)?)\.{1,3}", message) and (stop := recent("audit-stop", minutes=2)):
                flag("Audit service stopping reported", "Systemd reported the audit service stopping after a matching stop request.", stop, severity="critical")
        elif service == "crontab" and message == "(root) REPLACE (root)":
            remember("root-crontab")
        elif service == "cron" and (job := re.fullmatch(r"\(root\) CMD \((.+)\)", message)):
            args = words(job[1])
            if args and (copy := recent("hidden-bin", args[0], minutes=30)):
                flag("Root cron launched a linked hidden executable", "The cron command matches a recently copied hidden executable.",
                     copy, recent("root-crontab"))
        elif service == "bash" and re.fullmatch(r"HISTFILE unset; history -c executed by root", message) and (origin := recent("root-shell", event.process_id, minutes=45)):
            flag("Shell history clearing reported", "The log reports history clearing from the linked root shell.", origin, severity="critical")
        elif service in {"sshd", "sshd-session"} and event.actor == "root" and event.process_id is not None:
            if event.event_type == "auth_success" and message.startswith("Accepted publickey for root ") and (key := recent("root-key", minutes=120)):
                flag("Root public-key login after a recorded key change", "The log records a root public-key login after the earlier key append attempt. The accepted key needs independent verification.", key)
                remember("root-login", event.process_id)
            elif event.event_type == "session_open" and (login := recent("root-login", event.process_id, minutes=2)):
                flag("Root SSH session opened after linked login", "The root session and flagged login share a recorded SSH process ID.", login)
        elif service == "bash" and (entry := COMMAND.fullmatch(message)):
            args = words(entry[2])
            if len(args) >= 4 and basename(args[0]) == "tar" and args[1] in {"czf", "-czf"} and args[2].startswith(TEMP) and "/etc/shadow" in args[3:]:
                flag("Sensitive archive staging attempt", "The recorded archive command includes a credential file and targets temporary storage.", severity="critical")
                remember("archive", (entry[1], args[2]))
            elif len(args) >= 4 and basename(args[0]) == "curl" and args[1] in {"-T", "--upload-file"} and args[3].startswith(("http://", "https://")) and (stage := recent("archive", (entry[1], args[2]))):
                flag("Upload attempt for staged sensitive archive", "A recorded upload references the same archive and terminal as the staging command.", stage, severity="critical")
        elif service == "kernel" and (attempt := outbound_attempt(message)):
            peer, source_port = attempt
            download = recent("download-address", peer[1], minutes=60)
            started = recent("linked-service-start", minutes=60)
            if not download or not started or not nearby(download, started, 60):
                continue
            prior = recent("outbound-attempt", peer, minutes=45)
            if (prior and nearby(started, prior, 60) and nearby(download, prior, 60)
                    and outbound_attempt(prior.message.strip())[1] != source_port
                    and not recent("network-lead", peer, minutes=60)):
                entry = flag("Repeated outbound connection attempts to a linked address",
                     "The same host recorded two outbound TCP SYNs from different source ports to the same address and destination port. "
                     "An earlier flagged download request targeted that address, and the host recorded a linked service start before the attempts.",
                     download, started, prior, severity="lead")
                lead_attempts[entry["finding"]["finding_id"]] = {prior.event_id, event.event_id}
                remember("network-lead", peer)
            remember("outbound-attempt", peer)
    return [entry for entry in findings
            if entry["severity"] != "lead" or not lead_attempts[entry["finding"]["finding_id"]] <= cited_firewall]
