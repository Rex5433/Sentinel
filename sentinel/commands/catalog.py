"""Original fixed local-observation commands, source reviewed against linked manuals.

No values from imported logs or user questions are interpolated into commands.
Team operational review and permission remain required before manual use.
"""

from copy import deepcopy
from hashlib import sha256
import json
from textwrap import indent

VERSION = "read-only-reference-v4"
CATEGORIES = ("log_collection", "authentication", "services", "processes", "network", "users")
REVIEW = {
    "date": "2026-11-03", "reviewer": "Codex-assisted source review",
    "status": "source_reviewed_team_review_pending",
    "scope": "Fixed local observation only; manual Team 84 environment/permission review still required. Not runtime-validated on all target systems.",
}
LOG_COLLECTION_REVIEW = REVIEW | {"date": "2026-11-07"}


def _entry(identifier, platform, category, title, command, purpose, permissions, assumptions, limitations, reference):
    return dict(id=identifier, platform=platform, category=category, title=title, command=command,
                purpose=purpose, permissions=permissions, assumptions=assumptions,
                limitations=limitations, reference=reference, read_only=True,
                execution="copy_only", review=REVIEW)


WIN_EVENT_REFERENCE = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1"
JOURNAL_REFERENCE = "https://www.freedesktop.org/software/systemd/man/latest/journalctl.html"
WINDOWS_PROJECTION = """ForEach-Object {
    $record = $_
    $data = @{}
    $xml = [xml]$record.ToXml()
    $message = $null
    try { $message = $record.FormatDescription() } catch { $message = $null }
    $unnamed = @($xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data'][not(@Name)]") | ForEach-Object { $_.InnerText })
    foreach ($field in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data'][@Name]")) {
        $name = $field.GetAttribute('Name')
        if ($data.ContainsKey($name)) { $data[$name] = @($data[$name]) + $field.InnerText }
        else { $data[$name] = $field.InnerText }
    }
    if ($record.Id -eq 1102) {
        foreach ($field in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='UserData']/*[local-name()='LogFileCleared']/*[not(*)]")) {
            if (-not $data.ContainsKey($field.LocalName)) { $data[$field.LocalName] = $field.InnerText }
        }
    }
    [ordered]@{
        Id = $record.Id
        TimeCreated = $record.TimeCreated.ToUniversalTime().ToString('o')
        MachineName = $record.MachineName
        LogName = $record.LogName
        ProviderName = $record.ProviderName
        RecordId = $record.RecordId
        Message = $message
        UnnamedEventData = $unnamed
        EventData = $data
    } | ConvertTo-Json -Compress -Depth 6
}"""


def _windows_query(channel, ids, projection, *, provider=None, limit=100):
    source = f"LogName='{channel}'"
    if ids:
        source += f"; Id={','.join(map(str, ids))}"
    if provider:
        source += f"; ProviderName='{provider}'"
    query = (f"Get-WinEvent -FilterHashtable @{{{source}; StartTime=(Get-Date).AddHours(-1)}} "
             f"-MaxEvents {limit} -ErrorAction Stop | {projection}")
    return (
        f"try {{\n{indent(query, '    ')}\n}} catch {{\n"
        "    if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'NoMatchingEventsFound') { throw }\n"
        "    Write-Warning 'No matching events in the last hour.'\n"
        "}"
    )


def _windows_export(identifier, title, channel, ids, purpose, coverage, *, provider=None, limit=100):
    command = _windows_query(channel, ids, WINDOWS_PROJECTION, provider=provider, limit=limit)
    return _entry(
        identifier, "windows", "log_collection", title, command,
        f"{purpose} Paste the resulting JSON Lines into Logs with Windows selected.",
        f"Read access to the Windows {channel} event log.",
        "Windows PowerShell 5.1+ on the authorized host. Copy the entire command block into PowerShell.",
        f"Latest {limit} matching records from the past hour. {coverage} Copy only JSON output. "
        "Named event fields can contain sensitive data. Review before sharing.",
        WIN_EVENT_REFERENCE,
    ) | {"output_format": "windows-jsonl", "review": LOG_COLLECTION_REVIEW}


def _linux_export(identifier, title, arguments, purpose, coverage):
    return _entry(
        identifier, "linux", "log_collection", title,
        "journalctl --since '1 hour ago' --no-pager --quiet --lines=100 --output=json" + arguments,
        f"{purpose} Paste the resulting JSON Lines into Logs with Linux selected.",
        "Read access to the selected journal entries. Run as an authorized account with journal access.",
        "Linux with systemd-journald on the authorized host. Run locally or in your existing SSH session.",
        f"Latest 100 matching entries from the past hour. {coverage} Copy only JSON output. "
        "Journal fields can contain sensitive data. Review before sharing.",
        JOURNAL_REFERENCE,
    ) | {"output_format": "linux-journal-json", "review": LOG_COLLECTION_REVIEW}


ENTRIES = (
    _windows_export(
        "windows-security-jsonl", "Export recent Windows Security events", "Security", (),
        "Collect a mixed sample of recent events from the Security channel.",
        "Busy hosts can fill the cap quickly. Audit policy controls which events exist.", limit=25,
    ),
    _windows_export(
        "windows-logon-jsonl", "Export Windows logons and logoffs", "Security", (4624, 4625, 4634, 4647, 4648),
        "Collect successful and failed logons, logoffs and explicit-credential events for analysis.",
        "Coverage depends on audit policy and retention.",
    ),
    _windows_export(
        "windows-process-task-jsonl", "Export Windows process, task and audit events", "Security",
        (1102, 4688, 4697, 4698, 4699, 4700, 4701, 4702),
        "Collect audit-log clears, process starts, service installations and scheduled task changes.",
        "Process command lines appear only when the host records them.",
    ),
    _windows_export(
        "windows-account-jsonl", "Export Windows account and group events", "Security",
        (4672, 4720, 4722, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757),
        "Collect privilege assignment, account lifecycle and group membership events.",
        "Only the selected event IDs on this host are included.",
    ),
    _windows_export(
        "windows-service-jsonl", "Export Windows service events", "System", (7036, 7040, 7045),
        "Collect Service Control Manager state, startup configuration and installation events.",
        "Only Service Control Manager events are included. Some entries are retained as evidence without a rule match.",
        provider="Service Control Manager",
    ),
    _linux_export(
        "linux-journal-jsonl", "Export recent Linux journal entries", "",
        "Collect a mixed recent sample across visible journal sources.",
        "Busy hosts can fill the 100-entry cap quickly. The sample only includes records visible to your account.",
    ),
    _linux_export(
        "linux-ssh-jsonl", "Export Linux SSH activity",
        " SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session",
        "Collect SSH sign-ins, attempts and session activity.",
        "Only the two named OpenSSH identifiers are included.",
    ),
    _linux_export(
        "linux-privilege-jsonl", "Export Linux sudo and audit activity",
        " SYSLOG_IDENTIFIER=sudo SYSLOG_IDENTIFIER=su SYSLOG_IDENTIFIER=audit SYSLOG_IDENTIFIER=auditd + _TRANSPORT=audit",
        "Collect privilege-related messages and audit entries available in the journal.",
        "Audit records depend on host configuration. A separate audit file may contain additional evidence.",
    ),
    _linux_export(
        "linux-systemd-jsonl", "Export Linux systemd manager events", " SYSLOG_IDENTIFIER=systemd",
        "Collect system manager messages about service activity.",
        "Unit application messages from other identifiers are outside this selection.",
    ),
    _entry(
        "linux-auth-file-text", "linux", "log_collection", "Export legacy Linux auth log lines",
        "if [ -r /var/log/auth.log ]; then\n"
        "    tail -n 100 -- /var/log/auth.log\n"
        "elif [ -r /var/log/secure ]; then\n"
        "    tail -n 100 -- /var/log/secure\n"
        "else\n"
        "    printf '%s\\n' 'No readable auth.log or secure file.' >&2\n"
        "fi",
        "Collect recent authentication text from the first readable supported path. Paste into Logs with Linux selected.",
        "Read access to /var/log/auth.log or /var/log/secure.",
        "Linux shell with GNU tail and conventional syslog-formatted authentication logs.",
        "Up to 100 lines from one file. Rotated logs are outside this export. Legacy timestamps may omit the year and timezone.",
        "https://www.gnu.org/software/coreutils/manual/html_node/tail-invocation.html",
    ) | {"output_format": "linux-text", "review": LOG_COLLECTION_REVIEW},
    _entry("windows-auth", "windows", "authentication", "Recent authentication events",
           _windows_query("Security", (4624, 4625), "Select-Object TimeCreated, Id, MachineName, Message"),
           "Compare recent successful/failed logons with an authorized lab scenario.",
           "Security log read rights; elevation may be required by local policy.",
           "Windows PowerShell 5.1+ on the Windows host being investigated; relevant audit logging enabled.",
           "Latest 100 matching records from the last hour on that host; missing/rotated/disabled audit events are not evidence of safety. This does not export Sentinel's structured EventData fields.",
           "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1"),
    _entry("windows-services", "windows", "services", "Local service state",
           "Get-Service | Select-Object Name, DisplayName, Status",
           "Compare observed service names/state with the expected inventory.",
           "Local service query rights; some services may deny access.", "Windows PowerShell 5.1+ on the target Windows host.",
           "Current state only; does not establish installation time, legitimacy, or past activity.",
           "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-5.1"),
    _entry("windows-processes", "windows", "processes", "Local process snapshot",
           "Get-Process | Select-Object Id, ProcessName, CPU",
           "Inspect current process IDs/names and cumulative CPU time.", "Standard user for basic fields; protected process fields may be unavailable.",
           "Windows PowerShell 5.1+ on the target Windows host.", "Snapshot only; CPU is accumulated time, not utilization percent. A name does not prove executable identity.",
           "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-5.1"),
    _entry("windows-network", "windows", "network", "Local TCP connections",
           "Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess",
           "Inspect numeric TCP endpoints and owning PIDs.", "Local network query rights; visibility may vary by account/policy.",
           "Windows with the NetTCPIP PowerShell module installed.", "Current TCP only; no UDP, packet content, history, scanning, or proof an endpoint is malicious.",
           "https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2019-ps"),
    _entry("windows-users", "windows", "users", "Local user inventory",
           "Get-LocalUser | Select-Object Name, Enabled, LastLogon",
           "Compare local account inventory with the approved lab inventory.", "Local account query rights; policy may restrict visibility.",
           "64-bit Windows PowerShell 5.1 and Microsoft.PowerShell.LocalAccounts on a member or standalone server.",
           "Local accounts only; LastLogon can be absent and does not prove complete authentication history.",
           "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1"),
    _entry("windows-ad-users", "windows", "users", "Sample Active Directory users",
           "Get-ADUser -Filter '*' -ResultSetSize 100 | Select-Object SamAccountName, Enabled, DistinguishedName",
           "Inspect a bounded sample of users in the current authorized domain.",
           "Directory read access on the authorized domain.",
           "Windows PowerShell 5.1 and the ActiveDirectory module from AD DS tools or RSAT.",
           "Up to 100 visible domain users. For member-server local accounts use Local user inventory.",
           "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2019-ps")
    | {"review": LOG_COLLECTION_REVIEW},
    _entry("linux-auth", "linux", "authentication", "Recent SSH journal entries",
           "journalctl --since '-1 hour' --no-pager -n 100 -o short-iso SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session",
           "Compare recent SSH journal messages with expected lab logins.", "Read access to the system journal (often root or an approved journal-reading group). No sudo is automatically added.",
           "Linux with systemd/journalctl; SSH writes with one of the two named identifiers.", "At most 100 entries in the last hour. Distro/logging setups differ; no entries does not mean no SSH activity. Does not read legacy auth.log automatically.",
           "https://www.freedesktop.org/software/systemd/man/256/journalctl.html"),
    _entry("linux-services", "linux", "services", "Loaded systemd services",
           "systemctl list-units --type=service --all --no-pager",
           "Compare currently loaded services and states with the expected inventory.", "Standard user for list-units on typical systems; local policy may differ.",
           "Linux with a running systemd system manager.", "Loaded units only, not all installed unit files. State alone does not establish legitimacy or change history.",
           "https://www.freedesktop.org/software/systemd/man/latest/systemctl"),
    _entry("linux-processes", "linux", "processes", "Local process snapshot",
           "ps -eo pid,ppid,user,comm",
           "Inspect process IDs, parents, owners, and executable names.", "Standard user; procfs/container policies can restrict visibility.", "Linux with procps ps.",
           "Snapshot only; executable names are not verified paths or integrity evidence. Arguments are intentionally omitted.",
           "https://man7.org/linux/man-pages/man1/ps.1.html"),
    _entry("linux-network", "linux", "network", "Local TCP sockets",
           "ss -tn",
           "Inspect numeric non-listening TCP endpoints without a network scan.", "Standard user for endpoint information; namespace/policy limits apply.",
           "Linux with iproute2 ss.", "Current non-listening TCP only; excludes listening sockets/UDP and historical traffic. No ownership or packet inspection.",
           "https://www.man7.org/linux/man-pages/man8/ss.8.html"),
    _entry("linux-users", "linux", "users", "Local passwd inventory",
           "getent -s files passwd",
           "Read the local files-backed passwd account inventory without directory-service lookups.", "Standard user for local passwd entries; does not access password hashes.",
           "Linux with GNU libc getent supporting -s files.", "Local files backend only; deliberately omits LDAP/NIS/domain users. Listing an account does not establish legitimacy or login permission.",
           "https://man7.org/linux/man-pages/man1/getent.1.html"),
)


def catalog_hash():
    return sha256(json.dumps(ENTRIES, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def commands(*, platform=None, category=None, q=""):
    needle = q.casefold().strip()
    return deepcopy([entry for entry in ENTRIES
                     if (platform is None or entry["platform"] == platform)
                     and (category is None or entry["category"] == category)
                     and (not needle or needle in " ".join((entry["title"], entry["purpose"], entry["command"])).casefold())])


def command_ids(category, platform=None):
    return [entry["id"] for entry in commands(category=category, platform=platform)]
