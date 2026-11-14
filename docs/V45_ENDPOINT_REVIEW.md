# Sentinel V4.5 endpoint review

## Account tags

In **Logs → Account roster**, add the exact username and select its platform.
For one reporting host, copy the computer name shown on an event card. The
reporting name can differ from the SSH address or the display name in SIEM
Agents. Choose **All hosts on this platform** if the same account name belongs
to the team across that platform. A host-specific entry overrides an all-host
entry. Linux account matching is case-sensitive. Windows uses the recorded
`DOMAIN\user` when a domain is present.

Linux tags cover explicit SSH disconnect accounts, sudo commands, and sudo
session openings that name the initiating account. A failed sign-in or invalid
account record identifies a sign-in target. A sudo session closure can name
only the elevated account and cannot establish who initiated it. Account tags
appear alongside security flags.

The Linux review surfaces root-shell requests for context. It warns on a root
editor targeting known SSH, sudo, PAM, or audit configuration and on journal
vacuum requests. A sudo command records the request. It cannot establish that
the editor wrote the file or that cleanup completed.

## Managed findings

Recent findings appear above collectors and are ordered by severity. Expand
**Supporting records** to retrieve retained evidence, including records older
than the recent event list. Collector status, host settings, and local evidence
retention have separate expandable sections. For a longer review, use
**Host timeline** or the flagged recent-events filter.

Host controls are above **Recent findings**. Choose **Critical review only**
to narrow the list. **Pause updates** holds the selected host's view in place
while its scheduled collection continues. **Resume updates** reloads the
latest records. The browser remembers paused hosts across reloads and shows
**View paused** beside the host name. The sidebar still tracks SSH health.
A manual **Refresh** or host action can refresh a paused view.

**Download profile** saves shareable SSH settings as JSON. In **Add host**,
**Import agent profile** fills the form. Review the destination and select
**Test connection**. Each computer needs its own trusted host key and local
credentials. The export contains host and account details but excludes
passwords, key paths, trusted keys, and captured evidence.

**Automatic** authentication tries a key first and falls back to a supplied
password after key rejection. The password stays in memory. **Auto detect**
lets you choose Windows and Linux collectors separately before the test.

A Windows query with zero matches shows **No new events**. A disabled,
missing, or permission-denied channel still shows its own diagnostic. Linux
hosts using only the journal can show **Optional · absent** for unused
traditional log files. A previously collected file that disappears is still
reported as unavailable. A capped inventory snapshot is a successful read.

**Save Live Log** includes up to 50 recent retained native records and then
saves new records to **Logs** in bounded batches. A critical finding, a
256-record backlog, or five minutes can trigger a save on the next completed
pull. **Stop Live Save** saves pending records and stops that capture. Collection
can continue after stopping live save. Capture intent persists across app
restarts and follows the host's connection. A full library stops new saves
until space is available. Host retention limits still apply.

Defender events identify the reported detection, protection action, or settings
change. A detection and its subsequent quarantine are separate observations.
The SIEM SSH command inventory uses native reads, including `Get-WinEvent`,
`auditpol /get`, and `journalctl`. Sentinel does not request quarantine, delete
remote evidence, clear remote logs, or change endpoint audit settings.
**Clear Sentinel's local evidence** affects the local database only. Normal SSH
authentication and process execution may appear in the endpoint's own audit
trail. A Defender record alone cannot establish what caused a detection.
[Defender event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

## Passive scan coverage

Enable the **Network endpoints and firewall events** module on a Windows host,
or **Network endpoints and kernel firewall events** on Linux. Windows can read
existing Security records for Windows Filtering Platform connection and packet
audits. Linux reads the kernel/UFW journal and recognizes structured UFW packet
records. Scoped collection works only where the account can read the source.
Existing enabled profiles with the network module selected include these reads.
No collector changes audit policy or turns on firewall logging.
[Windows Filtering Platform audit reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)
[systemd journalctl reference](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)

The review warns when one source contacts at least 12 distinct TCP or UDP
destination ports on the same host and destination address within 60 seconds.
For Linux TCP it uses inbound initial SYN evidence. The rule requires timestamped
records and ignores repetitions on a single port. The pattern can indicate a
scan or authorized activity. A collector can miss an Nmap scan if the target
never logs the probes, if permissions prevent the read, or if the scan falls
outside the rule. Socket snapshots can miss short-lived probes. An authorized
packet capture imported into **Network** provides another source of evidence.

## Local verification

All six supplied exports imported through the local API. Four unique exports
contained 574 records with zero rejects. All received activity labels. With the
exact Linux account `blueteam` configured for all Linux hosts, 67 records
received roster tags. One Linux export showed two root-shell requests for
context. The other produced no findings. One Windows export showed two critical findings for audit-log
clearing and a severe Defender detection, plus two context findings for an audit
policy change and a Defender action. The other Windows export produced no
findings. The samples do not establish a scan ground truth.

The browser smoke test used mocked APIs. Linux command validation used Bash
and a mocked journal. Windows and Linux scan tests used authored records.
The final Windows run passed 820 Python tests and skipped six Linux-only tests.
The 11 JavaScript tests, Edge workflow, and fresh Windows launcher check passed.
Validate actual endpoint permissions and expected audit sources over the
authorized VPN before relying on the view.
