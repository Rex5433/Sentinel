# Sentinel V3 managed SSH monitoring

**SIEM Agents** manages outbound SSH collection. **Wazuh Tools** opens the
separate Wazuh integration. **Live logs** still has the manual SSH watch and
adds a **Managed SSH feeds** panel for recent events from registered hosts.

## Connect a host

1. Select **Stop Sentinel** in the old launcher's control window, or press
   Ctrl+C in its console. Reopen **Sentinel V5.lnk** and connect your authorized
   VPN before testing a remote host.
2. Verify the server's SSH fingerprint independently and accept that exact key
   in local OpenSSH. Use the same address and port in Sentinel. Its connection
   test displays SHA256 fingerprints and pins the accepted key for enrollment.
3. Open **SIEM Agents → Add host**. Enter the display name, SSH host, port,
   account, and collection interval. Select **SSH key** and enter a local
   private-key path, or leave it blank to use an available local key or SSH
   agent. An encrypted key can use its matching public key and a local signing
   agent. The password option holds the credential in memory for the session.
4. Choose the operating system or use **Auto Detect**, then select modules.
   Run **Test connection**. Check which collectors responded and which were
   unavailable. Save the tested configuration and choose **Connect**.
5. Check each collector's status. **Timeline** filters managed events by host,
   OS, collector, event category, severity, account, or time. **Save to Logs**
   copies recent native evidence of the latest format into the normal library
   and runs its standard checks.

Live Logs key-only mode also checks the selected collector at **Connect** and
reuses the pinned connection at **Start watch**. A readable source with zero
matching events can be a successful read. Check the selected channel and the
SSH account's log permissions if the source is unavailable.

## Troubleshooting

| Sentinel reports | Check |
| --- | --- |
| Network error or retrying | Confirm the VPN is connected and the target's SSH port is reachable from the machine running Sentinel. A change to Sentinel's VPN client address needs no profile edit. |
| Host key unavailable or changed | Verify the remote host fingerprint independently. Use the same hostname or IP and port in OpenSSH and Sentinel. Re-enroll a managed host after a verified rotation. |
| Key rejected | Confirm the selected account is authorized for that key and the private-key path is readable on the Sentinel machine. For a passphrase-protected key, load it into the local SSH agent before connecting. |
| Collector error or partial coverage | Check the platform, selected sources, and the SSH account's permissions. Other readable collectors can continue. |
| Collector gap | Export any records still available for the missing interval before resetting that collector. |

## Collection scope

| Windows | Linux |
| --- | --- |
| Security authentication, account and group changes, and optional domain-controller authentication events | SSH and login journal, sudo and account-management journal |
| Optional process-creation events and current process inventory | Optional process inventory and service state |
| System, Application and accessible Defender events, audit-policy inventory, and optional services, startup entries and scheduled tasks | Optional service and cron journal, native audit journal, and file-backed logs |
| Optional TCP, UDP and interface snapshots | Optional sockets, interfaces, and metadata and hashes for selected readable files |

Each Windows log stream uses a server-side filter with Windows PowerShell 5.1
compatible commands. Linux modules use the native tools available to the SSH
account. File-backed collection reads fixed auth and syslog paths and holds its
position if identity or continuity changes. Legacy syslog can omit the year and
time zone. Inventory snapshots describe observed state and can omit activity
between reads. Remote commands can produce native audit entries.
[Microsoft Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)
[systemd journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl)

Managed events use Sentinel's normal parsers, account labels and deterministic
rules. Managed review also flags additions to identified privileged Windows
groups and records context findings for new observed listeners or selected file
changes. Snapshot comparisons start from the first comparable observation. They
identify changes for review. The initial state needs independent verification
before treating it as an approved baseline.

## Interruptions and limits

- Enabled hosts use independent sessions. A process lease prevents two Sentinel
  processes from polling the same store. The normal single-worker launcher is
  the supported way to start Sentinel. Restarting resumes enabled key-based
  hosts. Password-based hosts ask for their password again.
- Transport failures close the old connection and retry with bounded backoff and
  jitter. Authentication rejection or a changed pinned key waits for operator
  action. A changed key requires independent verification and fresh enrollment.
- Each committed batch advances its collector bookmark in the same SQLite
  transaction as the evidence. A missing bookmark or a rotated log file pauses
  that stream. Preserve an export of the missing interval if available, then
  choose **Reset gap** to start at the source's latest bounded sample.
- Defaults are three concurrent collection cycles, 32 registered hosts,
  64 new Windows or journal records per page plus the anchor, and a 1 MiB output
  cap. Cycle, connection, retry and output settings are listed in `.env.example`.
  Integrity runs at most once every five minutes per host. Initial samples and
  retained histories have bounds.
- Managed event storage caps retained evidence at 8,000 events per host,
  50,000 events overall, and 128 MiB of event payloads. **Remove** retires the
  connection and preserves its Timeline evidence. Clear retained events
  explicitly on a paused host when needed.
- Closing the page leaves explicitly enabled monitoring running in the local
  Sentinel process. Sign-out stops active transports. Sign-in or a fresh
  launch resumes enabled profiles. Use **Disconnect** to disable a host across
  launches. To roll back the feature operationally, disconnect the hosts and
  keep the local evidence store for later review.

## VPN field check

Start with one authorized Windows host and one authorized Linux host. Compare
each collector's latest evidence with a source export. For a recovery check,
note the last record or cursor, interrupt the VPN, and verify that the host
shows a retry. After reconnecting the VPN, compare the recovered records with
the source export. Confirm gaps are visible and repeated records appear once
within the retention window.

## Local verification

The Windows regression run passed 814 Python tests and skipped six Linux-only
checks. The 11 JavaScript tests and the V3 launcher smoke test also passed.

The key-only Live Logs test used an encrypted loopback SSH connection from
**Connect** through **Start watch** and the first poll. Separate loopback
checks enrolled Windows and Linux profiles with synthetic source records and
verified incremental collection and deduplication in Timeline. Mock tests
covered interrupted transport, retry, checkpoint recovery after restart, and
collector errors. The dashboard workflow passed in Edge with mocked APIs.
Windows collector scripts ran locally in Windows PowerShell 5.1 and PowerShell 7
with mocked event and inventory commands. VPN routing and real endpoint log
permissions remain part of the field check.
