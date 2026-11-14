# Sentinel V4.5.3 operations

## Live watches and saved evidence

Start a watch on **Live logs**, then navigate to another page. The local
Sentinel process continues reading the source. Return to **Live logs** and
select it in **Running watches**. The browser tab remembers its last watch
while it is running. **Set up another watch** detaches the view and makes room
for another source.

Use **Stop watch**, sign out, or stop the Sentinel process to end collection.
Closing the browser tab alone leaves collection active. A watch also ends if
the sign-in expires or its existing failure or storage limits are reached.
Background collection does not extend the browser session's idle lifetime.

In **SIEM Agents**, green **Connected** identifies a reachable host. An
additional **Partial collection** badge indicates that some sources need
attention. Yellow **View paused** freezes browser updates to the selected
host's detail while SSH keeps collecting. Red identifies a disconnected or
blocked host. The green **Live** tag indicates enabled live saving while the
host is connected. Automatic refresh preserves the visible review position
and open supporting records for findings that remain on the page.

**Save Live Log** archives up to 50 recent native records and continues with
bounded batches of at most 256 records or 4 MiB. Timing, record size, format,
and early critical saves can make individual files smaller. Raw source bytes
are preserved. Critical flags from managed review stay visible in saved
imports when the relevant records span batches. If managed review raises a
previously saved record to critical during that capture, its saved import
gets the critical flag too. Reanalysis retains those flags. The underlying
managed evidence still follows its retention limits.

Use **Download profile** and **Import host profile** to move host settings.
Downloads use `sentinel-host-DISPLAYNAME.json`, with characters that are
invalid in filenames replaced. Each password field has a reveal control
for checking the typed value.

## Collector coverage and the library

The **Limited coverage** line identifies the affected collector or file on
an otherwise connected host. Open **View collector details** for the reason.
If a disabled Windows channel is required, have an authorized administrator
check it in Event Viewer. On a Linux host that already has the required
journal coverage, **Edit host** can turn off the optional **Authentication
log files** module. For required files, an authorized administrator must
review the SSH account's read access. Sentinel reports these source settings
and permissions without changing the endpoints.

**Search saved logs** matches full filenames across the library. Results
use six compact rows per page, with **Previous** and **Next** when needed.
The full filename is visible on hover or after opening the entry. The
three-dot menu and the account roster remain accessible.

## Review of the supplied captures

| Capture | Records | Interpretation |
| --- | ---: | --- |
| Mail, larger batch | 135 | Allowed connections and local port binds dominate. Mail, file sharing, PowerShell, and system processes appear in those records. The hourly weather task reported action exit code 0. |
| Mail, shorter batch | 50 | Connection and port-bind records dominate. The quarter-hour heartbeat reported action exit code 0. |
| Windows All channels | 106 | Mostly Windows startup and maintenance telemetry. The three BITS startup-type changes remain configuration review items. Two remote NTLM events call for checking the source and account. |

All 291 records parsed and received activity categories. No warning or
critical rule fired on these files. Firewall permission, a zero task exit
code, and a familiar executable name describe what was recorded. Verify
unexpected activity against the approved task, process path, and peer.
[Windows Filtering Platform event reference](https://learn.microsoft.com/en-us/windows/server/identity/ad-ds/plan/appendix-l--events-to-monitor)

## Verification

The full Windows regression suite passed 825 tests with six Linux-only
checks skipped. Eleven JavaScript tests passed. A local Edge workflow checked
status badges, scroll anchoring, password reveal, and leaving and rejoining
a live watch. The clean Windows launcher and desktop password toggle passed.
