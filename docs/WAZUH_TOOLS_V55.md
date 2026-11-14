# Wazuh Tools in Sentinel V5.5

Start Sentinel with **Start Sentinel.vbs** on Windows and open **Wazuh Tools**.
Each laptop saves a local SSH profile, dashboard URL, authorized targets and
scan history. Teammates need Sentinel and a route to the host laptop on the
private hotspot. Nmap runs at `/usr/bin/nmap` on the Linux Wazuh VM.

| Laptop | SSH host | SSH port | Dashboard HTTPS URL |
| --- | --- | ---: | --- |
| Host | `127.0.0.1` | `2222` | `https://127.0.0.1:8443` |
| Teammate | Host laptop's hotspot IP | `2222` | `https://HOTSPOT_IP:8443` |

The VirtualBox NAT SSH forward maps host TCP `2222` to guest TCP `22` if
the VM uses its default SSH port. Keep the current dashboard forward. A
loopback-only rule serves the host laptop. Teammates need forwarding bound
to the private hotspot interface and access through the Windows firewall on
that interface. Keep the dashboard's normal browser TLS verification. A
hostname matching the dashboard certificate can be saved if IP-based access
does not match it.

## Verify and save SSH

1. Enter the SSH host, port, and a non-root Linux account. Choose password
   or SSH private key. For key authentication,
   enter the absolute path to the local key or use the local SSH agent. A
   passphrase-protected key can be unlocked in that agent before connecting.
2. Select **Test connection** or **Save connection**. Sentinel checks its
   saved key first, then the current user's OpenSSH `~/.ssh/known_hosts`.
   A new address shows the server's key type and fingerprint. Compare it
   against the VM console before selecting **Trust and continue**. For
   ED25519, run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`
   on the VM. For ECDSA or RSA, use the corresponding public host key file.
   The same VM presents the same key for host and teammate connections.
3. Sentinel verifies the key before authenticating and reports the result of
   `/usr/bin/nmap --version`. **Save connection** saves the profile for scans.
   Opening Wazuh Tools reconnects with the saved profile. A blank password
   reuses the stored password for the same profile. Windows protects passwords
   with current-user DPAPI. On other platforms the password is held for the
   running Sentinel process and must be reentered after restart.
4. If the SSH port is unreachable, verify VM power, NAT forwarding, hotspot
   and firewall. On Windows, use `Test-NetConnection 127.0.0.1 -Port 2222`
   on the host or substitute the hotspot IP on a teammate laptop. If the
   key does not match, verify the VM's identity and check with the VM owner
   before replacing trusted key material. Sentinel blocks changed keys.
   If authentication fails, verify the VM account and chosen credential.
   Each scan opens a fresh verified SSH session.

## Scan and compare

Add a single authorized IP in **Authorized targets**. Select a profile and
confirm authorization before starting. Sensitive hosts default to a maximum
of four explicitly selected TCP ports. Other profiles offer a small fixed
TCP discovery list or bounded service probes. An Nmap `up` status caused by
`-Pn` is shown as assumed. Use the port responses as evidence of reachability.
Compare changes across scans from the same VM using the same target, profile,
and ports. Timeline records observed port changes for investigation.

The Linux VM uses `flock` and GNU `timeout` to allow one Sentinel scan at a
time across laptops and bound remote execution. **Stop scan** closes the
input of the current scan command. The VM signals that scan's own supervisor.
If SSH drops, Sentinel reports the interrupted connection and the remote
timeout limits any scan still running. A scan stops on Sentinel sign-out.
[Nmap TCP connect scans](https://nmap.org/book/scan-methods-connect-scan.html) ·
[GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html) ·
[VirtualBox NAT forwarding](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html#natforward)

## Dashboard and rollback

Save the HTTPS URL and select **Open Dashboard** to open it in a separate tab.
The native dashboard manages Wazuh alerts and monitoring. V5.5's independent
install does not copy V5 local state. Keep the V5 folder and its storage for
rollback. If reusing an existing database deliberately, V5.5 adds SSH and
dashboard tables and leaves the prior Manager, Indexer, and Agentless tables
intact. Existing Sentinel SIEM Agents profiles and connections remain separate.

## Verification

Local tests used a real loopback SSH server with simulated Nmap responses.
They exercised fingerprint validation before authentication, both sign-in
methods, scan results, interruption and recovery, and dashboard persistence.
A POSIX shell smoke test exercised the generated cancellation script with a
disposable process and confirmed a second process kept running. The Wazuh VM
was unavailable on Windows loopback port `2222`. Verify the live VM, its Nmap
installation, and hotspot forwarding before using the scanner on lab targets.
