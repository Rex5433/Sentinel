# Shared Sentinel on a private network

The normal V6 launcher opens an independent localhost workspace. Shared
hosting uses `V6/storage/shared` for the team’s accounts, evidence, SSH
profiles and scan history. Use a trusted private hotspot or LAN with a
route between devices. The host and teammates use the same HTTPS URL.

## Start the host

Install Python 3.11 or newer. The first start needs access to the Python
package index. Open **Start Sentinel.vbs** on Windows and select the adapter
your teammates use, then choose **Start Sentinel**. The interactive terminal
launchers also offer the adapter list. If you leave the picker alone for
10 seconds, Sentinel starts on localhost. An adapter selection uses the IP
and subnet reported by the operating system.

To skip the picker, open PowerShell in V6 and pass an address directly.
Substitute your actual address in these examples.

```powershell
& '.\Start Sentinel.bat' --shared 192.168.137.1
```

The launcher asks for a separate shared owner account on the first run.
It prints the HTTPS URL, allowed subnet, and public certificate path and
SHA-256 fingerprint. The default network is the address’s `/24`.
Use `--subnet 192.168.136.0/23` or your actual private network CIDR if it
differs. Use `--port 8001` if TCP 8000 is occupied. If the selected IP
changes, restart and select the new address. Sentinel generates a matching
certificate in `storage/shared/tls/<IP>`. Certificates from earlier V6 runs
can still be reused for the original IP.

On macOS use `bash "Start Sentinel.command" --shared 192.168.137.1`.
Keep the console open. Stop the server with Ctrl+C.

If Windows Firewall blocks incoming traffic, an administrator can run the
following in elevated PowerShell. Match the listener IP, port, and subnet.

```powershell
New-NetFirewallRule -DisplayName "Sentinel V6 Private HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.137.1 -LocalPort 8000 -RemoteAddress 192.168.137.0/24
```

To remove that rule, run `Remove-NetFirewallRule -DisplayName "Sentinel V6 Private HTTPS"`.
[Windows Firewall cmdlet reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)

## Give each teammate access

In a second terminal on the host, create one account per teammate. The
password is entered at a hidden prompt.

```powershell
& '.\Start Sentinel.bat' --add-teammate alex
```

On macOS the equivalent is `bash "Start Sentinel.command" --add-teammate alex`.
Use `--remove-teammate alex` to remove the account and revoke its sessions.
Use remove and add to issue a replacement password for a teammate.

Share only the `sentinel-team-ca.cer` shown by the launcher through a trusted team
channel. The host and each teammate should compare its SHA-256 fingerprint
with the one printed by the launcher, then trust it in their OS or browser.
On Windows PowerShell the current-user certificate store can be used:

```powershell
Get-FileHash .\sentinel-team-ca.cer -Algorithm SHA256
Import-Certificate -FilePath .\sentinel-team-ca.cer -CertStoreLocation Cert:\CurrentUser\Root
```

On macOS import the certificate into Keychain Access and trust it for SSL.
If using a browser with a separate certificate store, import it there.
The HTTPS URL is `https://192.168.137.1:8000/` in this example. Both devices
must be on the configured subnet and the network must allow client-to-client
connections. The trust certificate expires after 90 days. Remove its trust
entry from each device when the team retires this shared workspace or rotates
the certificate. [Windows certificate import](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate)

## Using the team workspace

- The owner configures SIEM Agents, ad-hoc Live Logs SSH, Wazuh SSH, scan
  targets, and the Wazuh Dashboard URL. The owner can also manage evidence
  retention and the account roster.
- Teammates can import and analyze evidence, use Timeline and command tools,
  review managed feeds in Live Logs and SIEM Agents, save managed snapshots,
  and run or stop scans against the team allowlist. The evidence, host status,
  and scan queue are shared. Signing out revokes only that browser’s session.
- Sentinel connects to Wazuh SSH from the host computer. For a VM on the
  same host, the existing SSH loopback forward can be used. Nmap runs in
  the VM. Teammates’ browsers only need access to Sentinel for scanning.
- **Open Dashboard** goes directly from the browser to Wazuh. Save a
  browser-reachable HTTPS URL such as `https://192.168.137.1:8443`, or a
  private DNS name that matches the Wazuh certificate. If the VM’s dashboard
  uses VirtualBox NAT, bind the dashboard forward to the private adapter and
  scope the firewall rule to the private subnet. Wazuh uses its own accounts
  and certificate trust. [VirtualBox NAT forwarding](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html#natforward)
