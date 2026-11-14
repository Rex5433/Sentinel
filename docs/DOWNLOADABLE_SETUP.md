# Start Sentinel V6

1. Extract the download to a writable folder. Install Python 3.11 or newer
   with Tk support for the Windows desktop launcher.
2. On Windows, open **Start Sentinel.vbs**. It creates a local **Sentinel V6**
   shortcut and opens the launcher without a command prompt. **Start Sentinel.bat**
   is the console launcher. On macOS, open **Start Sentinel.command** or run
   `bash "Start Sentinel.command"` from the extracted folder.
3. First launch installs pinned dependencies and needs access to the Python
   package index. Create your own local owner account when prompted. Subsequent
   launches can run offline after installation.
4. At startup, select **Local only** or select a private IPv4 adapter and
   confirm to start shared HTTPS. The picker starts **Local only** after
   10 seconds without confirmation.

Each extracted copy creates its own `.venv`, `tmp`, and `storage`. For authorized
SSH monitoring over VPN, see [SSH monitoring](SSH_SIEM_AGENTS.md).
See [V4.5 endpoint review](V45_ENDPOINT_REVIEW.md) for account scope, passive
scan coverage, and the local verification results.
See [V4.5.3 operations](V453_OPERATIONS.md) for background watches and saved
critical evidence.
See [Wazuh Tools V5.5](WAZUH_TOOLS_V55.md) for VM SSH, remote Nmap, and the
dashboard link.
See [shared hosting](SHARED_HOSTING.md) to let teammates sign in from other devices.
