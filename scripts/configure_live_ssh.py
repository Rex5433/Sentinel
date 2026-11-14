"""Optional console setup for live SSH collection."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from app.ssh_collection import CollectionError
from app.ssh_setup import parse_connection, save_profile

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", help="An existing ssh user@host command, quoted as one argument.")
    parser.add_argument("--platform", choices=("windows", "linux"))
    parser.add_argument("--channel", choices=("Security", "System"))
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    args = parser.parse_args()
    try:
        values = parse_connection(args.ssh or input("Paste your SSH command (ssh user@host -p port): ").strip())
        platform = args.platform or input("Remote system [windows/linux] (windows): ").strip().lower() or "windows"
        values["platform"] = platform
        if platform == "windows":
            choice = args.channel or input("Windows log [Security/System] (Security): ").strip() or "Security"
            values["channel"] = choice.capitalize()
        if "identity_file" not in values:
            print("Use an existing SSH private key. Load passphrase-protected keys with ssh-add first.")
            identity = input("Existing private key path (Enter uses your SSH agent): ").strip().strip('"')
            if identity:
                values["identity_file"] = identity
        if "identity_file" not in values:
            agent = subprocess.run(["ssh-add", "-l"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if agent.returncode:
                raise ValueError("Load your SSH key with ssh-add, or rerun and select an existing private key. Password-only SSH sessions need key setup first.")
        storage = Path(os.environ.get("SENTINEL_STORAGE_DIR", ROOT / "storage"))
        save_profile(storage, values, args.known_hosts)
        print(f"Configured {values['platform']} logs from {values['host']}:{values['port']}.")
        print("Windows Security logs require that SSH account to have event-log read permission.")
        return 0
    except (ValueError, CollectionError, OSError, subprocess.SubprocessError) as exc:
        print(f"Setup could not finish. {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
