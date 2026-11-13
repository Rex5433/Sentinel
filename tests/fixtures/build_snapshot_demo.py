"""Original synthetic snapshot fixtures, Codex-assisted 2026-11-03. Not host captures."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path


def file_values(text, platform="linux", acl="synthetic-acl-not-a-real-permission"):
    data = text.encode("utf-8")
    result = {"exists": True, "kind": "regular", "sha256": sha256(data).hexdigest(), "byte_count": len(data), "text": text}
    if platform == "windows":
        result["acl_sddl"] = acl
    else:
        result.update(mode="0o640", uid=0, gid=0)
    return result


def snapshots(platform="linux"):
    service = {"state": "active", "start_mode": "enabled", "exec_start": "/usr/sbin/sshd -D", "account": "root", "fragment_path": "/lib/systemd/system/ssh.service"}
    name, path = "ssh.service", "/etc/sentinel-demo.conf"
    if platform == "windows":
        service = {"state": "Running", "start_mode": "Auto", "binary_path": r"C:\Synthetic\demo.exe", "account": "LocalSystem", "delayed_auto_start": False}
        name, path = "SentinelDemo", r"C:\Synthetic\sentinel-demo.conf"
    before = {"schema_version": "system-snapshot-v1", "host": {"id": "a"*64, "name": "synthetic-lab-host", "platform": platform},
              "started_at_utc": "2026-11-03T15:00:00Z", "ended_at_utc": "2026-11-03T15:00:05Z", "collector": "synthetic-fixture-v1",
              "sections": {
                  "services": {"complete": True, "scope": "synthetic-services-v1", "items": [{"id": name, "values": service}, {"id": "legacy.service", "values": {"state": "inactive"}}]},
                  "files": {"complete": True, "scope": "synthetic-selected-config-v1", "items": [{"id": path, "values": file_values("Port=443\nListen=127.0.0.1\n", platform)}]},
                  "packages": {"complete": True, "scope": "synthetic-packages-v1", "items": [{"id": "demo-server", "values": {"version": "1.0"}}]},
                  "users": {"complete": True, "scope": "synthetic-users-v1", "items": [{"id": "demo-user", "values": {"enabled": True}}]},
                  "firewall": {"complete": False, "scope": "not-collected", "notes": ["Synthetic example intentionally has no firewall inventory."], "items": []}}}
    after = deepcopy(before)
    after.update(started_at_utc="2026-11-03T15:05:00Z", ended_at_utc="2026-11-03T15:05:05Z")
    after["sections"]["services"]["items"] = [{"id": name, "values": {**service, "state": "Stopped" if platform == "windows" else "inactive", "start_mode": "Disabled" if platform == "windows" else "disabled"}}]
    after["sections"]["files"]["items"][0]["values"] = file_values("Port=4444\nListen=0.0.0.0\n", platform)
    after["sections"]["packages"]["items"][0]["values"]["version"] = "2.0"
    after["sections"]["users"]["items"].append({"id": "unexpected-demo-user", "values": {"enabled": True}})
    return before, after


if __name__ == "__main__":
    for name, value in zip(("snapshot_before.json", "snapshot_after.json"), snapshots()):
        Path(__file__).with_name(name).write_bytes((json.dumps(value, indent=2)+"\n").encode("utf-8"))
    print("Wrote two original synthetic snapshot examples; no host was inspected or changed.")
