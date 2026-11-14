"""Manual local inventory export. Never imported/called by the web application.

Python 3.11+, standard library only. No elevation, remote access, or configuration
changes. Only explicitly selected regular files are hashed; --include-text opts
into capturing their UTF-8 content (may contain secrets; keep exports private).
"""

import argparse
from base64 import b64encode
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

VERSION = "sentinel-local-snapshot-1"


def powershell(script):
    code = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; " + script
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             b64encode(code.encode("utf-16-le")).decode()], capture_output=True, timeout=30, check=True)
    return result.stdout.decode("utf-8-sig").strip()


def host_id():
    if sys.platform == "win32":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            identity = winreg.QueryValueEx(key, "MachineGuid")[0]
    else:
        identity = Path("/etc/machine-id").read_text()
    identity = identity.strip().lower()
    if not identity:
        raise ValueError("Stable local machine identity unavailable")
    return sha256(identity.encode("utf-8")).hexdigest()


def section(scope, function):
    try:
        return {"complete": True, "scope": scope, "notes": [], "items": function()}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return {"complete": False, "scope": scope, "notes": ["Collection unavailable/incomplete; no additions/removals may be inferred."], "items": []}


def services():
    if sys.platform == "win32":
        import winreg
        data = json.loads(powershell("ConvertTo-Json -InputObject @(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName,StartName) -Depth 4 -Compress"))
        items = []
        for record in data:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\"+record["Name"]) as key:
                    try:
                        delay = bool(winreg.QueryValueEx(key, "DelayedAutoStart")[0])
                    except FileNotFoundError:
                        delay = False
            except OSError:
                delay = None
            items.append({"id": record["Name"], "values": {"state": record["State"], "start_mode": record["StartMode"],
                         "binary_path": record["PathName"], "account": record["StartName"], "delayed_auto_start": delay}})
        return sorted(items, key=lambda item: item["id"])
    result = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"], capture_output=True, text=True, timeout=15, check=True)
    names = sorted({line.split()[0] for line in result.stdout.splitlines() if line.strip()})
    names = [name for name in names if not name.endswith("@.service")]
    if len(names) > 2000 or any(re.fullmatch(r"[A-Za-z0-9_.@:\\-]{1,240}\.service", name) is None for name in names):
        raise ValueError("Service inventory outside supported limits")
    properties = "Id,ActiveState,UnitFileState,ExecStart,User,FragmentPath,LoadState"
    items = []
    for offset in range(0, len(names), 100):
        response = subprocess.run(["systemctl", "show", "--no-pager", "--property="+properties, "--", *names[offset:offset+100]], capture_output=True, text=True, timeout=15, check=True)
        for block in response.stdout.strip().split("\n\n"):
            values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if not values.get("Id") or values.get("LoadState") != "loaded":
                raise ValueError("A unit could not be fully inspected")
            items.append({"id": values["Id"], "values": {"state": values.get("ActiveState"), "start_mode": values.get("UnitFileState"),
                          "exec_start": values.get("ExecStart"), "account": values.get("User"), "fragment_path": values.get("FragmentPath")}})
    if {item["id"] for item in items} != set(names):
        raise ValueError("Incomplete service details")
    return items


def packages():
    if sys.platform == "win32":
        import winreg
        items = []
        for view, label in ((winreg.KEY_WOW64_64KEY, "64"), (winreg.KEY_WOW64_32KEY, "32")):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", access=winreg.KEY_READ | view) as root:
                for index in range(winreg.QueryInfoKey(root)[0]):
                    name = winreg.EnumKey(root, index)
                    with winreg.OpenKey(root, name) as key:
                        def value(field):
                            try:
                                result = winreg.QueryValueEx(key, field)[0]
                                return result if isinstance(result, str) else None
                            except FileNotFoundError:
                                return None
                        title = value("DisplayName")
                        if title:
                            items.append({"id": label+":"+name, "values": {"name": title, "version": value("DisplayVersion"), "publisher": value("Publisher")}})
        return sorted(items, key=lambda item: item["id"])
    if shutil.which("dpkg-query"):
        command = ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"]
    elif shutil.which("rpm"):
        command = ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
    else:
        raise ValueError("No supported package inventory tool")
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=True)
    items = []
    for line in result.stdout.splitlines():
        name, version, architecture = line.split("\t")
        items.append({"id": name+":"+architecture, "values": {"name": name, "version": version, "architecture": architecture}})
    return sorted(items, key=lambda item: item["id"])


def users():
    if sys.platform == "win32":
        records = json.loads(powershell("ConvertTo-Json -InputObject @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name,SID,Disabled,Lockout) -Depth 4 -Compress"))
        return sorted([{"id": record["SID"], "values": {"name": record["Name"], "disabled": record["Disabled"], "locked": record["Lockout"]}} for record in records], key=lambda item: item["id"])
    # Local files only; avoid NSS calls that may contact a directory service.
    items = []
    for line in Path("/etc/passwd").read_text().splitlines():
        fields = line.split(":")
        if len(fields) != 7:
            raise ValueError("Unexpected passwd layout")
        name, _, uid, gid, _, home, shell = fields
        items.append({"id": name, "values": {"name": name, "uid": int(uid), "gid": int(gid), "home": home, "shell": shell}})
    return sorted(items, key=lambda item: item["id"])


def files(paths, include_text):
    items = []
    for value in paths:
        path = Path(value).absolute()
        try:
            info = path.lstat()
        except FileNotFoundError:
            items.append({"id": str(path), "values": {"exists": False}})
            continue
        if path.is_symlink() or any(parent.is_symlink() or getattr(parent.lstat(), "st_file_attributes", 0) & 0x400 for parent in path.parents) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symlink/reparse-point file path refused")
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8*1024*1024:
            raise ValueError("Only regular selected files up to 8 MiB")
        with path.open("rb") as stream:
            data = stream.read(8*1024*1024+1)
        if len(data) > 8*1024*1024:
            raise ValueError("Selected file grew beyond the size limit")
        end = path.stat()
        if (info.st_ino, info.st_size, info.st_mtime_ns) != (end.st_ino, end.st_size, end.st_mtime_ns):
            raise ValueError("File changed while collecting")
        fields = {"exists": True, "kind": "regular", "sha256": sha256(data).hexdigest(), "byte_count": len(data)}
        if os.name == "nt":
            encoded_path = b64encode(str(path).encode("utf-8")).decode()
            # DACL auto-inherited bookkeeping may change on atomic replacement;
            # retain owner/group, protection/other flags, and every access entry.
            fields["acl_sddl"] = powershell(f"$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_path}')); [IO.File]::GetAccessControl($p).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -replace '(D:[A-Z]*?)AI','$1'")
        else:
            fields.update(mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid, gid=info.st_gid)
        if include_text and len(data) <= 32768:
            try:
                text = data.decode("utf-8")
                if "\x00" not in text:
                    fields["text"] = text
            except UnicodeError:
                pass
        items.append({"id": str(path), "values": fields})
    return items


def capture(paths=(), include_text=False):
    if sys.platform not in ("win32", "linux"):
        raise ValueError("Collector targets Windows/Linux hosts, not the Mac dashboard host")
    start = datetime.now(timezone.utc).isoformat()
    selected = sorted(set(str(Path(path).absolute()) for path in paths))
    if len(selected) > 20:
        raise ValueError("Choose at most 20 files")
    sections = {
        "services": section("local-services-v1;no-unit-templates", services),
        "packages": section("installed-inventory-v1;HKLM-uninstall-or-dpkg-rpm", packages),
        "users": section("local-accounts-v1;no-domain-or-password-data", users),
        "files": section("selected-files-v1:"+sha256(json.dumps(selected).encode()).hexdigest(), lambda: files(selected, include_text)),
        "firewall": {"complete": False, "scope": "not-collected", "notes": ["Firewall export/normalization not implemented by this collector."], "items": []},
    }
    return {"schema_version": "system-snapshot-v1", "host": {"id": host_id(), "name": platform.node(), "platform": "windows" if os.name == "nt" else "linux"},
            "started_at_utc": start, "ended_at_utc": datetime.now(timezone.utc).isoformat(), "collector": VERSION, "sections": sections}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--include-text", action="store_true")
    args = parser.parse_args()
    try:
        snapshot = capture(args.file, args.include_text)
        data = json.dumps(snapshot, ensure_ascii=True, indent=2).encode("utf-8")
        if len(data) > 4*1024*1024 or sum(len(section["items"]) for section in snapshot["sections"].values()) > 5000:
            raise ValueError("Snapshot exceeds supported limits")
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        print("Snapshot exported. Inspect incomplete sections and keep the file private.")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Snapshot export failed. Check host/tool access, selected paths, limits, and use a new output filename.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
