"""Generate reviewable local recovery scripts. This module never executes them."""

from base64 import b64encode
from hashlib import sha256
import re
from shlex import quote

VERSION = "manual-recovery-v1"


def ps(value):
    return "'" + value.replace("'", "''") + "'"


def host_guard(host):
    expected = host.id
    if host.platform == "windows":
        return ("$ErrorActionPreference = 'Stop'\n"
                "$machine = (Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid.Trim().ToLowerInvariant()\n"
                "$sha = [Security.Cryptography.SHA256]::Create()\n"
                "$hostHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machine)))).Replace('-','').ToLowerInvariant()\n"
                f"if ($hostHash -ne '{expected}') {{ throw 'Wrong host identity. Stop and verify the target.' }}\n")
    return ("set -eu\n"
            "host_hash=$(tr -d '\\r\\n' < /etc/machine-id | tr '[:upper:]' '[:lower:]' | sha256sum | cut -d ' ' -f 1)\n"
            f"[ \"$host_hash\" = '{expected}' ] || {{ echo 'Wrong host identity; refusing.' >&2; exit 1; }}\n")


def plan(change, before, after, *, baseline_trusted=False):
    response = {"version": VERSION, "execution": "copy_only", "status": "manual_review",
                "script": None, "reason": None, "change_id": change["change_id"],
                "baseline_sha256": before.source_sha256, "current_sha256": after.source_sha256,
                "warnings": ["Manual target-host administration only. Sentinel does not execute this script.",
                             "Verify baseline legitimacy, dependencies, other changes, and service-specific configuration before use.",
                             "State/hash checks cannot eliminate races with a concurrent attacker. Restoring one value does not secure the host."]}
    def refuse(reason):
        response["reason"] = reason
        return response
    if baseline_trusted is not True:
        return refuse("Review and explicitly mark the selected baseline trusted before generating recovery commands.")
    if change["status"] != "modified" or change["before_index"] is None or change["after_index"] is None:
        return refuse("Added/removed/unknown items require manual review and a trusted restoration procedure.")
    category = change["category"]
    left = before.snapshot.sections[category].items[change["before_index"]]
    right = after.snapshot.sections[category].items[change["after_index"]]
    a, b, field = left.values, right.values, change["field"]
    if left.id != right.id:
        return refuse("Item path/name differs; verify identity manually.")
    different = {key for key in a.keys() | b.keys() if key != "text" and (type(a.get(key)) is not type(b.get(key)) or a.get(key) != b.get(key))}
    platform = before.snapshot.host.platform
    script = host_guard(before.snapshot.host)
    if category == "files" and field == "sha256":
        if a.get("kind") != "regular" or b.get("kind") != "regular" or a.get("exists") is not True or b.get("exists") is not True:
            return refuse("Only existing regular files support this content restoration.")
        if not different <= {"sha256", "byte_count"}:
            return refuse("File permissions/ownership or other metadata also changed; review those before restoring content.")
        if platform == "windows" and (not isinstance(a.get("acl_sddl"), str) or not a["acl_sddl"]):
            return refuse("Windows ACL evidence is unavailable; review file permissions before restoring.")
        if platform == "linux" and any(a.get(key) is None for key in ("mode", "uid", "gid")):
            return refuse("Linux ownership/mode evidence is unavailable; review permissions before restoring.")
        if platform == "linux" and (not isinstance(a.get("mode"), str) or re.fullmatch(r"0o[0-7]{1,4}", a["mode"]) is None or any(type(a.get(key)) is not int or not 0 <= a[key] <= 2**32-1 for key in ("uid", "gid"))):
            return refuse("Linux ownership/mode metadata is not supported by this template.")
        content = a.get("text")
        if not isinstance(content, str) or sha256(content.encode("utf-8")).hexdigest() != a["sha256"]:
            return refuse("Verified baseline UTF-8 text is unavailable; restore from an independently trusted backup.")
        encoded = b64encode(content.encode("utf-8")).decode("ascii")
        if platform == "windows":
            script += ("function Get-SentinelFileAcl([string]$p) {\n"
                       "  if ($PSVersionTable.PSEdition -eq 'Desktop') { return [IO.File]::GetAccessControl($p) }\n"
                       "  return [IO.FileSystemAclExtensions]::GetAccessControl([IO.FileInfo]::new($p))\n}\n")
            script += ("function Get-SentinelFileHash([string]$p) {\n"
                       "  $stream = [IO.File]::OpenRead($p); $algorithm = [Security.Cryptography.SHA256]::Create()\n"
                       "  try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $stream.Dispose(); $algorithm.Dispose() }\n}\n")
            script += f"$path = {ps(left.id)}\n"
            script += ("$item = Get-Item -LiteralPath $path -Force\n"
                       "if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected a regular file without a reparse point.' }\n"
                       "$parent = $item.Directory\n"
                       "while ($parent) { if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point parent refused.' }; $parent = $parent.Parent }\n")
            script += f"if ((Get-SentinelFileHash $path) -ne '{b['sha256']}') {{ throw 'File changed since snapshot; refusing.' }}\n"
            script += f"if (((Get-SentinelFileAcl $path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -replace '(D:[A-Z]*?)AI','$1') -cne {ps(b['acl_sddl'])}) {{ throw 'File ACL changed since snapshot; refusing.' }}\n"
            script += ("$backup = $path + '.sentinel-backup-' + [Guid]::NewGuid().ToString('N')\n"
                       "$temporary = $path + '.sentinel-temp-' + [Guid]::NewGuid().ToString('N')\n"
                       "$acl = Get-SentinelFileAcl $path\n"
                       "try {\n"
                       f"  $bytes = [Convert]::FromBase64String('{encoded}')\n"
                       "  $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)\n"
                       "  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }\n"
                       "  if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.File]::SetAccessControl($temporary,$acl) } else { [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($temporary),$acl) }\n"
                       f"  if ((Get-SentinelFileHash $temporary) -ne '{a['sha256']}') {{ throw 'Baseline bytes failed verification.' }}\n"
                       f"  if ((Get-SentinelFileHash $path) -ne '{b['sha256']}') {{ throw 'File changed during preparation; refusing.' }}\n"
                       "  [IO.File]::Replace($temporary, $path, $backup)\n"
                       f"  if ((Get-SentinelFileHash $backup) -ne '{b['sha256']}') {{ throw 'Backup verification failed; preserve all evidence.' }}\n"
                       f"  if ((Get-SentinelFileHash $path) -ne '{a['sha256']}') {{ throw 'Post-restore verification failed; preserve the backup.' }}\n"
                       "  Write-Output ('Restored content. Previous bytes retained at: ' + $backup)\n"
                       "} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }\n")
        else:
            script += f"path={quote(left.id)}\n"
            script += ("[ -f \"$path\" ] && [ ! -L \"$path\" ] || { echo 'Expected regular non-symlink file.' >&2; exit 1; }\n"
                       "[ \"$(realpath -s -- \"$path\")\" = \"$(realpath -- \"$path\")\" ] || { echo 'Symlink parent refused.' >&2; exit 1; }\n"
                       f"[ \"$(stat -c '%a:%u:%g' -- \"$path\")\" = '{int(b['mode'],8):o}:{b['uid']}:{b['gid']}' ] || {{ echo 'Mode/owner changed since snapshot; refusing.' >&2; exit 1; }}\n"
                       f"[ \"$(sha256sum -- \"$path\" | cut -d ' ' -f 1)\" = '{b['sha256']}' ] || {{ echo 'File changed since snapshot; refusing.' >&2; exit 1; }}\n"
                       "backup=$(mktemp -- \"${path}.sentinel-backup.XXXXXXXX\")\n"
                       "cp --preserve=all -- \"$path\" \"$backup\"\n"
                       f"[ \"$(sha256sum -- \"$backup\" | cut -d ' ' -f 1)\" = '{b['sha256']}' ] || {{ echo 'Backup verification failed.' >&2; exit 1; }}\n"
                       "temporary=$(mktemp -- \"${path}.sentinel-temp.XXXXXXXX\")\n"
                       "trap 'rm -f -- \"$temporary\"' EXIT\n"
                       "cp --preserve=all -- \"$path\" \"$temporary\"\n"
                       f"printf '%s' '{encoded}' | base64 --decode > \"$temporary\"\n"
                       f"[ \"$(sha256sum -- \"$temporary\" | cut -d ' ' -f 1)\" = '{a['sha256']}' ] || {{ echo 'Baseline bytes failed verification.' >&2; exit 1; }}\n"
                       f"[ \"$(sha256sum -- \"$path\" | cut -d ' ' -f 1)\" = '{b['sha256']}' ] || {{ echo 'File changed during preparation; refusing.' >&2; exit 1; }}\n"
                       "mv -f -- \"$temporary\" \"$path\"\n"
                       f"[ \"$(sha256sum -- \"$path\" | cut -d ' ' -f 1)\" = '{a['sha256']}' ] || {{ echo 'Post-restore verification failed; preserve backup.' >&2; exit 1; }}\n"
                       "printf 'Restored content. Previous bytes retained at: %s\\n' \"$backup\"\n")
        response["warnings"].append("Content only: no service restart/reload is performed. Validate application configuration and choose the appropriate manual reload separately. Requires local file/parent write and metadata permissions.")
    elif category == "services" and field in ("state", "start_mode"):
        if not different <= {"state", "start_mode"}:
            return refuse("Other service configuration also changed; review executable/account/configuration before restoring service controls.")
        if platform == "windows":
            if re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", left.id) is None or a.get("delayed_auto_start") is not False or b.get("delayed_auto_start") is not False:
                return refuse("Unsupported service name or delayed/unknown startup configuration.")
            script += f"$name = {ps(left.id)}\n$service = Get-CimInstance Win32_Service | Where-Object {{ $_.Name -eq $name }}\n"
            script += "$delayKey = Get-Item -LiteralPath ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\' + $name)\nif ($delayKey.GetValue('DelayedAutoStart',0) -ne 0) { throw 'Delayed startup changed; refusing.' }\n"
            for key, property in (("state", "State"), ("start_mode", "StartMode"), ("binary_path", "PathName"), ("account", "StartName")):
                if not isinstance(b.get(key), str):
                    return refuse("Required current service properties are unknown.")
                script += f"if ($service.{property} -cne {ps(b[key])}) {{ throw 'Service changed since snapshot; refusing.' }}\n"
            if field == "start_mode" and a[field] in ("Auto", "Manual", "Disabled"):
                mode = {"Auto": "Automatic", "Manual": "Manual", "Disabled": "Disabled"}[a[field]]
                script += f"Set-Service -Name $name -StartupType {mode}\n"
            elif field == "state" and a[field] in ("Running", "Stopped"):
                script += ("Start-Service" if a[field] == "Running" else "Stop-Service") + " -Name $name\n"
            else:
                return refuse("Unsupported service state/start mode.")
            script += "Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $name } | Select-Object Name, State, StartMode\n"
        else:
            if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,240}\.service", left.id) is None:
                return refuse("Unsupported unit name.")
            script += f"unit={quote(left.id)}\n"
            for key, property in (("state", "ActiveState"), ("start_mode", "UnitFileState"), ("exec_start", "ExecStart"), ("account", "User"), ("fragment_path", "FragmentPath")):
                if not isinstance(b.get(key), str):
                    return refuse("Required current service properties are unknown.")
                script += f"[ \"$(systemctl show --property={property} --value -- \"$unit\")\" = {quote(b[key])} ] || {{ echo 'Service changed since snapshot; refusing.' >&2; exit 1; }}\n"
            actions = {"state": {"active": "start", "inactive": "stop"}, "start_mode": {"enabled": "enable", "disabled": "disable"}}
            action = actions[field].get(a[field])
            if action is None or b["start_mode"] not in ("enabled", "disabled"):
                return refuse("Masked/static/indirect or transitional unit states require manual review.")
            script += f"systemctl {action} -- \"$unit\"\nsystemctl show --property=ActiveState,UnitFileState -- \"$unit\"\n"
        response["warnings"].append("Service control changes may affect dependencies or availability and require administration rights. Inspect the displayed resulting state; recapture after manual use.")
    else:
        return refuse("No supported recovery template for this change. Use trusted backups/vendor procedures after reviewing evidence.")
    response.update(status="ready_for_manual_review", script=script, shell="PowerShell" if platform == "windows" else "Bash (GNU tools, systemd for services)",
                    target_host=before.snapshot.host.model_dump(), reason="Review the full script and baseline evidence, then run manually on the named authorized host only.")
    return response
