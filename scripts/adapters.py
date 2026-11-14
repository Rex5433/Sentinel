"""Discover named private IPv4 adapters and prompt before starting shared access."""

from dataclasses import dataclass
from ipaddress import IPv4Interface
import json
import os
import re
import shutil
import subprocess
import sys
from time import monotonic, sleep


TIMEOUT = 10


@dataclass(frozen=True)
class Adapter:
    name: str
    address: IPv4Interface

    @property
    def label(self):
        return f"{self.name} — {self.address} (Shared HTTPS)"


def command(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, errors="replace", check=True, timeout=5,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def windows_rows():
    powershell = shutil.which("powershell.exe")
    if powershell:
        raw = command(powershell, "-NoProfile", "-NonInteractive", "-Command",
                      "$ErrorActionPreference='Stop'; Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred | "
                      "Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress")
        try:
            rows = json.loads(raw)
            if isinstance(rows, dict):
                rows = [rows]
            if isinstance(rows, list) and rows:
                return [(row["InterfaceAlias"], f"{row['IPAddress']}/{row['PrefixLength']}") for row in rows]
        except (ValueError, TypeError, KeyError):
            pass
    rows = []
    name = ""
    previous = ""
    for line in command("ipconfig.exe").splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            name, previous = line.rstrip(":"), ""
            continue
        # Windows reports IPv4 immediately before its dotted subnet mask.
        address = re.search(r"[: ](\d+(?:\.\d+){3})(?:\s*\([^)]*\))?$", previous)
        mask = re.search(r"[: ](\d+(?:\.\d+){3})$", line.rstrip())
        if name and address and mask:
            candidate = f"{address[1]}/{mask[1]}"
            try:
                IPv4Interface(candidate)
            except ValueError:
                pass
            else:
                rows.append((name, candidate))
        previous = line.rstrip()
    return rows


def unix_rows():
    if sys.platform.startswith("linux") and shutil.which("ip"):
        raw = command("ip", "-j", "-4", "address", "show", "up")
        if raw:
            try:
                return [(row["ifname"], f"{address['local']}/{address['prefixlen']}")
                        for row in json.loads(raw) for address in row.get("addr_info", ()) if address["family"] == "inet"]
            except (ValueError, TypeError, KeyError):
                pass
    name = ""
    rows = []
    for line in command("ifconfig", "-a").splitlines():
        if line and not line[0].isspace():
            flags = re.search(r"<([^>]+)>", line)
            name = line.split(":", 1)[0] if flags and "UP" in flags[1].split(",") else ""
        match = re.search(r"\binet (\S+)\s+netmask (\S+)", line)
        if name and match:
            host, mask = match.groups()
            if mask.startswith("0x"):
                try:
                    mask = str(int(mask, 16).bit_count())
                except ValueError:
                    continue
            rows.append((name, f"{host}/{mask}"))
    return rows


def available():
    from app.shared_hosting import SharedHosting

    adapters = {}
    for name, raw in windows_rows() if os.name == "nt" else unix_rows():
        try:
            address = IPv4Interface(raw)
            SharedHosting.parse(str(address.ip), str(address.network), 8000)
        except ValueError:
            continue
        adapters.setdefault(address.ip, Adapter(name, address))
    return sorted(adapters.values(), key=lambda adapter: (adapter.name.casefold(), adapter.address.ip))


def read_choice(timeout):
    if os.name == "nt":
        import msvcrt

        deadline = monotonic() + timeout
        entered = ""
        while monotonic() < deadline:
            if not msvcrt.kbhit():
                sleep(.05)
                continue
            key = msvcrt.getwch()
            if key in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue
            if key == "\r":
                print(flush=True)
                return entered
            if key == "\b" and entered:
                entered = entered[:-1]
                print("\b \b", end="", flush=True)
            elif key in "0123456789" and len(entered) < 4:
                entered += key
                print(key, end="", flush=True)
        print(flush=True)
        return ""
    import select

    return sys.stdin.readline().strip() if select.select([sys.stdin], [], [], timeout)[0] else ""


def choose_console():
    if not sys.stdin.isatty():
        return None
    options = available()
    if not options:
        return None
    print("Network adapter\n  0. Local only (localhost)")
    for index, adapter in enumerate(options, 1):
        print(f"  {index}. {adapter.label}")
    print(f"Select an option and press Enter. Local only starts after {TIMEOUT} seconds: ", end="", flush=True)
    raw = read_choice(TIMEOUT)
    if raw.isascii() and raw.isdigit() and len(raw) <= 4 and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    print("Starting on localhost.", flush=True)
    return None
