"""Configure local log collection using an existing trusted SSH destination."""

import json
import os
from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory

from .ssh_collection import CollectionError, collect_output, lab_target, live_options, ssh_arguments

def parse_connection(command: str) -> dict:
    tokens = shlex.split(command, posix=False)
    for index, token in enumerate(tokens):
        if len(token) >= 2 and token[0] in {"'", '"'} and token[-1] == token[0]:
            tokens[index] = token[1:-1]
    if not tokens or tokens.pop(0).lower() not in {"ssh", "ssh.exe"}:
        raise ValueError("Enter a command such as ssh alex@192.168.1.50 -p 22.")
    values = {"port": 22}
    destination = None
    while tokens:
        token = tokens.pop(0)
        if token in {"-p", "-l", "-i"}:
            if not tokens:
                raise ValueError(f"Missing value after {token}.")
            key = {"-p": "port", "-l": "username", "-i": "identity_file"}[token]
            values[key] = tokens.pop(0)
        elif token.startswith("-") or destination is not None:
            raise ValueError("Use the hostname/IP, account, and optional -p or -i from your SSH command.")
        else:
            destination = token
    if destination is None:
        raise ValueError("An SSH destination is required.")
    if "@" in destination:
        username, destination = destination.rsplit("@", 1)
        if values.get("username", username) != username:
            raise ValueError("The command specifies conflicting account names.")
        values["username"] = username
    if not values.get("username"):
        raise ValueError("Include the account, for example ssh alex@192.168.1.50.")
    try:
        values["port"] = int(values["port"])
    except ValueError as exc:
        raise ValueError("Use a numeric SSH port.") from exc
    values["host"] = destination
    return values


def trusted_host_keys(host: str, port: int, source: Path, *, missing_ok: bool = False) -> bytes:
    lookup = host if port == 22 else f"[{host}]:{port}"
    if missing_ok:
        try:
            source.stat()
        except FileNotFoundError:
            return b""
    result = subprocess.run(["ssh-keygen", "-F", lookup, "-f", str(source)], capture_output=True, timeout=10)
    entries = [line for line in result.stdout.splitlines() if line and not line.startswith(b"#")]
    if missing_ok and result.returncode == 1 and not result.stderr and not entries:
        return b""
    if result.returncode or not entries:
        raise ValueError("No accepted host key was found. Connect once in your terminal, verify the host fingerprint, then select Connect here again.")
    return b"\n".join(entries) + b"\n"


def save_profile(storage: Path, values: dict, known_hosts: Path, *, password: str | None = None,
                 reuse_key_session: bool = False):
    values = {key: value for key, value in values.items()
              if key in {"host", "username", "port", "platform", "channel", "identity_file", "authentication"}}
    if password is not None:
        values.pop("identity_file", None)
        values["authentication"] = "password"
    storage = storage.resolve()
    storage.mkdir(parents=True, exist_ok=True)
    if values.get("identity_file"):
        values = values | {"identity_file": str(Path(values["identity_file"]).expanduser().resolve())}
    # Validate with the normal collector before publishing either local file.
    with TemporaryDirectory(prefix="ssh-setup-", dir=storage) as directory:
        stage = Path(directory)
        (stage / "ssh-lab.json").write_text(json.dumps(values), encoding="utf-8")
        (stage / "ssh-known-hosts").write_bytes(b"validation placeholder\n")
        lab_target(stage)
        keys = trusted_host_keys(values["host"], values["port"], known_hosts)
        (stage / "ssh-known-hosts").write_bytes(keys)
        target = lab_target(stage)
        options = live_options(stage)
        session = None
        try:
            if password is not None:
                from .password_ssh import PasswordSession
                session = PasswordSession.connect(target, password)
            elif reuse_key_session:
                from .ssh_transport import LIVE_IDLE_SECONDS, SSHSession
                session = SSHSession.connect(target, identity_file=options["identity_file"], idle_timeout=LIVE_IDLE_SECONDS)
                # Verify the selected collector and use this authenticated
                # transport for the watch. A successful login alone is weaker.
                session.collect(options)
            else:
                collect_output(ssh_arguments(*target, command="exit 0", identity_file=options["identity_file"]),
                               allow_empty=True, authentication_probe=True)
            for name in ("ssh-known-hosts", "ssh-lab.json"):
                destination = storage / name
                if destination.is_symlink() or destination.resolve().parent != storage:
                    raise ValueError("The SSH settings must stay in the local evidence store.")
            os.replace(stage / "ssh-known-hosts", storage / "ssh-known-hosts")
            os.replace(stage / "ssh-lab.json", storage / "ssh-lab.json")
            return session
        except BaseException:
            if session:
                session.close()
            raise
