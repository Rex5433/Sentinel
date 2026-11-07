import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from app import ssh_setup as setup


def test_parse_existing_windows_ssh_command():
    assert setup.parse_connection(r'ssh DOMAIN\alex@192.0.2.12 -p 2222 -i "C:\keys\lab key"') == {
        "host": "192.0.2.12", "username": "DOMAIN\\alex", "port": 2222, "identity_file": r"C:\keys\lab key",
    }
    assert setup.parse_connection("ssh -l alex@lab.example lab.example.test")["username"] == "alex@lab.example"
    assert setup.parse_connection("ssh alex@host -i 'C:\\keys\\lab key'")["identity_file"] == r"C:\keys\lab key"
    for command in ("ssh -o ProxyCommand=something alex@host", "ssh host", "ssh alex@host arbitrary-command"):
        with pytest.raises(ValueError):
            setup.parse_connection(command)


def test_setup_copies_only_previously_trusted_key_and_checks_auth(tmp_path, monkeypatch):
    storage = tmp_path / "storage"
    trust = tmp_path / "known_hosts"
    trust.write_text("accepted", encoding="utf-8")
    lookups = []

    def lookup(args, **kwargs):
        lookups.append(args)
        return subprocess.CompletedProcess(args, 0, b"# matched\n[lab.example.test]:2222 ssh-ed25519 test-key\n", b"")

    checks = []
    monkeypatch.setattr(setup.subprocess, "run", lookup)
    monkeypatch.setattr(setup, "collect_output", lambda args, **kwargs: checks.append(args) or b"")
    values = {"host": "lab.example.test", "port": 2222, "username": "DOMAIN\\alex", "platform": "windows", "channel": "System"}
    setup.save_profile(storage, values, trust)
    assert lookups[0] == ["ssh-keygen", "-F", "[lab.example.test]:2222", "-f", str(trust)]
    assert checks[0][-2:] == ["lab.example.test", "exit 0"]
    assert json.loads((storage / "ssh-lab.json").read_text()) == values
    assert (storage / "ssh-known-hosts").read_bytes() == b"[lab.example.test]:2222 ssh-ed25519 test-key\n"


def test_missing_trusted_key_leaves_existing_profile_intact(tmp_path, monkeypatch):
    storage = tmp_path / "storage"
    storage.mkdir()
    profile = storage / "ssh-lab.json"
    profile.write_text('{"prior":"settings"}', encoding="utf-8")
    monkeypatch.setattr(setup.subprocess, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 1, b"", b""))
    with pytest.raises(ValueError, match="accepted host key"):
        setup.save_profile(storage, {"host": "192.0.2.12", "port": 22, "username": "alex", "platform": "windows"}, tmp_path / "known")
    assert profile.read_text() == '{"prior":"settings"}'


def test_failed_key_authentication_does_not_publish_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "trusted_host_keys", lambda *_: b"host ssh-ed25519 verified\n")
    def failed(*args, **kwargs):
        raise setup.CollectionError("Key authentication failed.")
    monkeypatch.setattr(setup, "collect_output", failed)
    with pytest.raises(setup.CollectionError):
        setup.save_profile(tmp_path, {"host": "192.0.2.12", "port": 22, "username": "alex", "platform": "windows"}, tmp_path / "known")
    assert not (tmp_path / "ssh-lab.json").exists()
    assert not (tmp_path / "ssh-known-hosts").exists()


@pytest.mark.parametrize("arguments", [["scripts/configure_live_ssh.py"], ["-m", "scripts.configure_live_ssh"]])
def test_console_helper_imports_without_pythonpath(arguments):
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "--ssh" in result.stdout
