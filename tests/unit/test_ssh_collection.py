import json
import sys

import pytest

from app import ssh_collection as collection


def test_fixed_ssh_command_and_host_key_policy(tmp_path):
    path = tmp_path / "ssh-known-hosts"
    path.write_text("verified key fixture", encoding="utf-8")
    (tmp_path / "ssh-lab.json").write_text(json.dumps({
        "host": "192.0.2.25", "username": "journal_reader", "port": 2222,
        "command": "ignored",
    }), encoding="utf-8")
    args = collection.ssh_arguments(*collection.lab_target(tmp_path))
    assert args[:8] == ["ssh", "-F", "none", "-T", "-a", "-x", "-o", "BatchMode=yes"]
    assert args[-7:] == ["-l", "journal_reader", "-p", "2222", "--", "192.0.2.25",
                         "journalctl --no-pager --quiet --lines=100 --output=json"]
    assert {"StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none", "UpdateHostKeys=no",
            f'UserKnownHostsFile="{path.as_posix()}"', "IdentityFile=none", "ClearAllForwardings=yes"} <= set(args)


def test_windows_profile_and_key_file_reuse_fixed_ssh_policy(tmp_path):
    key = tmp_path / "existing key"
    key.write_text("fixture private key path", encoding="utf-8")
    (tmp_path / "ssh-known-hosts").write_text("verified public key", encoding="utf-8")
    profile = {"host": "lab.example.test", "port": 22, "username": "LAB\\Alex",
               "platform": "windows", "channel": "Security", "identity_file": str(key)}
    settings = tmp_path / "ssh-lab.json"
    settings.write_text(json.dumps(profile), encoding="utf-8")
    options = collection.live_options(tmp_path)
    target = collection.lab_target(tmp_path)
    assert target[1] == "LAB\\Alex" and options["identity_file"] == key
    args = collection.ssh_arguments(*target, identity_file=key)
    assert f'IdentityFile="{key.as_posix()}"' in args
    assert "StrictHostKeyChecking=yes" in args and "BatchMode=yes" in args
    for change in ({"channel": "Security;whoami"}, {"username": "Alex -oProxyCommand=x"}, {"platform": "unix"}):
        settings.write_text(json.dumps(profile | change), encoding="utf-8")
        with pytest.raises(collection.CollectionError):
            collection.lab_target(tmp_path)


@pytest.mark.parametrize("override", [
    {"host": "-oProxyCommand=x"}, {"host": "user@host"}, {"username": "root"},
    {"username": "ops;true"}, {"port": True}, {"port": 65536},
])
def test_rejects_invalid_destination_before_launch(tmp_path, override):
    (tmp_path / "ssh-known-hosts").write_text("verified key fixture", encoding="utf-8")
    (tmp_path / "ssh-lab.json").write_text(json.dumps({
        "host": "lab.example.test", "username": "operator",
    } | override), encoding="utf-8")
    with pytest.raises(collection.CollectionError, match="verified host key"):
        collection.lab_target(tmp_path)


@pytest.mark.parametrize(("program", "error"), [
    ("print('journal')", None),
    ("print('a' * 8192)", "exceeds 1 MiB"),
    ("import time; time.sleep(10)", "timed out"),
    ("import sys; print('partial'); sys.exit(255)", "retrieval failed"),
    ("pass", "no journal entries"),
])
def test_bounded_subprocess_output(tmp_path, monkeypatch, program, error):
    monkeypatch.setattr(collection, "ssh_arguments", lambda *_: [sys.executable, "-c", program])
    monkeypatch.setattr(collection, "MAX_BYTES", 64)
    monkeypatch.setattr(collection, "TIMEOUT_SECONDS", 0.4 if "sleep" in program else 5)
    if error:
        with pytest.raises(collection.CollectionError, match=error):
            collection.collect_journal("unused", "reader", 22, tmp_path)
    else:
        assert collection.collect_journal("unused", "reader", 22, tmp_path).strip() == b"journal"


def test_only_authentication_rejection_offers_password_fallback():
    for detail, expected in [("Permission denied (publickey,password).", collection.KeyAuthenticationRequired),
                             ("Host key verification failed.", collection.CollectionError)]:
        args = [sys.executable, "-c", f"import sys; sys.stderr.write({detail!r}); sys.exit(255)"]
        with pytest.raises(expected) as error:
            collection.collect_output(args, allow_empty=True, authentication_probe=True)
        if "Host key" in detail:
            assert not isinstance(error.value, collection.KeyAuthenticationRequired)
