"""Exact-byte, retry-safe archival using disposable team-authored records."""

from hashlib import sha256
import json

import pytest

from app.db import EvidenceStore, StorageFull
import app.db as database
from app import live_archive
from app.live_archive import LiveArchive


WATCH = "a" * 32


def record(index, platform="windows"):
    if platform == "windows":
        value = {"Id": 4624, "RecordId": index, "LogName": "Security",
                 "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": "test-host",
                 "TimeCreated": f"2026-11-06T12:00:{index:02}Z", "EventData": {"TargetUserName": "test-user"}}
    else:
        value = {"__CURSOR": f"cursor-{index}", "__REALTIME_TIMESTAMP": str(1793966400000000 + index * 1000000),
                 "_HOSTNAME": "test-host", "SYSLOG_IDENTIFIER": "sshd",
                 "MESSAGE": "Accepted publickey for test-user from 192.0.2.8 port 4180 ssh2"}
    return (json.dumps(value) + "\r\n").encode()


@pytest.fixture
def store(tmp_path):
    result = EvidenceStore(tmp_path / "storage")
    result.initialize()
    return result


@pytest.mark.parametrize("platform,expected_format", [("windows", "windows-jsonl"), ("linux", "linux-journal-json")])
def test_live_capture_preserves_exact_source_bytes_and_uses_normal_library(store, platform, expected_format):
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", platform)
    one, two = record(1, platform), record(2, platform)
    archive.append({"one": one})
    archive.append([two])
    assert archive.pending.read_bytes() == one + two
    saved = archive.save()
    assert len(saved) == 1
    item = saved[0]
    assert item["format"] == expected_format and item["accepted_count"] == 2
    assert item["sha256"] == sha256(one + two).hexdigest()
    assert store.blob_path(item["id"]).read_bytes() == one + two
    assert archive.save() == [] and store.uploads(0, 100)["total"] == 1
    assert archive.status()["pending_records"] == archive.status()["pending_bytes"] == 0
    assert archive.status()["saved_chunks"] == 1


def test_sealed_only_save_leaves_pending_and_repeated_saves_do_not_duplicate(store, monkeypatch):
    monkeypatch.setattr(live_archive, "CHUNK_RECORDS", 2)
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    archive.append([record(1), record(2)])
    archive.append([record(3)])
    assert archive.status()["sealed_chunks"] == 1
    first = archive.save(sealed_only=True)
    assert len(first) == 1 and archive.pending.read_bytes() == record(3)
    assert archive.status()["pending_records"] == 1
    assert archive.save(sealed_only=True) == []
    second = archive.save()
    assert len(second) == 1 and second[0]["id"] != first[0]["id"]
    assert store.blob_path(first[0]["id"]).read_bytes() == record(1) + record(2)
    assert store.blob_path(second[0]["id"]).read_bytes() == record(3)


def test_stage_full_keeps_prior_bytes_and_accepts_retry_after_save(store, monkeypatch):
    row = record(1)
    monkeypatch.setattr(live_archive, "STAGING_BYTES", len(row) + 1)
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    archive.append([row])
    with pytest.raises(StorageFull, match="staging is full"):
        archive.append([record(2)])
    assert archive.pending.read_bytes() == row
    assert archive.status()["pending_records"] == 1 and archive.status()["error"]
    archive.save()
    archive.append([record(2)])
    assert archive.status()["error"] is None


def test_interrupted_append_rolls_back_only_new_bytes(store, monkeypatch):
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    archive.append([record(1)])
    write = live_archive.os.write
    def interrupted(descriptor, data):
        write(descriptor, data[:10])
        raise OSError("Simulated interrupted write")
    monkeypatch.setattr(live_archive.os, "write", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        archive.append([record(2)])
    assert archive.pending.read_bytes() == record(1)
    monkeypatch.setattr(live_archive.os, "write", write)
    archive.append([record(2)])
    saved = archive.save()[0]
    assert store.blob_path(saved["id"]).read_bytes() == record(1) + record(2)


def test_recovery_after_library_commit_before_checkpoint_cleanup_is_idempotent(store, monkeypatch):
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    archive.append([record(1)])
    save = store.save
    def interrupted(data, parsed):
        save(data, parsed)
        raise OSError("Simulated crash after database commit")
    monkeypatch.setattr(store, "save", interrupted)
    with pytest.raises(OSError, match="database commit"):
        archive.save()
    assert store.uploads(0, 100)["total"] == 1 and archive.status()["pending_records"] == 1
    recovered = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    # The saved ID is detected before another store.save call is attempted.
    saved = recovered.save()
    assert len(saved) == 1 and store.uploads(0, 100)["total"] == 1
    assert store.blob_path(saved[0]["id"]).read_bytes() == record(1)


def test_full_library_retains_capture_for_retry_without_eviction(store, monkeypatch):
    monkeypatch.setattr(database, "MAX_UPLOADS", 1)
    first = LiveArchive(store, WATCH, "ssh-live-first.jsonl", "windows")
    first.append([record(1)])
    original = first.save()[0]
    second = LiveArchive(store, "b" * 32, "ssh-live-second.jsonl", "windows")
    second.append([record(2)])
    with pytest.raises(StorageFull, match="Import limit"):
        second.save()
    assert store.get(original["id"]) == original
    assert second.status()["pending_records"] == 1
    assert next(second.root.glob("chunk-*.jsonl")).read_bytes() == record(2)
    store.delete(original["id"])
    saved = second.save()[0]
    assert store.blob_path(saved["id"]).read_bytes() == record(2)


@pytest.mark.parametrize("watch,source,platform", [
    ("../elsewhere", "ssh-live-source.jsonl", "windows"),
    (WATCH, "../outside.jsonl", "windows"),
    (WATCH, "C:\\outside.jsonl", "windows"),
    (WATCH, "ssh-live-source.jsonl", "other"),
])
def test_invalid_capture_paths_or_platform_do_not_create_folders(store, watch, source, platform):
    with pytest.raises(ValueError):
        LiveArchive(store, watch, source, platform)
    assert not (store.root / "live").exists()


def test_reopened_capture_cannot_change_source_or_platform(store):
    LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    with pytest.raises(ValueError, match="checkpoint"):
        LiveArchive(store, WATCH, "ssh-live-different.jsonl", "windows")


@pytest.mark.parametrize("bad", [b"unterminated", b"two\nrecords\n", "not bytes"])
def test_invalid_record_framing_does_not_append_partial_batch(store, bad):
    archive = LiveArchive(store, WATCH, "ssh-live-source.jsonl", "windows")
    with pytest.raises(ValueError, match="complete"):
        archive.append([record(1), bad])
    assert archive.status()["pending_bytes"] == 0 and not archive.pending.exists()
