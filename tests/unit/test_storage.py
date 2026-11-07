from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import sqlite3
from uuid import uuid4

import pytest

from app.db import EvidenceStore
from sentinel.ingest import parse_windows


def test_failed_database_save_rolls_back_metadata_and_blob(tmp_path):
    store = EvidenceStore(tmp_path / "storage")
    store.initialize()
    data = b'{"Id":4625}'
    result = parse_windows(data, file_format="json", source_file="demo.json", upload_id=uuid4().hex)

    class BrokenEvent:
        record_index = 1
        parsing_errors = []

        def model_dump_json(self):
            raise RuntimeError("test write failure")

    result.events = [BrokenEvent()]
    with pytest.raises(RuntimeError, match="test write failure"):
        store.save(data, result)
    assert store.uploads(0, 10)["total"] == 0
    assert list(store.raw_dir.iterdir()) == []


def test_blob_paths_never_use_untrusted_path_components(tmp_path):
    store = EvidenceStore(tmp_path)
    for value in ("../file", "/absolute", "not-an-id"):
        with pytest.raises(ValueError):
            store.blob_path(value)


def test_same_identifier_cannot_overwrite_existing_evidence(tmp_path):
    store = EvidenceStore(tmp_path)
    store.initialize()
    data = b'{"Id":4625}'
    result = parse_windows(data, file_format="json", source_file="demo.json", upload_id=uuid4().hex)
    store.save(data, result)
    with pytest.raises(FileExistsError):
        store.save(b'other', result)
    assert store.blob_path(result.upload_id).read_bytes() == data


def test_record_stream_can_resume_on_another_asgi_worker_thread(tmp_path):
    store = EvidenceStore(tmp_path)
    store.initialize()
    data = b'[{"Id":4625},{"Id":4624}]'
    result = parse_windows(data, file_format="json", source_file="demo.json", upload_id=uuid4().hex)
    store.save(data, result)
    stream = store.iter_records(result.upload_id, "events")
    with ThreadPoolExecutor(max_workers=1) as first:
        assert first.submit(next, stream).result()["record_index"] == 1
    with ThreadPoolExecutor(max_workers=1) as second:
        assert second.submit(next, stream).result()["record_index"] == 2
        assert second.submit(next, stream, None).result() is None


def test_timeline_columns_migrate_existing_import_records(tmp_path):
    store = EvidenceStore(tmp_path)
    data = b'{"Id":4625,"TimeCreated":"2026-11-03T15:00:00.5Z","LogName":"Security","ProviderName":"Microsoft-Windows-Security-Auditing","TargetUserName":"synthetic-user","IpAddress":"192.0.2.20"}'
    result = parse_windows(data, file_format="json", source_file="demo.json", upload_id=uuid4().hex)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("CREATE TABLE events (upload_id TEXT, record_index INTEGER, payload TEXT, PRIMARY KEY(upload_id,record_index))")
        connection.execute("INSERT INTO events VALUES (?,?,?)", (result.upload_id, 1, result.events[0].model_dump_json()))
    store.initialize()
    assert store.timeline(0, 10)["items"][0]["event_id"] == result.events[0].event_id
    with store.connect() as connection:
        assert connection.execute("SELECT timestamp_utc FROM events").fetchone()[0] == "2026-11-03T15:00:00.500000+00:00"
        assert connection.execute("SELECT windows_event_id FROM events").fetchone()[0] == "4625"
    assert store.timeline(0, 10, windows_event_id=4625)["total"] == 1
    assert store.timeline(0, 10, actor="synthetic-user", source_ip="192.0.2.20")["total"] == 1
    # Reinitialization preserves the original payload and migrated values.
    store.initialize()
    assert store.timeline(0, 10, windows_event_id=4625)["items"][0]["raw_record"]["Id"] == 4625
