"""Long-running, owner-bound live collection with disposable synthetic telemetry."""

from hashlib import sha256
import json
import sqlite3
from time import sleep

from fastapi.testclient import TestClient
import pytest
from starlette.websockets import WebSocketDisconnect

from app import db, live_logs, ssh_collection, ssh_setup
from app.main import create_app
from app.password_ssh import PasswordSession


HEADERS = {"X-Sentinel-Import": "1"}
DESTINATION = {"host": "lab.example.test", "port": 2222}
ORIGIN = {"origin": "http://127.0.0.1"}


def line(number):
    # Capture receipt age must not depend on these old source timestamps.
    return (json.dumps({
        "__CURSOR": f"long-test-{number}",
        "__REALTIME_TIMESTAMP": str(1760000000000000 + number * 1000000),
        "_HOSTNAME": "long-session-host",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": "Failed password for test-user from 192.0.2.8 port 4180 ssh2",
    }) + "\n").encode()


@pytest.fixture
def lab(tmp_path, sign_in, monkeypatch):
    clock = [100.0]
    state = {"raw": line(1), "calls": 0}
    monkeypatch.setattr(live_logs, "monotonic", lambda: clock[0])
    # Keep socket tests fast without weakening the source/read safety bounds.
    monkeypatch.setattr(live_logs, "POLL_SECONDS", .02)

    def collect(*args):
        state["calls"] += 1
        return state["raw"]

    monkeypatch.setattr(ssh_collection, "collect_live", collect)
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50109)) as client:
        sign_in(client)
        (tmp_path / "ssh-lab.json").write_text(json.dumps(DESTINATION | {"username": "journal_reader"}))
        (tmp_path / "ssh-known-hosts").write_text("verified host-key fixture")
        yield client, clock, state


def start(client, *, autosave=False):
    response = client.post("/api/live/start", params=DESTINATION,
                           json={"autosave": autosave}, headers=HEADERS)
    return response.raise_for_status().json()


def action(client, watch, verb, **params):
    return client.post(f"/api/live/{watch['id']}/{verb}", params=params, headers=HEADERS)


def stream_path(watch, token=None):
    # TestClient otherwise defaults relative WebSocket paths to ws://testserver,
    # bypassing our HTTP base URL and correctly failing trusted-host protection.
    return f"ws://127.0.0.1/api/live/{watch['id']}/stream?token={watch['token'] if token is None else token}"


def received(socket, predicate=lambda value: value.get("pulls", 0) > 0):
    for _ in range(30):
        value = socket.receive_json()
        socket.send_text("ack")
        if predicate(value):
            return value
    raise AssertionError("Live stream did not deliver the expected state")


def saved_uploads(client):
    # Socket disconnect and archive promotion finish in the ASGI worker; give
    # that bounded cleanup time to complete after the client closes its end.
    for _ in range(50):
        page = client.get("/api/uploads").json()
        if page["total"]:
            return page
        sleep(.02)
    return page


def test_active_save_is_a_versioned_library_snapshot(lab):
    client, clock, state = lab
    watch = start(client)
    assert action(client, watch, "poll").raise_for_status().json()["active"]
    saved = action(client, watch, "save").raise_for_status().json()["upload_id"]
    assert action(client, watch, "save").json()["upload_id"] == saved
    original = client.get(f"/api/uploads/{saved}").json()
    assert original["sha256"] == sha256(line(1)).hexdigest()
    assert client.app.state.store.blob_path(saved).read_bytes() == line(1)
    assert client.get(f"/api/analysis/{saved}").json()["status"] == "current"

    clock[0] += live_logs.POLL_SECONDS
    state["raw"] = line(1) + line(2)
    assert action(client, watch, "poll").raise_for_status().json()["active"]
    revised = action(client, watch, "save").raise_for_status().json()["upload_id"]
    assert revised != saved
    assert client.get(f"/api/uploads/{revised}").json()["filename"] != original["filename"]
    assert "-snapshot-" in original["filename"]
    assert client.get("/api/uploads").json()["total"] == 2
    assert client.get(f"/api/uploads/{saved}").json() == original
    assert client.app.state.store.blob_path(saved).read_bytes() == line(1)
    assert client.app.state.store.blob_path(revised).read_bytes() == line(1) + line(2)
    assert client.get(f"/api/analysis/{revised}").json()["status"] == "current"


@pytest.mark.parametrize("error", [OSError("Test storage unavailable"), sqlite3.OperationalError("Test database unavailable")])
def test_archive_storage_failure_stays_visible_even_when_status_cannot_be_read(lab, monkeypatch, error):
    client, _, _ = lab
    class UnavailableArchive:
        def __init__(self, *args):
            pass
        def append(self, records):
            pass
        def save(self, **kwargs):
            raise error
        def status(self):
            raise OSError("Test status unavailable")
    monkeypatch.setattr(live_logs, "LiveArchive", UnavailableArchive)
    watch = start(client, autosave=True)
    result = action(client, watch, "poll").raise_for_status().json()
    assert not result["active"] and "unavailable" in result["archive_error"]


def test_receipt_window_rolls_at_one_hour_without_a_fifteen_minute_cutoff(lab, monkeypatch):
    client, clock, state = lab
    # This direct-poll compatibility test isolates elapsed-lifetime and retention
    # behavior; the live socket tests separately cover owner-based liveness.
    monkeypatch.setattr(live_logs, "IDLE_SECONDS", 2 * 24 * 60 * 60)
    watch = start(client)
    first = action(client, watch, "poll").raise_for_status().json()
    assert first["retained"] == 1
    clock[0] += 901
    state["raw"] = line(1) + line(2)
    later = action(client, watch, "poll").raise_for_status().json()
    assert later["active"] and later["retained"] == 2
    clock[0] += 2700
    state["raw"] = line(2) + line(3)
    rolled = action(client, watch, "poll").raise_for_status().json()
    assert rolled["active"] and rolled["retained"] == 2
    assert rolled["age_evicted"] == 1 and rolled["capacity_evicted"] == 0
    assert [event["raw_record"]["__CURSOR"] for event in rolled["review"]["events"]] == [
        "long-test-2", "long-test-3",
    ]


def test_quiet_source_expires_old_view_rows_without_readding_overlap(lab, monkeypatch):
    client, clock, _ = lab
    monkeypatch.setattr(live_logs, "IDLE_SECONDS", 2 * 24 * 60 * 60)
    watch = start(client)
    first = action(client, watch, "poll").raise_for_status().json()
    clock[0] += 3601
    result = action(client, watch, "poll", revision=first["revision"]).raise_for_status().json()
    assert result["active"] and result["retained"] == 0 and result["age_evicted"] == 1
    assert result["new_last_pull"] == 0
    assert result["review"]["events"] == []


@pytest.mark.parametrize("capacity", ["rows", "bytes"])
def test_capacity_limit_is_reported_separately_from_age(lab, monkeypatch, capacity):
    client, _, state = lab
    if capacity == "rows":
        monkeypatch.setattr(live_logs, "BUFFER_RECORDS", 2)
    else:
        monkeypatch.setattr(live_logs, "BUFFER_BYTES", 2 * len(line(1)))
    state["raw"] = line(1) + line(2) + line(3)
    watch = start(client)
    result = action(client, watch, "poll").raise_for_status().json()
    assert result["retained"] == 2
    assert result["capacity_evicted"] == 1 and result["age_evicted"] == 0


def test_another_tool_tab_does_not_stop_the_owner_but_owner_close_does(lab):
    client, clock, state = lab
    watch = start(client)
    with client.websocket_connect(stream_path(watch), headers=ORIGIN) as socket:
        assert received(socket)["active"]
        for path in ("/", "/?tool=network", "/live", "/api/uploads", "/api/live/status"):
            assert client.get(path).status_code == 200
        # A connected owner remains live past the former fixed lifetime even
        # when another tab reads the status route before the next socket tick.
        clock[0] += 901
        assert client.get("/api/live/status").status_code == 200
        state["raw"] = line(1) + line(2)
        assert received(socket, lambda value: value.get("retained") == 2)["active"]
    stopped = action(client, watch, "poll").raise_for_status().json()
    assert not stopped["active"]
    assert client.get("/api/uploads").json()["total"] == 0


def test_direct_poll_and_second_socket_cannot_replace_the_stream_owner(lab):
    client, _, _ = lab
    watch = start(client)
    with client.websocket_connect(stream_path(watch), headers=ORIGIN) as socket:
        assert received(socket)["active"]
        assert action(client, watch, "poll").status_code == 409
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(stream_path(watch), headers=ORIGIN) as duplicate:
                duplicate.receive_json()
        assert received(socket)["active"]


def test_owner_socket_close_ends_password_transport(lab, monkeypatch):
    client, _, state = lab

    class Session:
        active = True
        def touch(self):
            assert self.active
        def collect(self, options):
            return state["raw"]
        def close(self):
            self.active = False

    session = Session()
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda *_: b"host ssh-ed25519 verified\n")
    monkeypatch.setattr(PasswordSession, "connect", lambda *_: session)
    client.post("/api/live/password", json={"ssh_command": "ssh journal_reader@lab.example.test -p 2222",
        "platform": "linux", "password": "Disposable-test-only"}, headers=HEADERS).raise_for_status()
    watch = start(client)
    with client.websocket_connect(stream_path(watch), headers=ORIGIN) as socket:
        assert received(socket)["active"] and session.active
    assert not session.active
    assert client.get("/api/live/status").json()["password_required"]


@pytest.mark.parametrize("token,origin", [
    ("incorrect-token", "http://127.0.0.1"),
    (None, "https://untrusted.example"),
])
def test_socket_rejects_bad_token_or_cross_origin_without_reading(lab, token, origin):
    client, _, state = lab
    watch = start(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(stream_path(watch, token), headers={"origin": origin}) as socket:
            socket.receive_json()
    assert state["calls"] == 0


def test_socket_requires_authenticated_cookie(lab):
    client, _, state = lab
    watch = start(client)
    client.cookies.clear()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(stream_path(watch), headers=ORIGIN) as socket:
            socket.receive_json()
    assert state["calls"] == 0


def test_stale_owner_stop_token_does_not_stop_the_current_watch(lab):
    client, _, _ = lab
    watch = start(client)
    assert action(client, watch, "stop", token="incorrect-token").status_code == 409
    assert action(client, watch, "poll").raise_for_status().json()["active"]


def test_opt_in_autosave_flushes_on_owner_disconnect_into_logs(lab):
    client, _, state = lab
    state["raw"] = b"".join(line(number) for number in range(1, 6))
    watch = start(client, autosave=True)
    with client.websocket_connect(stream_path(watch), headers=ORIGIN) as socket:
        assert received(socket)["parsed"] == 5
    assert not action(client, watch, "poll").raise_for_status().json()["active"]
    page = saved_uploads(client)
    assert page["total"] >= 1
    saved = page["items"][0]
    assert saved["format"] == "linux-journal-json"
    assert client.app.state.store.blob_path(saved["id"]).read_bytes() == state["raw"]
    assert client.get(f"/api/analysis/{saved['id']}").json()["status"] == "current"


def test_periodic_autosave_and_stop_flush_do_not_duplicate_overlapping_batches(lab, monkeypatch):
    client, clock, state = lab
    monkeypatch.setattr(live_logs, "IDLE_SECONDS", 2 * 24 * 60 * 60)
    watch = start(client, autosave=True)
    action(client, watch, "poll").raise_for_status()
    clock[0] += 901
    state["raw"] = line(1) + line(2)
    period = action(client, watch, "poll").raise_for_status().json()
    assert period["archive_saved"] >= 1 and not period["archive_error"]
    clock[0] += live_logs.POLL_SECONDS
    state["raw"] = line(2) + line(3)
    action(client, watch, "poll").raise_for_status()
    action(client, watch, "stop").raise_for_status()
    uploads = client.get("/api/uploads").json()["items"]
    blobs = [client.app.state.store.blob_path(item["id"]).read_bytes() for item in uploads]
    saved_lines = [entry for blob in blobs for entry in blob.splitlines(keepends=True)]
    assert sorted(saved_lines) == sorted([line(1), line(2), line(3)])
    assert len(saved_lines) == len(set(saved_lines)) == 3


def test_full_library_stops_autosave_visibly_and_keeps_staged_bytes(lab, monkeypatch):
    client, clock, state = lab
    monkeypatch.setattr(live_logs, "IDLE_SECONDS", 2 * 24 * 60 * 60)
    monkeypatch.setattr(db, "MAX_UPLOADS", 0)
    watch = start(client, autosave=True)
    action(client, watch, "poll").raise_for_status()
    clock[0] += 901
    state["raw"] = line(1) + line(2)
    result = action(client, watch, "poll").raise_for_status().json()
    assert not result["active"] and result["archive_error"]
    assert "saving" in result["stopped"].lower()
    assert client.get("/api/uploads").json()["total"] == 0
    staged = client.app.state.store.root / "live" / watch["id"]
    files = list(staged.glob("*.jsonl"))
    assert files and b"".join(path.read_bytes() for path in sorted(files)) == state["raw"]
