"""Independent tab ownership, concurrent reads, and shared saved evidence."""

from concurrent.futures import ThreadPoolExecutor
import json
from threading import Event
from time import monotonic, sleep

from fastapi.testclient import TestClient
import pytest

from app import ssh_collection, ssh_setup
from app.main import create_app
from app.password_ssh import PasswordSession
from app.windows_live import TASK_SCHEDULER


HEADERS = {"X-Sentinel-Import": "1"}


def line(value):
    return (json.dumps(value) + "\n").encode()


def windows_event(channel, host="windows.test", number=1, *, code=7045, provider="Service Control Manager", fields=None):
    return line({"LogName": channel, "Id": code, "ProviderName": provider, "RecordId": number,
                 "MachineName": host, "TimeCreated": "2026-11-10T12:00:00Z", "EventData": fields or {}})


def journal_event(host, number=1):
    return line({"__CURSOR": f"fixture-{number}", "__REALTIME_TIMESTAMP": "1794312000000000", "_HOSTNAME": host,
                 "SYSLOG_IDENTIFIER": "CRON", "MESSAGE": "(root) CMD (/usr/local/bin/maintenance)"})


@pytest.fixture
def browser_store(tmp_path, sign_in, monkeypatch):
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda host, *_: f"{host} ssh-ed25519 fixture\n".encode())
    monkeypatch.setattr(ssh_setup, "collect_output", lambda *_args, **_kwargs: b"")
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50107)) as client:
        sign_in(client)
        yield client


def connect(client, host, platform, channel, *, password=None):
    body = {"ssh_command": f"ssh reader@{host} -p 2222", "platform": platform,
            "channel": channel, "isolated": True, "authentication": "auto"}
    if password:
        body["password"] = password
    path = "/api/live/password" if password else "/api/live/connect"
    return client.post(path, json=body, headers=HEADERS).raise_for_status().json()


def start(client, config, **settings):
    return client.post("/api/live/start", params={"host": config["host"], "port": config["port"]},
                       json={"connection_id": config["connection_id"], **settings}, headers=HEADERS)


def action(client, watch, name, *, token=None):
    return client.post(f"/api/live/{watch['id']}/{name}", headers=HEADERS,
                       params={"token": watch["token"] if token is None else token})


def test_background_watch_continues_between_pages_and_stops_on_request(browser_store, monkeypatch):
    client = browser_store
    monkeypatch.setattr("app.live_logs.POLL_SECONDS", .05)
    pulls = []

    def retrieve(*_args):
        pulls.append(len(pulls) + 1)
        return journal_event("journal.test", pulls[-1])

    monkeypatch.setattr(ssh_collection, "collect_live", retrieve)
    config = connect(client, "journal.test", "linux", "Journal")
    watch = start(client, config, background=True, autosave=True).raise_for_status().json()
    # No websocket, browser pull, or status request is needed to collect.
    client.get("/").raise_for_status()
    deadline = monotonic() + 5
    while len(pulls) < 3 and monotonic() < deadline:
        sleep(.05)
    assert len(pulls) >= 3
    client.get("/live").raise_for_status()
    running = client.get("/api/live/background").raise_for_status().json()["items"]
    assert running[0]["id"] == watch["id"]
    assert running[0]["token"] == watch["token"]
    path = f"/api/live/{watch['id']}/view"
    assert client.get(path, params={"token": "bad"}).status_code == 409
    assert client.get(path, params={"token": watch["token"]}).raise_for_status().json()["parsed"] >= 2
    assert action(client, watch, "poll").status_code == 409
    result = action(client, watch, "stop").raise_for_status().json()
    assert not result["active"] and result["archive_saved"] >= 1
    assert client.get("/api/live/background").json()["items"] == []


@pytest.mark.parametrize(("platform", "channel"), (("linux", "Journal"), ("windows", "System")))
def test_bookmark_restarts_and_catches_up_without_advancing_past_gap(browser_store, monkeypatch, platform, channel):
    client = browser_store
    store = client.app.state.store
    host = f"{platform}.test"
    config = connect(client, host, platform, channel)
    monkeypatch.setattr("app.live_logs.POLL_SECONDS", 0)

    def raw(number):
        if platform == "windows":
            return windows_event(channel, host=host, number=number)
        return journal_event(host, number).replace(b"fixture-", b"i=")

    available = [raw(1), raw(2)]
    positions = []

    def retrieve(target, options):
        assert target[0] == host and options["channel"] == channel
        positions.append(options.get("bookmark"))
        return b"".join(available)

    monkeypatch.setattr(ssh_collection, "collect_live", retrieve)
    assert start(client, config, resume=True).status_code == 400
    initial = start(client, config, resume=True, autosave=True).raise_for_status().json()
    view = action(client, initial, "poll").raise_for_status().json()
    assert view["received"] == 2 and view["bookmark_ready"]
    duplicate = connect(client, host, platform, channel)
    assert start(client, duplicate, resume=True, autosave=True).status_code == 409
    action(client, initial, "stop").raise_for_status()

    with TestClient(create_app(store.root), base_url="http://127.0.0.1", client=("127.0.0.1", 50108)) as restarted:
        restarted.cookies.update(client.cookies)
        profile = connect(restarted, host, platform, channel)
        second = start(restarted, profile, resume=True, autosave=True).raise_for_status().json()
        assert second["bookmark_ready"]
        available[:] = [raw(i) for i in range(2, 103)]
        full = action(restarted, second, "poll").raise_for_status().json()
        assert full["received"] == 100 and full["full_resume_page"] and not full["possible_gap"]
        available[:] = [raw(102), raw(103), raw(104)]
        final = action(restarted, second, "poll").raise_for_status().json()
        assert final["received"] == 102 and not final["full_resume_page"]
        available[:] = [raw(106)]
        gap = action(restarted, second, "poll").raise_for_status().json()
        assert gap["bookmark_lost"] and gap["possible_gap"] and not gap["active"]
        assert gap["received"] == 102
        with store.connect() as connection:
            saved, = [row["position"] for row in connection.execute("SELECT position FROM live_bookmarks")]
        assert saved == positions[-1] and positions[0] is None
        assert len({position for position in positions[1:]}) == 3
        action(restarted, second, "stop").raise_for_status()
        logs = restarted.get("/api/uploads").raise_for_status().json()["items"]
        staged = [line for item in logs for line in store.blob_path(item["id"]).read_bytes().splitlines(keepends=True)]
        assert sorted(staged) == sorted(raw(i) for i in range(1, 105))
        reset = start(restarted, profile, resume=True, autosave=True, restart_from_latest=True).raise_for_status().json()
        result = action(restarted, reset, "poll").raise_for_status().json()
        assert positions[-1] is None and result["received"] == 1 and result["bookmark_ready"]


def test_failed_archive_append_does_not_advance_bookmark(browser_store, monkeypatch):
    from app.live_archive import LiveArchive

    client = browser_store
    config = connect(client, "linux.test", "linux", "Journal")
    monkeypatch.setattr("app.live_logs.POLL_SECONDS", 0)
    latest = journal_event("linux.test").replace(b"fixture-", b"i=")
    batch = [latest]
    monkeypatch.setattr(ssh_collection, "collect_live", lambda *_: b"".join(batch))
    watch = start(client, config, autosave=True, resume=True).raise_for_status().json()
    assert action(client, watch, "poll").raise_for_status().json()["received"] == 1

    def failed_append(*_):
        raise OSError("Fixture disk full")

    monkeypatch.setattr(LiveArchive, "append", failed_append)
    batch.append(journal_event("linux.test", 2).replace(b"fixture-", b"i="))
    failed = action(client, watch, "poll").raise_for_status().json()
    assert failed["archive_error"] and not failed["active"]
    with client.app.state.store.connect() as connection:
        assert connection.execute("SELECT position FROM live_bookmarks").fetchone()[0] == "i=1"


def test_tabs_pull_concurrently_and_save_separate_sources(browser_store, monkeypatch):
    client = browser_store
    windows = connect(client, "windows.test", "windows", "Application")
    linux = connect(client, "linux.test", "linux", "Changes")
    assert windows["connection_id"] != linux["connection_id"]
    assert not (client.app.state.store.root / "ssh-lab.json").exists()
    assert start(client, linux | {"host": windows["host"]}).status_code == 409
    watched_win = start(client, windows).raise_for_status().json()
    watched_linux = start(client, linux).raise_for_status().json()
    assert start(client, linux).status_code == 409
    assert action(client, watched_linux, "stop", token=watched_win["token"]).status_code == 409
    assert client.post(f"/api/live/{watched_linux['id']}/save", headers=HEADERS).status_code == 409

    blocked, release = Event(), Event()
    keys = {}
    captures = {"windows.test": windows_event("Application"), "linux.test": journal_event("linux.test")}

    def retrieve(target, options):
        host, _, _, pinned = target
        assert pinned.read_text().startswith(host + " ")
        keys[host] = pinned
        if host == "windows.test":
            assert options["channel"] == "Application"
            blocked.set()
            assert release.wait(5)
        else:
            assert options["channel"] == "Changes"
        return captures[host]

    monkeypatch.setattr(ssh_collection, "collect_live", retrieve)
    with ThreadPoolExecutor() as executor:
        pending = executor.submit(action, client, watched_win, "poll")
        assert blocked.wait(5)
        try:
            other = executor.submit(action, client, watched_linux, "poll")
            result = other.result(3).raise_for_status().json()
            assert result["active"] and result["parsed"] == 1 and result["channel"] == "Changes"
            assert not pending.done()
        finally:
            release.set()
        assert pending.result(5).raise_for_status().json()["parsed"] == 1
    assert keys["windows.test"].parent != keys["linux.test"].parent
    assert client.post("/api/live/disconnect", params={"connection_id": windows["connection_id"]},
                       headers=HEADERS).status_code == 204
    assert not keys["windows.test"].exists() and keys["linux.test"].is_file()
    assert not action(client, watched_win, "poll").raise_for_status().json()["active"]
    assert action(client, watched_linux, "poll").status_code == 429
    for watch, host in ((watched_win, "windows.test"), (watched_linux, "linux.test")):
        saved = action(client, watch, "save").raise_for_status().json()["upload_id"]
        assert list(client.app.state.store.iter_records(saved, "events"))[0]["host"] == host
        assert client.app.state.store.blob_path(saved).read_bytes() == captures[host]


def test_two_password_connections_close_independently(browser_store, monkeypatch):
    client = browser_store
    sessions = {}

    class Session:
        active = True

        def __init__(self, host):
            self.host = host

        def touch(self):
            assert self.active

        def close(self):
            self.active = False

        def collect(self, options):
            self.touch()
            return journal_event(self.host)

    def authenticate(target, password):
        assert password == "disposable test credential"
        session = Session(target[0])
        sessions[target[0]] = session
        return session

    monkeypatch.setattr(PasswordSession, "connect", authenticate)
    first, second = [connect(client, host, "linux", "Journal", password="disposable test credential")
                     for host in ("linux-one.test", "linux-two.test")]
    a, b = [start(client, source).raise_for_status().json() for source in (first, second)]
    assert action(client, a, "stop").raise_for_status().json()["active"] is False
    assert start(client, first).status_code == 409
    assert not sessions["linux-one.test"].active and sessions["linux-two.test"].active
    assert action(client, b, "poll").raise_for_status().json()["parsed"] == 1
    client.post("/api/auth/logout", headers=HEADERS).raise_for_status()
    assert not sessions["linux-two.test"].active
    assert not list(client.app.state.store.root.glob("live-source-*"))


def test_window_channel_rotation_keeps_cursors_separate(browser_store, monkeypatch):
    client = browser_store
    config = connect(client, "windows.test", "windows", "All")
    watch = start(client, config).raise_for_status().json()
    security = windows_event("Security", code=4719, provider="Microsoft-Windows-Security-Auditing")
    system = windows_event("System", fields={"ImagePath": r"C:\Users\Public\unexpected.exe"})

    def coverage(channels, offset, total=9):
        return line({"SentinelCapture": 1, "total_channels": total, "next_offset": offset, "discovery_errors": 0,
                     "channels": [dict(channel=channel, status=status, capped=False, dropped=0)
                                  for channel, status in channels]})

    first = [("Security", "read"), ("System", "read")] + [(f"Channel-{i}", "empty") for i in range(6)]
    responses = iter([security + system + coverage(first, 8), coverage([(TASK_SCHEDULER, "empty")], 0),
                      security + system + coverage(first, 8), coverage([(TASK_SCHEDULER, "unavailable")], 0)])
    offsets = []

    def retrieve(_target, options):
        offsets.append(options["offset"])
        return next(responses)

    monkeypatch.setattr(ssh_collection, "collect_live", retrieve)
    monkeypatch.setattr("app.live_logs.POLL_SECONDS", 0)
    views = [action(client, watch, "poll").raise_for_status().json() for _ in range(4)]
    assert offsets == [0, 8, 0, 8]
    assert [view["new_last_pull"] for view in views] == [2, 0, 0, 0]
    assert [view["possible_gap"] for view in views] == [False, False, False, True]
    assert views[1]["coverage"]["observed_channels"] == 9
    assert views[-1]["coverage"]["unavailable_channels"] == 1
    live = views[0]["review"]
    assert set(live["flagged"].values()) == {"warning", "context"}
    saved = action(client, watch, "save").raise_for_status().json()["upload_id"]
    assert client.app.state.store.blob_path(saved).read_bytes() == security + system
    page = client.get("/api/events", params={"upload_id": saved, "include_flags": True}).raise_for_status().json()
    assert len(page["flagged_event_ids"]) == 1 and len(page["context_review_event_ids"]) == 1
