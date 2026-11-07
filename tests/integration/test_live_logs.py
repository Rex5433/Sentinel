"""Synthetic, no-network tests for the authenticated lab journal watch."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from types import SimpleNamespace
from threading import Event

from fastapi.testclient import TestClient
import pytest

from app import live_logs, ssh_collection, ssh_setup
from app.main import create_app


HEADERS = {"X-Sentinel-Import": "1"}
DESTINATION = {"host": "lab.example.test", "port": 2222}


def line(index):
    return (json.dumps({
        "__CURSOR": f"cursor-{index}",
        "__REALTIME_TIMESTAMP": str(1760000000000000 + index * 1000000),
        "_HOSTNAME": "lab-01",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": "Failed password for labuser from 192.0.2.8 port 4180 ssh2",
    }) + "\n").encode()


def post(client, path, **params):
    return client.post(f"/api/live/{path}", params=params, headers=HEADERS)


def test_live_page_and_api_require_owner_and_default_to_disabled(tmp_path, sign_in):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50107)) as client:
        assert client.get("/live", follow_redirects=False).status_code == 303
        assert client.get("/static/live.html", follow_redirects=False).status_code == 303
        assert client.get("/api/live/status").status_code == 401
        sign_in(client)
        assert "SSH log watch" in client.get("/live").text
        assert client.get("/api/live/status").json() == {"enabled": False}
        assert post(client, "start", **DESTINATION).status_code == 404


@pytest.fixture
def lab(tmp_path, sign_in, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(live_logs, "monotonic", lambda: clock[0])
    with TestClient(create_app(tmp_path, lab_ssh=True), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50107)) as client:
        sign_in(client)
        (tmp_path / "ssh-lab.json").write_text(json.dumps(DESTINATION | {"username": "journal_reader"}), encoding="utf-8")
        (tmp_path / "ssh-known-hosts").write_text("verified key fixture", encoding="utf-8")
        yield client, clock


def test_overlap_and_incremental_findings_save_into_normal_logs(lab, monkeypatch):
    client, clock = lab
    captures = [
        b"".join(map(line, range(1, 5))),
        b"".join(map(line, range(2, 6))),
        b"".join(map(line, range(2, 6))),
        line(20),
    ]
    monkeypatch.setattr(ssh_collection, "collect_journal", lambda *_: captures.pop(0))
    assert client.get("/api/live/status").json()["ready"] is True
    assert client.post("/api/live/start", params=DESTINATION).status_code == 403
    assert post(client, "start", **(DESTINATION | {"port": 22})).status_code == 409
    started = post(client, "start", **DESTINATION).raise_for_status().json()
    assert started["active"] and started["retained"] == 0 and len(captures) == 4
    assert post(client, "start", **DESTINATION).status_code == 409
    watch = started["id"]
    first = post(client, f"{watch}/poll", revision=0).raise_for_status().json()
    assert first["retained"] == 4 and not first["review"]["findings"]
    assert (first["pulls"], first["attempts"], first["new_last_pull"], first["received"]) == (1, 1, 4, 4)
    throttled = post(client, f"{watch}/poll")
    assert throttled.status_code == 429 and throttled.headers["Retry-After"] == "5"
    assert first["saved_revision"] == -1

    clock[0] += live_logs.POLL_SECONDS
    second = post(client, f"{watch}/poll", revision=first["revision"]).raise_for_status().json()
    assert second["retained"] == 5 and not second["possible_gap"]
    assert (second["pulls"], second["new_last_pull"], second["received"]) == (2, 1, 5)
    finding = second["review"]["findings"][0]["finding"]
    assert finding["method"] == "deterministic"
    evidence = {event["event_id"] for event in second["review"]["events"]}
    assert set(finding["evidence_event_ids"]) == evidence == set(second["review"]["flagged"])

    clock[0] += live_logs.POLL_SECONDS
    repeated = post(client, f"{watch}/poll", revision=second["revision"]).raise_for_status().json()
    assert repeated["retained"] == 5 and repeated["review"] is None
    assert (repeated["pulls"], repeated["new_last_pull"], repeated["received"]) == (3, 0, 5)
    clock[0] += live_logs.POLL_SECONDS
    gap = post(client, f"{watch}/poll").raise_for_status().json()
    assert gap["retained"] == 6 and gap["possible_gap"]
    assert client.get("/api/uploads").json()["total"] == 0
    assert post(client, f"{watch}/stop").json()["active"] is False
    assert post(client, f"{watch}/poll").json()["active"] is False

    saved = post(client, f"{watch}/save").raise_for_status().json()
    upload_id = saved["upload_id"]
    assert saved == post(client, f"{watch}/save").json()
    assert client.get("/api/uploads").json()["total"] == 1
    expected = b"".join(map(line, (1, 2, 3, 4, 5, 20)))
    item = client.get(f"/api/uploads/{upload_id}").json()
    assert item["sha256"] == sha256(expected).hexdigest()
    assert client.app.state.store.blob_path(upload_id).read_bytes() == expected
    assert client.get(f"/api/analysis/{upload_id}").json()["finding_count"] == 1


def test_no_cursor_errors_and_idle_expiry_do_not_poll_forever(lab, monkeypatch):
    client, clock = lab
    pulls = []

    def collect(*_):
        pulls.append(True)
        return b'{"MESSAGE":"Missing journal cursor"}\n'

    monkeypatch.setattr(ssh_collection, "collect_journal", collect)
    watch = post(client, "start", **DESTINATION).json()["id"]
    for _ in range(3):
        result = post(client, f"{watch}/poll").raise_for_status().json()
        clock[0] += live_logs.POLL_SECONDS
    assert result["active"] is False and result["possible_gap"] and result["skipped"] == 3
    assert "three unsuccessful pulls" in result["stopped"]
    assert post(client, f"{watch}/save").status_code == 400
    watch = post(client, "start", **DESTINATION).json()["id"]
    clock[0] += live_logs.IDLE_SECONDS
    expired = post(client, f"{watch}/poll").raise_for_status().json()
    assert expired["active"] is False and "expired" in expired["stopped"]
    assert len(pulls) == 3


def test_stop_discards_an_in_flight_pull(lab, monkeypatch):
    client, _ = lab
    entered, release = Event(), Event()

    def collect(*_):
        entered.set()
        assert release.wait(5)
        return line(1)

    monkeypatch.setattr(ssh_collection, "collect_journal", collect)
    watch = post(client, "start", **DESTINATION).json()["id"]
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(post, client, f"{watch}/poll")
        try:
            assert entered.wait(5)
            assert post(client, f"{watch}/stop").json()["active"] is False
        finally:
            release.set()
        assert pending.result(timeout=5).json()["retained"] == 0
    assert client.get("/api/uploads").json()["total"] == 0


def test_rolling_record_bound_and_malformed_rows(lab, monkeypatch):
    client, clock = lab
    monkeypatch.setattr(live_logs, "BUFFER_RECORDS", 3)
    captures = [line(1) + line(2), line(2) + line(3) + line(4) + b"unparseable\n"]
    monkeypatch.setattr(ssh_collection, "collect_journal", lambda *_: captures.pop(0))
    watch = post(client, "start", **DESTINATION).json()["id"]
    assert post(client, f"{watch}/poll").json()["retained"] == 2
    clock[0] += live_logs.POLL_SECONDS
    result = post(client, f"{watch}/poll").json()
    assert result["retained"] == 3 and result["evicted"] == result["skipped"] == 1
    assert result["possible_gap"]
    assert [event["raw_record"]["__CURSOR"] for event in result["review"]["events"]] == [
        "cursor-2", "cursor-3", "cursor-4",
    ]


def test_windows_watch_overlap_clear_empty_and_save(lab, monkeypatch):
    client, clock = lab
    root = client.app.state.store.root
    profile = DESTINATION | {"username": "DOMAIN\\alex", "platform": "windows", "channel": "Security"}
    (root / "ssh-lab.json").write_text(json.dumps(profile), encoding="utf-8")

    def win(number, minute=0, image="vssadmin.exe", args="delete shadows /quiet"):
        return (json.dumps({
            "Id": 4688, "RecordId": number, "LogName": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": "lab-win",
            "TimeCreated": f"2026-11-06T12:{minute:02}:00Z",
            "EventData": {"SubjectUserName": "alex", "NewProcessName": image, "CommandLine": f"{image} {args}"},
        }) + "\n").encode()

    first, second, reset = win(1), win(2, image="notepad.exe", args=""), win(1, minute=1)
    batches = [first, first + second, b"", reset]
    calls = []
    def collect(target, options):
        calls.append(options)
        return batches.pop(0)

    monkeypatch.setattr(ssh_collection, "collect_live", collect)
    status = client.get("/api/live/status").json()
    assert status["platform"] == "windows" and status["channel"] == "Security"
    assert not client.get("/api/collect/linux/status").json()["ready"]
    watch = post(client, "start", **DESTINATION).json()["id"]
    result = post(client, f"{watch}/poll").json()
    assert result["retained"] == 1 and result["review"]["findings"][0]["title"] == "Shadow copy deletion attempt"
    assert set(result["review"]["flagged"]) == {result["review"]["events"][0]["event_id"]}
    for expected in (2, 2, 3):
        clock[0] += live_logs.POLL_SECONDS
        result = post(client, f"{watch}/poll").raise_for_status().json()
        assert result["retained"] == expected and result["active"]
    assert result["possible_gap"]
    post(client, f"{watch}/stop").raise_for_status()
    saved = post(client, f"{watch}/save").raise_for_status().json()["upload_id"]
    assert client.app.state.store.blob_path(saved).read_bytes() == first + second + reset
    assert client.get(f"/api/uploads/{saved}").json()["format"] == "windows-jsonl"
    assert client.get(f"/api/analysis/{saved}").json()["finding_count"] == 2
    assert len(calls) == 4


def test_dashboard_connect_works_from_normal_launcher_and_survives_restart(tmp_path, sign_in, monkeypatch):
    calls = []
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda *_: b"lab.example.test ssh-ed25519 verified\n")
    monkeypatch.setattr(ssh_setup, "collect_output", lambda args, **kwargs: calls.append(args) or b"")
    monkeypatch.setattr(ssh_collection, "collect_live", lambda *_: line(1))
    body = {"ssh_command": "ssh reader@lab.example.test -p 2222", "platform": "linux"}
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50107)) as client:
        assert client.post("/api/live/connect", json=body, headers=HEADERS).status_code == 401
        password = sign_in(client)
        assert client.post("/api/live/connect", json=body).status_code == 403
        result = client.post("/api/live/connect", json=body, headers=HEADERS).raise_for_status().json()
        assert result["ready"] and result["platform"] == "linux"
        assert calls[0][-2:] == ["lab.example.test", "exit 0"]
        watch = post(client, "start", **DESTINATION).raise_for_status().json()["id"]
        assert client.post("/api/live/connect", json=body, headers=HEADERS).status_code == 409
        assert post(client, f"{watch}/poll").json()["parsed"] == 1
        post(client, f"{watch}/stop").raise_for_status()
        assert post(client, f"{watch}/save").status_code == 200
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50107)) as restarted:
        assert restarted.get("/api/live/status").status_code == 401
        restarted.post("/api/auth/login", json={"username": "test-owner", "password": password}, headers=HEADERS).raise_for_status()
        assert restarted.get("/api/live/status").json()["ready"]
        assert post(restarted, "start", **DESTINATION).status_code == 201


@pytest.mark.parametrize("body", [
    {"ssh_command": "ssh reader@host extra-command"},
    {"ssh_command": "ssh -o ProxyCommand=anything reader@host"},
    {"ssh_command": "ssh reader@host", "platform": "unsupported"},
    {"ssh_command": "ssh reader@host", "channel": "not-an-event-channel"},
    {"ssh_command": "ssh reader@host;whoami"},
])
def test_dashboard_rejects_unapproved_commands_before_network(tmp_path, sign_in, monkeypatch, body):
    def unexpected(*args):
        pytest.fail("Invalid input must not reach host-key lookup or SSH")
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", unexpected)
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50107)) as client:
        sign_in(client)
        assert client.post("/api/live/connect", json=body, headers=HEADERS).status_code in {400, 422}
        assert not (tmp_path / "ssh-lab.json").exists()


def test_dashboard_connect_failure_keeps_saved_settings(lab, monkeypatch):
    client, _ = lab
    profile = client.app.state.store.root / "ssh-lab.json"
    before = profile.read_bytes()
    monkeypatch.setattr(ssh_setup, "trusted_host_keys", lambda *_: b"host ssh-ed25519 verified\n")
    def failed(*args, **kwargs):
        raise ssh_collection.CollectionError("Key authentication failed.")
    monkeypatch.setattr(ssh_setup, "collect_output", failed)
    response = client.post("/api/live/connect", json={"ssh_command": "ssh alex@192.0.2.12"}, headers=HEADERS)
    assert response.status_code == 400 and "authentication" in response.json()["detail"]
    assert profile.read_bytes() == before


def test_busy_request_leaves_watch_available_for_the_next_poll(lab, monkeypatch):
    client, _ = lab
    watch = post(client, "start", **DESTINATION).json()["id"]
    lock = client.app.state.import_lock
    client.app.state.import_lock = SimpleNamespace(locked=lambda: True)
    assert post(client, f"{watch}/poll").status_code == 409
    client.app.state.import_lock = lock
    monkeypatch.setattr(ssh_collection, "collect_journal", lambda *_: line(1))
    result = post(client, f"{watch}/poll").raise_for_status().json()
    assert result["active"] and (result["pulls"], result["attempts"]) == (1, 1)


@pytest.mark.parametrize("event_id,command,expected", [
    (4624, "", (0, 0)), (4688, "", (1, 0)),
    (4688, "powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAZQBzAHQAJwA=", (1, 1)),
])
def test_windows_live_coverage_explains_missing_process_data(event_id, command, expected):
    data = (json.dumps({"Id": event_id, "RecordId": 1, "LogName": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": "test-host",
        "TimeCreated": "2026-11-06T12:00:00Z", "EventData": {
            "NewProcessName": "powershell.exe", "CommandLine": command,
        }}) + "\n").encode()
    result = live_logs.review_buffer(data, "test.jsonl", "test", "windows")
    assert (result["process_creation_events"], result["process_creation_with_command_line"]) == expected
    assert bool(result["findings"]) == bool(command)
