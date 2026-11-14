"""The managed SSH path uses synthetic event streams and simulated transports."""

import json
from threading import Event
from time import monotonic, sleep

from fastapi.testclient import TestClient
import pytest

from app.agent_collectors import collection_plan
from app.agent_manager import AgentManager
from app.agent_store import AgentStore
from app.db import EvidenceStore
from app.main import create_app
from app.ssh_transport import SSHFailure


HEADERS = {"X-Sentinel-Import": "1"}
PINS = b"test ssh-ed25519 dGVzdC1waW4=\n"


def native(platform, number, host="lab-host"):
    if platform == "linux":
        row = {"__CURSOR": f"s=abc;i={number:x}", "__REALTIME_TIMESTAMP": str(1794398400000000 + 1000000 * number),
               "SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": host,
               "MESSAGE": "Failed password for operator from 192.0.2.44 port 4422 ssh2"}
    else:
        row = {"Id": 4625, "RecordId": number, "TimeCreated": f"2026-11-11T12:00:{number:02d}Z",
               "MachineName": host, "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing",
               "EventData": {"TargetUserName": "operator", "TargetDomainName": "LAB", "IpAddress": "192.0.2.44",
                             "LogonType": "3"}}
    return (json.dumps(row) + "\n").encode()


class FakeSSH:
    def __init__(self, platform):
        self.platform = platform
        self.plan, = collection_plan(platform, ["authentication"])
        self.pages = {None: b"".join(native(platform, i) for i in (1, 2, 3))}
        self.connected = []
        self.position = None
        self.error = None
        self.failure = None
        self.closed = 0

    def connect(self, target, **_):
        assert target[3].read_bytes() == PINS
        self.connected.append(target[:3])
        if self.failure:
            raise self.failure
        fake = self

        class Session:
            active = True

            def read(self, command, **_):
                if command == "uname -s":
                    return b"Linux\n" if fake.platform == "linux" else b""
                if fake.error:
                    raise fake.error
                for position, data in fake.pages.copy().items():
                    if command == fake.plan.command(position):
                        return data
                raise AssertionError("Unexpected collector command")

            def close(self):
                if self.active:
                    fake.closed += 1
                self.active = False
        return Session()


def make_client(tmp_path, fake):
    return TestClient(create_app(tmp_path, agent_connect=fake.connect, agent_trust=lambda *_: PINS),
                      base_url="http://127.0.0.1", client=("127.0.0.1", 51022))


def form(platform, host="lab-host"):
    return {"name": host, "host": host, "username": "reader", "authentication": "key",
            "platform": platform, "modules": ["authentication"], "enabled": False}


def enroll(client, profile):
    test = client.post("/api/agents/test", headers=HEADERS, json=profile).raise_for_status().json()
    saved = client.post("/api/agents", headers=HEADERS, json={"test_id": test["test_id"]}).raise_for_status().json()
    return saved


def action(client, id, command, **fields):
    return client.post(f"/api/agents/{id}/action", headers=HEADERS, json={"action": command, **fields})


def wait(client, id, predicate):
    deadline = monotonic() + 8
    while monotonic() < deadline:
        detail = client.get(f"/api/agents/{id}").raise_for_status().json()
        if predicate(detail):
            return detail
        sleep(.025)
    pytest.fail(f"Expected managed state, last status was {detail['status']}")


def test_worker_lease_is_exclusive_and_readable(tmp_path):
    store = EvidenceStore(tmp_path)
    first, second = AgentManager(store), AgentManager(store)
    try:
        first.initialize()
        assert first.lease is not None
        assert (tmp_path / "ssh-agents.lock").read_bytes() == b""
        second.initialize()
        assert second.lease is None
        first.release()
        second.initialize()
        assert second.lease is not None
    finally:
        first.release()
        second.release()


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_enroll_collect_replay_gap_and_keep_timeline_after_removal(tmp_path, sign_in, platform):
    fake = FakeSSH(platform)
    anchor = fake.plan.parse(fake.pages[None]).bookmark
    fake.pages[anchor] = native(platform, 3) + native(platform, 4)
    final = fake.plan.parse(fake.pages[anchor], anchor).bookmark
    fake.pages[final] = native(platform, 4)
    with make_client(tmp_path, fake) as client:
        assert client.get("/api/agents").status_code == 401
        sign_in(client)
        assert client.post("/api/agents/test", json=form(platform)).status_code == 403
        host = enroll(client, form(platform))
        id = host["id"]
        assert host["status"] == "disabled"
        action(client, id, "connect").raise_for_status()
        detail = wait(client, id, lambda row: row["status"] == "connected" and len(row["events"]) == 3)
        assert detail["alert_count"] == 3 and len(fake.connected) == 2
        finding_id = detail["findings"][0]["finding"]["finding_id"]
        evidence = client.get(f"/api/agents/{id}/findings/{finding_id}/evidence").raise_for_status().json()
        assert len(evidence["events"]) == evidence["total_cited"] == 3
        assert all(event["agent_id"] == id and event["agent_severity"] == "warning" for event in evidence["events"])
        action(client, id, "collect").raise_for_status()
        wait(client, id, lambda row: len(row["events"]) == 4)
        action(client, id, "collect").raise_for_status()
        page = client.get("/api/timeline", params={"agent_id": id, "source_kind": "agents"}).raise_for_status().json()
        assert page["total"] == 4 and len({row["event_id"] for row in page["items"]}) == 4
        filtered = client.get("/api/timeline", params={"collector": fake.plan.id, "severity": "warning"}).raise_for_status().json()
        assert filtered["total"] >= 3 and all(row["agent_id"] == id for row in filtered["items"])
        live = client.get(f"/api/agents/{id}/live").raise_for_status().json()["review"]
        assert len(live["events"]) == 4 and live["flagged"]
        saved = client.post(f"/api/agents/{id}/save", headers=HEADERS).raise_for_status().json()
        assert client.get(f"/api/analysis/{saved['upload_id']}").json()["status"] == "current"
        fake.pages[final] = native(platform, 4) + b'{"bad":\n'
        action(client, id, "collect").raise_for_status()
        malformed = wait(client, id, lambda row: row["streams"][0]["status"] == "error")
        assert len(malformed["events"]) == 4
        fake.pages[final] = native(platform, 6)
        action(client, id, "collect").raise_for_status()
        gap = wait(client, id, lambda row: row["streams"][0]["status"] == "gap")
        assert len(gap["events"]) == 4
        assert len(fake.connected) == 2
        client.delete(f"/api/agents/{id}", headers=HEADERS).raise_for_status()
        assert client.get(f"/api/agents/{id}").status_code == 404
        assert client.get("/api/timeline", params={"agent_id": id}).json()["total"] == 4
        assert fake.closed == 2


def test_configurable_hosts_and_sanitized_test_failures(tmp_path, sign_in):
    fake = FakeSSH("linux")
    with make_client(tmp_path, fake) as client:
        sign_in(client)
        for i in range(7):
            enroll(client, form("auto", host=f"test-{i}.test"))
        assert len(client.get("/api/agents").json()["items"]) == 7
        for kind in ("authentication", "host_key", "timeout"):
            fake.failure = SSHFailure(kind, "Fixture SSH failure.")
            response = client.post("/api/agents/test", headers=HEADERS, json=form("linux", host="test-8.test"))
            assert response.status_code == 400 and response.json()["detail"]["kind"] == kind
        invalid = client.post("/api/agents/test", headers=HEADERS, json=form("linux") | {
            "port": "secret-test-value", "password": "secret-test-value"})
        assert invalid.status_code == 422 and "secret-test-value" not in invalid.text


def test_automatic_authentication_fallback_and_portable_profile(tmp_path, sign_in):
    fake = FakeSSH("linux")
    attempts = []
    def connect(target, **options):
        attempts.append(bool(options.get("password")))
        if not options.get("password"):
            raise SSHFailure("authentication", "Fixture key rejected.")
        return fake.connect(target, **options)

    app = create_app(tmp_path, agent_connect=connect, agent_trust=lambda *_: PINS)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 51022)) as client:
        sign_in(client)
        values = form("auto") | {"authentication": "auto", "modules": [],
                                 "auto_modules": {"windows": ["process"], "linux": ["authentication"]}}
        denied = client.post("/api/agents/test", headers=HEADERS, json=values)
        assert denied.json()["detail"]["kind"] == "password_required"
        host = enroll(client, values | {"password": "fixture-secret"})
        assert attempts == [False, False, True]
        assert host["platform"] == "linux" and host["modules"] == ["authentication"]
        export = client.get(f"/api/agents/{host['id']}/profile").raise_for_status()
        assert 'filename="sentinel-host-lab-host.json"' in export.headers["content-disposition"]
        assert export.json() == {"version": 1, **{key: host[key] for key in (
            "name", "host", "port", "username", "platform", "authentication", "role", "interval_seconds",
            "modules", "integrity_paths")}}


def test_save_live_batches_critical_records_and_stop_keeps_logs(tmp_path, sign_in):
    fake = FakeSSH("linux")
    anchor = fake.plan.parse(fake.pages[None]).bookmark
    critical = json.loads(native("linux", 4))
    critical.update(SYSLOG_IDENTIFIER="sudo", MESSAGE="operator : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/auditctl -e 0")
    fake.pages[anchor] = native("linux", 3) + (json.dumps(critical) + "\n").encode()
    final = fake.plan.parse(fake.pages[anchor], anchor).bookmark
    fake.pages[final] = (json.dumps(critical) + "\n").encode()
    with make_client(tmp_path, fake) as client:
        sign_in(client)
        id = enroll(client, form("linux"))["id"]
        path = f"/api/agents/{id}/capture"
        assert client.post(path + "/start", headers=HEADERS).status_code == 409
        action(client, id, "connect").raise_for_status()
        wait(client, id, lambda row: len(row["events"]) == 3)
        first = client.post(path + "/start", headers=HEADERS).raise_for_status().json()["last_upload_id"]
        assert first
        assert client.get("/api/agents").json()["items"][0]["live_capture"] is True
        action(client, id, "collect").raise_for_status()
        state = wait(client, id, lambda row: row["live_capture"]["last_upload_id"] not in {None, first})
        second = state["live_capture"]["last_upload_id"]
        assert client.get(f"/api/analysis/{second}").json()["status"] == "current"
        assert len(client.get("/api/events", params={"upload_id": second, "include_flags": True}).json()["critical_event_ids"]) == 1
        # A later managed correlation can make an already-saved event critical.
        with client.app.state.store.connect() as connection:
            connection.execute("UPDATE ssh_agent_events SET severity='critical' WHERE agent_id=? AND "
                               "seq=(SELECT MIN(seq) FROM ssh_agent_events WHERE agent_id=?)", (id, id))
        stopped = client.post(path + "/stop", headers=HEADERS).raise_for_status().json()
        assert stopped == {"last_upload_id": second, "live_capture": None}
        page = client.get("/api/events", params={"upload_id": first, "include_flags": True}).raise_for_status().json()
        assert page["critical_event_ids"] == [page["items"][0]["event_id"]]
        findings = client.get("/api/findings", params={"upload_id": first}).raise_for_status().json()["items"]
        assert any(finding["title"] == "Critical evidence from managed live review" for finding in findings)
        assert len(client.get("/api/uploads").json()["items"]) == 2
        assert client.get(f"/api/agents/{id}").json()["enabled"]


def test_transport_failure_auto_reconnect_and_process_restart_preserve_bookmark(tmp_path, sign_in, monkeypatch):
    fake = FakeSSH("linux")
    anchor = fake.plan.parse(fake.pages[None]).bookmark
    fake.pages[anchor] = native("linux", 3) + native("linux", 4)
    final = fake.plan.parse(fake.pages[anchor], anchor).bookmark
    fake.pages[final] = native("linux", 4) + native("linux", 5)
    real_uniform = __import__("random").uniform
    monkeypatch.setattr("app.agent_manager.random.uniform", lambda low, high: .05 if low == .8 else real_uniform(low, high))
    with make_client(tmp_path, fake) as client:
        password = sign_in(client)
        id = enroll(client, form("linux"))["id"]
        action(client, id, "connect").raise_for_status()
        wait(client, id, lambda row: row["status"] == "connected")
        fake.error = SSHFailure("network", "Fixture VPN route interrupted.")
        fake.failure = fake.error
        action(client, id, "collect").raise_for_status()
        retrying = wait(client, id, lambda row: row["status"] == "retrying")
        assert len(retrying["events"]) == 3
        fake.failure = fake.error = None
        wait(client, id, lambda row: row["status"] == "connected" and len(row["events"]) == 4)
    with make_client(tmp_path, fake) as restarted:
        restarted.post("/api/auth/login", headers=HEADERS,
                       json={"username": "test-owner", "password": password}).raise_for_status()
        detail = wait(restarted, id, lambda row: len(row["events"]) == 5)
        assert len({row["event_id"] for row in detail["events"]}) == 5


def test_live_capture_enforces_batch_size_without_losing_raw_records(tmp_path, sign_in, monkeypatch):
    monkeypatch.setattr("app.agent_capture.BATCH", 2)
    fake = FakeSSH("linux")
    with make_client(tmp_path, fake) as client:
        sign_in(client)
        id = enroll(client, form("linux"))["id"]
        action(client, id, "connect").raise_for_status()
        wait(client, id, lambda row: len(row["events"]) == 3)
        client.post(f"/api/agents/{id}/capture/start", headers=HEADERS).raise_for_status()
        items = client.get("/api/uploads").raise_for_status().json()["items"]
        assert len(items) == 2
        store = client.app.state.store
        chunks = [store.blob_path(item["id"]).read_bytes() for item in items]
        assert sorted(chunk.count(b"\n") for chunk in chunks) == [1, 2]
        assert sorted(b"".join(chunks).splitlines()) == sorted(fake.pages[None].splitlines())


def test_a_second_application_cannot_enroll_or_poll_the_same_store(tmp_path, sign_in):
    fake = FakeSSH("linux")
    with make_client(tmp_path, fake) as first:
        sign_in(first)
        enroll(first, form("linux"))
        with make_client(tmp_path, fake) as second:
            second.cookies.update(first.cookies)
            assert len(second.get("/api/agents").raise_for_status().json()["items"]) == 1
            assert second.post("/api/agents/test", headers=HEADERS, json=form("linux", "second.test")).status_code == 409
        assert len(fake.connected) == 1


def test_partial_permissions_do_not_pause_readable_sources(tmp_path, sign_in):
    fake = FakeSSH("windows")
    auth, accounts = collection_plan("windows", ["authentication", "accounts"])
    sessions = []

    def connect(*_args, **_kwargs):
        class Session:
            active = True

            def read(self, command, **_):
                if command == auth.command():
                    return fake.pages[None]
                assert command == accounts.command()
                return b'{"SentinelCollectorError":"permission"}\n'

            def close(self):
                self.active = False
        session = Session()
        sessions.append(session)
        return session

    fake.connect = connect
    with make_client(tmp_path, fake) as client:
        sign_in(client)
        saved = enroll(client, form("windows") | {"modules": ["authentication", "accounts"]})
        action(client, saved["id"], "connect").raise_for_status()
        view = wait(client, saved["id"], lambda row: row["status"] == "partial")
        assert len(view["events"]) == 3 and view["last_success_at"]
        assert {row["status"] for row in view["streams"]} == {"ready", "error"}
    assert all(not session.active for session in sessions)


def test_snapshot_change_is_persisted_with_context_and_excluded_from_log_export(tmp_path):
    store = EvidenceStore(tmp_path)
    store.initialize()
    repository = AgentStore(store)
    repository.initialize()
    profile = {"id": "f" * 32, "name": "lab", "platform": "linux", "host": "lab-host", "port": 22}
    repository.put(profile, PINS)
    stream = next(stream for stream in collection_plan("linux", ["network"]) if stream.id == "sockets")
    page = stream.parse(b"tcp LISTEN 0 128 127.0.0.1:9922 0.0.0.0:*\n")
    detail = {"observed_at": "2026-11-11T12:00:00.000000+00:00", "changes": [{"endpoint": "tcp 127.0.0.1:9922"}]}
    assert repository.page(profile, stream, page, detail, emit_change=True) == 1
    assert repository.review_pending(profile["id"])
    repository.analyze(profile)
    result = repository.detail(profile["id"])
    assert result["events"][0]["agent_severity"] == "context"
    assert result["findings"][0]["title"] == "New listening endpoint observed"
    assert not repository.review_pending(profile["id"])
    with pytest.raises(ValueError, match="Collect records"):
        repository.export(profile["id"], "lab")


def test_a_slow_host_does_not_delay_a_second_host(tmp_path, sign_in):
    slow = FakeSSH("linux")
    quick = FakeSSH("windows")
    entered, release = Event(), Event()
    monitoring = False

    def connect(target, **kwargs):
        fake = slow if target[0] == "slow.test" else quick
        session = fake.connect(target, **kwargs)
        if fake is slow and monitoring:
            read = session.read

            def blocked(command, **options):
                entered.set()
                assert release.wait(7)
                return read(command, **options)
            session.read = blocked
        return session

    app = create_app(tmp_path, agent_connect=connect, agent_trust=lambda *_: PINS)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 51022)) as client:
        sign_in(client)
        first = enroll(client, form("linux", "slow.test"))["id"]
        second = enroll(client, form("windows", "quick.test"))["id"]
        monitoring = True
        action(client, first, "connect").raise_for_status()
        try:
            assert entered.wait(5)
            action(client, second, "connect").raise_for_status()
            assert len(wait(client, second, lambda row: row["status"] == "connected")["events"]) == 3
            assert client.get(f"/api/agents/{first}").json()["events"] == []
        finally:
            release.set()
        assert len(wait(client, first, lambda row: row["status"] == "connected")["events"]) == 3
