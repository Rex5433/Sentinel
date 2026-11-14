"""One stream, same saved/live detections and strictly scoped context labels."""
from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest

from app import live_logs, ssh_collection
from app.main import create_app

HEADERS = {"X-Sentinel-Import": "1"}
DESTINATION = {"host": "lab.example.test", "port": 2222}
BASE = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)


def rows(platform):
    result = []
    for i in range(6):
        if platform == "windows":
            result.append({"Id": 4625 if i < 3 else 4624 if i == 3 else 4688 if i == 4 else 4799,
                           "RecordId": i + 1, "TimeCreated": (BASE + timedelta(seconds=i * 10)).isoformat(),
                           "MachineName": "lab-win", "LogName": "Security",
                           "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "test telemetry",
                           "EventData": {"TargetUserName": "blueteam", "TargetDomainName": "LAB",
                                         "SubjectUserName": "blueteam", "SubjectDomainName": "LAB",
                                         "NewProcessName": "vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /quiet",
                                         "IpAddress": "192.0.2.8"}})
        else:
            message = "Failed password for alex from 192.0.2.8 port 4180 ssh2" if i < 3 else (
                "Accepted password for alex from 192.0.2.8 port 4180 ssh2" if i == 3 else
                "alex : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/systemctl stop auditd" if i == 4 else
                "Unrecognized audit message")
            result.append({"__CURSOR": f"parity-{i}", "__REALTIME_TIMESTAMP": str(int((BASE + timedelta(seconds=i * 10)).timestamp() * 1e6)),
                           "_HOSTNAME": "lab-linux", "SYSLOG_IDENTIFIER": "sudo" if i == 4 else "sshd", "MESSAGE": message})
    return result


def raw(rows):
    return b"".join((json.dumps(row) + "\n").encode() for row in rows)


@pytest.fixture(params=["windows", "linux"])
def lab(request, tmp_path, monkeypatch, sign_in):
    platform = request.param
    clock = [100.0]
    data = {"raw": raw(rows(platform))}
    monkeypatch.setattr(live_logs, "monotonic", lambda: clock[0])
    monkeypatch.setattr(ssh_collection, "collect_live", lambda *_: data["raw"])
    with TestClient(create_app(tmp_path, lab_ssh=True), base_url="http://127.0.0.1", client=("127.0.0.1", 51100)) as client:
        sign_in(client)
        (tmp_path / "ssh-lab.json").write_text(json.dumps(DESTINATION | {"username": "reader", "platform": platform, "channel": "Security"}))
        (tmp_path / "ssh-known-hosts").write_text("verified test host key")
        watch = client.post("/api/live/start", params=DESTINATION, headers=HEADERS).raise_for_status().json()
        def poll(revision=None):
            clock[0] += 5.1
            return client.post(f"/api/live/{watch['id']}/poll", params={} if revision is None else {"revision": revision}, headers=HEADERS).raise_for_status().json()
        yield client, watch, poll, data, platform


def roster(platform):
    return {"platform": platform, "host": "lab-win" if platform == "windows" else "lab-linux",
            "account": "LAB\\blueteam" if platform == "windows" else "alex"}


def save(client, watch):
    return client.post(f"/api/live/{watch['id']}/save", headers=HEADERS).raise_for_status().json()["upload_id"]


def note(client, id, value):
    entry = next(row for row in client.get("/api/findings", params={"upload_id": id}).json()["items"]
                 if row.get("auth_review_version"))
    route = f"/api/findings/{entry['finding']['finding_id']}/maintenance"
    response = client.delete(route, params={"upload_id": id}, headers=HEADERS) if value is None else client.post(
        route, params={"upload_id": id}, json={"note": value}, headers=HEADERS)
    assert response.status_code == 204, response.text


def test_saved_live_flags_and_windows_coverage_agree_without_listing_saved_logs(lab):
    client, watch, poll, _, platform = lab
    client.post("/api/blue-team/accounts", json=roster(platform), headers=HEADERS).raise_for_status()
    view = poll()
    assert client.get("/api/uploads").json()["total"] == 0
    review = view["review"]
    assert review["finding_count"] == (3 if platform == "linux" else 2)
    id = save(client, watch)
    page = client.get("/api/events", params={"upload_id": id, "include_flags": True, "limit": 100}).json()
    def severity(id):
        return "critical" if id in page["critical_event_ids"] else "warning" if id in page["flagged_event_ids"] else "context" if id in page["context_review_event_ids"] else None
    assert {row["record_index"]: severity(row["event_id"]) for row in page["items"]} == {
        row["record_index"]: review["flagged"].get(row["event_id"]) for row in review["events"]}
    assert {row["record_index"]: page["blue_team_events"].get(row["event_id"]) for row in page["items"]} == {
        row["record_index"]: review["blue_team_events"].get(row["event_id"]) for row in review["events"]}
    assert len([v for v in review["flagged"].values() if v == "critical"]) == 1
    assert len([v for v in review["flagged"].values() if v == "warning"]) == (4 if platform == "linux" else 3)
    if platform == "windows":
        assert {row["record_index"] for row in page["items"] if row["event_id"] in page["windows_reviewed_event_ids"]} == {
            row["record_index"] for row in review["events"] if row["event_id"] in review["windows_reviewed_event_ids"]}
    assert "items" not in review and len(review["events"]) == 6


def test_roster_changes_refresh_live_badges_without_new_events_or_fake_capture_revision(lab):
    client, _, poll, _, platform = lab
    first = poll()
    assert first["review"]["blue_team_events"] == {}
    client.post("/api/blue-team/accounts", json=roster(platform), headers=HEADERS).raise_for_status()
    changed = poll(first["revision"])
    assert changed["revision"] == first["revision"] and changed["review"]["blue_team_events"]
    assert changed["review"]["flagged"] == first["review"]["flagged"]
    assert poll(first["revision"])["review"] is None
    account = client.get("/api/blue-team/accounts").json()["items"][0]
    client.delete(f"/api/blue-team/accounts/{account['id']}", headers=HEADERS).raise_for_status()
    removed = poll(first["revision"])
    assert removed["review"]["blue_team_events"] == {}
    assert removed["review"]["flagged"] == first["review"]["flagged"]


def test_live_maintenance_labels_bind_only_unchanged_current_watch_snapshot(lab):
    client, watch, poll, data, platform = lab
    first = poll()
    id = save(client, watch)
    note(client, id, "LAB-1: authorized login-error rehearsal")
    changed = poll(first["revision"])
    assert changed["revision"] == first["revision"]
    assert len(changed["review"]["maintenance_note_event_ids"]) == 3
    assert len([entry for entry in changed["review"]["findings"] if entry.get("maintenance_note")]) == 1
    assert changed["review"]["flagged"] == first["review"]["flagged"]
    note(client, id, None)
    assert poll(first["revision"])["review"]["maintenance_note_event_ids"] == []
    note(client, id, "LAB-2: exact prior snapshot only")
    extra = rows(platform)[0].copy()
    if platform == "windows":
        extra.update(RecordId=100, TimeCreated=(BASE + timedelta(seconds=55)).isoformat())
    else:
        extra.update(__CURSOR="new-event", __REALTIME_TIMESTAMP=str(int((BASE + timedelta(seconds=55)).timestamp() * 1e6)))
    data["raw"] += raw([extra])
    grown = poll(first["revision"])
    assert grown["revision"] > first["revision"]
    assert grown["review"]["maintenance_note_event_ids"] == []
    assert not any(entry.get("maintenance_note") for entry in grown["review"]["findings"])
    # A new watch must not inherit historical notes even for identical raw bytes.
    client.post(f"/api/live/{watch['id']}/stop", headers=HEADERS).raise_for_status()
    new = client.post("/api/live/start", params=DESTINATION, headers=HEADERS).raise_for_status().json()
    current = client.post(f"/api/live/{new['id']}/poll", headers=HEADERS).raise_for_status().json()
    assert current["review"]["maintenance_note_event_ids"] == []


def test_stale_or_removed_snapshot_cannot_supply_live_maintenance_labels(lab):
    client, watch, poll, _, _ = lab
    first = poll()
    id = save(client, watch)
    note(client, id, "LAB: exact snapshot")
    assert poll(first["revision"])["review"]["maintenance_note_event_ids"]
    with client.app.state.store.connect() as connection:
        value = json.loads(connection.execute("SELECT payload FROM analyses WHERE upload_id=?", (id,)).fetchone()[0])
        value["implementation_sha256"] = "0" * 64
        connection.execute("UPDATE analyses SET payload=? WHERE upload_id=?", (json.dumps(value), id))
    stale = poll(first["revision"])
    assert stale["review"]["maintenance_note_event_ids"] == []
    assert stale["review"]["flagged"] == first["review"]["flagged"]
    client.delete(f"/api/uploads/{id}", headers=HEADERS).raise_for_status()
    assert poll()["review"]["maintenance_note_event_ids"] == []
