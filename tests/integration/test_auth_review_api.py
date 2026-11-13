"""Short-auth findings reach event flags, evidence, reports and roster context."""
from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient

from app.main import create_app

HEADERS = {"X-Sentinel-Import": "1", "Content-Type": "application/x-ndjson"}


def capture(user="NOUSER"):
    base = datetime(2026, 11, 10, 16, 54, 45, tzinfo=timezone.utc)
    rows = []
    for index, offset in enumerate((0, 16, 30, 31), 1):
        rows.append({"Id": 4625 if index <= 3 else 4624, "RecordId": index,
                     "TimeCreated": (base + timedelta(seconds=offset)).isoformat(),
                     "MachineName": "lab-win", "LogName": "Security",
                     "ProviderName": "Microsoft-Windows-Security-Auditing",
                     "EventData": {"TargetUserName": user if index <= 3 else "blueteam",
                                   "TargetDomainName": "LAB", "IpAddress": "-",
                                   "SubStatus": "0xc0000064"}})
    return b"".join((json.dumps(row) + "\n").encode() for row in rows)


def test_short_auth_flags_exact_rows_and_exposes_policy_and_report(tmp_path, sign_in):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 51010)) as client:
        sign_in(client)
        raw = capture()
        item = client.post("/api/uploads?format=windows-jsonl&filename=short.jsonl", content=raw, headers=HEADERS).raise_for_status().json()
        route = f"/api/analysis/{item['id']}"
        result = client.post(route, headers=HEADERS).raise_for_status().json()
        assert result["finding_count"] == 1 and result["flagged_record_count"] == 3
        params = {"upload_id": item["id"], "include_flags": True}
        page = client.get("/api/events", params=params).json()
        assert set(page["flagged_event_ids"]) == {row["event_id"] for row in page["items"][:3]}
        assert page["critical_event_ids"] == []
        entry, = client.get("/api/findings", params=params).json()["items"]
        assert entry["severity"] == "warning" and entry["finding"]["evidence_count"] == 3
        evidence_route = f"/api/findings/{entry['finding']['finding_id']}/events"
        evidence = client.get(evidence_route, params={"upload_id": item["id"]}).json()
        assert [row["record_index"] for row in evidence["items"]] == [1, 2, 3]
        timeline = client.get("/api/timeline", params={"upload_id": item["id"], "finding_id": entry["finding"]["finding_id"]}).json()
        assert timeline["total"] == 3
        exported = client.get(f"/api/reports/{item['id']}").json()["baseline_analysis"]
        assert exported["auth_review_policy"]["failure_threshold"] == 3
        assert exported["auth_review_policy"]["rolling_seconds"] == 60
        assert exported["findings"][0]["finding"]["confidence"] is None
        assert client.get("/api/feature-schema").json()["auth_review_policy"] == exported["auth_review_policy"]
        assert client.app.state.store.blob_path(item["id"]).read_bytes() == raw
        before = client.get("/api/findings", params=params).json()
        client.post(route, headers=HEADERS).raise_for_status()
        assert client.get("/api/findings", params=params).json() == before
        with client.app.state.store.connect() as connection:
            stale = result.copy()
            stale.pop("auth_review_version")
            connection.execute("UPDATE analyses SET payload=? WHERE upload_id=?", (json.dumps(stale), item["id"]))
        assert client.get(route).json()["status"] == "stale"
        assert client.get("/api/findings", params=params).status_code == 409


def test_blue_team_label_does_not_suppress_failed_logon_warning(tmp_path, sign_in):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 51010)) as client:
        sign_in(client)
        item = client.post("/api/uploads?format=windows-jsonl&filename=team.jsonl", content=capture("blueteam"), headers=HEADERS).json()
        client.post("/api/blue-team/accounts", json={"platform": "windows", "host": "lab-win", "account": "LAB\\blueteam"}, headers={"X-Sentinel-Import": "1"}).raise_for_status()
        result = client.post(f"/api/analysis/{item['id']}", headers=HEADERS).json()
        assert result["flagged_record_count"] == 3
        page = client.get("/api/events", params={"upload_id": item["id"], "include_flags": True}).json()
        assert len(page["blue_team_events"]) == 4
        assert all(page["blue_team_events"][id]["role"] == "target" for id in page["flagged_event_ids"])
        assert page["items"][-1]["event_id"] not in page["flagged_event_ids"]
