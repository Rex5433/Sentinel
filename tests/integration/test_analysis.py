import json
import math
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import create_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HEADERS = {"X-Sentinel-Import": "1", "Content-Type": "application/json"}


@pytest.fixture
def client(tmp_path, sign_in):
    with TestClient(create_app(tmp_path / "storage"), base_url="http://127.0.0.1", client=("127.0.0.1", 50300)) as client:
        sign_in(client)
        yield client


def upload(client, data=None):
    data = data if data is not None else (FIXTURES / "windows_auth_burst.json").read_bytes()
    response = client.post("/api/uploads?format=windows-json&filename=synthetic.json", content=data, headers=HEADERS)
    assert response.status_code == 201, response.text
    return response.json()


def analyze(client, item):
    response = client.post(f"/api/analysis/{item['id']}", headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def test_maintenance_note_survives_reanalysis_without_changing_evidence(client):
    item = upload(client)
    analyze(client, item)
    params = {"upload_id": item["id"]}
    before = client.get("/api/findings", params=params).json()["items"][0]
    finding_id = before["finding"]["finding_id"]
    route = f"/api/findings/{finding_id}/maintenance"
    def save(text, *, query=params, headers=HEADERS):
        return client.post(route, params=query, headers=headers, json={"note": text})

    assert save("CHG-42", headers={}).status_code == 403
    assert save("   ").status_code == 422
    assert save("x" * 1001).status_code == 422
    other = upload(client)
    analyze(client, other)
    assert save("CHG-42", query={"upload_id": other["id"]}).status_code == 404
    assert save(" CHG-42 · Approved authentication drill ").status_code == 204
    assert save("CHG-43 · Updated approval scope").status_code == 204
    summary = analyze(client, item)
    assert summary["finding_count"] == 1 and summary["flagged_record_count"] == 6
    after = client.get("/api/findings", params=params).json()["items"][0]
    note = after.pop("maintenance_note")
    assert note["note"] == "CHG-43 · Updated approval scope"
    assert note["username"] == client.get("/api/auth/me").json()["username"]
    assert note["updated_at"].endswith("+00:00")
    assert after == {key: value for key, value in before.items() if key != "maintenance_note"}
    evidence = client.get(f"/api/findings/{finding_id}/events", params=params).json()
    assert evidence["total"] == 6
    assert set(evidence["maintenance_note_events"][item["id"]]) == {row["event_id"] for row in evidence["items"]}
    review = client.get("/api/events", params=params | {"include_flags": True, "limit": 2}).json()
    assert set(review["maintenance_note_events"][item["id"]]) == set(review["flagged_event_ids"])
    assert client.get("/api/events", params={"upload_id": other["id"]}).json()["maintenance_note_events"] == {}
    timeline = client.get("/api/timeline").json()
    assert {row["upload_id"] for row in timeline["items"]} == {item["id"], other["id"]}
    assert set(timeline["maintenance_note_events"]) == {item["id"]}
    assert client.delete(route, params=params, headers=HEADERS).status_code == 204
    assert client.get("/api/timeline", params=params).json()["maintenance_note_events"] == {}
    assert client.get("/api/findings", params=params).json()["items"] == [before]


def test_blue_team_roster_attributes_windows_identity_without_suppressing_warning(client):
    route = "/api/blue-team/accounts"
    roster_entry = {"platform": "windows", "host": "TEST-HOST", "account": "LAB\\Alex"}
    assert client.post(route, json=roster_entry).status_code == 403
    assert client.post(route, headers=HEADERS, json=roster_entry | {"host": "*"}).status_code == 422
    assert client.post(route, headers=HEADERS, json=roster_entry).status_code == 204
    assert client.post(route, headers=HEADERS, json=roster_entry | {"account": "lab\\alex"}).status_code == 204
    roster = client.get(route).json()["items"]
    assert len(roster) == 1
    base = {"Computer": "test-host", "TimeCreated": "2026-01-01T00:00:00Z", "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing"}
    action = base | {"EventID": 4688, "EventData": {
        "SubjectUserName": "ALEX", "SubjectDomainName": "LAB", "NewProcessName": "vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /quiet",
    }}
    failure = base | {"EventID": 4625, "TargetUserName": "Alex", "TargetDomainName": "LAB"}
    rows = [
        action, failure, action | {"Computer": "other-host"}, action | {"SubjectDomainName": "OTHER"},
        base | {"EventID": 4720, "TargetUserName": "Alex", "TargetDomainName": "LAB", "SubjectUserName": "someone-else"},
        failure | {"Provider": "some-other-provider"},
        failure | {"TargetDomainName": "OTHER"},
    ]
    item = upload(client, json.dumps(rows).encode())
    params = {"upload_id": item["id"], "include_flags": True}
    assert client.get("/api/events", params=params).json()["blue_team_events"]
    analyze(client, item)
    page = client.get("/api/events", params=params).json()
    action_id, failure_id = [row["event_id"] for row in page["items"][:2]]
    assert page["blue_team_events"] == {
        action_id: {"account": "LAB\\ALEX", "role": "account"},
        failure_id: {"account": "LAB\\Alex", "role": "target"},
    }
    assert action_id in page["critical_event_ids"]
    assert client.get("/api/timeline").json()["blue_team_events"] == page["blue_team_events"]
    assert client.delete(f"{route}/{roster[0]['id']}", headers=HEADERS).status_code == 204
    refreshed = client.get("/api/events", params=params).json()
    assert refreshed["blue_team_events"] == {}
    assert refreshed["critical_event_ids"] == page["critical_event_ids"]


def test_blue_team_roster_matches_linux_sudo_actor_and_case(client):
    lines = [
        "Nov  4 01:00:00 linux-box sudo: alex : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/systemctl stop auditd",
        "Nov  4 01:00:01 linux-box sudo: Alex : TTY=pts/1 ; PWD=/tmp ; USER=alex ; COMMAND=/bin/systemctl status auditd",
        "Nov  4 01:00:02 linux-box sshd[400]: Failed password for alex from 192.0.2.12 port 5555 ssh2",
        "Nov  4 01:00:03 linux-box sudo: pam_unix(sudo:session): session opened for user alex(uid=1000) by (uid=0)",
    ]
    item = client.post("/api/uploads?format=linux-text&filename=linux.log", headers=HEADERS | {"Content-Type": "text/plain"},
                       content="\n".join(lines).encode()).raise_for_status().json()
    assert client.post("/api/blue-team/accounts", headers=HEADERS,
                       json={"platform": "linux", "host": "linux-box", "account": "alex"}).status_code == 204
    analyze(client, item)
    page = client.get("/api/events", params={"upload_id": item["id"], "include_flags": True}).json()
    ids = [row["event_id"] for row in page["items"]]
    assert page["blue_team_events"] == {ids[0]: {"account": "alex", "role": "account"},
                                        ids[2]: {"account": "alex", "role": "target"}}
    assert ids[0] in page["critical_event_ids"]


def test_explicit_analysis_feature_contract_and_coverage(client):
    item = upload(client)
    assert client.get(f"/api/analysis/{item['id']}").json()["status"] == "not_run"
    assert client.get("/api/features", params={"upload_id": item["id"]}).status_code == 409
    schema = client.get("/api/feature-schema").json()
    assert len(schema["feature_schema"]["feature_order"]) == 18
    result = analyze(client, item)
    assert result["coverage"]["used_records"] == 6 and result["coverage"]["excluded_records"] == 2
    assert result["coverage"]["exclusion_counts"] == {"missing_host": 1, "missing_timestamp": 1}
    assert result["finding_count"] == 1 and result["assessment"] == "review_patterns"
    assert result["model_ready"] is False and result["model_version"] is None
    assert result["competition_use_enabled"] is False
    feature = client.get("/api/features", params={"upload_id": item["id"]}).json()["items"][0]
    assert feature["feature_values"]["auth_failure_count"] == 5
    assert len(feature["vector"]) == 18 and all(math.isfinite(x) for x in feature["vector"])
    assert feature["feature_schema_sha256"] == schema["feature_schema_sha256"]
    assert feature["evidence_count"] == 6 and len(feature["evidence_preview_ids"]) == 5


def test_finding_detail_traces_every_evidence_id_to_imported_events(client):
    item = upload(client)
    analyze(client, item)
    notices = client.get("/api/findings", params={"upload_id": item["id"]}).json()
    entry = notices["items"][0]
    assert entry["finding"]["triage_priority"] == 75
    assert entry["finding"]["evidence_count"] == 6
    response = client.get(f"/api/findings/{entry['finding']['finding_id']}", params={"upload_id": item["id"]})
    detail = response.json()
    events = client.get("/api/events", params={"upload_id": item["id"]}).json()["items"]
    ids = {event["event_id"] for event in events}
    assert set(detail["finding"]["evidence_event_ids"]) <= ids
    assert detail["source"]["sha256"] == item["sha256"]
    assert detail["finding"]["confidence"] is None and detail["finding"]["method"] == "deterministic"
    window = client.get(f"/api/features/{entry['window_id']}", params={"upload_id": item["id"]}).json()
    assert set(window["event_ids"]) == set(detail["finding"]["evidence_event_ids"])
    evidence = client.get(f"/api/findings/{entry['finding']['finding_id']}/events",
                          params={"upload_id": item["id"], "offset": 1, "limit": 2}).json()
    assert evidence["total"] == 6
    assert [event["event_id"] for event in evidence["items"]] == detail["finding"]["evidence_event_ids"][1:3]
    assert all(event["raw_record"] and event["source_sha256"] == item["sha256"] for event in evidence["items"])
    timeline_scope = {"upload_id": item["id"], "finding_id": entry["finding"]["finding_id"]}
    timeline = client.get("/api/timeline", params=timeline_scope).json()
    assert timeline["total"] == 6
    assert {event["event_id"] for event in timeline["items"]} == set(detail["finding"]["evidence_event_ids"])
    assert client.get("/api/timeline", params={"finding_id": timeline_scope["finding_id"]}).status_code == 400
    assert client.get("/api/timeline", params=timeline_scope | {"finding_id": "0" * 64}).status_code == 404


def test_rerun_keeps_ids_and_report_contains_versions_without_fake_model_results(client):
    item = upload(client)
    analyze(client, item)
    before = client.get("/api/findings", params={"upload_id": item["id"]}).json()
    analyze(client, item)
    assert client.get("/api/findings", params={"upload_id": item["id"]}).json() == before
    report = client.get(f"/api/reports/{item['id']}").json()
    assert report["report_version"] == "evidence-v2"
    assert report["baseline_analysis"]["summary"]["status"] == "current"
    assert report["baseline_analysis"]["summary"]["feature_version"] == "event-window-v1"
    assert len(report["baseline_analysis"]["findings"]) == 1
    assert len(report["baseline_analysis"]["feature_schema"]["feature_order"]) == 18
    assert report["baseline_analysis"]["baseline_policy"]["failure_threshold"] == 5
    assert report["model_version"] is None and report["model_ready"] is False
    text = client.get(f"/api/reports/{item['id']}?format=text").text
    assert "auth-burst-v1" in text and "no model inference" in text


def test_stale_results_are_blocked_and_omitted_from_reports_until_rerun(client):
    item = upload(client)
    analyze(client, item)
    with client.app.state.store.connect() as connection:
        payload = json.loads(connection.execute("SELECT payload FROM analyses WHERE upload_id=?", (item["id"],)).fetchone()[0])
        payload["baseline_policy_sha256"] = "0" * 64
        connection.execute("UPDATE analyses SET payload=? WHERE upload_id=?", (json.dumps(payload), item["id"]))
    assert client.get(f"/api/analysis/{item['id']}").json()["status"] == "stale"
    assert client.get("/api/findings", params={"upload_id": item["id"]}).status_code == 409
    assert client.get("/api/features", params={"upload_id": item["id"]}).status_code == 409
    exported = client.get(f"/api/reports/{item['id']}").json()["baseline_analysis"]
    assert client.get("/api/events", params={"upload_id": item["id"], "include_flags": True}).json()["flagged_event_ids"] == []
    assert exported["findings"] == [] and exported["feature_windows"] == []
    assert analyze(client, item)["status"] == "current"


def test_review_flags_are_exact_evidence_and_limited_to_the_event_page(client):
    item = upload(client)
    params = {"upload_id": item["id"], "include_flags": True}
    assert client.get("/api/events", params=params).json()["flagged_event_ids"] == []
    assert analyze(client, item)["finding_count"] == 1
    page = client.get("/api/events", params=params).json()
    assert len(page["flagged_event_ids"]) == 6
    short = client.get("/api/events", params=params | {"limit": 2}).json()
    assert set(short["flagged_event_ids"]) == set(page["flagged_event_ids"]) & {event["event_id"] for event in short["items"]}
    other = upload(client)
    assert client.get("/api/events", params=params | {"upload_id": other["id"]}).json()["flagged_event_ids"] == []


def test_windows_raw_review_exposes_critical_and_checked_events_without_model(client):
    base = {"EventID": 4688, "Computer": "test-host", "TimeCreated": "2026-01-01T00:00:00Z"}
    rows = [
        base | {"NewProcessName": "vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /quiet"},
        base | {"NewProcessName": "vssadmin.exe", "CommandLine": "vssadmin.exe list shadows"},
        base | {"NewProcessName": "vssadmin.exe"},
    ]
    item = upload(client, json.dumps(rows).encode())
    summary = analyze(client, item)
    assert summary["finding_count"] == summary["flagged_record_count"] == 1
    assert summary["windows_reviewed_count"] == 2
    assert summary["model_ready"] is False
    params = {"upload_id": item["id"]}
    page = client.get("/api/events", params=params | {"include_flags": True}).json()
    ids = [record["event_id"] for record in page["items"]]
    assert page["critical_event_ids"] == page["flagged_event_ids"] == ids[:1]
    assert page["windows_reviewed_event_ids"] == ids[:2]
    entry = client.get("/api/findings", params=params).json()["items"][0]
    assert entry["title"] == "Shadow copy deletion attempt"
    assert entry["source_metadata_complete"] is False
    endpoint = f"/api/findings/{entry['finding']['finding_id']}"
    detail = client.get(endpoint, params=params).json()
    assert "windows-processes" in detail["manual_check_command_ids"]
    evidence = client.get(endpoint + "/events", params=params).json()["items"]
    assert [event["raw_record"] for event in evidence] == rows[:1]


def test_sparse_windows_task_keeps_review_evidence_separate_from_flags(client):
    row = {"EventID": 4698, "Computer": "test-host", "TimeCreated": "2026-01-01T00:00:00Z",
           "TaskContent": r"C:\Users\ops\AppData\Roaming\agent.exe"}
    item = upload(client, json.dumps([row]).encode())
    summary = analyze(client, item)
    assert summary["finding_count"] == summary["context_review_count"] == 1
    assert summary["flagged_record_count"] == 0
    params = {"upload_id": item["id"]}
    page = client.get("/api/events", params=params | {"include_flags": True}).json()
    assert page["flagged_event_ids"] == page["network_lead_event_ids"] == []
    assert page["context_review_event_ids"] == [page["items"][0]["event_id"]]
    entry = client.get("/api/findings", params=params).json()["items"][0]
    assert entry["severity"] == "context" and entry["source_metadata_complete"] is False
    endpoint = f"/api/findings/{entry['finding']['finding_id']}/events"
    assert client.get(endpoint, params=params).json()["items"][0]["raw_record"] == row


def test_missing_and_unknown_only_imports_never_get_a_safe_classification(client):
    item = upload(client, b'[{"Id":4625,"Message":"Synthetic unknown time/host"}]')
    result = analyze(client, item)
    assert result["assessment"] == "insufficient_evidence"
    assert result["coverage"]["window_count"] == 0 and result["finding_count"] == 0
    assert client.get(f"/api/analysis/{'a'*32}").status_code == 404
    assert client.post(f"/api/analysis/{'a'*32}", headers=HEADERS).status_code == 404


def test_features_and_findings_paginate_and_delete_with_original_import(client):
    records = json.loads((FIXTURES / "windows_auth_burst.json").read_bytes())[:5]
    later = [dict(record, TimeCreated=record["TimeCreated"].replace("15:00", "15:05")) for record in records]
    item = upload(client, json.dumps(records + later).encode())
    analyze(client, item)
    page = client.get("/api/features", params={"upload_id": item["id"], "limit": 1, "offset": 1}).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert client.get("/api/findings", params={"upload_id": item["id"], "limit": 1}).json()["total"] == 2
    assert client.delete(f"/api/uploads/{item['id']}", headers=HEADERS).status_code == 204
    with client.app.state.store.connect() as connection:
        for table in ("analyses", "feature_windows", "baseline_findings"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_linux_legacy_finding_uses_original_records_and_preserves_unknown_utc(client):
    raw = (
        b'Nov  4 01:00:00 box audit[11]: EXECVE uid=0 ppid=1 exe="/usr/bin/systemctl" a0="systemctl" a1="stop" a2="auditd"\n'
        b'Nov  4 01:00:01 box systemd[1]: Stopping Security Auditing Service...\n'
        b'Nov  4 01:00:02 box CRON[12]: (root) CMD (/usr/local/bin/backup.sh)\n'
    )
    item = client.post("/api/uploads?format=linux-text&filename=legacy.log", content=raw,
                       headers={**HEADERS, "Content-Type": "text/plain"}).json()
    summary = analyze(client, item)
    assert summary["finding_count"] == summary["linux_finding_count"] == 2
    assert summary["flagged_record_count"] == 2 and summary["coverage"]["window_count"] == 0
    assert summary["assessment"] == "review_patterns"
    params = {"upload_id": item["id"]}
    events = client.get("/api/events", params=params | {"include_flags": True}).json()
    assert set(events["flagged_event_ids"]) == {event["event_id"] for event in events["items"][:2]}
    findings = client.get("/api/findings", params=params).json()["items"]
    assert [entry["source_record_index"] for entry in findings] == [1, 2]
    assert all(entry["finding"]["timestamp_utc"] is None and entry["window_id"] is None for entry in findings)
    endpoint = f"/api/findings/{findings[-1]['finding']['finding_id']}"
    detail = client.get(endpoint, params=params).json()
    assert detail["window"] is None and detail["manual_check_command_ids"] == ["linux-processes"]
    evidence = client.get(endpoint + "/events", params=params).json()["items"]
    assert [event["raw_record"] for event in evidence] == raw.decode().splitlines(keepends=True)[:2]
    report = client.get(f"/api/reports/{item['id']}").json()["baseline_analysis"]
    assert [entry["finding"]["timestamp_utc"] for entry in report["findings"]] == [None, None]


def test_native_journal_pair_cites_both_stored_records(client):
    common = {"_HOSTNAME": "box", "SYSLOG_IDENTIFIER": "auditd", "__REALTIME_TIMESTAMP": "1760000000120000"}
    records = [
        common | {"MESSAGE": 'type=SYSCALL msg=audit(1760000000.120:38): success=yes pid=123 ppid=1 uid=0 exe="/usr/sbin/iptables"'},
        common | {"MESSAGE": 'type=EXECVE msg=audit(1760000000.120:38): argc=2 a0="iptables" a1="-F"'},
    ]
    raw = "\n".join(json.dumps(record) for record in records).encode()
    response = client.post("/api/uploads?format=linux-journal-json&filename=review.jsonl", content=raw, headers=HEADERS)
    assert response.status_code == 201, response.text
    item = response.json()
    summary = analyze(client, item)
    assert summary["finding_count"] == 1 and summary["flagged_record_count"] == 2
    params = {"upload_id": item["id"]}
    entry = client.get("/api/findings", params=params).json()["items"][0]
    assert entry["title"] == "Firewall rules flush attempt" and entry["finding"]["timestamp_utc"]
    endpoint = f"/api/findings/{entry['finding']['finding_id']}/events"
    evidence = client.get(endpoint, params=params).json()["items"]
    assert [event["raw_record"] for event in evidence] == records


def test_analysis_and_new_result_routes_require_authentication_and_mutation_header(client):
    item = upload(client)
    assert client.post(f"/api/analysis/{item['id']}").status_code == 403
    client.cookies.clear()
    for route in (f"/api/analysis/{item['id']}", "/api/feature-schema", f"/api/features?upload_id={item['id']}",
                  f"/api/findings?upload_id={item['id']}", f"/api/findings/{'a'*64}?upload_id={item['id']}"):
        assert client.get(route).status_code == 401
    assert client.post(f"/api/analysis/{item['id']}", headers=HEADERS).status_code == 401


def test_analysis_does_not_queue_behind_another_heavy_operation(client):
    item = upload(client)
    lock = client.app.state.import_lock
    client.portal.call(lock.acquire)
    try:
        assert client.post(f"/api/analysis/{item['id']}", headers=HEADERS).status_code == 409
    finally:
        client.portal.call(lock.release)
    assert analyze(client, item)["status"] == "current"


def test_inconsistent_stored_records_fail_without_partial_analysis(client):
    item = upload(client)
    with client.app.state.store.connect() as connection:
        rows = connection.execute("SELECT payload FROM events WHERE upload_id=? ORDER BY record_index LIMIT 2", (item["id"],)).fetchall()
        first, second = (json.loads(row["payload"]) for row in rows)
        second["event_id"] = first["event_id"]
        connection.execute("UPDATE events SET payload=? WHERE upload_id=? AND record_index=2", (json.dumps(second), item["id"]))
    response = client.post(f"/api/analysis/{item['id']}", headers=HEADERS)
    assert response.status_code == 400
    assert client.get(f"/api/analysis/{item['id']}").json()["status"] == "not_run"
