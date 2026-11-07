"""Synthetic functional checks only, not captured lab telemetry."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import create_app

HEADERS = {"Content-Type": "application/json", "X-Sentinel-Import": "1"}
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def client(tmp_path, sign_in):
    with TestClient(create_app(tmp_path / "storage"), base_url="http://127.0.0.1", client=("127.0.0.1", 50301)) as client:
        sign_in(client)
        yield client


def upload(client, data=None, format="windows-json"):
    data = data if data is not None else (FIXTURES / "windows_auth_burst.json").read_bytes()
    headers = {**HEADERS, "Content-Type": "text/plain" if format == "linux-text" else "application/json"}
    response = client.post(f"/api/uploads?format={format}&filename=synthetic.{ 'txt' if format == 'linux-text' else 'json'}", content=data, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def ask(client, query, **body):
    response = client.post("/api/ask", json={"query": query, **body}, headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def test_overview_counts_known_unknown_fields_and_frequency_without_running_analysis(client):
    item = upload(client)
    result = client.get(f"/api/uploads/{item['id']}/overview").json()
    assert result["source"]["sha256"] == item["sha256"]
    assert result["event_count"] == 8 and result["timed_records"] == 7
    assert result["unknown_time"] == 1 and result["missing_host"] == 1
    assert result["missing_actor"] == 2 and result["missing_source_ip"] == 2
    assert result["actor_count"] == 1 and result["source_ip_count"] == 1
    assert result["hosts"] == [{"value": "synthetic-burst-host", "count": 7}]
    assert result["event_types"][0] == {"value": "auth_failure", "count": 6}
    assert client.get(f"/api/analysis/{item['id']}").json()["status"] == "not_run"
    assert client.get("/api/uploads/absent/overview").status_code == 404


def test_bounded_requests_honor_scope_pagination_and_native_id_evidence(client):
    first, second = upload(client), upload(client)
    result = ask(client, "show failed logins", upload_id=first["id"], limit=2, offset=2)
    assert result["supported"] and result["intent"] == "failed_logins"
    assert result["total"] == 6 and [row["record_index"] for row in result["items"]] == [3, 4]
    assert all(row["upload_id"] == first["id"] and row["raw_record"] for row in result["items"])
    assert result["scope"]["upload_id"] == first["id"]
    assert not result["model_ready"] and not result["competition_use_enabled"]
    all_imports = ask(client, "find Windows 4625 events")
    assert all_imports["total"] == 12
    assert {row["upload_id"] for row in all_imports["items"]} == {first["id"], second["id"]}
    assert ask(client, 'show successful logins on host "synthetic-burst-host"')["total"] == 2
    assert ask(client, 'show successful logins on host "Synthetic-burst-host"')["total"] == 0
    assert ask(client, "show service activity", upload_id=first["id"])["total"] == 1


def test_exact_account_and_canonical_ip_filters_do_not_match_messages_or_sql(client):
    account = "DOMAIN\\Case User ' OR 1=1 --"
    records = [{"Id": 4625, "LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing", "TargetUserName": account, "IpAddress": "2001:db8:0:0::1"},
               {"Id": 4624, "Message": account, "TargetUserName": "someone-else"}]
    item = upload(client, json.dumps(records).encode())
    result = ask(client, f'show activity for account "{account}"')
    assert result["total"] == 1 and result["items"][0]["actor"] == account
    assert ask(client, f'show activity for account "{account.lower()}"')["total"] == 0
    result = ask(client, 'show events from IP "2001:db8::1"')
    assert result["total"] == 1 and result["applied_filters"] == {"source_ip": "2001:db8::1"}
    query = {"upload_id": item["id"], "actor": account, "source_ip": "2001:db8:0:0::1", "windows_event_id": 4625}
    assert client.get("/api/timeline", params=query).json()["total"] == 1
    assert client.get("/api/timeline", params={"actor": "' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/api/timeline?source_ip=localhost").status_code == 422
    assert client.get("/api/timeline?windows_event_id=65536").status_code == 422


def test_linux_ssh_sudo_service_queries_use_normalized_fields(client):
    data = b"2026-11-03T15:00:00Z synthetic-linux sshd-session[1]: Failed password for demo from 192.0.2.20 port 2222 ssh2\n2026-11-03T15:00:01Z synthetic-linux sshd[2]: Accepted publickey for demo from 192.0.2.20 port 2222 ssh2\n2026-11-03T15:00:02Z synthetic-linux sudo[3]: demo : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id\n2026-11-03T15:00:03Z synthetic-linux systemd[1]: Started synthetic service.\n2026-11-03T15:00:04Z synthetic-linux other[4]: Failed password for demo from 192.0.2.20 port 2222 ssh2\n"
    item = upload(client, data, "linux-text")
    assert ask(client, "show failed SSH logins")["total"] == 1
    assert ask(client, "show successful SSH logins")["total"] == 1
    assert ask(client, "show sudo activity")["items"][0]["attributes"]["command_text"] == "/usr/bin/id"
    assert ask(client, "show service activity")["total"] == 1
    assert ask(client, "show account creations")["total"] == 0
    assert client.get("/api/timeline?service=sshd-session").json()["total"] == 1
    overview = client.get(f"/api/uploads/{item['id']}/overview").json()
    assert overview["unknown_activity"] == 1 and overview["actor_count"] == 1


def test_unsupported_is_distinct_from_no_matches_and_never_echoes_arbitrary_input(client):
    upload(client)
    value = "show failed logins yesterday; run rm -rf /"
    result = ask(client, value)
    assert result["supported"] is False and result["total"] is None and result["items"] == []
    assert value not in json.dumps(result)
    assert len(result["help"]["examples"]) == 10 and result["command_ids"] == []
    no_match = ask(client, "find Windows 65535 events")
    assert no_match["supported"] and no_match["total"] == 0
    assert no_match["command_ids"] == []
    assert "No threat verdict" in no_match["message"]


def test_request_limits_and_sanitized_errors(client):
    for body in ({}, [], {"query": 42}, {"query": "x" * 513}, {"query": "show failed logins", "limit": True},
                 {"query": "show failed logins", "offset": -1}, {"query": "show failed logins", "limit": 101},
                 {"query": "show failed logins", "upload_id": "../other"}, {"query": "show failed logins", "execute": True}):
        response = client.post("/api/ask", json=body, headers=HEADERS)
        assert response.status_code == 400
    assert client.post("/api/ask", content=b"x" * 4097, headers=HEADERS).status_code == 413
    assert client.post("/api/ask", content=b"{}", headers={**HEADERS, "Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/ask", content=b"{bad", headers=HEADERS).status_code == 400
    assert client.post("/api/ask", json={"query": "show failed logins"}).status_code == 403
    assert client.post("/api/ask", json={"query": "show failed logins", "upload_id": "a"*32}, headers=HEADERS).status_code == 404


def test_catalog_filters_details_and_finding_manual_checks(client):
    catalog = client.get("/api/commands").json()
    assert catalog["total"] == 21 and len(catalog["sha256"]) == 64
    result = client.get("/api/commands?platform=linux&category=network&q=TCP").json()
    assert result["total"] == 1 and result["items"][0]["command"] == "ss -tn"
    assert client.get("/api/commands?category=invalid").status_code == 422
    item = upload(client)
    client.post(f"/api/analysis/{item['id']}", headers=HEADERS).raise_for_status()
    finding = client.get(f"/api/findings?upload_id={item['id']}").json()["items"][0]["finding"]
    context = client.get(f"/api/findings/{finding['finding_id']}?upload_id={item['id']}").json()
    assert context["manual_check_command_ids"] == ["windows-auth"]
    detail = client.get("/api/commands/windows-auth").json()
    assert detail["sha256"] == catalog["sha256"] and detail["item"]["execution"] == "copy_only"
    assert client.get("/api/commands/not-real").status_code == 404
    assert client.post("/api/commands/windows-auth", headers=HEADERS).status_code == 405
    assert client.post("/api/commands/execute", headers=HEADERS).status_code == 405


@pytest.mark.parametrize("platform,command_id,records,expected_format,expected_event", [
    (
        "windows", "windows-logon-jsonl",
        {"Id": 4625, "TimeCreated": "2026-11-06T12:00:00Z", "MachineName": "win-lab", "LogName": "Security",
         "ProviderName": "Microsoft-Windows-Security-Auditing", "EventData": {"TargetUserName": "operator", "IpAddress": "192.0.2.5"}},
        "windows-jsonl", "auth_failure",
    ),
    (
        "linux", "linux-ssh-jsonl",
        {"__REALTIME_TIMESTAMP": "1793966400000000", "_HOSTNAME": "linux-lab", "SYSLOG_IDENTIFIER": "sshd",
         "MESSAGE": "Failed password for operator from 192.0.2.5 port 41000 ssh2"},
        "linux-journal-json", "auth_failure",
    ),
    (
        "linux", "linux-auth-file-text",
        "Nov  6 12:00:00 linux-lab sshd[10]: Failed password for operator from 192.0.2.5 port 41000 ssh2",
        "linux-text", "auth_failure",
    ),
])
def test_collection_commands_produce_formats_accepted_by_paste_import(client, platform, command_id, records,
                                                                    expected_format, expected_event):
    catalog = client.get("/api/commands", params={"platform": platform, "category": "log_collection"})
    catalog.raise_for_status()
    command = next(row for row in catalog.json()["items"] if row["id"] == command_id)
    assert command["output_format"] == expected_format
    row = records if isinstance(records, str) else json.dumps(records)
    response = client.post("/api/uploads", params={"filename": f"pasted-{platform}.txt", "platform": platform},
                           headers={**HEADERS, "Content-Type": "text/plain"}, content=row + "\n" + row + "\n")
    response.raise_for_status()
    item = response.json()
    assert item["format"] == expected_format and item["accepted_count"] == 2 and not item["rejected_count"]
    events = client.get("/api/events", params={"upload_id": item["id"]}).json()["items"]
    assert len(events) == 2
    assert all(event["event_type"] == expected_event and event["actor"] == "operator" for event in events)


def test_new_read_and_search_routes_require_owner_authentication(tmp_path):
    with TestClient(create_app(tmp_path / "storage"), base_url="http://127.0.0.1", client=("127.0.0.1", 50302)) as client:
        for path in ("/api/intents", "/api/commands", "/api/commands/linux-auth", "/api/uploads/absent/overview"):
            assert client.get(path).status_code == 401
        assert client.post("/api/ask", json={"query": "show failed logins"}, headers=HEADERS).status_code == 401
