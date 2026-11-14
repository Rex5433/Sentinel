from hashlib import sha256
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
import app.main as main_module
import app.db as db_module

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HEADERS = {"X-Sentinel-Import": "1", "Content-Type": "application/octet-stream"}


@pytest.fixture
def client(tmp_path, sign_in):
    application = create_app(tmp_path / "storage")
    with TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        sign_in(client)
        yield client


def upload(client, data=b'{"Id":4625}', filename="demo.json", fmt="windows-json", headers=None):
    return client.post("/api/uploads", params={"format": fmt, "filename": filename},
                       content=data, headers=HEADERS if headers is None else headers)


@pytest.mark.parametrize("fmt,filename,accepted,rejected", [
    ("windows-json", "windows_events.json", 5, 0),
    ("windows-csv", "windows_events.csv", 2, 0),
    ("linux-text", "linux_auth.txt", 7, 1),
    ("linux-journal-json", "linux_journal.jsonl", 3, 0),
])
@pytest.mark.parametrize("automatic", [False, True])
def test_import_formats_source_hash_and_raw_storage(client, fmt, filename, accepted, rejected, automatic):
    data = (FIXTURES / filename).read_bytes()
    response = upload(client, data, filename, "auto" if automatic else fmt)
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["format"] == fmt
    assert item["accepted_count"] == accepted and item["rejected_count"] == rejected
    assert item["sha256"] == sha256(data).hexdigest() and item["byte_count"] == len(data)
    assert client.app.state.store.blob_path(item["id"]).read_bytes() == data
    assert not (client.app.state.store.raw_dir / filename).exists()
    assert client.get(f"/storage/raw/{item['id']}.bin").status_code == 404
    assert client.get(f"/api/uploads/{item['id']}").json() == item


@pytest.mark.parametrize("filename", ["events.jsonl", "events.ndjson", "events.json"])
def test_auto_windows_json_lines_retains_evidence_and_line_positions(client, filename):
    data = b'broken\r\n{"EventID":4625,"Computer":"test-host"}\r\n\r\n{"EventID":4624,"Channel":"Security","Provider":"Microsoft-Windows-Security-Auditing"}\r\n'
    response = client.post("/api/uploads", params={"filename": filename}, content=data, headers=HEADERS)
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["format"] == "windows-jsonl"
    assert (item["accepted_count"], item["rejected_count"], item["warning_count"]) == (2, 1, 2)
    assert client.app.state.store.blob_path(item["id"]).read_bytes() == data
    events = client.get("/api/events", params={"upload_id": item["id"]}).json()["items"]
    assert [(row["record_index"], row["windows_event_id"], row["event_type"]) for row in events] == [
        (2, 4625, None), (4, 4624, "auth_success"),
    ]
    rejected = client.get(f"/api/uploads/{item['id']}/rejected").json()["items"]
    assert rejected == [{"record_index": 1, "reason": "invalid Windows JSON line", "raw_record": "broken\r\n"}]


def test_auto_network_import_and_unrecognized_json(client):
    response = upload(client, (FIXTURES / "network_demo.pcap").read_bytes(), "network_demo.pcap", "auto")
    assert response.status_code == 201 and response.json()["format"] == "pcap"
    response = upload(client, b'{"unrelated":"object"}', "unknown.jsonl", "auto")
    assert response.status_code == 400
    assert "No supported Windows event or Linux journal JSON objects" in response.json()["detail"]


def test_events_and_rejected_pagination(client):
    item = upload(client, (FIXTURES / "linux_auth.txt").read_bytes(), "auth.txt", "linux-text").json()
    first = client.get("/api/events", params={"upload_id": item["id"], "limit": 2}).json()
    second = client.get("/api/events", params={"upload_id": item["id"], "offset": 2, "limit": 2}).json()
    assert first["total"] == 7 and [e["record_index"] for e in first["items"]] == [1, 2]
    assert [e["record_index"] for e in second["items"]] == [3, 4]
    bad = client.get(f"/api/uploads/{item['id']}/rejected?limit=1").json()
    assert bad["total"] == 1 and bad["items"][0]["record_index"] == 7
    assert "malformed" in bad["items"][0]["raw_record"]
    empty = client.get("/api/events", params={"upload_id": item["id"], "offset": 100}).json()
    assert empty["items"] == [] and empty["total"] == 7


def test_history_and_events_persist_after_restart(client):
    item = upload(client).json()
    application = create_app(client.app.state.store.root)
    with TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50001)) as restarted:
        restarted.cookies.update(client.cookies)
        assert restarted.get("/api/uploads").json()["items"][0]["id"] == item["id"]
        assert restarted.get("/api/events", params={"upload_id": item["id"]}).json()["total"] == 1


def test_duplicate_content_preserves_ids_and_separate_imports(client):
    one, two = upload(client).json(), upload(client).json()
    assert one["id"] != two["id"]
    events = [client.get("/api/events", params={"upload_id": item["id"]}).json()["items"][0] for item in (one, two)]
    assert events[0]["event_id"] == events[1]["event_id"]
    assert events[0]["upload_id"] != events[1]["upload_id"]
    assert client.get("/api/uploads?limit=1&offset=1").json()["total"] == 2


def test_delete_removes_blob_events_and_rejections(client):
    item = upload(client, (FIXTURES / "linux_auth.txt").read_bytes(), "auth.txt", "linux-text").json()
    assert client.delete(f"/api/uploads/{item['id']}").status_code == 403
    assert client.delete(f"/api/uploads/{item['id']}", headers=HEADERS).status_code == 204
    assert not client.app.state.store.blob_path(item["id"]).exists()
    assert client.get("/api/uploads").json()["total"] == 0
    assert client.get("/api/events", params={"upload_id": item["id"]}).status_code == 404
    with client.app.state.store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM rejected").fetchone()[0] == 0


@pytest.mark.parametrize("fmt,filename", [("windows-json", "windows_events.json"), ("linux-text", "linux_auth.txt")])
def test_editable_text_and_revised_copy_preserve_original_evidence(client, fmt, filename):
    data = (FIXTURES / filename).read_bytes()
    original = upload(client, data, filename, fmt).json()
    response = client.get(f"/api/uploads/{original['id']}/text")
    response.raise_for_status()
    source = response.json()
    assert source["text"] == data.decode("utf-8-sig")
    assert source["platform"] == ("windows" if fmt.startswith("windows") else "linux")
    revised = client.post("/api/uploads", params={"platform": source["platform"], "filename": "edited.txt", "name": "Reviewed copy"},
                          content=(source["text"] + "\n").encode(), headers=HEADERS | {"Content-Type": "text/plain"})
    revised.raise_for_status()
    assert revised.json()["id"] != original["id"]
    assert revised.json()["filename"] == "Reviewed copy"
    assert client.get("/api/uploads").json()["total"] == 2
    assert client.app.state.store.blob_path(original["id"]).read_bytes() == data
    assert client.get(f"/api/uploads/{original['id']}").json() == original
    assert client.post(f"/api/analysis/{revised.json()['id']}", headers=HEADERS).status_code == 200


def test_editable_text_is_authenticated_bounded_and_log_only(client):
    item = upload(client).json()
    endpoint = f"/api/uploads/{item['id']}/text"
    with TestClient(client.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as anonymous:
        assert anonymous.get(endpoint).status_code == 401
    blob = client.app.state.store.blob_path(item["id"])
    blob.write_bytes(b"x" * (1024 * 1024 + 1))
    assert client.get(endpoint).status_code == 413
    blob.write_bytes(b"different bytes")
    assert client.get(endpoint).status_code == 409
    assert client.get("/api/uploads/missing/text").status_code == 404
    capture = upload(client, (FIXTURES / "network_demo.pcap").read_bytes(), "demo.pcap", "auto").json()
    assert client.get(f"/api/uploads/{capture['id']}/text").status_code == 400


def test_editable_text_decodes_supported_utf16(client):
    data = '{"Id":4625}'.encode("utf-16")
    item = upload(client, data).json()
    response = client.get(f"/api/uploads/{item['id']}/text")
    assert response.status_code == 200
    assert response.json()["text"] == '{"Id":4625}'


@pytest.mark.parametrize("filename", ["../bad.json", "C:\\secret.json", "folder/file.json", "bad\x00.json", " "])
def test_pathlike_or_invalid_filename_rejected(client, filename):
    assert upload(client, filename=filename).status_code == 400
    assert client.get("/api/uploads").json()["total"] == 0


@pytest.mark.parametrize("data,filename,fmt,headers,code", [
    (b'{}', "demo.exe", "windows-json", HEADERS, 415),
    (b'{}', "demo.json", "windows-json", HEADERS | {"Content-Type": "text/html"}, 415),
    (b'{broken', "demo.json", "windows-json", HEADERS, 400),
    (b'\x00binary', "demo.json", "windows-json", HEADERS, 400),
    (b'', "demo.json", "windows-json", HEADERS, 400),
    (b'[]', "demo.json", "windows-json", HEADERS, 400),
    (b'{}', "demo.json", "evtx", HEADERS, 422),
])
def test_bad_import_is_not_persisted(client, data, filename, fmt, headers, code):
    assert upload(client, data, filename, fmt, headers).status_code == code
    assert client.get("/api/uploads").json()["total"] == 0
    assert list(client.app.state.store.raw_dir.iterdir()) == []


def test_declared_and_streamed_size_limits(client, monkeypatch):
    monkeypatch.setattr(main_module, "MAX_INPUT_BYTES", 8)
    assert upload(client, headers=HEADERS | {"Content-Length": "999"}).status_code == 413
    assert upload(client, data=b'{"Id":4625}', headers=HEADERS | {"Content-Length": "1"}).status_code == 413
    assert client.get("/api/uploads").json()["total"] == 0


@pytest.mark.parametrize("length", ["-1", "NaN", "9" * 50])
def test_invalid_length(client, length):
    assert upload(client, headers=HEADERS | {"Content-Length": length}).status_code == 400


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"upload_id": "not-an-id"}])
def test_pagination_validation(client, params):
    query = {"upload_id": "a" * 32} | params
    assert client.get("/api/events", params=query).status_code == 422


def test_cross_origin_request_guards_and_host_validation(client):
    assert upload(client, headers={"Content-Type": "application/json"}).status_code == 403
    assert upload(client, headers=HEADERS | {"Origin": "https://untrusted.example"}).status_code == 403
    assert upload(client, headers=HEADERS | {"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert upload(client, headers=HEADERS | {"Origin": "http://127.0.0.1"}).status_code == 201
    assert client.get("/api/uploads", headers={"Host": "rebind.example"}).status_code == 400
    assert client.get("/api/uploads", headers={"Origin": "null"}).status_code == 403
    response = client.get("/")
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "access-control-allow-origin" not in response.headers


def test_remote_clients_are_denied(tmp_path):
    with TestClient(create_app(tmp_path / "private"), base_url="http://127.0.0.1", client=("192.0.2.20", 50100)) as remote:
        assert remote.get("/").status_code == 403
        assert upload(remote).status_code == 403


def test_upload_quota(client, monkeypatch):
    monkeypatch.setattr(db_module, "MAX_UPLOADS", 1)
    assert upload(client).status_code == 201
    assert upload(client).status_code == 409
    assert client.get("/api/uploads").json()["total"] == 1
    assert len(list(client.app.state.store.raw_dir.iterdir())) == 1


def test_expired_evidence_pruned_on_next_import(client):
    old = upload(client).json()
    with client.app.state.store.connect() as connection:
        connection.execute("UPDATE uploads SET created_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", old["id"]))
    assert upload(client).status_code == 201
    assert not client.app.state.store.blob_path(old["id"]).exists()
    assert client.get(f"/api/uploads/{old['id']}").status_code == 404


def test_source_markup_is_returned_as_evidence_not_html(client):
    message = '<img src=x onerror="window.evidenceExecuted=true">'
    item = upload(client, json.dumps({"Id": 4625, "Message": message}).encode()).json()
    response = client.get("/api/events", params={"upload_id": item["id"]})
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["items"][0]["message"] == message
