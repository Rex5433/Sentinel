"""Exercise the opt-in lab collector through the normal log import API."""

from hashlib import sha256
import json

from fastapi.testclient import TestClient
import pytest

from app import ssh_collection
from app.main import create_app

PATH = "/api/collect/linux"
HEADERS = {"X-Sentinel-Import": "1"}
TARGET = {"host": "lab.example.test", "port": 2222}
EVENT = (b'{"_HOSTNAME":"lab-01","SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":"1760000000123000",'
         b'"MESSAGE":"Failed password for alex from 192.0.2.8 port 4180 ssh2"}\n')


def test_lab_ssh_is_disabled_by_default(tmp_path, sign_in):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1", client=("127.0.0.1", 50102)) as client:
        assert client.get(PATH + "/status").status_code == 401
        sign_in(client)
        assert client.get(PATH + "/status").json() == {"enabled": False}
        assert client.post(PATH, params=TARGET, headers=HEADERS).status_code == 404


@pytest.fixture
def lab_client(tmp_path, sign_in):
    with TestClient(create_app(tmp_path, lab_ssh=True), base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50102)) as client:
        sign_in(client)
        yield client


def configure_lab(root):
    (root / "ssh-lab.json").write_text(json.dumps(TARGET | {"username": "journal_reader"}), encoding="utf-8")
    (root / "ssh-known-hosts").write_text("verified key fixture", encoding="utf-8")


def test_configured_pull_saves_original_bytes_and_can_be_analyzed(lab_client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.monotonic", lambda: 100.0)
    assert lab_client.get(PATH + "/status").json()["ready"] is False
    assert lab_client.post(PATH, params=TARGET, headers=HEADERS).status_code == 503
    configure_lab(tmp_path)
    attempts = []

    def retrieve(*target):
        attempts.append(target)
        return EVENT

    monkeypatch.setattr(ssh_collection, "collect_journal", retrieve)
    assert lab_client.get(PATH + "/status").json() == TARGET | {"enabled": True, "ready": True, "max_records": 100}
    assert lab_client.post(PATH, params=TARGET).status_code == 403
    assert lab_client.post(PATH, params=TARGET | {"host": "other.example.test"}, headers=HEADERS).status_code == 409
    assert not attempts
    response = lab_client.post(PATH, params=TARGET, headers=HEADERS)
    assert response.status_code == 201
    item = response.json()
    assert attempts == [("lab.example.test", "journal_reader", 2222, tmp_path / "ssh-known-hosts")]
    assert item["sha256"] == sha256(EVENT).hexdigest()
    assert item["accepted_count"] == 1 and item["format"] == "linux-journal-json"
    assert lab_client.post(PATH, params=TARGET, headers=HEADERS).status_code == 429
    assert len(attempts) == 1
    assert lab_client.app.state.store.blob_path(item["id"]).read_bytes() == EVENT
    page = lab_client.get("/api/events", params={"upload_id": item["id"]}).json()
    assert page["items"][0]["event_type"] == "auth_failure"
    assert lab_client.post(f"/api/analysis/{item['id']}", headers=HEADERS).json()["status"] == "current"


@pytest.mark.parametrize("output", [b"unsupported data\n", EVENT * 101, None])
def test_failed_or_unbounded_pull_does_not_save_import(lab_client, tmp_path, monkeypatch, output):
    configure_lab(tmp_path)

    def retrieve(*_):
        if output is None:
            raise ssh_collection.CollectionError("Simulated SSH failure.")
        return output

    monkeypatch.setattr(ssh_collection, "collect_journal", retrieve)
    assert lab_client.post(PATH, params=TARGET, headers=HEADERS).status_code == 502
    assert lab_client.get("/api/uploads").json()["total"] == 0
