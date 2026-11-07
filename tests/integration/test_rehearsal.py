"""Synthetic rehearsal stays within the authenticated, hash-pinned local store."""
from hashlib import sha256

from fastapi.testclient import TestClient
import pytest

from app import rehearsal
from app.main import create_app
from training.adjudication_holdout import SEEDS, plan
from training.fresh_scenarios import emit

HEADERS = {"X-Sentinel-Import": "1"}
BASE = "/api/rehearsal"


@pytest.fixture
def client(tmp_path, monkeypatch):
    raw, _ = emit(plan("maintenance_with_quiet_afterward", SEEDS[0], "windows"), "windows-json")
    monkeypatch.setattr(rehearsal, "synthetic_exports", lambda: {("windows-json", sha256(raw).hexdigest())})
    monkeypatch.setattr(rehearsal, "load_rehearsal_model", lambda: lambda vectors: [[.99, .01, 0., 0.] for _ in vectors])
    with TestClient(create_app(tmp_path / "storage", rehearsal=True), base_url="http://127.0.0.1", client=("127.0.0.1", 50101)) as api:
        yield api, raw


def upload(api, raw):
    response = api.post("/api/uploads?format=windows-json&filename=exercise.json", content=raw,
                        headers={**HEADERS, "Content-Type": "application/json"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def queue(api, capture):
    response = api.post(f"{BASE}/{capture}/analysis", headers=HEADERS)
    assert response.status_code == 200, response.text
    return api.get(f"{BASE}/{capture}/queue").json()["queue"]


def account_finding(value):
    return next(item for item in value["items"] if item["kind"] == "finding" and item["windows"][0]["activity_class"] == 2)


def test_default_app_has_no_rehearsal(tmp_path, sign_in):
    with TestClient(create_app(tmp_path / "default"), base_url="http://127.0.0.1", client=("127.0.0.1", 50101)) as api:
        sign_in(api)
        assert api.get("/rehearsal").status_code == 404
        assert api.get("/static/rehearsal.html").status_code == 404
        assert api.get(f"{BASE}/imports").status_code == 404
        assert api.get("/health").json()["competition_use_enabled"] is False


def test_authentication_allowlist_and_raw_integrity(client, sign_in):
    api, raw = client
    assert api.get("/rehearsal", follow_redirects=False).status_code == 303
    assert api.get(f"{BASE}/imports").status_code == 401
    sign_in(api)
    assert api.get("/rehearsal").status_code == 200
    invalid = upload(api, raw + b" ")
    approved = upload(api, raw)
    assert [row["id"] for row in api.get(f"{BASE}/imports").json()["items"]] == [approved]
    assert api.post(f"{BASE}/{invalid}/analysis", headers=HEADERS).status_code == 409
    assert api.post(f"{BASE}/{approved}/analysis", headers={**HEADERS, "Origin":"http://untrusted.test"}).status_code == 403
    api.app.state.store.blob_path(approved).write_bytes(raw + b" ")
    assert api.post(f"{BASE}/{approved}/analysis", headers=HEADERS).status_code == 409


def test_dashboard_sample_is_authenticated_pinned_and_reused(client, sign_in, tmp_path, monkeypatch):
    api, raw = client
    sample = tmp_path / "sample.raw"
    sample.write_bytes(raw)
    monkeypatch.setattr(rehearsal, "SAMPLE_PATH", sample)
    assert api.post(f"{BASE}/sample", headers=HEADERS).status_code == 401
    sign_in(api)
    dashboard = api.get("/").text
    assert 'id="model-review-panel"' in dashboard and "Machine learning lab" in dashboard
    health = api.get("/health").json()
    assert health["rehearsal_enabled"] is True
    assert health["competition_use_enabled"] is False
    assert api.post(f"{BASE}/sample").status_code == 403
    response = api.post(f"{BASE}/sample", headers=HEADERS)
    assert response.status_code == 200, response.text
    item = response.json()
    assert item["sha256"] == sha256(raw).hexdigest()
    assert api.post(f"{BASE}/sample", headers=HEADERS).json()["id"] == item["id"]
    assert [row["id"] for row in api.get("/api/uploads").json()["items"]] == [item["id"]]
    assert account_finding(queue(api, item["id"]))
    sample.write_bytes(raw + b" ")
    assert api.post(f"{BASE}/sample", headers=HEADERS).status_code == 503


def test_original_evidence_confirmation_audit_and_capture_isolation(client, sign_in):
    api, raw = client
    sign_in(api)
    first, second = upload(api, raw), upload(api, raw)
    value = queue(api, first)
    queue(api, second)
    finding = account_finding(value)
    item_id = finding["item_id"]
    endpoint = f"{BASE}/{first}/items/{item_id}/events"
    evidence = api.get(endpoint).json()
    assert {row["event_id"] for row in evidence["action_records"]} == set(finding["windows"][0]["activity_evidence_ids"])
    assert all(row["upload_id"] == first for row in evidence["items"])
    assert api.get(f"{BASE}/{second}/items/{item_id}/events").status_code == 404
    confirmation = {"item_id":item_id, "reference":"exercise-change-01"}
    assert api.post(f"{BASE}/{second}/confirmations", json=confirmation, headers=HEADERS).status_code == 409
    assert api.post(f"{BASE}/{first}/confirmations", json={**confirmation,"reviewer":"forged"}, headers=HEADERS).status_code == 400
    assert api.post(f"{BASE}/{first}/confirmations", json=confirmation).status_code == 403
    result = api.post(f"{BASE}/{first}/confirmations", json=confirmation, headers=HEADERS)
    assert result.status_code == 200, result.text
    history = result.json()["confirmation_history"]
    assert len(history) == 1 and history[0]["confirmation"]["reviewer"] == "test-owner"
    assert result.json()["queue"]["reviewed_windows"] == value["reviewed_windows"]
    assert result.json()["queue"]["active_items"] == value["active_items"] - 1
    assert api.post(f"{BASE}/{first}/confirmations", json=confirmation, headers=HEADERS).status_code == 409
    assert api.post(f"{BASE}/{first}/analysis", headers=HEADERS).json()["cached"] is True
    assert api.get(f"{BASE}/{first}/queue").json()["confirmation_history"] == history
    assert api.delete(f"/api/uploads/{first}", headers=HEADERS).status_code == 204
    with api.app.state.store.connect() as connection:
        assert connection.execute("SELECT upload_id FROM rehearsal_reviews").fetchall()[0][0] == second
    assert api.get(f"{BASE}/{first}/queue").status_code == 404


def test_uncertainty_stays_active(client, sign_in, monkeypatch):
    api, raw = client
    sign_in(api)
    monkeypatch.setattr(rehearsal, "load_rehearsal_model", lambda: lambda vectors: [[.51, .49, 0., 0.] for _ in vectors])
    capture = upload(api, raw)
    value = queue(api, capture)
    finding = account_finding(value)
    assert api.post(f"{BASE}/{capture}/confirmations", headers=HEADERS,
                    json={"item_id":finding["item_id"], "reference":"uncertain-action"}).status_code == 409
    assert api.get(f"{BASE}/{capture}/queue").json()["queue"]["active_items"] == value["active_items"]


def test_confirmation_requires_retrievable_action_records(client, sign_in):
    api, raw = client
    sign_in(api)
    capture = upload(api, raw)
    value = queue(api, capture)
    finding = account_finding(value)
    with api.app.state.store.connect() as connection:
        connection.execute("DELETE FROM events WHERE upload_id=? AND event_id=?",
                           (capture, finding["windows"][0]["activity_evidence_ids"][0]))
    assert api.post(f"{BASE}/{capture}/confirmations", headers=HEADERS,
                    json={"item_id":finding["item_id"], "reference":"missing-record"}).status_code == 409
    assert api.get(f"{BASE}/{capture}/queue").json()["queue"]["active_items"] == value["active_items"]
