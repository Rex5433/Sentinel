"""Hand-authored contract examples only; not a training/evaluation dataset."""

import pytest
import secrets


@pytest.fixture
def sign_in():
    """Provision disposable test credentials only, never the real local owner."""
    def provision(client):
        password = "Test-only-" + secrets.token_urlsafe(24)
        client.app.state.auth.create_owner("test-owner", password)
        response = client.post("/api/auth/login", json={"username": "test-owner", "password": password},
                               headers={"X-Sentinel-Import": "1"})
        assert response.status_code == 200
        return password
    return provision


@pytest.fixture
def event_data():
    return {
        "event_id": "synthetic-linux-1",
        "platform": "linux",
        "source": "auth.log",
        "upload_id": "synthetic-upload-1",
        "timestamp_utc": "2026-11-02T09:00:00-06:00",
        "original_timestamp": "2026-11-02T09:00:00-06:00",
        "host": "synthetic-host",
        "source_ip": "192.0.2.20",
        "message": "  synthetic evidence only  ",
        "raw_record": "  synthetic evidence only  ",
        "source_sha256": "a" * 64,
        "record_index": 1,
    }


@pytest.fixture
def finding_data():
    return {
        "finding_id": "synthetic-finding-1",
        "timestamp_utc": "2026-11-02T15:00:00Z",
        "activity_class": "unknown/insufficient_evidence",
        "triage_priority": 0,
        "evidence_event_ids": ["synthetic-linux-1"],
        "explanation": "Schema test only; no detector ran.",
        "method": "deterministic",
        "limitations": ["No analysis implemented."],
    }
