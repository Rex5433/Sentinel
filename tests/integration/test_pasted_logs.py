"""Pasted UTF-8 bodies use the same authenticated import/evidence pipeline."""
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app.main import create_app


@pytest.mark.parametrize('format,filename,platform', [
    ('windows-json','windows_events.json','windows'),
    ('windows-csv','windows_events.csv','windows'),
    ('linux-text','linux_auth.txt','linux'),
    ('linux-journal-json','linux_journal.jsonl','linux'),
])
def test_pasted_body_preserves_submitted_text_and_platform(tmp_path, sign_in, format, filename, platform):
    text = (Path(__file__).resolve().parents[1]/'fixtures'/filename).read_text(encoding='utf-8')
    body = text.encode('utf-8')
    with TestClient(create_app(tmp_path/'storage'), base_url='http://127.0.0.1', client=('127.0.0.1',50000)) as client:
        sign_in(client)
        response = client.post('/api/uploads', params={"platform": platform, "filename": f"pasted-{platform}.txt", "name": " DC-01 morning / audit "}, content=body,
                               headers={'Content-Type':'text/plain','X-Sentinel-Import':'1'})
        assert response.status_code == 201, response.text
        item = response.json()
        assert item['format'] == format
        assert item['filename'] == "DC-01 morning / audit"
        assert item['accepted_count'] > 0 and item['sha256'] == sha256(body).hexdigest()
        assert client.app.state.store.blob_path(item['id']).read_bytes() == body
        events = client.get('/api/events',params={'upload_id':item['id']}).json()['items']
        assert events and all(event['platform'] == platform for event in events)
        assert all(event["source_file"] == item["filename"] for event in events)
