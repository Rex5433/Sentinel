from pathlib import Path
from fastapi.testclient import TestClient
from app.main import create_app

def test_all_import_kinds_share_one_raw_store(tmp_path,sign_in):
    fixtures=Path(__file__).resolve().parents[1]/'fixtures'
    with TestClient(create_app(tmp_path/'storage'),base_url='http://127.0.0.1',client=('127.0.0.1',50100)) as client:
        sign_in(client);root=client.app.state.store.root;paths=[]
        sources=[('windows-json','windows_events.json'),('windows-csv','windows_events.csv'),
                 ('linux-text','linux_auth.txt'),('linux-journal-json','linux_journal.jsonl'),
                 ('pcap','network_demo.pcap'),('snapshot','snapshot_before.json')]
        for format,name in sources:
            raw=(fixtures/name).read_bytes()
            response=client.post('/api/uploads',params={'format':format,'filename':name},content=raw,
                                 headers={'X-Sentinel-Import':'1','Content-Type':'application/octet-stream'})
            assert response.status_code==201,response.text
            path=client.app.state.store.blob_path(response.json()['id']);paths.append(path)
            assert path.parent==root/'raw' and path.read_bytes()==raw
        # Same body path as the paste UI; no file picker/source path is needed.
        response=client.post('/api/uploads?format=linux-text&filename=pasted-linux-text.txt',
            content=(fixtures/'linux_auth.txt').read_text(encoding='utf-8').encode(),
            headers={'X-Sentinel-Import':'1','Content-Type':'text/plain'})
        assert response.status_code==201
        assert client.app.state.store.blob_path(response.json()['id']).parent==root/'raw'
        assert len(list((root/'raw').iterdir()))==7


def test_independent_installs_isolate_sessions_and_evidence(tmp_path, sign_in):
    first = create_app(tmp_path / "first" / "storage")
    second = create_app(tmp_path / "second" / "storage")
    with (
        TestClient(first, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50101)) as a,
        TestClient(second, base_url="http://127.0.0.1:8001", client=("127.0.0.1", 50102)) as b,
    ):
        sign_in(a)
        sign_in(b)
        assert a.get("/health").json()["instance_id"] != b.get("/health").json()["instance_id"]
        assert a.get("/api/auth/me").status_code == b.get("/api/auth/me").status_code == 200

        source = Path(__file__).resolve().parents[1] / "fixtures" / "linux_auth.txt"
        item = a.post(
            "/api/uploads", params={"format": "linux-text", "filename": source.name},
            headers={"X-Sentinel-Import": "1", "Content-Type": "text/plain"},
            content=source.read_bytes(),
        ).raise_for_status().json()
        assert a.get("/api/uploads").json()["total"] == 1
        assert b.get("/api/uploads").json()["total"] == 0
        assert b.get(f"/api/uploads/{item['id']}").status_code == 404

        first_cookie, first_token = next(iter(a.cookies.items()))
        second_cookie, _ = next(iter(b.cookies.items()))
        assert first_cookie != second_cookie
        b.cookies.clear()
        assert b.get("/api/auth/me", headers={"Cookie": f"{first_cookie}={first_token}"}).status_code == 401
        assert b.get("/api/auth/me", headers={"Cookie": f"{second_cookie}={first_token}"}).status_code == 401
