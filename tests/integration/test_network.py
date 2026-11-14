"""Authenticated PCAP import/storage/report/evidence checks with synthetic bytes."""

from hashlib import sha256
import json
from pathlib import Path
import runpy
import struct
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from app.db import EvidenceStore
from sentinel.ingest.pcap import parse_pcap

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
builder = runpy.run_path(str(FIXTURES / "build_network_demo.py"))
HEADERS = {"Content-Type": "application/vnd.tcpdump.pcap", "X-Sentinel-Import": "1"}


def scan_capture():
    frames = []
    for index in range(12):
        frame = bytearray(builder["tcp_frame"]())
        struct.pack_into("!HH", frame, 34, 40000+index, 1000+index)
        frame[50:52] = b"\x00\x00"
        pseudo = bytes(frame[26:34]) + struct.pack("!BBH", 0, 6, len(frame)-34)
        struct.pack_into("!H", frame, 50, builder["checksum"](pseudo+bytes(frame[34:])))
        frames.append((1793718000+index, 0, bytes(frame), len(frame)))
    return builder["pcap"](frames)


@pytest.fixture
def client(tmp_path, sign_in):
    with TestClient(create_app(tmp_path / "storage"), base_url="http://127.0.0.1", client=("127.0.0.1", 50400)) as client:
        sign_in(client)
        yield client


def upload(client, source=None):
    source = source if source is not None else (FIXTURES / "network_demo.pcap").read_bytes()
    response = client.post("/api/uploads?format=pcap&filename=network_demo.pcap", content=source, headers=HEADERS)
    assert response.status_code == 201, response.text
    return response.json()


def test_capture_is_saved_with_truthful_coverage_and_original_bytes(client):
    item = upload(client)
    assert item["format"] == "pcap" and item["accepted_count"] == 7 and item["rejected_count"] == 2
    assert item["warning_count"] == 2
    source = (FIXTURES / "network_demo.pcap").read_bytes()
    assert client.app.state.store.blob_path(item["id"]).read_bytes() == source
    summary = client.get(f"/api/network/{item['id']}").json()
    assert summary["source"]["sha256"] == sha256(source).hexdigest()
    assert summary["packet_count"] == 9 and summary["decoded_packets"] == 7 and summary["flow_count"] == 4
    assert summary["syn_without_ack_packets"] == 2 and summary["reset_packets"] == 1
    assert summary["parser_version"] == "network-headers-v1"
    assert len(summary["implementation_sha256"]) == 64
    assert not summary["model_ready"] and not summary["competition_use_enabled"]


def test_flow_filters_pagination_and_packet_references_are_scoped_to_source(client):
    first, second = upload(client), upload(client)
    base = f"/api/network/{first['id']}"
    result = client.get(base+"/flows?limit=1&destination_port=443&protocol=tcp&peer=192.0.2.10").json()
    assert result["total"] == 1 and result["items"][0]["packet_count"] == 4
    flow = result["items"][0]
    evidence = client.get(base+f"/packets?flow_id={flow['flow_id']}&limit=2&offset=2").json()
    assert evidence["total"] == 4 and [p["record_index"] for p in evidence["items"]] == [4, 9]
    assert all(p["upload_id"] == first["id"] and p["flow_id"] == flow["flow_id"] for p in evidence["items"])
    other = client.get(f"/api/network/{second['id']}/packets?flow_id={flow['flow_id']}")
    assert other.status_code == 404
    assert client.get(base+"/flows?offset=1&limit=1").json()["total"] == 4
    assert client.get(base+"/flows?peer=192.0.2.1").json()["total"] == 0
    assert client.get(base+"/flows?peer=2001:db8:0:0::10&protocol=udp").json()["total"] == 2
    packet = client.get(base+"/packets?status=skipped").json()["items"][0]
    assert packet["reason"] == "unsupported_ethertype" and packet["record_index"] == 7
    malformed = client.get(base+"/packets?status=malformed").json()["items"][0]
    assert malformed["record_index"] == 8 and malformed["captured_length"] == 10


def test_network_report_contains_all_headers_and_aggregates_without_payload_or_model_claims(client):
    item = upload(client)
    response = client.get(f"/api/reports/{item['id']}")
    assert response.headers["content-disposition"].startswith("attachment;")
    report = response.json()
    assert report["report_version"] == "network-evidence-v2"
    assert report["network_review"]["version"] == "network-patterns-v1"
    assert len(report["flows"]) == 4 and len(report["packets"]) == 9
    assert report["source"]["sha256"] == item["sha256"]
    assert report["model_ready"] is False and report["model_version"] is None
    assert "checksum validation" in " ".join(report["network_summary"]["limitations"])
    assert "synthetic-test-only" not in response.text and "raw_record" not in response.text
    text = client.get(f"/api/reports/{item['id']}?format=text").text
    assert "NETWORK HEADER REPORT" in text and "PACKETS" in text and "FLOWS" in text
    assert item["sha256"] in text and "No threat verdict" in text


def test_log_and_network_pipelines_are_explicit_and_do_not_produce_fake_empty_analysis(client):
    item = upload(client)
    for path in (f"/api/events?upload_id={item['id']}", f"/api/uploads/{item['id']}/rejected",
                 f"/api/uploads/{item['id']}/overview", f"/api/analysis/{item['id']}",
                 f"/api/features?upload_id={item['id']}", f"/api/timeline?upload_id={item['id']}"):
        assert client.get(path).status_code == 400
    assert client.post(f"/api/analysis/{item['id']}", headers=HEADERS).status_code == 400
    headers = {**HEADERS, "Content-Type": "application/json"}
    assert client.post("/api/ask", json={"query": "show failed logins", "upload_id": item["id"]}, headers=headers).status_code == 400
    assert client.post("/api/ask", json={"query": "show failed logins"}, headers=headers).json()["total"] == 0
    assert client.get("/api/timeline").json()["total"] == 0
    log = client.post("/api/uploads?format=windows-json&filename=test.json", content=b'{"Id":4625}', headers=headers).json()
    assert client.get(f"/api/network/{log['id']}").status_code == 400


def test_bad_framing_unsupported_and_empty_captures_do_not_persist_partial_imports(client):
    data = (FIXTURES / "network_demo.pcap").read_bytes()
    for source in (data[:-1], data+b"\0", b"not a pcap", b"\x0a\x0d\x0d\x0a"+b"\0"*20, builder["pcap"]([])):
        response = client.post("/api/uploads?format=pcap&filename=bad.pcap", content=source, headers=HEADERS)
        assert response.status_code == 400, response.text
    assert client.get("/api/uploads").json()["total"] == 0
    assert list(client.app.state.store.raw_dir.iterdir()) == []
    assert client.post("/api/uploads?format=pcap&filename=bad.pcap", content=data, headers={**HEADERS, "Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/uploads?format=pcap&filename=bad.pcapng", content=data, headers=HEADERS).status_code == 415


def test_all_excluded_capture_has_evidence_without_invented_flows_or_rates(client):
    data = builder["pcap"]([(1, 0, b"\0"*10, 10)])
    item = upload(client, data)
    summary = client.get(f"/api/network/{item['id']}").json()
    assert summary["decoded_packets"] == 0 and summary["malformed_packets"] == 1
    assert summary["top_peers"] == [] and summary["observed_timed_packets_per_second"] is None
    assert client.get(f"/api/network/{item['id']}/flows").json()["total"] == 0
    assert client.get(f"/api/network/{item['id']}/packets").json()["total"] == 1


def test_capture_deletion_and_retention_cascade_all_network_rows(client):
    item = upload(client)
    assert client.delete(f"/api/uploads/{item['id']}", headers=HEADERS).status_code == 204
    assert not client.app.state.store.blob_path(item["id"]).exists()
    assert client.get(f"/api/network/{item['id']}").status_code == 404
    item = upload(client)
    with client.app.state.store.connect() as connection:
        connection.execute("UPDATE uploads SET created_at='2000-01-01' WHERE id=?", (item["id"],))
    client.app.state.store.prune_expired()
    with client.app.state.store.connect() as connection:
        for table in ("network_summaries", "network_packets", "network_flows"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_failed_capture_save_rolls_back_raw_copy_summary_flows_and_packets(tmp_path):
    store = EvidenceStore(tmp_path / "storage"); store.initialize()
    data = (FIXTURES / "network_demo.pcap").read_bytes()
    result = parse_pcap(data, source_file="synthetic.pcap", upload_id=uuid4().hex)
    result.packets[-1]["tcp_flags"] = float("nan")
    with pytest.raises(ValueError):
        store.save(data, result)
    assert store.uploads(0, 10)["total"] == 0 and list(store.raw_dir.iterdir()) == []
    with store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0] == 0


def test_route_auth_validation_origin_and_input_limits(client):
    item = upload(client)
    base = f"/api/network/{item['id']}"
    for suffix in ("/flows?limit=101", "/flows?peer=localhost", "/flows?destination_port=65536",
                   "/flows?protocol=icmp", "/packets?flow_id=bad", "/packets?status=normal"):
        assert client.get(base+suffix).status_code == 422
    assert client.get(base, headers={"Origin": "http://example.test"}).status_code == 403
    client.cookies.clear()
    for path in (base, base+"/flows", base+"/packets"):
        assert client.get(path).status_code == 401


def test_pattern_findings_resolve_all_packets_and_tags_without_reimport(client):
    source = scan_capture()
    one, two = upload(client, source), upload(client, source)
    base = f"/api/network/{one['id']}"
    summary = client.get(base).raise_for_status().json()
    assert summary["review"]["finding_count"] == 1
    assert summary["review"]["severity_counts"] == {"warning": 1}
    finding = client.get(base+"/findings?limit=1").json()["items"][0]
    assert finding["rule"] == "port_sweep" and finding["packet_count"] == 12
    evidence = client.get(base+f"/findings/{finding['finding_id']}/packets?offset=10&limit=2").raise_for_status().json()
    assert evidence["total"] == 12
    assert [p["record_index"] for p in evidence["items"]] == [11,12]
    assert all(p["network_indicators"][0]["finding_id"] == finding["finding_id"] for p in evidence["items"])
    assert all(f["network_indicators"] for f in client.get(base+"/flows?limit=100").json()["items"])
    assert client.get(f"/api/network/{two['id']}/findings/{finding['finding_id']}/packets").status_code == 404
    assert client.get(base+"/findings/not-valid/packets").status_code == 422
    report = client.get(f"/api/reports/{one['id']}").raise_for_status().json()
    assert report["network_review"]["findings"][0]["evidence_indices"] == list(range(1,13))
    assert client.app.state.store.blob_path(one["id"]).read_bytes() == source
    client.cookies.clear()
    for path in (base+"/findings",base+f"/findings/{finding['finding_id']}/packets"):
        assert client.get(path).status_code == 401
