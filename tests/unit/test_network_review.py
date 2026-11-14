"""Hand-counted original behavioral cases, not training data or accuracy claims."""
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from sentinel.detection.network_review import review_packets


def packet(index, seconds=0, *, src="192.0.2.8", dst="198.51.100.9", sport=None, dport=443,
           protocol="tcp", flags=2, vlan=(), size=54):
    sport = 40000 + index if sport is None else sport
    key = (src, dst, sport, dport, protocol, vlan)
    return {"record_index": index, "status": "decoded", "source_ip": src, "destination_ip": dst,
            "source_port": sport, "destination_port": dport, "protocol": protocol,
            "tcp_flags": flags if protocol == "tcp" else None, "vlan_ids": list(vlan),
            "captured_length": size, "timestamp_ns": str(int(seconds * 1e9)),
            "timestamp_utc": datetime.fromtimestamp(seconds, timezone.utc).isoformat(),
            "flow_id": sha256(repr(key).encode()).hexdigest(),
            "packet_sha256": sha256(repr((key, flags, size)).encode()).hexdigest()}


def review(rows, upload="unit-import"):
    return review_packets(rows, "a"*64, upload)


def rules(rows):
    return {finding["rule"] for finding in review(rows)["findings"]}


@pytest.mark.parametrize("count,expected", [(11, False), (12, True)])
def test_port_sweep_boundary_and_exact_packet_evidence(count, expected):
    rows = [packet(i+1, 59+i/10, dport=1000+i) for i in range(count)]
    result = review(rows)
    matched = [f for f in result["findings"] if f["rule"] == "port_sweep"]
    assert bool(matched) is expected
    if expected:
        assert matched[0]["evidence_indices"] == list(range(1,13))
        assert matched[0]["measured"]["distinct_ports"] == 12


def test_slow_varied_traffic_is_not_combined_across_the_entire_capture():
    assert "port_sweep" not in rules([packet(i+1, i*10, dport=i+1000) for i in range(12)])


@pytest.mark.parametrize("count,expected", [(7, False), (8, True)])
def test_horizontal_probe_boundary(count, expected):
    rows = [packet(i+1, i, dst=f"198.51.100.{i+1}") for i in range(count)]
    assert ("host_sweep" in rules(rows)) is expected


def test_vlan_context_does_not_merge_identical_address_space():
    rows = [packet(i+1, i, dst=f"198.51.100.{i+1}", vlan=(10 if i<4 else 20,)) for i in range(8)]
    assert "host_sweep" not in rules(rows)


def test_retransmissions_do_not_inflate_attempt_count():
    rows = [packet(i+1, i/10, sport=40001, dport=22) for i in range(100)]
    result = review(rows)
    assert result["findings"] == []
    assert result["collapsed_probe_records"] == 99


@pytest.mark.parametrize("port,count,expected", [(22,9,False),(22,10,True),(443,10,False)])
def test_access_port_retries_are_not_called_authentication_failures(port, count, expected):
    result = review([packet(i+1, i/10, dport=port) for i in range(count)])
    matched = [f for f in result["findings"] if f["rule"] == "repeated_access"]
    assert bool(matched) is expected
    if matched:
        assert "does not prove failed authentication" in matched[0]["explanation"]
        assert matched[0]["verdict"] == "review_required"


@pytest.mark.parametrize("count,severity", [(99,None),(100,"warning"),(500,"critical")])
def test_syn_burst_has_measured_priority_boundaries(count, severity):
    result = review([packet(i+1, i/1000) for i in range(count)])
    matched = [f for f in result["findings"] if f["rule"] == "syn_burst"]
    assert bool(matched) == bool(severity)
    if matched:
        assert matched[0]["severity"] == severity


def test_periodic_benign_monitor_is_only_a_context_lead():
    result = review([packet(i+1, i*10) for i in range(6)])
    assert [f["rule"] for f in result["findings"]] == ["periodic"]
    assert result["findings"][0]["severity"] == "lead"
    assert result["findings"][0]["measured"]["median_interval_seconds"] == 10


def test_irregular_or_insufficient_samples_do_not_establish_periodicity():
    assert "periodic" not in rules([packet(i+1,t) for i,t in enumerate([0,10,22,30,45,51])])
    assert "periodic" not in rules([packet(i+1,i*10) for i in range(5)])


def test_exact_duplicate_udp_records_do_not_make_a_beacon():
    rows = [packet(i+1, 10, sport=53000, dport=53, protocol="udp") for i in range(10)]
    assert review(rows)["collapsed_probe_records"] == 9
    assert not review(rows)["findings"]


def test_udp_port_probing_is_supported_but_syn_ack_or_rst_is_not_an_initiation():
    assert "port_sweep" in rules([packet(i+1,i/10,dport=1000+i,protocol="udp") for i in range(12)])
    for flags in (18, 6, 3):
        assert not rules([packet(i+1,i/10,dport=1000+i,flags=flags) for i in range(12)])


def test_missing_timestamps_and_excluded_headers_do_not_become_suspicious():
    rows = [packet(i+1,i,dport=1000+i) for i in range(12)]
    for row in rows:
        row["timestamp_ns"] = None
    result = review(rows)
    assert result["unknown_timestamp_packets"] == 12 and not result["findings"]
    for row in rows:
        row["status"] = "skipped"
    assert review(rows)["eligible_packets"] == 0


def test_large_transfer_counts_captured_bytes_without_claiming_exfiltration():
    rows = [packet(i+1,i,flags=24,size=60000) for i in range(18)]
    finding = next(f for f in review(rows)["findings"] if f["rule"] == "large_transfer")
    assert finding["measured"]["captured_bytes_including_headers"] == 1080000
    assert finding["severity"] == "lead"


def test_source_scope_order_and_separated_bursts_are_reproducible():
    rows = [packet(i+1,i/10,dport=1000+i) for i in range(12)]
    assert review(rows) == review(list(reversed(rows)))
    assert review(rows)["findings"][0]["finding_id"] != review(rows,"other-import")["findings"][0]["finding_id"]
    rows += [packet(i+13,300+i/10,dport=2000+i) for i in range(12)]
    assert len([f for f in review(rows)["findings"] if f["rule"] == "port_sweep"]) == 2


def test_finding_cap_is_visible_and_does_not_call_remaining_packets_safe():
    rows = [packet(12*g+i+1,i/100,src=f"10.0.{g}.1",dport=1000+i) for g in range(201) for i in range(12)]
    result = review(rows)
    assert result["returned_findings"] == 200 and result["finding_count"] > 200
