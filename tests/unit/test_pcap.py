"""Original byte-level functional cases; no captured/training telemetry."""

from hashlib import sha256
import json
from pathlib import Path
import random
import runpy
import struct

import pytest

from sentinel.ingest import pcap as parser
from sentinel.ingest.common import ParseInputError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
builder = runpy.run_path(str(FIXTURES / "build_network_demo.py"))
pcap, tcp, udp6 = builder["pcap"], builder["tcp_frame"], builder["udp6_frame"]


def parse(data):
    return parser.parse_pcap(data, source_file="synthetic.pcap", upload_id="test-import")


def one(frame, **kwargs):
    return pcap([(1793718000, 0, frame, len(frame))], **kwargs)


def test_demo_is_reproducible_and_matches_hand_counted_packet_flow_byte_and_flag_totals():
    source = (FIXTURES / "network_demo.pcap").read_bytes()
    assert source == builder["demo_bytes"]()
    result = parse(source)
    summary = result.summary
    assert summary["packet_count"] == 9 and summary["decoded_packets"] == 7
    assert summary["skipped_packets"] == 1 and summary["malformed_packets"] == 1
    assert summary["flow_count"] == 4 and summary["protocol_counts"] == {"tcp": 5, "udp": 2}
    assert summary["decoded_captured_bytes"] == 5*54 + 2*66 == 402
    assert summary["decoded_declared_original_bytes"] == 402 + 21 == 423
    assert summary["syn_without_ack_packets"] == 2 and summary["reset_packets"] == 1
    assert summary["capture_truncated_packets"] == summary["packets_with_warnings"] == 2
    assert summary["decoded_span_seconds"] == 8 and summary["observed_timed_packets_per_second"] == 7/8
    assert summary["top_peers"][0] == {"address": "192.0.2.10", "packet_count": 5, "captured_bytes": 270}
    assert summary["top_destination_ports"][0] == {"protocol": "tcp", "port": 443, "packet_count": 4}
    forward = result.flows[0]
    assert forward["packet_count"] == 4 and forward["packet_index_preview"] == [1, 2, 4, 9]
    assert forward["syn_without_ack_packets"] == 2 and forward["reset_packets"] == 1
    assert not summary["model_ready"] and not summary["competition_use_enabled"]
    assert result.source_sha256 == sha256(source).hexdigest()
    for packet in result.packets:
        start = packet["packet_data_offset"]
        raw = source[start:start+packet["captured_length"]]
        assert packet["packet_sha256"] == sha256(raw).hexdigest()
        assert packet["source_sha256"] == result.source_sha256
        assert packet["record_header_offset"] + 16 == start
        assert "payload" not in packet and "raw_record" not in packet
    assert "synthetic-test-only" not in json.dumps(result.summary)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanos", [False, True])
def test_byte_order_and_timestamp_precision_keep_original_fields(endian, nanos):
    frame = tcp()
    fraction = 123456789 if nanos else 123456
    result = parse(pcap([(0, fraction, frame, len(frame))], endian=endian, nanos=nanos))
    packet = result.packets[0]
    assert packet["timestamp_utc"] == "1970-01-01T00:00:00.123456+00:00"
    assert packet["timestamp_ns"] == str(fraction if nanos else fraction*1000)
    assert packet["timestamp_fraction"] == fraction
    assert result.summary["observed_timed_packets_per_second"] is None


def test_out_of_order_times_and_invalid_fraction_do_not_invent_dates_or_bad_rates():
    frame = tcp()
    result = parse(pcap([(10, 0, frame, len(frame)), (5, 0, frame, len(frame)), (2, 1_000_000, frame, len(frame))]))
    assert result.summary["decoded_span_seconds"] == 5
    assert result.summary["observed_timed_packets_per_second"] == 2/5
    assert result.summary["unknown_timestamps"] == 1 and result.packets[-1]["timestamp_utc"] is None
    assert result.packets[-1]["warnings"] == ["invalid_timestamp_fraction"]
    assert [p["record_index"] for p in result.packets] == [1, 2, 3]


def test_raw_ip_and_vlan_contexts_do_not_merge_distinct_observations():
    assert parse(one(tcp()[14:], linktype=101)).summary["decoded_packets"] == 1
    assert parse(one(udp6()[14:], linktype=101)).packets[0]["destination_ip"] == "2001:db8::20"
    frames = [tcp(vlan_ids=tags) for tags in ((), (10,), (10, 20), (11,))]
    result = parse(pcap([(1, 0, frame, len(frame)) for frame in frames]))
    assert result.summary["flow_count"] == 4
    assert {tuple(f["vlan_ids"]) for f in result.flows} == {(), (10,), (10, 20), (11,)}
    assert parse(one(tcp(vlan_ids=(1, 2, 3)))).packets[0]["reason"] == "more_than_two_vlan_tags"


@pytest.mark.parametrize("offset,value,reason", [
    (14, 0x44, "invalid_ipv4_lengths"),
    (14, 0x46, "short_transport_header"),
    (14, 0x65, "ethertype_ip_version_mismatch"),
    (23, 1, "unsupported_ip_protocol_or_ipv6_extension"),
    (46, 0x40, "invalid_tcp_header_length"),
    (46, 0xF0, "invalid_tcp_header_length"),
])
def test_malformed_and_unsupported_headers_never_infer_ports(offset, value, reason):
    frame = bytearray(tcp()); frame[offset] = value
    result = parse(one(frame))
    assert result.summary["decoded_packets"] == 0 and not result.flows
    assert result.packets[0]["reason"] == reason
    assert result.packets[0]["source_port"] is None


def test_fragmentation_and_ipv6_extensions_are_explicitly_excluded():
    for bits in (0x2000, 1):
        frame = bytearray(tcp()); struct.pack_into("!H", frame, 20, bits)
        result = parse(one(frame))
        assert result.packets[0]["reason"] == "fragmented_ipv4_not_reassembled"
        assert result.packets[0]["source_port"] is None
    for next_header in (0, 43, 44, 50, 51, 60, 58):
        frame = bytearray(udp6()); frame[20] = next_header
        result = parse(one(frame))
        assert result.summary["skipped_packets"] == 1 and not result.flows
        assert result.packets[0]["source_ip"] == "2001:db8::10"


def test_capture_truncation_can_keep_complete_headers_but_cannot_invent_missing_ports():
    full = tcp(payload=b"abcdefghij")
    result = parse(pcap([(1, 0, full[:54], len(full)), (1, 0, full[:35], len(full))]))
    assert result.packets[0]["status"] == "decoded"
    assert result.packets[0]["warnings"] == ["capture_snaplen_truncation", "ip_packet_truncated"]
    assert result.packets[1]["status"] == "malformed" and result.packets[1]["source_port"] is None


def test_bad_udp_length_and_incomplete_ipv6_are_visible_not_silent_empty_success():
    frame = bytearray(udp6()); struct.pack_into("!H", frame, 58, 7)
    assert parse(one(frame)).packets[0]["reason"] == "invalid_udp_length"
    assert parse(one(udp6()[:30])).packets[0]["reason"] == "short_ipv6_header"


@pytest.mark.parametrize("data", [b"", b"\x0a\x0d\x0d\x0a" + b"\0"*20, b"x"*24,
                                  b"\xd4\xc3\xb2\xa1", "not bytes"])
def test_unsupported_or_incomplete_file_header_is_fatal(data):
    with pytest.raises(ParseInputError):
        parse(data)


def test_broken_container_and_limits_never_return_partial_results(monkeypatch):
    source = one(tcp())
    for data in (source[:-1], source+b"\0", pcap([], linktype=113), pcap([], snaplen=0),
                 pcap([(1, 0, tcp(), 1)]), pcap([(1, 0, tcp(), 54)], snaplen=10)):
        with pytest.raises(ParseInputError):
            parse(data)
    monkeypatch.setattr(parser, "MAX_FLOWS", 1)
    with pytest.raises(ParseInputError, match="flow limit"):
        parse(pcap([(1, 0, frame, len(frame)) for frame in (tcp(), tcp(reverse=True))]))
    monkeypatch.setattr(parser, "MAX_RECORDS", 1)
    with pytest.raises(ParseInputError, match="packet limit"):
        parse(pcap([(1, 0, tcp(), 54), (1, 0, tcp(), 54)]))
    monkeypatch.setattr(parser, "MAX_INPUT_BYTES", 20)
    with pytest.raises(ParseInputError, match="25 MiB"):
        parse(source)


def test_seeded_arbitrary_packet_bytes_remain_bounded_and_do_not_crash_header_decoder():
    rng = random.Random(84)
    for index in range(400):
        frame = bytearray(tcp() if index % 4 == 1 else udp6()) if index % 2 else rng.randbytes(rng.randrange(150))
        if isinstance(frame, bytearray):
            for _ in range(rng.randrange(1, 5)):
                frame[rng.randrange(len(frame))] = rng.randrange(256)
        result = parse(one(frame))
        assert result.summary["packet_count"] == 1
        assert result.packets[0]["status"] in ("decoded", "skipped", "malformed")
