"""Bounded classic-PCAP header summaries, without payload decoding or live capture.

Format references and explicit unsupported cases are in docs/NETWORK_ANALYSIS.md.
This intentionally small decoder handles Ethernet (at most two VLAN tags) or
raw IPv4/IPv6, then unfragmented TCP/UDP with no IPv6 extension headers.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from pathlib import Path
import struct

from .common import MAX_INPUT_BYTES, MAX_RECORDS, ParseInputError

VERSION = "network-headers-v1"
IMPLEMENTATION_SHA256 = sha256(Path(__file__).read_text(encoding="utf-8-sig").encode()).hexdigest()
MAX_FLOWS = 10_000
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
         b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
LIMITATIONS = [
    "Header statistics only, not a threat verdict or a trained model. Zero indicators do not establish safety.",
    "Directional five-tuples group observed packets, not verified connections. SYN counts include retransmissions; no TCP/session or fragment reassembly.",
    "Only classic PCAP 2.4, Ethernet with up to two VLAN tags, or raw IP; unfragmented IPv4 and IPv6 without extension headers; TCP/UDP. PCAPNG and other protocols/link types are unsupported.",
    "No checksum validation, DNS/service-name lookup, application payload inspection, decryption, live capture, or remote action. Packet lengths/timestamps are capture claims, not independently verified wire measurements.",
    "Top values and rates cover decoded packets only. Capture gaps, retransmissions, duplicates, offload, snaplen truncation, and unsupported/malformed packets limit interpretation.",
    "UTC display truncates nanoseconds to microseconds; original seconds/fraction/resolution and exact timestamp_ns text remain in packet evidence.",
]


@dataclass
class CaptureResult:
    source_file: str
    source_sha256: str
    upload_id: str
    packets: list[dict]
    flows: list[dict]
    summary: dict
    parser: str = "pcap"


class PacketProblem(ValueError):
    def __init__(self, code: str, *, malformed=False):
        self.code, self.malformed = code, malformed


def _fail(code, *, malformed=False):
    raise PacketProblem(code, malformed=malformed)


def _headers(frame: memoryview, linktype: int, packet: dict) -> None:
    offset = 0
    ether_type = None
    if linktype == 1:
        if len(frame) < 14:
            _fail("short_ethernet_header", malformed=True)
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        tags = []
        while ether_type in (0x8100, 0x88A8):
            if len(tags) == 2:
                _fail("more_than_two_vlan_tags")
            if len(frame) < offset + 4:
                _fail("short_vlan_header", malformed=True)
            control, ether_type = struct.unpack_from("!HH", frame, offset)
            tags.append(control & 0x0FFF)
            offset += 4
        packet["vlan_ids"] = tags
        if ether_type not in (0x0800, 0x86DD):
            _fail("unsupported_ethertype")
    data = frame[offset:]
    if not data:
        _fail("missing_ip_header", malformed=True)
    version = data[0] >> 4
    if (ether_type == 0x0800 and version != 4) or (ether_type == 0x86DD and version != 6):
        _fail("ethertype_ip_version_mismatch", malformed=True)
    if version == 4:
        if len(data) < 20:
            _fail("short_ipv4_header", malformed=True)
        size = (data[0] & 15) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        if size < 20 or total < size:
            _fail("invalid_ipv4_lengths", malformed=True)
        if len(data) < size:
            _fail("short_ipv4_options", malformed=True)
        packet.update(ip_version=4, source_ip=str(ip_address(bytes(data[12:16]))),
                      destination_ip=str(ip_address(bytes(data[16:20]))), ip_protocol=data[9])
        fragment = struct.unpack_from("!H", data, 6)[0]
        if fragment & 0x8000:
            _fail("ipv4_reserved_fragment_flag", malformed=True)
        if fragment & 0x3FFF:
            _fail("fragmented_ipv4_not_reassembled")
        protocol = data[9]
    elif version == 6:
        if len(data) < 40:
            _fail("short_ipv6_header", malformed=True)
        size = 40
        payload_length = struct.unpack_from("!H", data, 4)[0]
        packet.update(ip_version=6, source_ip=str(ip_address(bytes(data[8:24]))),
                      destination_ip=str(ip_address(bytes(data[24:40]))), ip_protocol=data[6])
        if payload_length == 0:
            _fail("empty_or_jumbogram_ipv6_not_supported")
        total, protocol = 40 + payload_length, data[6]
    else:
        _fail("unsupported_ip_version")
    if total > len(data):
        packet["warnings"].append("ip_packet_truncated")
    if protocol not in (6, 17):
        _fail("unsupported_ip_protocol_or_ipv6_extension")
    transport = data[size:min(total, len(data))]
    declared = total - size
    minimum = 20 if protocol == 6 else 8
    if declared < minimum or len(transport) < minimum:
        _fail("short_transport_header", malformed=True)
    source_port, destination_port = struct.unpack_from("!HH", transport)
    if protocol == 6:
        tcp_size = (transport[12] >> 4) * 4
        if tcp_size < 20 or tcp_size > declared:
            _fail("invalid_tcp_header_length", malformed=True)
        if tcp_size > len(transport):
            _fail("short_tcp_options", malformed=True)
        packet["tcp_flags"] = ((transport[12] & 1) << 8) | transport[13]
    else:
        udp_size = struct.unpack_from("!H", transport, 4)[0]
        if udp_size < 8 or udp_size > declared:
            _fail("invalid_udp_length", malformed=True)
    packet.update(protocol="tcp" if protocol == 6 else "udp", source_port=source_port,
                  destination_port=destination_port, status="decoded", reason=None)


def _utc(nanos: int) -> str:
    seconds, fraction = divmod(nanos, 1_000_000_000)
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) +
            timedelta(seconds=seconds, microseconds=fraction // 1000)).isoformat(timespec="microseconds")


def _aggregate(packets: list[dict], source_sha256: str, upload_id: str) -> tuple[list[dict], dict]:
    flows, peers, ports = {}, {}, Counter()
    protocols, reasons = Counter(), Counter()
    captured_bytes = original_bytes = timed_decoded = syn_packets = reset_packets = 0
    first = last = None
    for packet in packets:
        if packet["status"] != "decoded":
            reasons[packet["reason"]] += 1
            continue
        protocols[packet["protocol"]] += 1
        captured_bytes += packet["captured_length"]
        original_bytes += packet["original_length"]
        stamp = int(packet["timestamp_ns"]) if packet["timestamp_ns"] is not None else None
        if stamp is not None:
            timed_decoded += 1
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
        key = (packet["protocol"], packet["source_ip"], packet["source_port"],
               packet["destination_ip"], packet["destination_port"], tuple(packet.get("vlan_ids", [])))
        if key not in flows:
            if len(flows) >= MAX_FLOWS:
                raise ParseInputError("Capture exceeds the 10000-directional-flow limit; no partial import saved.")
            identity = json.dumps([VERSION, source_sha256, upload_id, key], separators=(",", ":"))
            flows[key] = {"flow_id": sha256(identity.encode()).hexdigest(), "protocol": key[0],
                          "source_ip": key[1], "source_port": key[2], "destination_ip": key[3],
                          "destination_port": key[4], "vlan_ids": list(key[5]), "packet_count": 0,
                          "captured_bytes": 0, "declared_original_bytes": 0,
                          "syn_without_ack_packets": 0, "reset_packets": 0, "packets_with_warnings": 0,
                          "first_timestamp_ns": None, "last_timestamp_ns": None, "packet_index_preview": []}
        flow = flows[key]
        packet["flow_id"] = flow["flow_id"]
        flow["packet_count"] += 1
        flow["captured_bytes"] += packet["captured_length"]
        flow["declared_original_bytes"] += packet["original_length"]
        flow["packets_with_warnings"] += bool(packet["warnings"])
        if len(flow["packet_index_preview"]) < 5:
            flow["packet_index_preview"].append(packet["record_index"])
        if stamp is not None:
            for name, operation in (("first_timestamp_ns", min), ("last_timestamp_ns", max)):
                old = flow[name]
                flow[name] = str(stamp if old is None else operation(int(old), stamp))
        flags = packet.get("tcp_flags") or 0
        syn = bool(flags & 2 and not flags & 16)
        reset = bool(flags & 4)
        flow["syn_without_ack_packets"] += syn
        flow["reset_packets"] += reset
        syn_packets += syn
        reset_packets += reset
        for address in {packet["source_ip"], packet["destination_ip"]}:
            peer = peers.setdefault(address, {"address": address, "packet_count": 0, "captured_bytes": 0})
            peer["packet_count"] += 1
            peer["captured_bytes"] += packet["captured_length"]
        ports[(packet["protocol"], packet["destination_port"])] += 1
    for flow in flows.values():
        flow["first_utc"] = _utc(int(flow["first_timestamp_ns"])) if flow["first_timestamp_ns"] else None
        flow["last_utc"] = _utc(int(flow["last_timestamp_ns"])) if flow["last_timestamp_ns"] else None
    duration = (last - first) / 1e9 if first is not None else None
    summary = {
        "parser_version": VERSION, "implementation_sha256": IMPLEMENTATION_SHA256,
        "packet_count": len(packets), "decoded_packets": sum(protocols.values()),
        "skipped_packets": sum(p["status"] == "skipped" for p in packets),
        "malformed_packets": sum(p["status"] == "malformed" for p in packets),
        "capture_truncated_packets": sum(p["captured_length"] < p["original_length"] for p in packets),
        "packets_with_warnings": sum(bool(p["warnings"]) for p in packets),
        "unknown_timestamps": sum(p["timestamp_ns"] is None for p in packets),
        "flow_count": len(flows), "protocol_counts": dict(protocols), "exclusion_counts": dict(reasons),
        "decoded_captured_bytes": captured_bytes, "decoded_declared_original_bytes": original_bytes,
        "first_decoded_utc": _utc(first) if first is not None else None,
        "last_decoded_utc": _utc(last) if last is not None else None,
        "decoded_span_seconds": duration, "timed_decoded_packets": timed_decoded,
        "observed_timed_packets_per_second": timed_decoded / duration if duration and duration > 0 else None,
        "syn_without_ack_packets": syn_packets, "reset_packets": reset_packets,
        "top_peers": sorted(peers.values(), key=lambda p: (-p["packet_count"], p["address"]))[:8],
        "top_destination_ports": [dict(protocol=key[0], port=key[1], packet_count=count)
                                  for key, count in sorted(ports.items(), key=lambda p: (-p[1], p[0]))[:8]],
        "method": "deterministic", "model_ready": False, "competition_use_enabled": False,
        "limitations": LIMITATIONS.copy(),
    }
    return sorted(flows.values(), key=lambda p: (-p["packet_count"], p["flow_id"])), summary


def parse_pcap(data: bytes, *, source_file: str, upload_id: str) -> CaptureResult:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ParseInputError("PCAP input must be bytes within the 25 MiB limit.")
    if any(not isinstance(value, str) or not value.strip() for value in (source_file, upload_id)):
        raise ParseInputError("source_file and upload_id must be nonblank strings")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise ParseInputError("PCAPNG is not supported in this version. Export classic PCAP for this header view.")
    if len(data) < 24 or data[:4] not in MAGIC:
        raise ParseInputError("Expected a complete classic PCAP header.")
    endian, resolution = MAGIC[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_INPUT_BYTES:
        raise ParseInputError("Unsupported PCAP version or snapshot length.")
    if linktype not in (1, 101):
        raise ParseInputError("Supported PCAP link types are Ethernet (1) and raw IP (101), without extra link flags.")
    digest, offset, packets = sha256(data).hexdigest(), 24, []
    view = memoryview(data)
    while offset < len(data):
        if len(packets) >= MAX_RECORDS:
            raise ParseInputError("Capture exceeds the 100000-packet limit; no partial import saved.")
        if len(data) - offset < 16:
            raise ParseInputError("Incomplete PCAP packet header; no partial import saved.")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        start = offset + 16
        if captured > snaplen or captured > original or captured > len(data) - start:
            raise ParseInputError("Inconsistent or incomplete PCAP packet lengths; no partial import saved.")
        frame = view[start:start + captured]
        stamp = seconds * 1_000_000_000 + fraction * (1_000_000_000 // resolution) if fraction < resolution else None
        index = len(packets) + 1
        packet = {"record_index": index, "packet_id": sha256(f"{VERSION}:{digest}:{index}".encode()).hexdigest(),
                  "upload_id": upload_id, "source_sha256": digest, "packet_sha256": sha256(frame).hexdigest(),
                  "record_header_offset": offset, "packet_data_offset": start,
                  "captured_length": captured, "original_length": original,
                  "timestamp_seconds": seconds, "timestamp_fraction": fraction,
                  "timestamp_resolution": resolution, "timestamp_ns": str(stamp) if stamp is not None else None,
                  "timestamp_utc": _utc(stamp) if stamp is not None else None,
                  "status": "skipped", "reason": None, "warnings": [], "flow_id": None,
                  "source_ip": None, "destination_ip": None, "source_port": None,
                  "destination_port": None, "protocol": None, "tcp_flags": None}
        if captured < original:
            packet["warnings"].append("capture_snaplen_truncation")
        if stamp is None:
            packet["warnings"].append("invalid_timestamp_fraction")
        try:
            _headers(frame, linktype, packet)
        except PacketProblem as exc:
            packet["status"] = "malformed" if exc.malformed else "skipped"
            packet["reason"] = exc.code
        packets.append(packet)
        offset = start + captured
    flows, summary = _aggregate(packets, digest, upload_id)
    summary.update(linktype=linktype, snapshot_length=snaplen,
                   timestamp_resolution=resolution, byte_order="little" if endian == "<" else "big")
    return CaptureResult(source_file, digest, upload_id, packets, flows, summary)
