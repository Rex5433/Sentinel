"""Original synthetic protocol fixture builder; never sends packets.

Codex-assisted test source, 2026-11-03. Documentation-only addresses. Not a
capture from any machine, training data, scenario truth, or accuracy evidence.
Run from V1: python tests/fixtures/build_network_demo.py
"""

from ipaddress import ip_address
from pathlib import Path
import struct

EPOCH = 1793718000  # 2026-11-03 15:00:00 UTC


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def tcp_frame(flags=2, *, reverse=False, payload=b"", vlan_ids=()):
    source, destination = ("192.0.2.10", "198.51.100.20")
    sport, dport = 50100, 443
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    src, dst = ip_address(source).packed, ip_address(destination).packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 8192, 0, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("020000000020020000000010")
    for vlan in vlan_ids:
        ethernet += struct.pack("!HH", 0x8100, vlan)
    return ethernet + struct.pack("!H", 0x0800) + ip + tcp


def udp6_frame(*, reverse=False):
    source, destination, sport, dport = "2001:db8::10", "2001:db8::20", 53000, 53
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    src, dst, payload = ip_address(source).packed, ip_address(destination).packed, b"demo"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, src, dst)
    return bytes.fromhex("02000000002002000000001086dd") + ip + udp


def pcap(records, *, endian="<", nanos=False, linktype=1, snaplen=65535):
    """Each record: (seconds, fraction, captured bytes, declared original length)."""
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, snaplen, linktype))
    for seconds, fraction, frame, original in records:
        result.extend(struct.pack(endian + "IIII", seconds, fraction, len(frame), original))
        result.extend(frame)
    return bytes(result)


def demo_bytes():
    frames = [tcp_frame(), tcp_frame(), tcp_frame(0x12, reverse=True), tcp_frame(0x10),
              udp6_frame(), udp6_frame(reverse=True),
              bytes.fromhex("ffffffffffff0200000000100806") + b"\0" * 28, b"\0" * 10]
    records = [(EPOCH + index, 0, frame, len(frame) if index != 7 else 60)
               for index, frame in enumerate(frames)]
    full = tcp_frame(4, payload=b"synthetic-test-only!!")
    records.append((EPOCH + 8, 0, full[:54], len(full)))
    return pcap(records)


if __name__ == "__main__":
    destination = Path(__file__).with_name("network_demo.pcap")
    destination.write_bytes(demo_bytes())
    print(f"Wrote original synthetic functional fixture: {destination}")
