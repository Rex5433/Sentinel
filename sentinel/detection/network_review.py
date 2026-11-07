"""Original, bounded header-pattern review; indicators are not attack verdicts."""

from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
from statistics import median

VERSION = "network-patterns-v1"
IMPLEMENTATION_HASH = sha256(Path(__file__).read_text(encoding="utf-8-sig").encode()).hexdigest()
MAX_FINDINGS = 200
POLICY = {
    "port_sweep": {"distinct_ports": 12, "seconds": 60},
    "host_sweep": {"distinct_hosts": 8, "seconds": 60},
    "repeated_access": {"distinct_client_ports": 10, "seconds": 60,
                        "ports": [22, 23, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986]},
    "syn_burst": {"distinct_attempt_tuples": 100, "seconds": 10, "urgent_at": 500},
    "periodic": {"observations": 6, "minimum_interval_seconds": 5, "relative_tolerance": .15},
    "large_transfer": {"captured_bytes": 1048576, "seconds": 300},
}
POLICY_HASH = sha256(json.dumps(POLICY, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
LIMITATIONS = [
    "Thresholds are initial review policy, not validated accuracy or compromise probabilities.",
    "A scan, retry burst, periodic task or large transfer may be authorized. No automatic safe/malicious verdict.",
    "Headers cannot reveal encrypted commands, process identity, successful authentication, file names or every attacker action.",
    "TCP SYNs collapse by directional five-tuple/VLAN across this capture; reused tuples may undercount. No handshake or sequence reassembly.",
    "UDP observations do not prove requests or sessions. Periodicity may be monitoring, DNS, backups or other routine work.",
    "Captured byte counts include headers and retransmissions; they do not prove application data volume or exfiltration.",
    "Only supported decoded packets with valid timestamps are evaluated. Capture gaps, missing directions and unsupported traffic limit coverage.",
]


def _bursts(events, value, threshold, seconds, *, byte_sum=False):
    """Pick the strongest real sliding window per contiguous qualifying episode."""
    events = sorted(events, key=lambda p: (int(p["timestamp_ns"]), p["record_index"]))
    counts, left, total = Counter(), 0, 0
    best = None
    last_match = None
    span = seconds * 1_000_000_000
    for right, packet in enumerate(events):
        stamp = int(packet["timestamp_ns"])
        key = value(packet)
        counts[key] += 1
        total += packet["captured_length"]
        while int(events[left]["timestamp_ns"]) < stamp - span:
            old = events[left]
            counts[value(old)] -= 1
            if not counts[value(old)]:
                del counts[value(old)]
            total -= old["captured_length"]
            left += 1
        score = total if byte_sum else len(counts)
        if best and last_match is not None and stamp - last_match > span:
            yield events[best[1]:best[2] + 1], best[0]
            best = None
        if score >= threshold:
            if best is None or score > best[0]:
                best = (score, left, right)
            last_match = stamp
    if best:
        yield events[best[1]:best[2] + 1], best[0]


def review_packets(packets, source_sha256, upload_id):
    findings = []
    eligible, candidates = [], []
    seen_syn, seen_udp = set(), set()
    duplicates = unknown = 0
    for packet in packets:
        if packet.get("status") != "decoded":
            continue
        if packet.get("timestamp_ns") is None:
            unknown += 1
            continue
        eligible.append(packet)
    # File order need not be chronological. Keep earliest observed tuple timestamp.
    eligible.sort(key=lambda p: (int(p["timestamp_ns"]), p["record_index"]))
    for packet in eligible:
        flags = packet.get("tcp_flags") or 0
        context = tuple(packet.get("vlan_ids", []))
        key = (context, packet["protocol"], packet["source_ip"], packet["source_port"],
               packet["destination_ip"], packet["destination_port"])
        if packet["protocol"] == "tcp" and flags & 2 and not flags & (16 | 4 | 1):
            if key in seen_syn:
                duplicates += 1
                continue
            seen_syn.add(key)
            candidates.append(packet)
        elif packet["protocol"] == "udp":
            identity = (context, packet.get("packet_sha256"), packet["timestamp_ns"])
            if identity in seen_udp:
                duplicates += 1
                continue
            seen_udp.add(identity)
            candidates.append(packet)

    def emit(rule, title, severity, members, measured, explanation, next_check):
        indices = sorted({p["record_index"] for p in members})
        ordered = sorted(members, key=lambda p: (int(p["timestamp_ns"]), p["record_index"]))
        identifier = sha256(json.dumps([VERSION, POLICY_HASH, upload_id, source_sha256, rule, indices], separators=(",", ":")).encode()).hexdigest()
        findings.append({"finding_id": identifier, "rule": rule, "title": title, "severity": severity,
            "explanation": explanation, "next_check": next_check, "measured": measured,
            "first_utc": ordered[0]["timestamp_utc"], "last_utc": ordered[-1]["timestamp_utc"],
            "source_ips": sorted({p["source_ip"] for p in members}),
            "destination_ips": sorted({p["destination_ip"] for p in members}),
            "destination_ports": sorted({p["destination_port"] for p in members}),
            "protocols": sorted({p["protocol"] for p in members}),
            "vlan_ids": list(members[0].get("vlan_ids", [])),
            "evidence_indices": indices, "flow_ids": sorted({p["flow_id"] for p in members}),
            "packet_count": len(indices), "method": "deterministic", "verdict": "review_required"})

    port_groups, host_groups, access_groups, syn_groups, pairs = (defaultdict(list) for _ in range(5))
    for packet in candidates:
        vlan = tuple(packet.get("vlan_ids", []))
        protocol, src, dst, port = packet["protocol"], packet["source_ip"], packet["destination_ip"], packet["destination_port"]
        port_groups[(vlan, protocol, src, dst)].append(packet)
        host_groups[(vlan, protocol, src, port)].append(packet)
        pairs[(vlan, protocol, src, dst, port)].append(packet)
        if protocol == "tcp":
            syn_groups[(vlan, dst, port)].append(packet)
            if port in POLICY["repeated_access"]["ports"]:
                access_groups[(vlan, src, dst, port)].append(packet)

    for values in port_groups.values():
        policy = POLICY["port_sweep"]
        for members, count in _bursts(values, lambda p: p["destination_port"], policy["distinct_ports"], policy["seconds"]):
            emit("port_sweep", "Many ports contacted on one host", "warning", members,
                 {"distinct_ports": count, "window_seconds": 60},
                 f"Observed probes to {count} distinct destination ports within one 60-second window.",
                 "Check whether this source is an authorized scanner; correlate destination host logs at these times.")
    for values in host_groups.values():
        policy = POLICY["host_sweep"]
        for members, count in _bursts(values, lambda p: p["destination_ip"], policy["distinct_hosts"], policy["seconds"]):
            emit("host_sweep", "One port contacted across many hosts", "warning", members,
                 {"distinct_hosts": count, "window_seconds": 60},
                 f"Observed the same destination port on {count} hosts within one 60-second window.",
                 "Compare with team inventory/discovery tasks and inspect the contacted hosts' logs.")
    for values in access_groups.values():
        policy = POLICY["repeated_access"]
        for members, count in _bursts(values, lambda p: p["source_port"], policy["distinct_client_ports"], policy["seconds"]):
            emit("repeated_access", "Repeated connection attempts to an access port", "warning", members,
                 {"distinct_client_ports": count, "window_seconds": 60},
                 f"Observed {count} distinct client ports initiating TCP to one configured access-port number within 60 seconds. This does not prove failed authentication.",
                 "Check the destination's authentication/service logs and approved administration activity.")
    for values in syn_groups.values():
        policy = POLICY["syn_burst"]
        for members, count in _bursts(values, lambda p: (p["source_ip"], p["source_port"]), policy["distinct_attempt_tuples"], policy["seconds"]):
            emit("syn_burst", "Concentrated TCP connection-attempt burst", "critical" if count >= policy["urgent_at"] else "warning", members,
                 {"distinct_attempt_tuples": count, "window_seconds": 10},
                 f"Observed {count} distinct source-address/client-port pairs sending TCP SYNs to one destination port within 10 seconds. Priority reflects volume, not confirmed malice.",
                 "Check service availability, capture coverage, load tests and source addresses; correlate with host logs.")

    for values in pairs.values():
        policy = POLICY["periodic"]
        if len(values) < policy["observations"]:
            continue
        times = sorted({int(p["timestamp_ns"]) for p in values})
        if len(times) < policy["observations"]:
            continue
        gaps = [(b-a)/1e9 for a,b in zip(times,times[1:])]
        interval = median(gaps)
        if interval >= policy["minimum_interval_seconds"] and max(abs(gap-interval)/interval for gap in gaps) <= policy["relative_tolerance"]:
            emit("periodic", "Periodic connection or datagram pattern", "lead", values,
                 {"distinct_times": len(times), "median_interval_seconds": interval,
                  "maximum_relative_deviation": max(abs(gap-interval)/interval for gap in gaps)},
                 f"Observed {len(times)} regularly spaced initiation/datagram times, about {interval:g} seconds apart.",
                 "Compare scheduled monitoring/backup jobs; inspect endpoint process and destination context before suspecting command-and-control.")

    transfers = defaultdict(list)
    for packet in eligible:
        transfers[(tuple(packet.get("vlan_ids", [])), packet["protocol"], packet["source_ip"], packet["destination_ip"], packet["destination_port"])].append(packet)
    for values in transfers.values():
        policy = POLICY["large_transfer"]
        for members, count in _bursts(values, lambda p: p["record_index"], policy["captured_bytes"], policy["seconds"], byte_sum=True):
            emit("large_transfer", "Large captured transfer toward one endpoint", "lead", members,
                 {"captured_bytes_including_headers": count, "window_seconds": 300},
                 f"Observed {count} captured bytes toward one destination/port within 300 seconds, including headers and possible retransmissions.",
                 "Compare expected backups/downloads and destination ownership. Headers do not establish file contents or exfiltration.")

    priority = {"critical": 0, "warning": 1, "lead": 2}
    findings.sort(key=lambda f: (priority[f["severity"]], f["first_utc"], f["finding_id"]))
    total = len(findings)
    findings = findings[:MAX_FINDINGS]
    return {"version": VERSION, "policy_sha256": POLICY_HASH, "implementation_sha256": IMPLEMENTATION_HASH, "policy": POLICY,
            "findings": findings, "finding_count": total, "returned_findings": len(findings),
            "severity_counts": dict(Counter(f["severity"] for f in findings)),
            "eligible_packets": len(eligible), "unknown_timestamp_packets": unknown,
            "collapsed_probe_records": duplicates, "limitations": LIMITATIONS}


def public_finding(finding):
    return {key: value for key, value in finding.items() if key not in {"evidence_indices", "flow_ids"}} | {
        "packet_index_preview": finding["evidence_indices"][:20], "flow_count": len(finding["flow_ids"])}
