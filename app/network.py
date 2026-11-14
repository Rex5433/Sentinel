"""Read-only capture views and streaming reports. No event/ML schema coercion."""

from datetime import datetime, timezone
import json
from sentinel.detection.network_review import review_packets, public_finding


def review(store, item):
    packets = [json.loads(row) for row in _records(store, item["id"], "packets")]
    return review_packets(packets, item["sha256"], item["id"]), packets


def _tags(result, *, packet_index=None, flow_id=None):
    if "_packet_tags" not in result:
        result["_packet_tags"], result["_flow_tags"] = {}, {}
        for finding in result["findings"]:
            tag = {key: finding[key] for key in ("finding_id", "title", "severity")}
            for index in finding["evidence_indices"]:
                result["_packet_tags"].setdefault(index, []).append(tag)
            for flow in finding["flow_ids"]:
                result["_flow_tags"].setdefault(flow, []).append(tag)
    return result["_packet_tags"].get(packet_index, []) if packet_index is not None else result["_flow_tags"].get(flow_id, [])


def findings(store, item, offset, limit):
    result, _ = review(store, item)
    return {"items": [public_finding(f) for f in result["findings"][offset:offset+limit]],
            "total": len(result["findings"]), "detected_total": result["finding_count"],
            "offset": offset, "limit": limit, "upload_id": item["id"]}


def finding_packets(store, item, finding_id, offset, limit):
    result, packets = review(store, item)
    finding = next((f for f in result["findings"] if f["finding_id"] == finding_id), None)
    if finding is None:
        return None
    indices = set(finding["evidence_indices"])
    evidence = [p for p in packets if p["record_index"] in indices]
    return {"items": [p | {"network_indicators": _tags(result, packet_index=p["record_index"])} for p in evidence[offset:offset+limit]],
            "total": len(evidence), "offset": offset, "limit": limit, "upload_id": item["id"],
            "finding": public_finding(finding)}


def summary(store, item):
    with store.connect() as connection:
        row = connection.execute("SELECT payload FROM network_summaries WHERE upload_id=?", (item["id"],)).fetchone()
    if not row:
        return None
    result, _ = review(store, item)
    return {"source": item, **json.loads(row["payload"]),
            "review": {key: value for key, value in result.items() if key != "findings"}}


def page(store, upload_id, kind, offset, limit, *, protocol=None, peer=None, destination_port=None, flow_id=None, status=None):
    if kind not in ("flows", "packets"):
        raise ValueError("Unknown network view")
    table = "network_" + kind
    clauses, values = ["upload_id = ?"], [upload_id]
    if kind == "flows":
        for name, value in (("protocol", protocol), ("destination_port", destination_port)):
            if value is not None:
                clauses.append(f"{name} = ?")
                values.append(value)
        if peer is not None:
            clauses.append("(source_ip = ? OR destination_ip = ?)")
            values.extend((peer, peer))
    else:
        for name, value in (("flow_id", flow_id), ("status", status)):
            if value is not None:
                clauses.append(f"{name} = ?")
                values.append(value)
    where = " WHERE " + " AND ".join(clauses)
    order = " ORDER BY packet_count DESC, flow_id" if kind == "flows" else " ORDER BY record_index"
    with store.connect() as connection:
        connection.execute("BEGIN")
        total = connection.execute("SELECT COUNT(*) FROM " + table + where, values).fetchone()[0]
        rows = connection.execute("SELECT payload FROM " + table + where + order + " LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
    result, _ = review(store, store.get(upload_id))
    items = [json.loads(row["payload"]) for row in rows]
    for entry in items:
        entry["network_indicators"] = _tags(result, packet_index=entry["record_index"]) if kind == "packets" else _tags(result, flow_id=entry["flow_id"])
    return {"items": items, "total": total, "offset": offset,
            "limit": limit, "upload_id": upload_id,
            "order": "packet count descending, flow ID" if kind == "flows" else "original capture order"}


def _metadata(store, item):
    result, _ = review(store, item)
    return {"report_version": "network-evidence-v2", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": item, "network_summary": summary(store, item),
            "network_review": result,
            "model_ready": False, "model_version": None, "competition_use_enabled": False,
            "analysis": "Deterministic header statistics and versioned traffic-pattern indicators. No threat verdict, model inference, live capture, or remote command."}


def _records(store, upload_id, kind):
    if kind not in ("flows", "packets"):
        raise ValueError("Unknown network report kind")
    order = "flow_id" if kind == "flows" else "record_index"
    with store.connect() as connection:
        cursor = connection.execute(f"SELECT payload FROM network_{kind} WHERE upload_id=? ORDER BY {order}", (upload_id,))
        while rows := cursor.fetchmany(100):
            for row in rows:
                yield row["payload"]


def json_report(store, item):
    yield json.dumps(_metadata(store, item), ensure_ascii=True, allow_nan=False)[:-1]
    for kind in ("flows", "packets"):
        yield ',"' + kind + '":['
        first = True
        for payload in _records(store, item["id"], kind):
            yield ("" if first else ",") + payload
            first = False
        yield "]"
    yield "}\n"


def text_report(store, item):
    yield "SENTINEL / Roar Cyber | Team 84 / NETWORK HEADER REPORT\n"
    yield json.dumps(_metadata(store, item), ensure_ascii=True, indent=2) + "\n"
    for kind in ("flows", "packets"):
        yield "\n" + kind.upper() + "\n"
        for payload in _records(store, item["id"], kind):
            yield payload + "\n"
