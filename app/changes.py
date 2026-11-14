"""Read-only comparison service. Recovery returns text only; no execution path."""

from datetime import datetime, timezone
import json

from fastapi import HTTPException

from sentinel.snapshots import SnapshotResult, validate_snapshot, compare, detail, IncompatibleSnapshots
from sentinel.recovery import plan


def snapshot_summary(item, value):
    return {"source": item, "host": value.host.model_dump(), "collector": value.collector,
            "started_at_utc": value.started_at_utc.isoformat(), "ended_at_utc": value.ended_at_utc.isoformat(),
            "sections": {name: {"complete": section.complete, "scope": section.scope,
                                "notes": section.notes, "item_count": len(section.items)} for name, section in value.sections.items()}}


def snapshots(store):
    with store.connect() as connection:
        rows = connection.execute("SELECT u.*, s.payload FROM uploads u JOIN snapshots s ON u.id=s.upload_id ORDER BY created_at DESC,id DESC").fetchall()
    return {"items": [snapshot_summary({key: row[key] for key in row.keys() if key != "payload"}, validate_snapshot(json.loads(row["payload"]))) for row in rows], "total": len(rows)}


def comparison(store, baseline_id, current_id):
    pair = []
    with store.connect() as connection:
        connection.execute("BEGIN")
        for identifier in (baseline_id, current_id):
            row = connection.execute("SELECT u.*, s.payload FROM uploads u JOIN snapshots s ON u.id=s.upload_id WHERE u.id=?", (identifier,)).fetchone()
            if row is None:
                raise HTTPException(404, "Snapshot not found or expired. Refresh the snapshot list.")
            try:
                value = validate_snapshot(json.loads(row["payload"]))
            except (ValueError, OverflowError):
                raise HTTPException(503, "Stored snapshot is inconsistent. Re-import the original export.") from None
            pair.append(SnapshotResult(row["filename"], row["sha256"], row["id"], value))
    try:
        summary, entries = compare(*pair)
    except IncompatibleSnapshots as exc:
        raise HTTPException(409, str(exc)) from None
    return summary, entries, pair


def page(store, baseline_id, current_id, offset, limit, category=None, status=None):
    summary, entries, _ = comparison(store, baseline_id, current_id)
    selected = [entry for entry in entries if (category is None or entry["category"] == category) and (status is None or entry["status"] == status)]
    def preview(entry):
        return {**entry, **{key: (str(entry[key])[:200] if entry[key] is not None else None) for key in ("before", "after")},
                "preview_truncated": any(entry[key] is not None and len(str(entry[key])) > 200 for key in ("before", "after"))}
    return {"summary": summary, "items": [preview(entry) for entry in selected[offset:offset+limit]],
            "total": len(selected), "offset": offset, "limit": limit}


def change_detail(store, baseline_id, current_id, change_id, recovery=False):
    summary, entries, pair = comparison(store, baseline_id, current_id)
    entry = next((entry for entry in entries if entry["change_id"] == change_id), None)
    if entry is None:
        raise HTTPException(404, "Difference not found in this snapshot pair.")
    if recovery:
        return plan(entry, *pair, baseline_trusted=True)
    return {"comparison": summary, **detail(entry, *pair)}


def report(store, baseline_id, current_id, format):
    summary, entries, pair = comparison(store, baseline_id, current_id)
    metadata = {"report_version": "change-evidence-v1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "summary": summary, "model_ready": False, "competition_use_enabled": False,
                "execution": "No recovery command executed by Sentinel."}
    def stream():
        if format == "json":
            yield json.dumps(metadata, ensure_ascii=True)[:-1] + ',"changes":['
            for index, entry in enumerate(entries):
                yield ("," if index else "") + json.dumps(detail(entry, *pair), ensure_ascii=True, allow_nan=False)
            yield "]}\n"
        else:
            yield "SENTINEL / Roar Cyber | Team 84 / SNAPSHOT CHANGE REPORT\n" + json.dumps(metadata, indent=2, ensure_ascii=True) + "\n"
            for entry in entries:
                yield json.dumps(detail(entry, *pair), indent=2, ensure_ascii=True) + "\n"
    return stream()
