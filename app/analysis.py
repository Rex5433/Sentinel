"""Versioned local analysis orchestration. Only explicit operator requests run it."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from sentinel.features import FEATURE_VERSION, feature_schema, schema_hash
from sentinel.detection.rules import BASELINE_VERSION, baseline_policy, policy_hash
from sentinel.detection.auth_review import VERSION as AUTH_REVIEW_VERSION, policy as auth_policy, policy_hash as auth_policy_hash
from sentinel.detection.auth_transition import VERSION as AUTH_TRANSITION_VERSION
from sentinel.detection.linux_review import VERSION as LINUX_REVIEW_VERSION
from sentinel.detection.windows_review import VERSION as WINDOWS_REVIEW_VERSION
from sentinel.detection.windows_configuration import VERSION as WINDOWS_CONFIGURATION_VERSION
from sentinel.schemas import WindowsEventRecord, LinuxEventRecord
from .log_review import review_events, windows_checked

ROOT = Path(__file__).resolve().parents[1]
# Freeze the fingerprint at import time so an old process cannot claim new disk code.
IMPLEMENTATION_SHA256 = sha256("\n".join(
    (ROOT / path).read_text(encoding="utf-8-sig")
    for path in ("sentinel/features.py", "sentinel/detection/rules.py",
                 "sentinel/detection/windows_review.py", "sentinel/detection/linux_review.py",
                 "sentinel/detection/auth_review.py", "sentinel/detection/auth_transition.py",
                 "sentinel/detection/windows_configuration.py",
                 "app/event_activity.py", "app/endpoint_review.py", "app/log_review.py", "app/analysis.py")
).encode("utf-8")).hexdigest()
FINDING_ORDER = ("priority DESC, timestamp_utc = '', timestamp_utc, "
                 "CAST(json_extract(payload, '$.source_record_index') AS INTEGER), finding_id")


def analysis_versions() -> dict:
    return {"analysis_version": "deterministic-analysis-v8", "feature_version": FEATURE_VERSION,
            "auth_review_version": AUTH_REVIEW_VERSION, "auth_review_policy_sha256": auth_policy_hash(),
            "feature_schema_sha256": schema_hash(), "baseline_version": BASELINE_VERSION,
            "windows_review_version": WINDOWS_REVIEW_VERSION,
            "auth_transition_version": AUTH_TRANSITION_VERSION,
            "windows_configuration_version": WINDOWS_CONFIGURATION_VERSION,
            "linux_review_version": LINUX_REVIEW_VERSION,
            "baseline_policy_sha256": policy_hash(), "implementation_sha256": IMPLEMENTATION_SHA256}


class AnalysisUnavailable(ValueError):
    pass


class ImportGone(ValueError):
    pass


def normalized_events(store, upload_id):
    for payload in store.iter_records(upload_id, "events"):
        contract = WindowsEventRecord if payload.get("platform") == "windows" else LinuxEventRecord
        yield contract.model_validate(payload)


def run_analysis(store, item: dict) -> dict:
    versions = analysis_versions()
    is_linux = item["format"].startswith("linux-")
    review = review_events(normalized_events(store, item["id"]), "linux" if is_linux else "windows")
    extraction, findings = review.extraction, review.findings
    native_critical = {id for entry in findings if entry.get("severity") == "critical"
                       for id in entry["finding"]["evidence_event_ids"]}
    with store.connect() as connection:
        carried = [(id, stamp) for id, stamp in connection.execute(
            "SELECT event_id,timestamp_utc FROM captured_critical_events WHERE upload_id=? ORDER BY event_id",
            (item["id"],)) if id not in native_critical]
    if carried:
        findings.append({
            "title": "Critical evidence from managed live review", "severity": "critical",
            "rule_version": "managed-live-evidence-v1", "platform": "linux" if is_linux else "windows",
            "window_id": None, "finding": {
                "finding_id": sha256(f"managed-live-criticals:{item['id']}".encode()).hexdigest(),
                "timestamp_utc": max((stamp for _, stamp in carried if stamp), default=None),
                "activity_class": "unknown/insufficient_evidence", "triage_priority": 90,
                "evidence_event_ids": [id for id, _ in carried], "method": "deterministic",
                "explanation": "Managed SSH review flagged these records as critical. The host Timeline may contain related evidence from other batches.",
                "limitations": ["The original live review may have used evidence outside this saved batch."],
            },
        })
    windows_reviewed = review.windows_reviewed_count
    linux_results = [entry for entry in findings if entry.get("rule_version") == LINUX_REVIEW_VERSION]
    leads = [entry for entry in linux_results if entry.get("severity") == "lead"]
    context_count = sum(entry.get("severity") == "context" for entry in findings)
    cited = {event_id for entry in findings if entry.get("severity") not in {"lead", "context"}
             for event_id in entry["finding"]["evidence_event_ids"]}
    lead_only = {event_id for entry in leads for event_id in entry["finding"]["evidence_event_ids"]} - cited
    summary = {
        **versions, "upload_id": item["id"], "source_sha256": item["sha256"],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "coverage": extraction.coverage, "rejected_record_count": item["rejected_count"],
        "finding_count": len(findings), "flagged_record_count": len(cited), "windows_reviewed_count": windows_reviewed,
        "linux_finding_count": len(linux_results), "network_lead_count": len(leads),
        "network_lead_record_count": len(lead_only),
        "context_review_count": context_count,
        "method": "deterministic", "model_ready": False,
        "model_version": None, "competition_use_enabled": False,
        "assessment": "review_patterns" if findings else
                      "insufficient_evidence" if not extraction.coverage["used_records"] else "no_baseline_pattern",
        "limitations": ["Deterministic review; model inference is limited to the separate synthetic Model Lab.",
                        "No match does not establish safety; rule output is not training ground truth.",
                        "Records without host/time and rejected input cannot contribute to these windows."],
    }
    with store.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM uploads WHERE id=?", (item["id"],)).fetchone() is None:
            raise ImportGone("Import was removed during analysis.")
        connection.execute("DELETE FROM analyses WHERE upload_id=?", (item["id"],))
        connection.execute("INSERT INTO analyses VALUES (?,?)", (item["id"], json.dumps(summary, allow_nan=False)))
        connection.executemany("INSERT INTO feature_windows VALUES (?,?,?,?)", (
            (item["id"], window.window_id, window.start_utc.isoformat(timespec="microseconds"), window.model_dump_json())
            for window in extraction.windows
        ))
        connection.executemany("INSERT INTO baseline_findings VALUES (?,?,?,?,?)", (
            (item["id"], record["finding"]["finding_id"], record["finding"]["triage_priority"],
             # Keep the existing non-null sort column. The payload retains null for unknown UTC.
             record["finding"]["timestamp_utc"] or "", json.dumps(record, allow_nan=False)) for record in findings
        ))
        connection.execute("UPDATE captured_critical_events SET reviewed=1 WHERE upload_id=?", (item["id"],))
    return {**summary, "status": "current"}


def analysis_summary(store, item: dict) -> dict:
    with store.connect() as connection:
        row = connection.execute("SELECT payload FROM analyses WHERE upload_id=?", (item["id"],)).fetchone()
    if row is None:
        return {"status": "not_run", "upload_id": item["id"], "model_ready": False,
                "model_version": None, "competition_use_enabled": False, "current_versions": analysis_versions()}
    result = json.loads(row["payload"])
    current = all(result.get(name) == value for name, value in analysis_versions().items()) and result.get("source_sha256") == item["sha256"]
    return {**result, "status": "current" if current else "stale"}


def require_current(store, item: dict):
    if analysis_summary(store, item)["status"] != "current":
        raise AnalysisUnavailable("Run Analyze import before viewing these results; missing or stale analysis is not used.")


def event_review_page(store, item: dict, offset: int, limit: int) -> dict:
    return with_event_review(store, store.records(item["id"], "events", offset, limit))


def with_event_review(store, page: dict) -> dict:
    """Attach current finding severities to a page from one or more imports."""
    page.update(flagged_event_ids=[], critical_event_ids=[], network_lead_event_ids=[], windows_reviewed_event_ids=[])
    page.update(context_review_event_ids=[], reviewed_upload_ids=[])
    if not page["items"]:
        return page
    uploads = {row["upload_id"] for row in page["items"]}
    versions = analysis_versions()
    with store.connect() as connection:
        analyses = connection.execute(
            "SELECT a.upload_id, a.payload, u.sha256 FROM analyses AS a JOIN uploads AS u ON u.id=a.upload_id "
            "WHERE a.upload_id IN (SELECT value FROM json_each(?))", (json.dumps(sorted(uploads)),),
        )
        current = set()
        for upload_id, payload, digest in analyses:
            summary = json.loads(payload)
            if summary.get("source_sha256") == digest and all(summary.get(key) == value for key, value in versions.items()):
                current.add(upload_id)
        reviewed = [row for row in page["items"] if row["upload_id"] in current]
        ids = [row["event_id"] for row in reviewed]
        if not ids:
            return page
        page["reviewed_upload_ids"] = sorted(current)
        matches = connection.execute(
            "SELECT evidence.value, MAX(CASE json_extract(f.payload, '$.severity') "
            "WHEN 'critical' THEN 3 WHEN 'lead' THEN 1 WHEN 'context' THEN 0 ELSE 2 END) "
            "FROM baseline_findings AS f, "
            "json_each(f.payload, '$.finding.evidence_event_ids') AS evidence "
            "WHERE f.upload_id IN (SELECT value FROM json_each(?)) "
            "AND evidence.value IN (SELECT value FROM json_each(?)) GROUP BY evidence.value",
            (json.dumps(sorted(current)), json.dumps(ids)),
        )
        for event_id, priority in matches:
            if priority == 0:
                page["context_review_event_ids"].append(event_id)
            elif priority == 1:
                page["network_lead_event_ids"].append(event_id)
            else:
                page["flagged_event_ids"].append(event_id)
            if priority == 3:
                page["critical_event_ids"].append(event_id)
    page["windows_reviewed_event_ids"] = [row["event_id"] for row in reviewed
                                         if row["platform"] == "windows" and windows_checked(WindowsEventRecord.model_validate(row))]
    return page


def analysis_page(store, item: dict, kind: str, offset: int, limit: int) -> dict:
    require_current(store, item)
    if kind == "features":
        table, order = "feature_windows", "start_utc, window_id"
    elif kind == "findings":
        table, order = "baseline_findings", FINDING_ORDER
    else:
        raise ValueError("unknown analysis record kind")
    with store.connect() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM {table} WHERE upload_id=?", (item["id"],)).fetchone()[0]
        rows = connection.execute(f"SELECT payload FROM {table} WHERE upload_id=? ORDER BY {order} LIMIT ? OFFSET ?",
                                  (item["id"], limit, offset)).fetchall()
        values = [json.loads(row["payload"]) for row in rows]
        if kind == "findings" and values:
            ids = [record["finding"]["finding_id"] for record in values]
            notes = connection.execute(
                "SELECT finding_id,note,username,updated_at FROM finding_maintenance_notes "
                "WHERE upload_id=? AND finding_id IN (SELECT value FROM json_each(?))",
                (item["id"], json.dumps(ids)),
            )
            by_id = {row["finding_id"]: {key: row[key] for key in ("note", "username", "updated_at")} for row in notes}
            for record in values:
                record["maintenance_note"] = by_id.get(record["finding"]["finding_id"])
    for index, record in enumerate(values):
        if kind == "features":
            from sentinel.features import FeatureWindow
            values[index] = FeatureWindow.model_validate(record).summary()
        else:
            finding = record["finding"]
            ids = finding.pop("evidence_event_ids")
            finding.update(evidence_count=len(ids), evidence_preview_ids=ids[:5])
    return {"items": values, "total": total, "offset": offset, "limit": limit, "upload_id": item["id"]}


def analysis_detail(store, item: dict, kind: str, record_id: str) -> dict | None:
    require_current(store, item)
    if kind not in ("features", "findings"):
        raise ValueError("unknown analysis record kind")
    table, field = ("feature_windows", "window_id") if kind == "features" else ("baseline_findings", "finding_id")
    with store.connect() as connection:
        row = connection.execute(f"SELECT payload FROM {table} WHERE upload_id=? AND {field}=?", (item["id"], record_id)).fetchone()
    return json.loads(row["payload"]) if row else None


def update_maintenance_note(store, item: dict, finding_id: str, username: str, note: str | None) -> bool:
    require_current(store, item)
    key = item["id"], finding_id
    with store.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM baseline_findings WHERE upload_id=? AND finding_id=?", key,
        ).fetchone() is None:
            return False
        if note is None:
            connection.execute("DELETE FROM finding_maintenance_notes WHERE upload_id=? AND finding_id=?", key)
        else:
            connection.execute(
                "INSERT INTO finding_maintenance_notes VALUES (?,?,?,?,?) "
                "ON CONFLICT(upload_id,finding_id) DO UPDATE SET "
                "note=excluded.note, username=excluded.username, updated_at=excluded.updated_at",
                (*key, note, username, datetime.now(timezone.utc).isoformat()),
            )
    return True


def finding_evidence(store, item: dict, finding_id: str, offset: int, limit: int) -> dict | None:
    detail = analysis_detail(store, item, "findings", finding_id)
    if detail is None:
        return None
    ids = detail["finding"]["evidence_event_ids"]
    page_ids = ids[offset:offset + limit]
    records = {}
    if page_ids:
        with store.connect() as connection:
            rows = connection.execute(
                "SELECT event_id,payload FROM events WHERE upload_id=? AND event_id IN (" + ",".join("?" for _ in page_ids) + ")",
                (item["id"], *page_ids),
            ).fetchall()
        records = {row["event_id"]: json.loads(row["payload"]) for row in rows}
        if len(records) != len(page_ids):
            raise AnalysisUnavailable("Stored evidence references no longer match. Re-import the original export.")
    return {"items": [records[event_id] for event_id in page_ids], "total": len(ids),
            "offset": offset, "limit": limit, "upload_id": item["id"], "finding_id": finding_id}


def report_analysis(store, item: dict) -> dict:
    summary = analysis_summary(store, item)
    if summary["status"] != "current":
        return {"summary": summary, "findings": [], "feature_windows": []}
    with store.connect() as connection:
        findings = [json.loads(row["payload"]) for row in connection.execute(
            f"SELECT payload FROM baseline_findings WHERE upload_id=? ORDER BY {FINDING_ORDER}", (item["id"],))]
        windows = [json.loads(row["payload"]) for row in connection.execute(
            "SELECT payload FROM feature_windows WHERE upload_id=? ORDER BY start_utc, window_id", (item["id"],))]
    return {"summary": summary, "findings": findings, "feature_windows": windows,
            "feature_schema": feature_schema(), "baseline_policy": baseline_policy(), "auth_review_policy": auth_policy()}
