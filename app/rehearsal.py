"""Authenticated rehearsal on pinned synthetic exports in the local evidence store."""
import asyncio
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
from time import perf_counter
from typing import Annotated
from uuid import uuid4

from fastapi import HTTPException, Path as PathParameter, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import Field, ValidationError
from starlette.concurrency import run_in_threadpool

from sentinel.detection.offline_review import review_capture
from sentinel.detection.review_queue import TeamConfirmation, build_review_queue
from sentinel.ingest import parse_windows
from sentinel.ingest.common import MAX_INPUT_BYTES, ParseInputError
from sentinel.schemas import Contract, Sha256
from .db import StorageFull

LEDGER = Path(__file__).resolve().parents[1] / "data/private/activity-adjudication-b2f6ee21ec0f/sources.json"
LEDGER_SHA256 = "be61377c3450664e5c6a63a90fee228744512fd5ad29bf7a54315fdfb48b6021"
CHECKPOINT_SHA256 = "7ce72c9852d3e4d25e5dd57737ebe7d45912ea3fd454317e16652834ad1ba465"
SAMPLE_PATH = LEDGER.parent / "holdout-0048.raw"
SAMPLE_FILENAME = "synthetic-maintenance.json"
UploadId = Annotated[str, PathParameter(pattern=r"^[a-f0-9]{32}$")]


class ConfirmationRequest(Contract):
    item_id: Sha256
    reference: str = Field(min_length=1, max_length=256)


@lru_cache(maxsize=1)
def synthetic_exports():
    try:
        raw = LEDGER.read_bytes()
    except OSError as exc:
        raise HTTPException(503, "Pinned synthetic export list is unavailable.") from exc
    if sha256(raw).hexdigest() != LEDGER_SHA256:
        raise HTTPException(503, "Pinned synthetic export list failed its integrity check.")
    return frozenset((row["format"], row["raw_sha256"]) for row in json.loads(raw))


@lru_cache(maxsize=1)
def load_rehearsal_model():
    try:
        from scripts.preview_review_queue import scorer
        score, checkpoint = scorer()
        if checkpoint != CHECKPOINT_SHA256:
            raise ValueError("Unexpected checkpoint")
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, "Pinned rehearsal model is unavailable or failed verification.") from exc
    return score


def sample_bytes():
    try:
        raw = SAMPLE_PATH.read_bytes()
    except OSError as exc:
        raise HTTPException(503, "The pinned model test sample is unavailable.") from exc
    if len(raw) > MAX_INPUT_BYTES or ("windows-json", sha256(raw).hexdigest()) not in synthetic_exports():
        raise HTTPException(503, "The model test sample failed its integrity check.")
    return raw


def register_rehearsal(application, store):
    def capture(upload_id):
        item = store.get(upload_id)
        if item is None:
            raise HTTPException(404, "Import not found.")
        if (item["format"], item["sha256"]) not in synthetic_exports():
            raise HTTPException(409, "Rehearsal accepts only the pinned synthetic exports.")
        return item

    def saved(connection, upload_id):
        row = connection.execute("SELECT payload, confirmations FROM rehearsal_reviews WHERE upload_id=?", (upload_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Run rehearsal analysis for this import first.")
        return json.loads(row["payload"]), json.loads(row["confirmations"])

    def view(report, confirmations):
        approvals = [TeamConfirmation.model_validate(entry["confirmation"]) for entry in confirmations]
        return build_review_queue(report["rows"], {report["capture_id"]: report["source_sha256"]}, approvals)

    def analyze(upload_id):
        item = capture(upload_id)
        with store.connect() as connection:
            existing = connection.execute("SELECT payload FROM rehearsal_reviews WHERE upload_id=?", (upload_id,)).fetchone()
        if existing:
            return {"cached": True, "analysis_ms": json.loads(existing["payload"])["analysis_ms"]}
        start = perf_counter()
        with store.blob_path(upload_id).open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES or sha256(raw).hexdigest() != item["sha256"]:
            raise HTTPException(409, "Stored capture failed its integrity check.")
        try:
            report = review_capture(raw, item["format"], upload_id, item["filename"], load_rehearsal_model(), collection_complete=True)
        except ParseInputError as exc:
            raise HTTPException(409, "The pinned export could not be parsed.") from exc
        report.pop("queue")
        report.update(checkpoint_sha256=CHECKPOINT_SHA256, analysis_ms=round((perf_counter() - start) * 1000, 1))
        with store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM uploads WHERE id=?", (upload_id,)).fetchone() is None:
                raise HTTPException(404, "Import was removed during analysis.")
            connection.execute("INSERT OR IGNORE INTO rehearsal_reviews VALUES (?, ?, '[]')",
                               (upload_id, json.dumps(report, allow_nan=False)))
        return {"cached": False, "analysis_ms": report["analysis_ms"]}

    @application.get("/rehearsal", response_class=RedirectResponse)
    @application.get("/static/rehearsal.html", response_class=RedirectResponse)
    def rehearsal_page():
        return RedirectResponse("/", status_code=303)

    @application.get("/api/rehearsal/imports")
    def rehearsal_imports():
        permitted = synthetic_exports()
        return {"items": [item for item in store.uploads(0, 25)["items"] if (item["format"], item["sha256"]) in permitted]}

    def import_sample():
        raw = sample_bytes()
        digest = sha256(raw).hexdigest()
        for item in store.uploads(0, 25)["items"]:
            if item["format"] == "windows-json" and item["sha256"] == digest:
                return item
        try:
            parsed = parse_windows(raw, file_format="json", source_file=SAMPLE_FILENAME, upload_id=uuid4().hex)
            return store.save(raw, parsed)
        except (StorageFull, ParseInputError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @application.post("/api/rehearsal/sample")
    async def rehearsal_sample():
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or analysis is in progress.")
        async with application.state.import_lock:
            return await run_in_threadpool(import_sample)

    @application.post("/api/rehearsal/{upload_id}/analysis")
    async def rehearsal_analyze(upload_id: UploadId):
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or analysis is in progress.")
        async with application.state.import_lock:
            return await run_in_threadpool(analyze, upload_id)

    @application.get("/api/rehearsal/{upload_id}/queue")
    def rehearsal_queue(upload_id: UploadId):
        capture(upload_id)
        with store.connect() as connection:
            report, confirmations = saved(connection, upload_id)
        return {"queue": view(report, confirmations), "analysis_ms": report["analysis_ms"], "confirmation_history": confirmations}

    @application.get("/api/rehearsal/{upload_id}/items/{item_id}/events")
    def rehearsal_events(upload_id: UploadId, item_id: str, offset: Annotated[int, Query(ge=0)] = 0):
        def records(connection, references):
            rows = connection.execute(
                "SELECT events.payload FROM json_each(?) AS ref JOIN events ON events.event_id=ref.value "
                "WHERE events.upload_id=? ORDER BY ref.key", (json.dumps(references), upload_id)).fetchall()
            return [json.loads(row["payload"]) for row in rows]

        capture(upload_id)
        with store.connect() as connection:
            report, confirmations = saved(connection, upload_id)
            item = next((entry for entry in view(report, confirmations)["items"] if entry["item_id"] == item_id), None)
            if item is None:
                raise HTTPException(404, "Review item not found in this capture.")
            references = list(dict.fromkeys(event_id for window in item["windows"] for event_id in window["evidence_ids"]))
            actions = item["windows"][0]["activity_evidence_ids"] if item["kind"] == "finding" else []
            action_records = records(connection, actions)
            evidence = records(connection, references[offset:offset+25])
        return {"items": evidence, "offset": offset, "total": len(references),
                "action_records": action_records if len(action_records) == len(actions) else []}

    def record_confirmation(upload_id, requested, reviewer):
        item = capture(upload_id)
        with store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            report, confirmations = saved(connection, upload_id)
            finding = next((entry for entry in view(report, confirmations)["items"]
                            if entry["item_id"] == requested.item_id and entry["kind"] == "finding"), None)
            if finding is None or not finding["windows"][0]["activity_evidence_ids"]:
                raise HTTPException(409, "The active finding has no confirmable action evidence.")
            window = finding["windows"][0]
            evidence = window["activity_evidence_ids"]
            available = connection.execute("SELECT COUNT(DISTINCT event_id) FROM events WHERE upload_id=? "
                "AND event_id IN (SELECT value FROM json_each(?))", (upload_id, json.dumps(evidence))).fetchone()[0]
            if available != len(evidence):
                raise HTTPException(409, "Original action records are unavailable. The finding stays active.")
            confirmation = TeamConfirmation(capture_sha256=item["sha256"], window_id=window["window_id"],
                evidence_ids=evidence, reviewer=reviewer, reference=requested.reference)
            entry = {"confirmation": confirmation.model_dump(mode="json"), "recorded_utc": datetime.now(timezone.utc).isoformat()}
            updated = view(report, [*confirmations, entry])
            if confirmation.window_id in updated["unmatched_confirmations"]:
                raise HTTPException(409, "The finding has additional signals or uncertainty and stays active.")
            confirmations.append(entry)
            connection.execute("UPDATE rehearsal_reviews SET confirmations=? WHERE upload_id=?",
                               (json.dumps(confirmations, allow_nan=False), upload_id))
        return {"queue": updated, "analysis_ms": report["analysis_ms"], "confirmation_history": confirmations}

    @application.post("/api/rehearsal/{upload_id}/confirmations")
    async def rehearse_confirmation(upload_id: UploadId, request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Confirmation requires JSON.")
        data = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(data) + len(chunk) > 2048:
                        raise HTTPException(413, "Confirmation is too large.")
                    data.extend(chunk)
        except TimeoutError as exc:
            raise HTTPException(408, "Confirmation timed out.") from exc
        try:
            confirmation = ConfirmationRequest.model_validate_json(data)
            confirmation.reference = confirmation.reference.strip()
            if not confirmation.reference:
                raise ValueError("Blank reference")
        except (ValidationError, ValueError) as exc:
            raise HTTPException(400, "Enter a valid finding and change reference.") from exc
        return await run_in_threadpool(record_confirmation, upload_id, confirmation, request.state.user["username"])
