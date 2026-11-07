"""Local capture-to-review adapter for Windows and Linux log exports."""
from collections import defaultdict

from sentinel.detection.activity_adjudication import postprocess
from sentinel.detection.context_verification_v2 import verify_series
from sentinel.detection.review_queue import build_review_queue
from sentinel.features import FEATURE_VERSION, extract_features, schema_hash
from sentinel.ingest.linux import parse_linux
from sentinel.ingest.windows import parse_windows

FORMATS = {
    "windows-json": ("windows", "json", parse_windows),
    "windows-csv": ("windows", "csv", parse_windows),
    "linux-text": ("linux", "text", parse_linux),
    "linux-journal-json": ("linux", "journal-json", parse_linux),
}


def review_capture(raw, fmt, capture_id, source_file, score_segment, *, collection_complete=False, confirmations=()):
    """Parse, score causal segments, verify evidence and build a local queue."""
    platform, parser_format, parse = FORMATS[fmt]
    parsed = parse(raw, file_format=parser_format, source_file=source_file, upload_id=capture_id)
    extraction = extract_features(parsed.events)
    coverage = dict(rejected_records=len(parsed.rejected), missing_host=sum(event.host is None for event in parsed.events),
                    missing_timestamp=sum(event.timestamp_utc is None for event in parsed.events),
                    excluded_records=extraction.coverage["excluded_records"])
    source_complete = collection_complete is True and not any(coverage.values())
    by_host = defaultdict(list)
    for window in extraction.windows:
        by_host[window.host].append(window)

    def entry(host, start, window=None, history=0):
        members = extraction.members[window.window_id] if window else ()
        quality = dict(coverage, collection_complete=bool(window and source_complete and not window.quality["warning_event_count"]),
                       unrecognized_events=sum(event.event_type is None for event in members))
        return dict(source=capture_id, platform=platform, host=host, start_utc=start,
                    window_id=window.window_id if window else None, vector=window.vector if window else None,
                    event_ids=window.event_ids if window else [], coverage=quality, history_windows=history,
                    prediction=None, scores=None)

    rows, segments = [], []
    for host, windows in by_host.items():
        previous = None
        segment = []
        for window in windows:
            if previous is not None and previous.end_utc != window.start_utc:
                segments.append(segment)
                segment = []
                gap = entry(host, previous.end_utc.isoformat())
                gap["gap_end_utc"] = window.start_utc.isoformat()
                rows.append(gap)
            row = entry(host, window.start_utc.isoformat(), window, min(4, len(segment)))
            rows.append(row)
            segment.append(row)
            previous = window
        segments.append(segment)
    if not rows:
        rows.append(entry(None, None))

    for segment in segments:
        scores = score_segment([row["vector"] for row in segment])
        for row, probabilities in zip(segment, scores, strict=True):
            row["scores"] = probabilities
            row["prediction"] = max(range(4), key=probabilities.__getitem__)

    inputs = [dict(platform=platform, host=row["host"], session_id=capture_id, start_utc=row["start_utc"],
                   verification=dict(vector=row["vector"], model_class=row["prediction"], probabilities=row["scores"],
                       coverage=row["coverage"], history_windows=row["history_windows"], feature_version=FEATURE_VERSION,
                       feature_schema_sha256=schema_hash(), evidence_ids=row["event_ids"])) for row in rows]
    for row, result in zip(rows, verify_series(inputs), strict=True):
        row["combined"] = dict(result, reasons=[reason["code"] for reason in result["reasons"]])
    for row, result in zip(rows, postprocess(rows, extraction), strict=True):
        row["post"] = result
    queue = build_review_queue(rows, {capture_id: parsed.source_sha256}, confirmations)
    return dict(capture_id=capture_id, source_sha256=parsed.source_sha256, format=fmt,
                accepted_records=len(parsed.events), rejected_records=len(parsed.rejected), rows=rows, queue=queue)
