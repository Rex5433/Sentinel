"""Streaming evidence exports; no model outputs or findings are invented."""

from datetime import datetime, timezone
import json

from sentinel.ingest.common import PARSER_VERSION
from .analysis import report_analysis


def report_metadata(item: dict, analysis: dict) -> dict:
    description = ("Deterministic authentication and host evidence review; no model inference ran."
                   if analysis["summary"]["status"] == "current" else
                   "Deterministic parsing only; no incident detection performed.")
    return {"report_version": "evidence-v2", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "parser_version": PARSER_VERSION, "model_version": None, "model_ready": False,
            "competition_use_enabled": False, "analysis": description, "baseline_analysis": analysis,
            "source": item}


def json_report(store, item):
    metadata = json.dumps(report_metadata(item, report_analysis(store, item)), ensure_ascii=True, allow_nan=False)
    yield metadata[:-1] + ',"events":['
    for kind in ("events", "rejected"):
        if kind == "rejected":
            yield '],"rejected":['
        first = True
        for record in store.iter_records(item["id"], kind):
            if not first:
                yield ","
            yield json.dumps(record, ensure_ascii=True, allow_nan=False)
            first = False
    yield "]}\n"


def text_report(store, item):
    metadata = report_metadata(item, report_analysis(store, item))
    yield "SENTINEL / Roar Cyber | Team 84 / LOCAL EVIDENCE REPORT\n"
    yield "PENDING - NO SCORED AI USE\n"
    yield metadata["analysis"] + "\n\n"
    yield json.dumps(metadata, ensure_ascii=True, indent=2) + "\n"
    for kind in ("events", "rejected"):
        yield "\n" + kind.upper() + "\n"
        for record in store.iter_records(item["id"], kind):
            yield json.dumps(record, ensure_ascii=True, indent=2) + "\n"
