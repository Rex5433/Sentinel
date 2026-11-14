"""Resolve file and pasted-log formats before dispatching to the evidence parsers."""

import csv
from io import StringIO
from pathlib import Path

from sentinel.ingest.common import ParseInputError, bounded, load_json, prepare, text_records
from sentinel.ingest.windows_jsonl import WINDOWS_FIELDS
from sentinel.ingest.pcap import MAGIC

EXTENSION_FORMATS = {".csv": "windows-csv", ".txt": "linux-text", ".log": "linux-text", ".pcap": "pcap"}
JSON_EXTENSIONS = {".json", ".jsonl", ".ndjson"}
FILE_EXTENSIONS = {*EXTENSION_FORMATS, *JSON_EXTENSIONS, ".bin"}
JOURNAL_FIELDS = frozenset({"MESSAGE", "__REALTIME_TIMESTAMP", "_HOSTNAME", "SYSLOG_IDENTIFIER", "_COMM"})


def _platform(value):
    if isinstance(value, dict):
        windows = bool(WINDOWS_FIELDS.intersection(value))
        linux = bool(JOURNAL_FIELDS.intersection(value))
        if windows != linux:
            return "windows" if windows else "linux"
    return None


def _detect_json(text, *, lines_only=False, platform=None):
    if not lines_only and platform != "linux":
        if text.lstrip().startswith("["):
            return "windows-json"
        try:
            document = load_json(text)
        except (ValueError, RecursionError):
            pass
        else:
            if _platform(document) == "windows":
                return "windows-json"
    for _, line in bounded(text_records(text)):
        try:
            record = load_json(line)
        except (ValueError, RecursionError):
            continue
        detected = _platform(record)
        if detected and (platform is None or detected == platform):
            return "windows-jsonl" if detected == "windows" else "linux-journal-json"
    if platform:
        raise ParseInputError(f"No supported {platform.title()} event objects found. Check the selected log system and export format.")
    raise ParseInputError("No supported Windows event or Linux journal JSON objects found. Check the export format.")


def detect_format(data, filename, upload_id, platform=None):
    suffix = Path(filename).suffix.lower()
    if platform is None and suffix in EXTENSION_FORMATS:
        return EXTENSION_FORMATS[suffix]
    if platform is None and suffix == ".bin" and data[:4] in MAGIC:
        return "pcap"
    text, _ = prepare(data, filename, upload_id, "auto")
    if not text.strip():
        raise ParseInputError("The export contains no records.")
    if platform and not text.lstrip().startswith(("{", "[")):
        return "windows-csv" if platform == "windows" else "linux-text"
    if suffix == ".bin" and not text.lstrip().startswith(("{", "[")):
        try:
            header = next(csv.reader(StringIO(text)), [])
        except csv.Error:
            header = []
        return "windows-csv" if len(header) > 1 and WINDOWS_FIELDS.intersection(header) else "linux-text"
    return _detect_json(text, lines_only=suffix in {".jsonl", ".ndjson"}, platform=platform)
