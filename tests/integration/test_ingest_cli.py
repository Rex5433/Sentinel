import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("fmt,file,code,count", [
    ("windows-json", "windows_events.json", 0, 5),
    ("windows-csv", "windows_events.csv", 0, 2),
    ("linux-text", "linux_auth.txt", 1, 7),
    ("linux-journal-json", "linux_journal.jsonl", 0, 3),
])
def test_cli_parses_each_supported_format(fmt, file, code, count):
    process = subprocess.run(
        [sys.executable, "-m", "sentinel.ingest", fmt, str(ROOT / "tests" / "fixtures" / file),
         "--upload-id", "synthetic-cli-test"],
        cwd=ROOT, capture_output=True, text=True, timeout=15,
    )
    assert process.returncode == code, process.stderr
    result = json.loads(process.stdout)
    assert result["accepted_count"] == count
    assert result["source_file"] == file
    assert result["upload_id"] == "synthetic-cli-test"
    assert result["parser_version"] == "exports-v2"


def test_cli_fatal_input_has_nonzero_status_and_no_partial_json(tmp_path):
    source = tmp_path / "bad.json"
    source.write_text('{"Id":')
    process = subprocess.run(
        [sys.executable, "-m", "sentinel.ingest", "windows-json", str(source), "--upload-id", "demo"],
        cwd=ROOT, capture_output=True, text=True, timeout=15,
    )
    assert process.returncode == 2 and process.stdout == ""
    assert "invalid JSON document" in process.stderr
    assert str(source) not in process.stderr
