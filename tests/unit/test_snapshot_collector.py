import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import capture_snapshot as collector
from sentinel.snapshots import parse_snapshot


def test_collector_file_bytes_scope_and_private_content_are_explicit(tmp_path):
    path=tmp_path/"selected.conf"; path.write_bytes(b"Port=443\n")
    fields=collector.files([str(path)],False)[0]["values"]
    assert "text" not in fields and fields["byte_count"]==9
    assert collector.files([str(path)],True)[0]["values"]["text"]=="Port=443\n"
    assert collector.files([str(tmp_path/"absent.conf")],True)[0]["values"]=={"exists":False}


def test_failed_collection_is_unknown_not_empty_complete():
    def fail(): raise OSError("synthetic unavailable")
    section=collector.section("test-scope",fail)
    assert section["complete"] is False and section["items"]==[]


@pytest.mark.skipif(os.name!="nt",reason="Actual Windows local collector")
def test_manual_windows_collector_output_validates_without_modifying_selected_config(tmp_path):
    path=tmp_path/"selected.conf"; path.write_bytes(b"Port=443\n")
    output=tmp_path/"snapshot.json"
    result=subprocess.run([sys.executable,str(Path(collector.__file__)),"--output",str(output),"--file",str(path),"--include-text"],capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stderr
    parsed=parse_snapshot(output.read_bytes(),source_file="snapshot.json",upload_id="test")
    assert parsed.snapshot.host.platform=="windows"
    assert parsed.snapshot.sections["files"].items[0].values["text"]=="Port=443\n"
    assert parsed.snapshot.sections["firewall"].complete is False
    assert path.read_bytes()==b"Port=443\n"
    result=subprocess.run([sys.executable,str(Path(collector.__file__)),"--output",str(output)],capture_output=True,text=True,timeout=60)
    assert result.returncode==1  # Existing exports are never overwritten.
