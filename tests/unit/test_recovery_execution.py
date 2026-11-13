"""Execute generated file recovery only against disposable local test files.

Never execute generated service controls or touch actual configuration paths.
"""

import os
from pathlib import Path
import json
import runpy
import subprocess
import shutil
from base64 import b64encode

import pytest

from scripts import capture_snapshot as collector
from sentinel.snapshots import parse_snapshot, compare
from sentinel.recovery import plan

builder=runpy.run_path(str(Path(__file__).resolve().parents[1]/"fixtures/build_snapshot_demo.py"))


@pytest.mark.skipif(os.name!="nt",reason="Actual Windows file restore in disposable tmp only")
@pytest.mark.parametrize("case",["restore","stale","wrong_host"])
@pytest.mark.parametrize("shell",["desktop","core"])
def test_generated_windows_file_restore_and_guards(tmp_path,case,shell):
    if shell=="core" and not shutil.which("pwsh"):
        pytest.skip("PowerShell Core unavailable")
    def execute(script):
        if shell=="desktop": return collector.powershell(script)
        return subprocess.run([shutil.which("pwsh"),"-NoProfile","-NonInteractive","-EncodedCommand",b64encode(script.encode("utf-16-le")).decode()],capture_output=True,timeout=30,check=True)
    target=tmp_path/"safe' demo.conf"
    current="Port=4444\n"
    target.write_text(current,encoding="utf-8",newline="")
    current_fields=collector.files([str(target)],True)[0]["values"]
    original="Port=443\nLiteral=$(Write-Output never-executed)\nUnicode=café\n"
    a,b=builder["snapshots"]("windows")
    for snapshot in (a,b): snapshot["host"]["id"]=collector.host_id()
    if case=="wrong_host":
        a["host"]["id"]=b["host"]["id"]="b"*64
    a["sections"]["files"]["items"]=[{"id":str(target),"values":builder["file_values"](original,"windows",current_fields["acl_sddl"])}]
    b["sections"]["files"]["items"]=[{"id":str(target),"values":current_fields}]
    before=parse_snapshot(json.dumps(a).encode(),source_file="test.json",upload_id="before")
    after=parse_snapshot(json.dumps(b).encode(),source_file="test.json",upload_id="after")
    _,entries=compare(before,after)
    entry=next(entry for entry in entries if entry["category"]=="files" and entry["field"]=="sha256")
    recovery=plan(entry,before,after,baseline_trusted=True)
    assert recovery["status"]=="ready_for_manual_review"
    if case=="stale": target.write_text("changed again",encoding="utf-8")
    if case=="restore":
        try:
            execute(recovery["script"])
        except subprocess.CalledProcessError as error:
            pytest.fail("Disposable restore failed: "+error.stderr.decode(errors="replace"))
        assert target.read_bytes()==original.encode("utf-8")
        backups=list(tmp_path.glob("*.sentinel-backup-*"))
        assert len(backups)==1 and backups[0].read_bytes()==current.encode()
        assert collector.files([str(target)],False)[0]["values"]["acl_sddl"]==current_fields["acl_sddl"]
    else:
        with pytest.raises(subprocess.CalledProcessError): execute(recovery["script"])
        assert target.read_text()==("changed again" if case=="stale" else current)
        assert not list(tmp_path.glob("*.sentinel-backup-*"))
    assert not list(tmp_path.glob("*.sentinel-temp-*"))
