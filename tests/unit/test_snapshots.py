from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import runpy

import pytest

from sentinel.snapshots import parse_snapshot, compare, detail, IncompatibleSnapshots
from sentinel.ingest.common import ParseInputError
from sentinel.recovery import plan

builder = runpy.run_path(str(Path(__file__).resolve().parents[1]/"fixtures/build_snapshot_demo.py"))


def parsed(value, identifier="before"):
    return parse_snapshot(json.dumps(value).encode(), source_file="synthetic.json", upload_id=identifier)


def pair(platform="linux"):
    a,b=builder["snapshots"](platform)
    return parsed(a),parsed(b,"after")


def test_hand_counted_changes_and_source_evidence_text_diff():
    a,b=pair(); summary,entries=compare(a,b)
    assert summary["counts"] == {"added":1,"removed":1,"modified":5,"unverified":0}
    assert next(c for c in summary["coverage"] if c["category"]=="firewall")["comparable"] is False
    config=next(c for c in entries if c["field"]=="sha256")
    evidence=detail(config,a,b)
    assert "-Port=443" in evidence["text_diff"] and "+Port=4444" in evidence["text_diff"]
    assert evidence["before_evidence"]["source_sha256"]==a.source_sha256
    assert evidence["after_evidence"]["json_pointer"]=="/sections/files/items/0"
    assert compare(a,b)[1]==entries


@pytest.mark.parametrize("change", ["host", "platform", "collector", "time", "same"])
def test_incompatible_observations_refused(change):
    a,b=builder["snapshots"]()
    if change=="host": b["host"]["id"]="b"*64
    if change=="platform": b["host"]["platform"]="windows"; b["sections"].pop("files")
    if change=="collector": b["collector"]="other-version"
    if change=="time": b["started_at_utc"]="2026-11-03T15:00:05Z"
    with pytest.raises(IncompatibleSnapshots): compare(parsed(a),parsed(b,"before" if change=="same" else "after"))


@pytest.mark.parametrize("case", ["incomplete","scope","missing"])
def test_missing_coverage_never_becomes_a_removed_service(case):
    a,b=builder["snapshots"]()
    if case=="incomplete": b["sections"]["services"]["complete"]=False
    if case=="scope": b["sections"]["services"]["scope"]="selected-service-only"
    if case=="missing": b["sections"].pop("services")
    summary,changes=compare(parsed(a),parsed(b,"after"))
    assert not any(c["category"]=="services" for c in changes)
    assert summary["counts"]["removed"]==0


def test_unknown_fields_are_unverified_and_lists_and_types_compare_exactly():
    a,b=builder["snapshots"](); b["sections"]["packages"]["items"][0]["values"]["version"]=None
    _,changes=compare(parsed(a),parsed(b,"after"))
    assert next(c for c in changes if c["category"]=="packages")["status"]=="unverified"
    a["sections"]["users"]["items"][0]["values"]["enabled"]=1
    _,changes=compare(parsed(a),parsed(b,"after"))
    assert any(c["category"]=="users" and c["field"]=="enabled" and c["status"]=="modified" for c in changes)


@pytest.mark.parametrize("case", ["hash","duplicate","path","nested","float","oversize","extra","surrogate","bool"])
def test_invalid_snapshots_fail_without_echoing_contents(case):
    a,_=builder["snapshots"]()
    if case=="hash": a["sections"]["files"]["items"][0]["values"]["text"]="secret-mismatch"
    if case=="duplicate": a["sections"]["users"]["items"]*=2
    if case=="path": a["sections"]["files"]["items"][0]["id"]="../sensitive.conf"
    if case=="nested": a["sections"]["users"]["items"][0]["values"]["nested"]={"a":1}
    if case=="float": a["sections"]["users"]["items"][0]["values"]["uid"]=1.5
    if case=="oversize": a["sections"]["users"]["items"][0]["values"]["note"]="x"*4097
    if case=="extra": a["execute"]="whoami"
    if case=="surrogate": a["host"]["name"]="\ud800"
    if case=="bool": a["sections"]["users"]["complete"]="true"
    with pytest.raises(ParseInputError) as error: parsed(a)
    assert "secret-mismatch" not in str(error.value)


@pytest.mark.parametrize("platform",["linux","windows"])
def test_recovery_is_explicit_copy_only_encoded_data_with_state_guards(platform):
    a,b=pair(platform); _,entries=compare(a,b)
    config=next(c for c in entries if c["field"]=="sha256")
    assert plan(config,a,b)["script"] is None
    result=plan(config,a,b,baseline_trusted=True)
    assert result["status"]=="ready_for_manual_review" and result["execution"]=="copy_only"
    assert a.snapshot.host.id in result["script"]
    assert config["before"] in result["script"] and config["after"] in result["script"]
    assert "sentinel-backup" in result["script"] and "Port=443" not in result["script"]
    service=next(c for c in entries if c["category"]=="services" and c["field"]=="start_mode")
    service_plan=plan(service,a,b,baseline_trusted=True)
    assert service_plan["status"]=="ready_for_manual_review"
    assert ("Set-Service" if platform=="windows" else "systemctl enable") in service_plan["script"]


@pytest.mark.parametrize("case",["text_missing","permissions","removed","package","executable_changed","delay"])
def test_unsupported_undo_never_guesses_a_command(case):
    a,b=builder["snapshots"]("windows")
    if case=="text_missing": a["sections"]["files"]["items"][0]["values"].pop("text")
    if case=="permissions": b["sections"]["files"]["items"][0]["values"]["acl_sddl"]="changed-acl"
    if case=="executable_changed": b["sections"]["services"]["items"][0]["values"]["binary_path"]="C:\\unexpected.exe"
    if case=="delay": a["sections"]["services"]["items"][0]["values"]["delayed_auto_start"]=None
    left,right=parsed(a),parsed(b,"after"); _,entries=compare(left,right)
    target=next(c for c in entries if c["status"]=="removed") if case=="removed" else next(c for c in entries if c["category"]=="packages") if case=="package" else next(c for c in entries if c["category"]=="services" and c["field"]=="state") if case in ("executable_changed","delay") else next(c for c in entries if c["field"]=="sha256")
    result=plan(target,left,right,baseline_trusted=True)
    assert result["script"] is None and result["status"]=="manual_review" and result["reason"]
