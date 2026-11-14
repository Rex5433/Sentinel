"""Original synthetic inventories; no real infrastructure modification."""

from pathlib import Path
import json
import runpy

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

FIXTURES=Path(__file__).resolve().parents[1]/"fixtures"
builder=runpy.run_path(str(FIXTURES/"build_snapshot_demo.py"))
HEADERS={"Content-Type":"application/json","X-Sentinel-Import":"1"}


@pytest.fixture
def client(tmp_path,sign_in):
    with TestClient(create_app(tmp_path/"storage"),base_url="http://127.0.0.1",client=("127.0.0.1",50500)) as client:
        sign_in(client); yield client


def upload(client,value):
    response=client.post("/api/uploads?format=snapshot&filename=synthetic.json",content=json.dumps(value).encode(),headers=HEADERS)
    assert response.status_code==201,response.text
    return response.json()


def pair(client):
    a,b=builder["snapshots"](); return {"baseline_id":upload(client,a)["id"],"current_id":upload(client,b)["id"]}


def test_import_compare_evidence_line_diff_and_no_execution(client):
    params=pair(client)
    listing=client.get("/api/snapshots").json()
    assert listing["total"]==2 and listing["items"][0]["host"]["name"]=="synthetic-lab-host"
    assert "Port=443" not in json.dumps(listing)
    response=client.get("/api/changes",params={**params,"category":"files","limit":1})
    result=response.json(); assert result["total"]==2 and len(result["items"])==1
    assert result["summary"]["counts"]=={"added":1,"removed":1,"modified":5,"unverified":0}
    entries=client.get("/api/changes",params=params).json()["items"]
    config=next(entry for entry in entries if entry["field"]=="sha256")
    path=f"/api/changes/{config['change_id']}"
    evidence=client.get(path,params=params).json()
    assert "-Port=443" in evidence["text_diff"] and "+Port=4444" in evidence["text_diff"]
    assert evidence["before_evidence"]["upload_id"]==params["baseline_id"]
    rejected=client.post(path+"/recovery",params=params,json={"baseline_trusted":False},headers=HEADERS)
    assert rejected.status_code==400
    plan=client.post(path+"/recovery",params=params,json={"baseline_trusted":True},headers=HEADERS).json()
    assert plan["execution"]=="copy_only" and "sentinel-backup" in plan["script"]
    # Generating text never changes the retained source file.
    raw=client.app.state.store.blob_path(params["current_id"]).read_bytes()
    assert b"Port=4444" in raw and b"Port=443" not in raw
    assert client.get("/changes").status_code==200 and client.get("/static/changes.js").status_code==200


def test_reports_filters_unsupported_recovery_and_foreign_change(client):
    params=pair(client)
    added=client.get("/api/changes",params={**params,"status":"added"}).json()
    assert added["total"]==1
    route=f"/api/changes/{added['items'][0]['change_id']}"
    result=client.post(route+"/recovery",params=params,json={"baseline_trusted":True},headers=HEADERS).json()
    assert result["script"] is None and result["status"]=="manual_review"
    report=client.get("/api/change-report",params=params)
    assert report.status_code==200 and report.json()["report_version"]=="change-evidence-v1"
    assert len(report.json()["changes"])==7
    assert report.json()["model_ready"] is False and report.json()["competition_use_enabled"] is False
    assert "SNAPSHOT CHANGE REPORT" in client.get("/api/change-report",params={**params,"format":"text"}).text
    assert client.get("/api/changes/absent",params=params).status_code==404
    reverse={"baseline_id":params["current_id"],"current_id":params["baseline_id"]}
    assert client.get("/api/changes",params=reverse).status_code==409


def test_incomplete_scope_cannot_report_removal_and_sources_expire_cleanly(client):
    a,b=builder["snapshots"](); b["sections"]["services"]["complete"]=False
    params={"baseline_id":upload(client,a)["id"],"current_id":upload(client,b)["id"]}
    result=client.get("/api/changes",params=params).json()
    assert result["summary"]["counts"]["removed"]==0
    assert not any(entry["category"]=="services" for entry in result["items"])
    assert client.delete(f"/api/uploads/{params['baseline_id']}",headers=HEADERS).status_code==204
    assert client.get("/api/changes",params=params).status_code==404
    with client.app.state.store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]==1
        connection.execute("UPDATE uploads SET created_at='2000-01-01'")
    client.app.state.store.prune_expired()
    assert client.get("/api/snapshots").json()["total"]==0


def test_invalid_documents_limits_and_pipeline_boundaries(client):
    a,b=builder["snapshots"](); a["sections"]["files"]["items"][0]["values"]["text"]="bad hash"
    response=client.post("/api/uploads?format=snapshot&filename=bad.json",json=a,headers=HEADERS)
    assert response.status_code==400 and "bad hash" not in response.text
    assert client.post("/api/uploads?format=snapshot&filename=big.json",content=b"x"*(4*1024*1024+1),headers=HEADERS).status_code==413
    item=upload(client,b)
    for route in (f"/api/analysis/{item['id']}",f"/api/events?upload_id={item['id']}",f"/api/reports/{item['id']}"):
        assert client.get(route).status_code==400
    assert client.get("/api/timeline").json()["total"]==0
    assert client.get("/api/changes",params={"baseline_id":item["id"],"current_id":item["id"]}).status_code==409


def test_access_origin_and_recovery_body_controls(client):
    params=pair(client)
    entry=client.get("/api/changes",params=params).json()["items"][0]
    route=f"/api/changes/{entry['change_id']}/recovery"
    assert client.post(route,params=params,json={"baseline_trusted":True}).status_code==403
    assert client.post(route,params=params,json={"baseline_trusted":True,"execute":True},headers=HEADERS).status_code==400
    assert client.post(route,params=params,content=b"x"*257,headers=HEADERS).status_code==413
    assert client.get("/api/snapshots",headers={"Origin":"http://example.test"}).status_code==403
    client.cookies.clear()
    assert client.get("/api/snapshots").status_code==401
    assert client.get("/api/changes",params=params).status_code==401
    assert client.post(route,params=params,json={"baseline_trusted":True},headers=HEADERS).status_code==401
    assert client.get("/changes",follow_redirects=False).status_code==303
    assert client.get("/static/changes.html",follow_redirects=False).status_code==303
