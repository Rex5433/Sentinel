"""Original V5 synthetic candidate preparation. No model imports or training."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import csv
import io
import ipaddress
import json
from pathlib import Path
import random
import uuid

from sentinel.features import FEATURE_VERSION, canonical_hash, extract_features, schema_hash
from sentinel.ingest import parse_linux, parse_windows
from sentinel.ingest.common import PARSER_VERSION
from training.experiment_data import ROOT, hashfile
from training.label_contract import CLASS_ORDER, LABEL_VERSION, WindowAnnotation
from training.mixed_candidate import activity_categories, reference_vector

VERSION = "team-diverse-v5.0"
CADENCES = ("uniform", "early_cluster", "two_clusters", "stratified", "late_cluster", "alternating_edges")
IDENTITIES = ("shared_terminal", "rotating_users", "shared_gateway", "roaming_clients")
FAMILIES = tuple(f"{cadence}/{identity}" for cadence in CADENCES for identity in IDENTITIES)
REPLICATES = tuple(range(8))
AUTH_STYLES = ("concentrated", "five_single_failures", "distributed_pairs", "distributed_with_quiet")
LOAD_BINS = ((1, 3), (4, 9), (10, 24), (25, 59), (60, 119), (120, 249), (250, 499), (500, 850))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def split_for(family):
    if family not in range(len(FAMILIES)):
        raise ValueError("Unsupported family")
    return "train" if family < 16 else "validation" if family < 20 else "test"


def _auth_count(style, i):
    return (7 + i % 7 if style == "concentrated" else 1 if style == "five_single_failures"
            else (2, 1, 2)[i % 3] if style == "distributed_pairs" else (2, 0, 1, 0, 2)[i % 5])


def plan(family, replicate, platform):
    if family not in range(24) or replicate not in REPLICATES or platform not in ("windows", "linux"):
        raise ValueError("Unsupported recipe")
    seed = 8_450_000 + family * 1009 + replicate * 100_003
    rng = random.Random(f"{VERSION}/{seed}/{platform}")
    group = f"v5-f{family:02d}-r{replicate:02d}"
    host = f"original-{platform}-{seed}"
    start = datetime(2026, 2, 1, tzinfo=timezone.utc) + timedelta(days=family * 8 + replicate)
    cadence, identity = family // 4, family % 4
    auth_style = AUTH_STYLES[replicate % 4]
    loads = [rng.randint(*bounds) for bounds in LOAD_BINS]
    rng.shuffle(loads)  # Identical load distribution across all four primary classes.
    order = list(range(4)); rng.shuffle(order)
    events, slots = [], []
    service_state = {}

    def add(slot, kind):
        index = len(events) + 1
        if cadence == 0:
            delta = rng.randrange(300_000_000)
        elif cadence == 1:
            delta = rng.randrange(35_000_000) if rng.random() < .8 else rng.randrange(300_000_000)
        elif cadence == 2:
            delta = rng.randrange(25_000_000) + rng.choice((0, 270_000_000))
        elif cadence == 3:
            delta = (index * 7_919_119 + rng.randrange(100_000)) % 300_000_000
        elif cadence == 4:
            delta = rng.randrange(265_000_000, 300_000_000) if rng.random() < .8 else rng.randrange(300_000_000)
        else:
            delta = rng.randrange(3_000_000) + (297_000_000 if index % 2 else 0)
        actor_number = (rng.randrange(2), index % (5 + replicate), rng.randrange(2 + replicate * 2), index % 3)[identity]
        ip_number = (rng.randrange(2 + replicate), index % 7, 0, rng.randrange(3 + replicate * 3))[identity]
        actor = f"member{actor_number}"
        ip = f"2001:db8:{family:x}::{ip_number+1}" if replicate % 2 else f"198.51.{family+1}.{ip_number+10}"
        ip = str(ipaddress.ip_address(ip))
        name = f"created_{seed}_{index}"
        service = f"newsvc_{seed}_{index}" if kind == "install" else f"existing{index%3}"
        running = service_state.get(service, False)
        if kind == "service": service_state[service] = not running
        emitter = "sshd-session" if replicate % 3 == 1 else "sshd"
        code = {"success": 4624, "failure": 4625, "close": 4634, "privilege": 4672,
                "account": 4720, "install": 4697 if replicate % 2 else 7045, "service": 7036,
                "unknown": 4732}.get(kind)
        event_type = {"success":"auth_success", "failure":"auth_failure", "close":"session_close",
                      "open":"session_open", "privilege":"privilege_assigned" if platform=="windows" else "sudo_command",
                      "account":"account_created", "install":"service_installed" if platform=="windows" else "service_activity",
                      "service":"service_state_change" if platform=="windows" else "service_activity"}.get(kind)
        fact_actor = actor if kind in ("success", "failure", "close", "open", "privilege") or (platform=="windows" and kind=="account") else None
        target = (name if kind=="account" else service if kind=="install" and platform=="windows"
                  else actor if platform=="windows" and kind in ("success", "failure", "close")
                  else emitter if platform=="linux" and kind in ("success", "failure", "close", "open")
                  else "root" if platform=="linux" and kind=="privilege" else None)
        events.append(dict(record_index=index, slot=slot, kind=kind, code=code, actor=actor, ip=ip,
            account=name, service=service, running=running, emitter=emitter,
            timestamp=(start+timedelta(seconds=slot*300,microseconds=delta)).isoformat(),
            event_type=event_type, normalized_actor=fact_actor, target=target,
            source_ip=ip if kind in ("success","failure") else None))

    for block, mode in enumerate(order):
        failures = []
        primary_candidates = []
        for within in range(20):
            nfail = _auth_count(auth_style, within-4) if mode==1 and within>=4 else 0
            failures.append(nfail)
            if within>=4 and (mode!=1 or nfail>=5 or (nfail>0 and sum(failures[-5:])>=5 and sum(n>0 for n in failures[-5:])>=2)):
                primary_candidates.append(within)
        if len(primary_candidates)<8: raise ValueError("Insufficient planned activity support")
        chosen = sorted(rng.sample(primary_candidates,8))
        load_by_slot = dict(zip(chosen, loads, strict=True))
        prior_failures = []
        for within in range(20):
            slot = block*20+within
            primary = within in chosen
            load = load_by_slot.get(within, rng.randint(1,40))
            background = ["success","close","privilege"] + (["open"] if platform=="linux" else [])
            weights = (12,3,1,2) if platform=="linux" else (12,3,1)
            for _ in range(load): add(slot,rng.choices(background,weights=weights)[0])
            if mode==0 and within>=4:
                # Difficult benign attempts: total stays below five in every causal input.
                room = max(0,4-sum(prior_failures[-4:]))
                nfail = min(room, rng.choice((0,1,2,4)))
            else:
                nfail = failures[within]
            prior_failures.append(nfail)
            for _ in range(nfail): add(slot,"failure")
            if within>=4 and mode in (2,3):
                number = 1 if replicate%2==0 else rng.choice((1,1,2,3,7))
                for _ in range(number): add(slot,"account" if mode==2 else rng.choice(("service","install")))
            slots.append(dict(slot=slot,phase="activity" if within>=4 else "context",primary=primary,
                planned_class=mode if primary else None,background_events=load,
                authorization="authorized" if (replicate+block)%2==0 else "simulated_unapproved",
                invisible=False))
    for slot in range(80,96):
        if slot==88: continue  # Explicit missing interval, never zero-filled.
        load=rng.randint(1,35)
        for _ in range(load): add(slot,"success")
        if slot==80:
            add(slot,"account")
            for _ in range(6): add(slot,"failure")
        if slot==81: add(slot,"account"); add(slot,"service")
        if slot==82: add(slot,"unknown")
        slots.append(dict(slot=slot,phase="quality_challenge",primary=False,planned_class=None,
            background_events=load,authorization="simulated_unapproved" if slot in (80,81,82,87) else "authorized",
            invisible=slot==87))
    # File order follows actual timestamps; facts refer to exact source positions.
    events.sort(key=lambda row:row["timestamp"])
    for i,row in enumerate(events,1): row["record_index"]=i
    return dict(version=VERSION,group=group,family=FAMILIES[family],family_index=family,seed=seed,
        replicate=replicate,platform=platform,host=host,split=split_for(family),auth_style=auth_style,
        offset_minutes=(0,330,-360,60,345,-210,120,-300)[replicate],start=start.isoformat(),
        missing_slots=[88],slots=slots,events=events,
        origin="Original team-generated Codex-assisted synthetic; no public telemetry or field truth")


def render(side, format):
    platform=side["platform"]
    if format not in (("windows-json","windows-csv") if platform=="windows" else ("linux-text","linux-journal-json")):
        raise ValueError("Format/platform mismatch")
    rows=[]
    for event in side["events"]:
        e=event;kind=e["kind"]
        stamp=datetime.fromisoformat(e["timestamp"]).astimezone(timezone(timedelta(minutes=side["offset_minutes"]))).isoformat()
        if platform=="windows":
            fields=({"SubjectUserName":e["actor"],"TargetUserName":e["account"]} if kind=="account"
                    else {"ServiceName":e["service"]} if kind in ("service","install")
                    else {"SubjectUserName":e["actor"]} if kind=="privilege"
                    else {"TargetUserName":e["actor"]} if kind in ("success","failure","close") else {})
            if kind in ("success","failure"): fields["IpAddress"]=e["ip"]
            system=e["code"] in (7036,7045)
            row=dict(EventID=e["code"],Timestamp=stamp,Computer=side["host"],RecordId=e["record_index"],
                Channel="System" if system else "Security",
                Provider="Service Control Manager" if system else "Microsoft-Windows-Security-Auditing",
                Message="Original team synthetic observation")
            if format=="windows-json": row["EventData"]=fields
            else: row.update(fields)
        else:
            emitter,message={
                "success":(e["emitter"],f'Accepted publickey for {e["actor"]} from {e["ip"]} port 41000 ssh2'),
                "failure":(e["emitter"],f'Failed password for {e["actor"]} from {e["ip"]} port 41000 ssh2'),
                "close":(e["emitter"],f'pam_unix(sshd:session): session closed for user {e["actor"]}'),
                "open":(e["emitter"],f'pam_unix(sshd:session): session opened for user {e["actor"]} by (uid=0)'),
                "privilege":("sudo",f'{e["actor"]} : TTY=pts/3 ; USER=root ; COMMAND=/usr/bin/id'),
                "account":("useradd",f'new user: name={e["account"]}, UID={20000+e["record_index"]}'),
                "install":("systemd",f'Started {e["service"]}.service'),
                "service":("systemd",f'{"Stopped" if e["running"] else "Started"} {e["service"]}.service'),
                "unknown":("usermod",f'add {e["actor"]} to group wheel'),
            }[kind]
            if format=="linux-text": row=f'{stamp} {side["host"]} {emitter}[{10000+e["record_index"]}]: {message}'
            else:
                delta=datetime.fromisoformat(e["timestamp"])-datetime(1970,1,1,tzinfo=timezone.utc)
                row=dict(MESSAGE=message,_HOSTNAME=side["host"],SYSLOG_IDENTIFIER=emitter,
                         __REALTIME_TIMESTAMP=str((delta.days*86400+delta.seconds)*1_000_000+delta.microseconds))
        rows.append(row)
    if format=="windows-json": text=json.dumps(rows)
    elif format=="windows-csv":
        buffer=io.StringIO(newline="")
        writer=csv.DictWriter(buffer,fieldnames=["EventID","Timestamp","Computer","RecordId","Channel","Provider","Message","SubjectUserName","TargetUserName","ServiceName","IpAddress"])
        writer.writeheader();writer.writerows(rows);text=buffer.getvalue()
    elif format=="linux-journal-json": text="\n".join(json.dumps(r) for r in rows)+"\n"
    else: text="\n".join(rows)+"\n"
    return text.encode("utf-16" if side["replicate"]%4==2 else "utf-8")


def inspect_source(raw,side,source_id,format):
    parsed=(parse_windows(raw,file_format="json" if format.endswith("json") else "csv",source_file="candidate.export",upload_id=source_id)
            if side["platform"]=="windows" else parse_linux(raw,file_format="text" if format.endswith("text") else "journal-json",source_file="candidate.export",upload_id=source_id))
    extraction=extract_features(parsed.events)
    if parsed.rejected or len(parsed.events)!=len(side["events"]) or len(extraction.windows)!=95:
        raise ValueError("Unexpected parser/window coverage")
    byslot={slot["slot"]:[] for slot in side["slots"]}
    for event,fact in zip(parsed.events,side["events"],strict=True):
        actual=(event.record_index,event.event_type,event.timestamp_utc.isoformat(),event.host,event.actor,event.target,str(event.source_ip) if event.source_ip else None)
        expected=(fact["record_index"],fact["event_type"],fact["timestamp"],side["host"],fact["normalized_actor"],fact["target"],fact["source_ip"])
        if actual!=expected or bool(event.parsing_errors)!=(fact["kind"]=="unknown"):
            raise ValueError("Parser disagrees with independent event facts")
        byslot[fact["slot"]].append(dict(event_type=fact["event_type"],timestamp=fact["timestamp"],actor=fact["normalized_actor"],target=fact["target"],source_ip=fact["source_ip"]))
    annotations=[];history=[]
    for window,slot in zip(extraction.windows,side["slots"],strict=True):
        number=slot["slot"]
        if window.start_utc!=datetime.fromisoformat(side["start"])+timedelta(seconds=number*300):
            raise ValueError("UTC chronology mismatch")
        if window.vector!=reference_vector(byslot[number],side["platform"]):
            raise ValueError("Independent 18-feature arithmetic mismatch")
        if history and number!=history[-1][0]+1: history=[]
        history=(history+[(number,window)])[-5:]
        categories=activity_categories([byslot[n] for n,_ in history])
        status="mixed_activity" if len(categories)>1 else "supported"
        if len(history)<5 or any(any(f["event_type"] is None for f in byslot[n]) for n,_ in history):
            status="insufficient_evidence"
        if slot["invisible"]: status="feature_unobservable"
        target=categories[0] if status=="supported" else None
        if slot["primary"] and (target!=CLASS_ORDER[slot["planned_class"]]):
            raise ValueError("Planned balanced anchor is not supported by causal facts")
        annotation=WindowAnnotation(label_version=LABEL_VERSION,feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),
            window_id=window.window_id,source_sha256=window.source_sha256,causal_window_ids=[w.window_id for _,w in history],
            origin="team_generated_synthetic",scenario_group=side["group"],split=side["split"],observed_categories=categories,
            observable_activity=target,label_status=status,evidence_event_ids=window.event_ids,
            activity_evidence_refs=[f"scenario:slots/{number}"],rationale="Frozen observable rubric from original scenario facts; authorization is separate.",
            review_status="pending",reviewer=None,authorization=dict(status=slot["authorization"],basis="scenario_manifest",
                evidence_refs=[f"scenario:slots/{number}/authorization"],rationale="Declared simulation context; not field-confirmed intent."))
        annotations.append(annotation.model_dump(mode="json"))
    return annotations,parsed,extraction


def generate(base=None,families=range(24),replicates=REPLICATES):
    base=(ROOT/"data/private" if base is None else Path(base)).resolve()
    if not base.is_relative_to(ROOT): raise ValueError("Output must stay inside V1")
    folder=base/("candidate-v5-"+uuid.uuid4().hex[:12]);folder.mkdir(parents=True,exist_ok=False)
    sources=[]
    for family in families:
        for replicate in replicates:
            for platform in ("windows","linux"):
                side=plan(family,replicate,platform)
                format=("windows-json" if replicate%2==0 else "windows-csv") if platform=="windows" else ("linux-text" if replicate%2==0 else "linux-journal-json")
                source_id=canonical_hash([VERSION,family,replicate,platform])[:24]
                raw=render(side,format)
                annotations,_,_=inspect_source(raw,side,source_id,format)
                side["annotations"]=annotations
                rawname=source_id+{"windows-json":".json","windows-csv":".csv","linux-text":".log","linux-journal-json":".jsonl"}[format]
                labelname=source_id+".labels.json"
                (folder/rawname).write_bytes(raw);(folder/labelname).write_bytes(encode(side))
                sources.append(dict(id=source_id,raw=rawname,labels=labelname,raw_sha256=hashfile(folder/rawname),labels_sha256=hashfile(folder/labelname),
                    **{key:side[key] for key in ("split","group","family","seed","platform","host","auth_style")},
                    format=format,events=len(side["events"]),windows=len(annotations)))
            print(f"Prepared {FAMILIES[family]} replicate {replicate}: {len(sources)} sources",flush=True)
    paths=[Path(__file__),ROOT/"training/diverse_data.py",ROOT/"training/mixed_candidate.py",ROOT/"training/mixed_data.py",
           ROOT/"training/experiment_data.py",ROOT/"training/label_contract.py",ROOT/"scripts/prepare_candidate_v5.py",
           ROOT/"sentinel/features.py",ROOT/"sentinel/ingest/windows.py",ROOT/"sentinel/ingest/linux.py",ROOT/"sentinel/ingest/common.py",
           ROOT/"docs/CANDIDATE_V5_PROTOCOL.md",ROOT/"docs/OBSERVABLE_ACTIVITY_LABEL_CONTRACT.md"]
    hashes={}
    for path in paths:
        name=path.relative_to(ROOT).as_posix();target=folder/"source"/name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(path.read_bytes());hashes[name]=hashfile(path)
    manifest=dict(version=VERSION,label_version=LABEL_VERSION,classes=CLASS_ORDER,feature_schema_sha256=schema_hash(),parser_version=PARSER_VERSION,
        sources=sources,source_hashes=hashes,review_status="pending_owner_review",training_approved=False,
        origin="Original team-generated Codex-assisted; no public telemetry, pretrained weights or model-based filtering",
        split_policy="Whole cadence/identity families: first 16 train, next 4 validation, last 4 test; both OS and all replicates stay together",
        target_selection="Eight supported anchors per class/session; other observations retained for context/diagnostics, not extra primary targets",
        context_policy="Current plus four prior contiguous windows; incomplete, unknown-history, mixed and invisible targets masked")
    (folder/"manifest.json").write_bytes(encode(manifest))
    return folder
