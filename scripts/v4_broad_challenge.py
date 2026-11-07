"""Frozen-checkpoint, evaluation-only fresh scenarios. No training or policy edits."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
from pathlib import Path
import uuid

import torch

from sentinel.features import FEATURE_VERSION, extract_features, canonical_hash, schema_hash
from sentinel.ingest import parse_linux, parse_windows, ParseInputError
from sentinel.ingest.common import PARSER_VERSION
from sentinel.detection.verification import verify
from sentinel.detection.temporal_verification import verify_series
from training.experiment_data import ROOT, hashfile, metrics
from training.experimental_cnn import SentinelCNN
from training.mixed_experiment import checked_run,DATA as V4_DATA,MANIFEST_PIN
from training.mixed_data import observable_rule,load as load_v4
from training.fresh_scenarios import CASES, FORMATS, SEEDS, VERSION, emit, plan, event_type
from scripts.audit_existing_dataset import independent_vector
from scripts.temporal_challenge import binary, confidence_diagnostics

RUN=ROOT/"training/runs/cnn-v4-20261105T015542Z-21891974"


def decode(raw, episode, format, expected, source):
    expected={int(k):v for k,v in expected.items()}
    try:
        parsed=(parse_windows(raw,file_format="json" if format.endswith("json") else "csv",source_file=source,upload_id=source)
                if format.startswith("windows") else parse_linux(raw,file_format="text" if format.endswith("text") else "journal-json",source_file=source,upload_id=source))
    except ParseInputError as error:
        if episode["pattern"]!="broken": raise
        return dict(parsed=None,extraction=None,fatal=str(error),mapping_mismatches=0)
    for event in parsed.events:
        want=expected[event.record_index]
        assert not want.get("rejected",False)
        assert event.event_type==want["event_type"],"Scenario/parser event-type disagreement"
        assert (event.host is None)==want["missing_host"]
        assert (event.timestamp_utc is None)==want["missing_time"]
    if episode["pattern"]!="broken":
        assert {r.record_index for r in parsed.rejected}=={i for i,r in expected.items() if r.get("rejected",False)}
        assert len(parsed.events)+len(parsed.rejected)==len(expected)
    extraction=extract_features(parsed.events)
    for window in extraction.windows:
        assert window.vector==independent_vector(extraction.members[window.window_id]),"18-feature arithmetic mismatch"
    return dict(parsed=parsed,extraction=extraction,fatal=None,mapping_mismatches=0)


def truth(episode,host,slot,history_slots):
    """Independent event-fact rubric; no feature vector/model/rule prediction input."""
    byslot=defaultdict(Counter)
    for row in episode["events"]:
        if row["host"]==host:
            byslot[row["slot"]][event_type(row["kind"],episode["platform"])]+=1
    failures=[byslot[s]["auth_failure"] for s in history_slots]
    current=byslot[slot]
    classes=[]
    if failures[-1]>=5 or (failures[-1]>0 and sum(failures)>=5 and sum(v>0 for v in failures)>=2): classes.append(1)
    if current["account_created"]: classes.append(2)
    if current["service_installed"]+current["service_state_change"]+current["service_activity"]: classes.append(3)
    activity=classes[0] if len(classes)==1 else None if classes else 0
    hidden=any(r["host"]==host and r["slot"]==slot for r in episode["invisible"])
    unauthorized=any(r["host"]==host and r["slot"]==slot and r["malicious"] for r in episode["events"]) or hidden
    return activity,unauthorized,hidden,len(classes)>1


def analyze(raw, episode, format, expected, source, model=None, norm=None):
    decoded=decode(raw,episode,format,expected,source)
    parsed,extraction=decoded["parsed"],decoded["extraction"]
    rows=[]
    if extraction is None or not extraction.windows:
        kwargs=dict(vector=None,model_class=None,probabilities=None,coverage={"collection_complete":False},
                    history_windows=0,feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),evidence_ids=[])
        return [dict(case=episode["case"],pattern=episode["pattern"],seed=episode["seed"],platform=episode["platform"],format=format,
                     source=source,unit="unassessed_import",activity_truth=None,truth=None,prediction=None,scores=None,
                     label_status="insufficient_evidence",cnn={"requires_review":False},combined=verify(**kwargs),
                     context_sha256=None,raw_events=0,feature_schema_sha256=schema_hash())],decoded
    windows={(w.host,int((w.start_utc-datetime.fromisoformat(episode["start"])).total_seconds()//300)):w for w in extraction.windows}
    source_issues=dict(rejected_records=len(parsed.rejected),missing_host=sum(e.host is None for e in parsed.events),
                       missing_timestamp=sum(e.timestamp_utc is None for e in parsed.events),excluded_records=extraction.coverage["excluded_records"])
    global_gap=any(source_issues.values())
    for host in episode["hosts"]:
        history=[]; host_rows=[]; blocks=[];block=[]
        for slot in range(episode["length"]):
            window=windows.get((host,slot))
            if window is None:
                if block: blocks.append(block);block=[]
                history=[]
            else:
                history.append((slot,window));history=history[-5:]
            context_slots=[s for s,_ in history]
            current_truth,security,hidden,mixed=truth(episode,host,slot,context_slots or [slot])
            status="supported"
            if mixed: status="mixed_activity"
            context_bad=bool(history) and any(e.parsing_errors for _,w in history for e in extraction.members[w.window_id])
            if global_gap or window is None or len(history)<5 or context_bad: status="insufficient_evidence"
            if hidden: status="feature_unobservable"
            if slot in episode["expected_missing_slots"] and episode["pattern"]=="gap": security=None
            values=window.vector if window else None
            coverage=dict(source_issues,collection_complete=not global_gap and window is not None,
                          unrecognized_events=sum(e.event_type is None for e in extraction.members[window.window_id]) if window else 0)
            row=dict(case=episode["case"],pattern=episode["pattern"],seed=episode["seed"],platform=episode["platform"],format=format,
                     source=source,host=host,slot=slot,start_utc=(datetime.fromisoformat(episode["start"])+timedelta(seconds=slot*300)).isoformat(),
                     unit="observed_window" if window else "unassessed_interval",vector=values,
                     activity_truth=current_truth if status=="supported" else None,truth=security,
                     label_status=status,context_sha256=canonical_hash([w.vector for _,w in history]) if window else None,
                     coverage=coverage,history_windows=max(0,len(history)-1),raw_events=len(window.event_ids) if window else 0,
                     window_id=window.window_id if window else None,evidence_preview_ids=window.event_ids[:6] if window else [],
                     evidence_count=len(window.event_ids) if window else 0,prediction=None,scores=None,
                     feature_schema_sha256=schema_hash())
            row["_evidence"]=window.event_ids if window else []
            if window:
                row["rule_prediction"]=observable_rule([w.vector for _,w in history])
                if row["activity_truth"] is not None:
                    assert row["rule_prediction"]==row["activity_truth"],"Latent facts/feature rubric conflict"
                block.append(row)
            host_rows.append(row)
        if block: blocks.append(block)
        if model is not None:
            for segment in blocks:
                x=torch.tensor([[r["vector"] for r in segment]],dtype=torch.float32)
                x=(x-torch.tensor(norm["mean"]))/torch.tensor(norm["scale"])
                with torch.no_grad():scores=model(x.transpose(1,2)).softmax(1)[0].transpose(0,1).tolist()
                for row,score in zip(segment,scores,strict=True):
                    row["scores"]=score;row["prediction"]=max(range(4),key=score.__getitem__)
        sequence=[dict(host=host,platform=episode["platform"],session_id=source,start_utc=r["start_utc"],
                       verification=dict(vector=r["vector"],model_class=r["prediction"],probabilities=r["scores"],
                           coverage=r["coverage"],history_windows=r["history_windows"],feature_version=FEATURE_VERSION,
                           feature_schema_sha256=schema_hash(),evidence_ids=r["_evidence"])) for r in host_rows]
        for row,decision in zip(host_rows,verify_series(sequence),strict=True):
            row["cnn"]={"requires_review":row["prediction"] not in (None,0)}
            row["combined"]=dict(requires_review=decision["requires_review"],disposition=decision["disposition"],
                                 reasons=[r["code"] for r in decision["reasons"]],rule_hits=decision["rule_hits"],
                                 evidence_count=len(decision["evidence_ids"]))
            row.pop("_evidence")
        rows.extend(host_rows)
    return rows,decoded


def score_rows(rows):
    known=[r for r in rows if r["activity_truth"] is not None and r["prediction"] is not None]
    result=dict(units=len(rows),observed_windows=sum(r["unit"]=="observed_window" for r in rows),supported=len(known),
                masked_or_unassessed=len(rows)-len(known),context={k:binary(rows,k) for k in ("cnn","combined")},
                no_assessment_review=dict(total=sum(r["activity_truth"] is None for r in rows),
                                         reviewed=sum(r["activity_truth"] is None and r["combined"]["requires_review"] for r in rows)))
    if known:
        result["activity"]=metrics([r["activity_truth"] for r in known],[r["prediction"] for r in known])
        result["rule"]=metrics([r["activity_truth"] for r in known],[r["rule_prediction"] for r in known])
        result["confidence"]=confidence_diagnostics([dict(truth=r["activity_truth"],prediction=r["prediction"],scores=r["scores"]) for r in known])
        activity_rows=[dict(r,truth=r["activity_truth"]) for r in known]
        result["activity_review"]={k:binary(activity_rows,k) for k in ("cnn","combined")}
    return result


def run_challenge():
    run,config,selected=checked_run(RUN)
    assert (run/"test_metrics.json").is_file(),"Complete the fixed final evaluation first"
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    paths=[Path(__file__).resolve(),ROOT/"training/fresh_scenarios.py",ROOT/"scripts/audit_existing_dataset.py",
           ROOT/"docs/V4_FRESH_SCENARIO_PROTOCOL.md"]
    freeze={str(p.relative_to(ROOT)):hashfile(p) for p in paths}
    out=ROOT/"data/private"/("v4-fresh-"+uuid.uuid4().hex[:12]);out.mkdir(exist_ok=False)
    write=lambda name,value: (out/name).write_text(json.dumps(value,indent=2,allow_nan=False),encoding="utf-8")
    write("freeze.json",dict(version=VERSION,new_sources=freeze,frozen_model_sources=config["source_hashes"],
                             checkpoint_sha256=selected["best_checkpoint_sha256"],config_sha256=selected["config_sha256"],
                             seeds=SEEDS,cases=[vars(c) for c in CASES],formats=FORMATS,training_performed=False))
    for path in paths:(out/path.name).write_bytes(path.read_bytes())
    model=SentinelCNN().eval();model.load_state_dict(torch.load(run/"best.pt",map_location="cpu",weights_only=True)["state_dict"])
    training_inputs=load_v4(V4_DATA,{"train"},MANIFEST_PIN)
    training_contexts=set()
    train_values=[v for s in training_inputs for v in s["vectors"]]
    feature_bounds=[(min(v[i] for v in train_values),max(v[i] for v in train_values)) for i in range(18)]
    for session in training_inputs:
        for i in range(4,len(session["vectors"])):
            training_contexts.add((session["platform"],canonical_hash(session["vectors"][i-4:i+1])))
    rows=[];ledger=[];equivalence=defaultdict(dict);prediction_equivalence=defaultdict(dict)
    existing_raw={s["raw_sha256"] for s in config["dataset_manifest"]["sources"]}
    for case in CASES:
        for seed in SEEDS:
            for format in FORMATS:
                platform="windows" if format.startswith("windows") else "linux"
                episode=plan(case,seed,platform);raw,expected=emit(episode,format)
                source=f"{len(ledger):04d}"; rawname=source+".raw";metaname=source+".truth.json"
                (out/rawname).write_bytes(raw)
                write(metaname,dict(episode=episode,expected_record_types=expected))
                analyzed,decoded=analyze(raw,episode,format,expected,source,model,config["normalization"])
                rows.extend(analyzed)
                assert hashfile(out/rawname) not in existing_raw,"Raw input reused from the V4 corpus"
                parsed=decoded["parsed"]
                ledger.append(dict(id=source,case=case.name,seed=seed,format=format,raw=rawname,truth=metaname,
                    raw_sha256=hashfile(out/rawname),truth_sha256=hashfile(out/metaname),
                    raw_events=len(episode["events"]),accepted=len(parsed.events) if parsed else None,
                    rejected=len(parsed.rejected) if parsed else None,fatal=decoded["fatal"],
                    parser_warnings=sum(bool(e.parsing_errors) for e in parsed.events) if parsed else None))
                signature=[(r.get("slot"),r.get("host"),r.get("vector")) for r in analyzed]
                equivalence[case.name,seed,platform][format]=canonical_hash(signature)
                prediction_equivalence[case.name,seed,platform][format]=canonical_hash([(r.get("slot"),r.get("prediction"),r.get("scores")) for r in analyzed])
    canonical=[r for r in rows if r["format"] in ("windows-json","linux-text")]
    known={};conflicts=defaultdict(set)
    for row in canonical:
        if row["activity_truth"] is not None:
            key=(row["platform"],row["context_sha256"])
            conflicts[key].add(row["activity_truth"])
            known.setdefault(key,row)
    assert all(len(v)==1 for v in conflicts.values()),"Same causal X has conflicting activity labels"
    exact_equivalence=sum(len(set(formats.values()))==1 for formats in equivalence.values())
    raw_counts=Counter(s["raw_sha256"] for s in ledger)
    novel=[row for key,row in known.items() if key not in training_contexts]
    shift_counts=Counter()
    for row in known.values():
        for i,(low,high) in enumerate(feature_bounds):
            if not low<=row["vector"][i]<=high:shift_counts[i]+=1
    summary=dict(version=VERSION,sources=len(ledger),recipes=len(CASES),seeds=len(SEEDS),
        unique_pattern_seed_os_groups=len({(c.pattern,s,p) for c in CASES for s in SEEDS for p in ("windows","linux")}),
        declared_raw_event_records=sum(s["raw_events"] for s in ledger),
        accepted_events=sum(s["accepted"] or 0 for s in ledger),rejected_records=sum(s["rejected"] or 0 for s in ledger),
        fatal_sources=sum(s["fatal"] is not None for s in ledger),parser_warning_events=sum(s["parser_warnings"] or 0 for s in ledger),
        unique_raw_artifacts=len(raw_counts),repeated_raw_artifacts=sum(n-1 for n in raw_counts.values()),
        canonical_exports=score_rows(canonical),unique_supported_causal_inputs=score_rows(list(known.values())),
        unique_supported_contexts_seen_in_training=len(known)-len(novel),novel_supported_causal_inputs=score_rows(novel),
        feature_range_shift_counts={str(i):n for i,n in sorted(shift_counts.items())},
        by_case={c.name:score_rows([r for r in canonical if r["case"]==c.name]) for c in CASES},
        by_format={f:score_rows([r for r in rows if r["format"]==f]) for f in FORMATS},
        format_feature_equivalence_groups=dict(matched=exact_equivalence,total=len(equivalence)),
        format_prediction_equivalence_groups=dict(matched=sum(len(set(v.values()))==1 for v in prediction_equivalence.values()),total=len(prediction_equivalence)),
        by_status={status:score_rows([r for r in canonical if r["label_status"]==status]) for status in sorted({r["label_status"] for r in canonical})},
        training_performed=False,checkpoint_sha256=selected["best_checkpoint_sha256"],
        limitations=["Fresh team synthetic challenge, not independent field telemetry or exhaustive incident coverage.",
                     "Primary unique-input metrics deduplicate matching causal vectors; scenario/context views remain correlated.",
                     "Labels follow the observable rubric; baseline agreement is not maliciousness truth.",
                     "Unrecognized coverage is per current window; unlocalizable rejected/missing identity/time affects the entire source.",
                     "No checkpoint/policy tuning or deployment in this study."])
    write("sources.json",ledger)
    with (out/"predictions.jsonl").open("x",encoding="utf-8") as stream:
        for row in rows:stream.write(json.dumps(row,allow_nan=False)+"\n")
    write("results.json",summary)
    assert {str(p.relative_to(ROOT)):hashfile(p) for p in paths}==freeze
    checked_run(RUN)
    write("complete.json",dict(results_sha256=hashfile(out/"results.json"),predictions_sha256=hashfile(out/"predictions.jsonl"),
                               checkpoint_unchanged=hashfile(run/"best.pt")==selected["best_checkpoint_sha256"]))
    print("OUTPUT",out)
    print(json.dumps({k:summary[k] for k in ("sources","recipes","accepted_events","fatal_sources","format_feature_equivalence_groups")},indent=2))
    print("UNIQUE_ACTIVITY",json.dumps(summary["unique_supported_causal_inputs"].get("activity",{})))
    print("CANONICAL_CONTEXT",json.dumps(summary["canonical_exports"]["context"]))
    return out


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--run",action="store_true")
    if parser.parse_args().run:run_challenge()
    else:print("Evaluation only; explicit --run required. No training.")
