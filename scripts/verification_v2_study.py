"""Regression + separately generated holdout study for frozen-model verification v2."""
from collections import defaultdict,Counter
import json
from pathlib import Path
import uuid

import torch

from sentinel.features import FEATURE_VERSION,schema_hash,canonical_hash
from sentinel.detection.context_verification_v2 import verify_series,VERSION
from training.experiment_data import ROOT,hashfile
from training.mixed_experiment import checked_run
from training.experimental_cnn import SentinelCNN
from training.fresh_scenarios import FORMATS,emit
from training.verification_holdout import plan_holdout,RECIPES,SEEDS
from scripts.v4_broad_challenge import decode,analyze,score_rows,RUN

OLD=ROOT/"data/private/v4-fresh-0e04a0f9cef9"


def _file(folder,name):
    path=(folder/name).resolve()
    if not path.is_relative_to(folder.resolve()) or not path.is_file():
        raise ValueError("Missing or outside-project artifact")
    return path


def compact(decision):
    return dict(version=decision["version"],requires_review=decision["requires_review"],disposition=decision["disposition"],
        reasons=[r["code"] for r in decision["reasons"]],rule_hits=decision["rule_hits"],
        evidence_count=len(decision["evidence_ids"]),evidence_preview_ids=decision["evidence_ids"][:6],
        derived_prior_windows=decision.get("derived_prior_windows",0),unassessed_prior_starts=decision.get("unassessed_prior_starts",[]))


def recheck(rows,extractions):
    sequence=[]
    for row in rows:
        extraction=extractions.get(row["source"])
        byid={w.window_id:w for w in extraction.windows} if extraction else {}
        window=byid.get(row.get("window_id"))
        if row.get("vector") is not None:
            assert window is not None and row["vector"]==window.vector
        evidence=window.event_ids if window else []
        sequence.append(dict(platform=row["platform"],host=row.get("host","unassessed"),session_id=row["source"],
            start_utc=row.get("start_utc"),verification=dict(vector=row.get("vector"),model_class=row["prediction"],
                probabilities=row["scores"],coverage=row.get("coverage",{"collection_complete":False}),
                history_windows=row.get("history_windows",0),feature_version=FEATURE_VERSION,
                feature_schema_sha256=schema_hash(),evidence_ids=evidence)))
    decisions=verify_series(sequence)
    result=[dict(row,previous_combined=row["combined"],combined=compact(decision)) for row,decision in zip(rows,decisions,strict=True)]
    assert all(not r["previous_combined"]["requires_review"] or r["combined"]["requires_review"] for r in result),"Prior reviews suppressed"
    return result


def summarize(rows):
    canonical=[r for r in rows if r["format"] in ("windows-json","linux-text")]
    unique={}
    for row in canonical:
        if row["activity_truth"] is not None:unique.setdefault((row["platform"],row["context_sha256"]),row)
    old=[dict(r,combined=r["previous_combined"]) for r in rows]
    old_canonical=[r for r in old if r["format"] in ("windows-json","linux-text")]
    old_unique={}
    for row in old_canonical:
        if row["activity_truth"] is not None:old_unique.setdefault((row["platform"],row["context_sha256"]),row)
    return dict(v1_canonical=score_rows(old_canonical),v2_canonical=score_rows(canonical),
        v1_unique_activity=score_rows(list(old_unique.values())),v2_unique_activity=score_rows(list(unique.values())),
        reviews_added=sum(not r["previous_combined"]["requires_review"] and r["combined"]["requires_review"] for r in canonical),
        reviews_suppressed=sum(r["previous_combined"]["requires_review"] and not r["combined"]["requires_review"] for r in canonical),
        unreviewed_unassessed_by_case=dict(Counter(r["case"] for r in canonical if r["activity_truth"] is None and not r["combined"]["requires_review"])),
        context_misses_by_case=dict(Counter(r["case"] for r in canonical if r["truth"] is True and not r["combined"]["requires_review"])),
        by_case={name:dict(v1=score_rows([r for r in old_canonical if r["case"]==name]),v2=score_rows([r for r in canonical if r["case"]==name]))
                 for name in sorted({r["case"] for r in canonical})})


def regression():
    old=json.loads((OLD/"complete.json").read_text())
    assert hashfile(OLD/"predictions.jsonl")==old["predictions_sha256"] and hashfile(OLD/"results.json")==old["results_sha256"]
    rows=[json.loads(line) for line in (OLD/"predictions.jsonl").read_text().splitlines()]
    # Context/quality assertions on every format; primary summaries avoid export duplication.
    ledger=json.loads((OLD/"sources.json").read_text());extractions={}
    for source in ledger:
        rawpath=_file(OLD,source["raw"]);truthpath=_file(OLD,source["truth"])
        assert hashfile(rawpath)==source["raw_sha256"] and hashfile(truthpath)==source["truth_sha256"]
        side=json.loads(truthpath.read_text())
        extractions[source["id"]]=decode(rawpath.read_bytes(),side["episode"],source["format"],side["expected_record_types"],source["id"])["extraction"]
    output=recheck(rows,extractions)
    for row in output:
        if row["activity_truth"] not in (None,0):assert row["combined"]["requires_review"],"Supported regression activity still missed"
        if row["label_status"]=="insufficient_evidence":assert row["combined"]["requires_review"],"Regression input-quality gap still unreviewed"
    return output


def holdout(model,norm,out):
    rows=[];ledger=[];extractions={}
    for recipe in RECIPES:
        for seed in SEEDS:
            for format in FORMATS:
                platform="windows" if format.startswith("windows") else "linux"
                episode=plan_holdout(recipe,seed,platform);raw,expected=emit(episode,format)
                if seed%3==2:raw=raw.decode("utf-8").encode("utf-16")
                source=f"holdout-{len(ledger):04d}"
                rawname=source+".raw";truthname=source+".truth.json"
                (out/rawname).write_bytes(raw)
                (out/truthname).write_text(json.dumps(dict(episode=episode,expected=expected),allow_nan=False),encoding="utf-8")
                analyzed,decoded=analyze(raw,episode,format,expected,source,model,norm)
                extractions[source]=decoded["extraction"];rows.extend(analyzed)
                ledger.append(dict(id=source,recipe=recipe,seed=seed,format=format,raw=rawname,truth=truthname,
                                   raw_sha256=hashfile(out/rawname),truth_sha256=hashfile(out/truthname),events=len(episode["events"])))
    raw_old={s["raw_sha256"] for s in json.loads((OLD/"sources.json").read_text())}
    assert not raw_old.intersection(s["raw_sha256"] for s in ledger),"Holdout reused regression raw bytes"
    return recheck(rows,extractions),ledger


def run_study():
    run,config,selection=checked_run(RUN)
    paths=[Path(__file__).resolve(),ROOT/"sentinel/detection/context_verification_v2.py",ROOT/"training/verification_holdout.py",
           ROOT/"training/fresh_scenarios.py",ROOT/"scripts/v4_broad_challenge.py",ROOT/"docs/VERIFICATION_V2_PROTOCOL.md"]
    freeze={str(p.relative_to(ROOT)):hashfile(p) for p in paths}
    base=(ROOT/"data/private").resolve()
    if not base.is_relative_to(ROOT):raise ValueError("Study output must stay inside V1")
    out=base/("verification-v2-"+uuid.uuid4().hex[:12]);out.mkdir(exist_ok=False)
    def write(name,value):
        with (out/name).open("x",encoding="utf-8") as stream:json.dump(value,stream,indent=2,allow_nan=False)
    write("freeze.json",dict(version=VERSION,new_sources=freeze,checkpoint_sha256=selection["best_checkpoint_sha256"],
        config_sha256=selection["config_sha256"],regression_folder=OLD.relative_to(ROOT).as_posix(),
        holdout_recipes=RECIPES,holdout_seeds=SEEDS,formats=FORMATS,training_performed=False))
    for path in paths:(out/path.name).write_bytes(path.read_bytes())
    regressions=regression()
    write("regression-results.json",summarize(regressions))
    with (out/"regression-predictions.jsonl").open("x",encoding="utf-8") as stream:
        for row in regressions:stream.write(json.dumps(row,allow_nan=False)+"\n")
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    model=SentinelCNN().eval();model.load_state_dict(torch.load(run/"best.pt",map_location="cpu",weights_only=True)["state_dict"])
    new,ledger=holdout(model,config["normalization"],out)
    write("holdout-sources.json",ledger);write("holdout-results.json",summarize(new))
    with (out/"holdout-predictions.jsonl").open("x",encoding="utf-8") as stream:
        for row in new:stream.write(json.dumps(row,allow_nan=False)+"\n")
    assert {str(p.relative_to(ROOT)):hashfile(p) for p in paths}==freeze
    checked_run(RUN)
    write("complete.json",dict(checkpoint_unchanged=True,
        files={name:hashfile(out/name) for name in ("regression-results.json","regression-predictions.jsonl","holdout-results.json","holdout-predictions.jsonl","holdout-sources.json")}))
    print("OUTPUT",out)
    for phase in ("regression","holdout"):
        result=json.loads((out/f"{phase}-results.json").read_text())
        print(phase,json.dumps({version:{"context":result[version+"_canonical"]["context"]["combined"],
            "supported_activity_review":result[version+"_unique_activity"].get("activity_review",{}).get("combined"),
            "unassessed":result[version+"_canonical"]["no_assessment_review"]} for version in ("v1","v2")},indent=2))
    return out


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--run",action="store_true")
    if parser.parse_args().run:run_study()
    else:print("Explicit --run required for regression and new holdout evaluation. No training.")
