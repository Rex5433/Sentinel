"""Hash-pinned, local V5 experiment. Default execution is preflight only."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import uuid

import torch
from torch.nn import functional as F

from scripts.temporal_challenge import binary, confidence_diagnostics
from training.diverse_data import IGNORE_TARGET, load, manifest_for
from training.experiment_data import ROOT, baseline, hashfile, metrics, normalize_fit
from training.experimental_cnn import SentinelCNN
from training.mixed_data import observable_rule
from training.mixed_preflight import masked_loss, tensors

DATA = ROOT / "data/private/candidate-v5-e3bfbee69ae4"
MANIFEST_PIN = "04384711440d62e3b7c2de27eabb362b119e4f674012814a1c0f4968a80214be"
AUDIT_PIN = "5c0ed2e9ef96e501a04d83f47098d6e519a0b89c1c44544b9c611e0413c086d9"
CNN_SOURCE_PIN = "5bcb23bd2ccea158655d32d0ad4669a48030784dfee42075a4a098c074b2c5a6"
RUNS = ROOT / "training/runs"
PROTOCOL = "masked-cnn-v5-experiment-v1"
CONFIG = dict(seed=84, epochs=200, patience=25, min_delta=.0001, learning_rate=.001,
              weight_decay=.0001, batch_segments=16, device="cpu",
              architecture="causal-18-32-32-k3-dropout0.1-linear4-v1")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)


def candidate():
    folder, manifest = manifest_for(DATA, MANIFEST_PIN)
    if hashfile(folder / "audit.json") != AUDIT_PIN:
        raise ValueError("V5 audit hash changed")
    audit = _read(folder / "audit.json")
    if (audit["manifest_sha256"] != MANIFEST_PIN or audit["status"] != "candidate_pending_review"
            or audit["training_approved"] or manifest["training_approved"]):
        raise ValueError("V5 audit or original pending review state changed")
    return manifest, audit


def _counts(sessions, split, audit):
    expected = {(row["platform"], row["target"]): row["count"]
                for row in audit["selected_class_counts"] if row["split"] == split}
    counts = Counter()
    for session in sessions:
        if session["split"] != split or any(t != IGNORE_TARGET for t in session["targets"]):
            raise ValueError("Unexpected split or already unmasked targets")
        for i, (target, annotation) in enumerate(zip(session["candidate_targets"], session["annotations"], strict=True)):
            if target == IGNORE_TARGET:
                continue
            if i < 4 or annotation.label_status != "supported" or len(annotation.causal_window_ids) != 5:
                raise ValueError("Selected target lacks supported causal input")
            counts[session["platform"], target] += 1
    observed = sum(len(s["vectors"]) for s in sessions)
    split_audit = next(row for row in audit["by_split"] if row["split"] == split)
    if (counts != expected or observed != split_audit["windows"]
            or len({s["id"] for s in sessions}) != split_audit["sources"]
            or len({(s["id"], s["segment"]) for s in sessions}) != len(sessions)):
        raise ValueError("Loaded split counts disagree with audited candidate")
    return dict(selected=sum(counts.values()), observed=observed, ignored=observed-sum(counts.values()),
                segments=len(sessions), sources=split_audit["sources"],
                by_platform_and_class={f"{os}:{target}": count for (os,target),count in sorted(counts.items())})


def prepare():
    """Open train and validation only. Keep original labels pending."""
    _, audit = candidate()
    sessions = load(DATA, {"train", "validation"}, MANIFEST_PIN)
    train = [s for s in sessions if s["split"] == "train"]
    validation = [s for s in sessions if s["split"] == "validation"]
    if len(train) + len(validation) != len(sessions):
        raise ValueError("Preparation received an unexpected split")
    summary = dict(train=_counts(train, "train", audit), validation=_counts(validation, "validation", audit))
    norm = normalize_fit(train)
    return train, validation, norm, summary


def _model():
    if hashfile(ROOT / "training/experimental_cnn.py") != CNN_SOURCE_PIN:
        raise ValueError("Original CNN source changed")
    model = SentinelCNN()
    if sum(p.numel() for p in model.parameters()) != 4996:
        raise ValueError("Original CNN parameter count changed")
    return model


def _baseline_predictions(session, i):
    current = session["vectors"][i]
    rule = observable_rule(session["vectors"][max(0, i-4):i+1])
    if rule is None:
        raise ValueError("Selected target has mixed feature evidence")
    return baseline(current), rule


def _baselines(sessions):
    truth, simple, rubric = [], [], []
    for session in sessions:
        for i, target in enumerate(session["candidate_targets"]):
            if target != IGNORE_TARGET:
                a,b = _baseline_predictions(session, i)
                truth.append(target); simple.append(a); rubric.append(b)
    return dict(single_window_threshold=metrics(truth, simple), observable_rubric=metrics(truth, rubric))


def preflight():
    """Inspect data and an untrained sample. No optimizer, writes or test input."""
    train, validation, norm, summary = prepare()
    active = next(s for s in train if any(y != IGNORE_TARGET for y in s["candidate_targets"]))
    short = min(train, key=lambda s:len(s["vectors"]))
    with torch.random.fork_rng(devices=[]), torch.no_grad():
        torch.manual_seed(CONFIG["seed"])
        model = _model().eval()
        x, proposals = tensors([active, short], norm, proposals=True)
        _, pending = tensors([active, short], norm)
        logits = model(x)
        changed = x.clone(); changed[:, :, 5:] += 100
        torch.testing.assert_close(model(changed)[:, :, :5], logits[:, :, :5])
        selected = proposals != IGNORE_TARGET
        if not selected.any() or (pending != IGNORE_TARGET).any() or (proposals[1, len(short["vectors"]):] != IGNORE_TARGET).any():
            raise ValueError("Selected, pending or right-padding mask mismatch")
        loss = masked_loss(logits, proposals)
        torch.testing.assert_close(loss, F.cross_entropy(logits.transpose(1,2)[selected], proposals[selected]))
        if not torch.isfinite(loss):
            raise ValueError("Nonfinite preflight loss")
    bases = {name:_baselines(data) for name,data in (("train",train),("validation",validation))}
    return dict(status="passed_preflight_training_not_started", manifest_sha256=MANIFEST_PIN, audit_sha256=AUDIT_PIN,
                split_counts=summary, normalization_fit_train_windows=norm["fit_windows"], normalization=norm,
                parameters=4996, input_shape=list(x.shape), output_shape=list(logits.shape),
                masks_checked=True, causal_prefix_checked=True, pending_targets_unmasked=0,
                baseline_macro_f1={split:{name:report["macro_f1"] for name,report in result.items()} for split,result in bases.items()},
                rubric_note="The observable rule reproduces procedural labels by design; it is not independent attack truth.",
                training_started=False, optimizer_created=False, final_test_inputs_loaded=False)


def _active(sessions):
    # Overlay is local to explicitly approved execution. No source annotations are rewritten.
    return [dict(s, targets=list(s["candidate_targets"])) for s in sessions
            if any(t != IGNORE_TARGET for t in s["candidate_targets"])]


def _evaluate(model, sessions, norm, *, details=False):
    """Score only selected anchors. Full observed prefixes still feed the CNN."""
    active = _active(sessions)
    model.eval()
    total_loss, rows, simple, rubric = 0., [], [], []
    with torch.no_grad():
        for offset in range(0,len(active),CONFIG["batch_segments"]):
            batch = active[offset:offset+CONFIG["batch_segments"]]
            x,y = tensors(batch,norm)
            logits = model(x)
            total_loss += F.cross_entropy(logits,y,ignore_index=IGNORE_TARGET,reduction="sum").item()
            scores = logits.softmax(1).transpose(1,2)
            for b,i in (y != IGNORE_TARGET).nonzero().tolist():
                session = batch[b]
                target = session["targets"][i]
                score = scores[b,i].tolist()
                prediction = max(range(4), key=score.__getitem__)
                row = dict(truth=target,prediction=prediction,scores=score)
                if details:
                    annotation = session["annotations"][i]
                    row.update(source=session["id"],group=session["group"],platform=session["platform"],
                               start_utc=session["starts_utc"][i],window_id=annotation.window_id,
                               evidence_preview=annotation.evidence_event_ids[:6])
                    a,b_rule = _baseline_predictions(session,i); simple.append(a); rubric.append(b_rule)
                rows.append(row)
    if not rows:
        raise ValueError("No selected targets to evaluate")
    truth,prediction = [r["truth"] for r in rows],[r["prediction"] for r in rows]
    loss = total_loss/len(rows)
    if not torch.isfinite(torch.tensor(loss)):
        raise ValueError("Nonfinite evaluation loss")
    result = dict(loss=loss, activity=metrics(truth,prediction), selected_windows=len(rows),
                  observed_windows=sum(len(s["vectors"]) for s in sessions))
    if details:
        result.update(single_window_threshold=metrics(truth,simple), observable_rubric=metrics(truth,rubric),
            confidence=confidence_diagnostics(rows),
            activity_review={name:binary([dict(truth=t!=0, decision=dict(requires_review=p!=0))
                                          for t,p in zip(truth,values,strict=True)],"decision")
                             for name,values in (("cnn",prediction),("single_window_threshold",simple),("observable_rubric",rubric))},
            by_platform={os:metrics([r["truth"] for r in rows if r["platform"]==os],
                                    [r["prediction"] for r in rows if r["platform"]==os])
                         for os in sorted({r["platform"] for r in rows})}, predictions=rows,
            note="Selected observable activity only; false negatives here are missed activity, not missed real incidents.")
    return result


def _run_root():
    root = RUNS.resolve()
    if not root.is_relative_to(ROOT):
        raise ValueError("Run files must stay inside V1")
    return root


def _hashes():
    manifest,_ = candidate()
    names = set(manifest["source_hashes"]) | {
        "training/diverse_experiment.py", "training/experimental_cnn.py", "training/mixed_preflight.py",
        "sentinel/schemas.py", "scripts/temporal_challenge.py", "docs/CANDIDATE_V5_RUN_PROTOCOL.md",
    }
    return {name:hashfile(ROOT/name) for name in sorted(names)}


def _claim():
    return _run_root()/f"v5-run-{MANIFEST_PIN}.json"


def owner_run(*, approve_training=False):
    """A deliberate owner opt-in; reuse a completed run, never restart a partial run."""
    if approve_training is not True:
        raise ValueError("Explicit owner approval is required before V5 optimization")
    claim = _claim()
    if claim.exists():
        pointer = _read(claim)
        run = (_run_root()/pointer["directory"]).resolve()
        if run.parent != _run_root() or pointer["manifest_sha256"] != MANIFEST_PIN:
            raise ValueError("Invalid V5 run claim")
        if not (run/"selection.json").is_file():
            raise RuntimeError("V5 already started but is incomplete; inspect saved artifacts before any new run")
        checked_run(run)
        print("Reusing completed V5 run:",run,flush=True)
        return run
    train,validation,norm,summary = prepare()
    hashes = _hashes()
    root = _run_root(); root.mkdir(parents=True,exist_ok=True)
    run = root/("cnn-v5-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8])
    _write(claim,dict(directory=run.name,manifest_sha256=MANIFEST_PIN))  # Exclusive across kernels.
    run.mkdir()
    acceptance = dict(decision="owner_opted_in_to_limited_experimental_training", manifest_sha256=MANIFEST_PIN,
                      audit_sha256=AUDIT_PIN, recorded_utc=datetime.now(timezone.utc).isoformat(),
                      scope="Procedural selected targets only; original annotations remain pending; no field truth or scored use")
    _write(run/"acceptance.json",acceptance)
    config = dict(protocol=PROTOCOL, config=CONFIG, manifest_sha256=MANIFEST_PIN, audit_sha256=AUDIT_PIN,
                  source_hashes=hashes, acceptance_sha256=hashfile(run/"acceptance.json"), normalization=norm,
                  split_counts=summary, python=platform.python_version(), torch=torch.__version__, platform=platform.platform(),
                  pretrained_weights=False, normalization_basis="All observed train windows only, before padding")
    _write(run/"config.json",config)
    for name in hashes:
        path = run/"source"/name; path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes((ROOT/name).read_bytes())
    return _fit(run,train,validation,norm,hashes)


def _fit(run, train, validation, norm, hashes):
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(CONFIG["seed"])
    model = _model()
    torch.save(dict(state_dict=model.state_dict(),rng=torch.get_rng_state()),run/"initial.pt")
    optimizer = torch.optim.Adam(model.parameters(),lr=CONFIG["learning_rate"],weight_decay=CONFIG["weight_decay"])
    primary = _active(train)
    x,y = tensors(primary,norm)
    best = reference = float("inf")
    best_epoch = stale = 0
    for epoch in range(1,CONFIG["epochs"]+1):
        model.train()
        for batch in torch.randperm(len(primary)).split(CONFIG["batch_segments"]):
            optimizer.zero_grad()
            loss = masked_loss(model(x[batch]),y[batch])
            if not torch.isfinite(loss):
                raise ValueError("Nonfinite training loss")
            loss.backward(); optimizer.step()
        tr,va = _evaluate(model,train,norm),_evaluate(model,validation,norm)
        row = dict(epoch=epoch,train_loss=tr["loss"],validation_loss=va["loss"],
                   train_macro_f1=tr["activity"]["macro_f1"],validation_macro_f1=va["activity"]["macro_f1"])
        with (run/"history.jsonl").open("a",encoding="utf-8") as stream:
            stream.write(json.dumps(row,allow_nan=False)+"\n")
        state = dict(state_dict=model.state_dict(),optimizer=optimizer.state_dict(),epoch=epoch,rng=torch.get_rng_state())
        if va["loss"] < best:
            best,best_epoch = va["loss"],epoch
            torch.save(state,run/"best.pt")
        if va["loss"] < reference-CONFIG["min_delta"]:
            reference,stale = va["loss"],0
        else:
            stale += 1
        if epoch == 1 or epoch%10 == 0: print(row,flush=True)
        if stale >= CONFIG["patience"]: break
    torch.save(state,run/"last.pt")
    model.load_state_dict(torch.load(run/"best.pt",map_location="cpu",weights_only=True)["state_dict"])
    _write(run/"train_metrics.json",_evaluate(model,train,norm,details=True))
    _write(run/"validation_metrics.json",_evaluate(model,validation,norm,details=True))
    if _hashes() != hashes:
        raise ValueError("V5 sources changed during optimization; final evaluation refused")
    names = ("config.json","acceptance.json","history.jsonl","initial.pt","best.pt","last.pt","train_metrics.json","validation_metrics.json")
    _write(run/"selection.json",dict(best_epoch=best_epoch,epochs_run=epoch,validation_loss=best,
               files={name:hashfile(run/name) for name in names},final_test_performed=False))
    print("V5 saved:",run,"Selected epoch:",best_epoch,"Final test reserved.",flush=True)
    return run


def checked_run(run):
    run = Path(run).resolve()
    claim = _read(_claim())
    if (run.parent != _run_root() or claim["directory"] != run.name
            or claim["manifest_sha256"] != MANIFEST_PIN):
        raise ValueError("Run does not match the local V5 claim")
    config,selected = _read(run/"config.json"),_read(run/"selection.json")
    if (config["protocol"] != PROTOCOL or config["config"] != CONFIG or config["manifest_sha256"] != MANIFEST_PIN
            or config["audit_sha256"] != AUDIT_PIN or config["source_hashes"] != _hashes()):
        raise ValueError("V5 run sources, data or configuration changed")
    names = {"config.json","acceptance.json","history.jsonl","initial.pt","best.pt","last.pt","train_metrics.json","validation_metrics.json"}
    if set(selected["files"]) != names or any(hashfile(run/name) != digest for name,digest in selected["files"].items()):
        raise ValueError("V5 checkpoint or run artifacts changed")
    if any(hashfile(run/"source"/name) != digest for name,digest in config["source_hashes"].items()):
        raise ValueError("V5 archived source snapshot changed")
    return run,config,selected


def final_test(run, *, accept_selected=False):
    """Separate one-shot test; claim before opening any reserved raw records."""
    if accept_selected is not True:
        raise ValueError("Review validation and explicitly accept the selected checkpoint")
    run,config,selected = checked_run(run)
    if (run/"test-started.json").exists() or (run/"test_metrics.json").exists():
        raise RuntimeError("Final test already attempted; inspect saved artifacts without reopening the test")
    _write(run/"test-started.json",dict(best_checkpoint_sha256=selected["files"]["best.pt"],epoch=selected["best_epoch"]))
    _,audit = candidate()
    test = load(DATA,{"test"},MANIFEST_PIN)
    _counts(test,"test",audit)
    torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
    model = _model()
    model.load_state_dict(torch.load(run/"best.pt",map_location="cpu",weights_only=True)["state_dict"])
    report = _evaluate(model,test,config["normalization"],details=True)
    checked_run(run)
    _write(run/"test_metrics.json",report)
    _write(run/"test-complete.json",dict(test_metrics_sha256=hashfile(run/"test_metrics.json"),
                                        best_checkpoint_sha256=selected["files"]["best.pt"]))
    return report


if __name__ == "__main__":
    print(json.dumps(preflight(),indent=2,allow_nan=False))
