"""Explicit owner-run V4 experiment. Import/check/evaluate never optimize weights."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib.metadata import distributions
import json
from pathlib import Path
import platform
import random
import uuid

from pydantic import Field
import torch
from torch.nn import functional as F

from sentinel.features import FEATURE_VERSION, schema_hash
from sentinel.schemas import Contract, Sha256, Text
from sentinel.detection.temporal_verification import verify_series
from training.experimental_cnn import SentinelCNN
from training.experiment_data import ROOT, hashfile, metrics, normalize_fit
from training.label_contract import LABEL_VERSION
from training.mixed_data import IGNORE_TARGET, load, observable_rule
from training.mixed_preflight import tensors, masked_loss
from scripts.temporal_challenge import binary, confidence_diagnostics

DATA = ROOT / "data/private/candidate-v4-cebc93b57424"
MANIFEST_PIN = "f9905a7cc06427dc41f7c6d35faa91e2878f5e5dd311b718fc0e66507e4b3f23"
REVIEW = ROOT / "training/reviews/candidate_v4_owner_run.json"
PROTOCOL = "masked-cnn-v4-experiment-v1"
CONFIG = dict(seed=84, epochs=200, patience=25, min_delta=.0001, learning_rate=.001,
              weight_decay=.0001, batch_segments=8, device="cpu",
              architecture="causal-18-32-32-k3-dropout0.1-linear4-v1",
              class_weighting="none", pair_policy="one-approved-counterpart-per-group-os-segment")


class ExperimentReview(Contract):
    protocol: Text
    candidate: Text
    manifest_sha256: Sha256
    audit_sha256: Sha256
    label_version: Text
    decision: Text
    reviewer: Text
    authorization_reference: Text
    recorded_local_date: Text
    execution: Text
    annotation_review_scope: Text
    accepted_limitations: list[Text] = Field(min_length=1)
    pair_policy: Text


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)


def load_review(path=REVIEW):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError("Review record must be an existing V1-local file")
    record = ExperimentReview.model_validate_json(path.read_text(encoding="utf-8"))
    candidate = (ROOT / record.candidate).resolve()
    if candidate != DATA.resolve() or not candidate.is_relative_to(ROOT):
        raise ValueError("Review is for a different or outside candidate")
    if (record.protocol != PROTOCOL or record.manifest_sha256 != MANIFEST_PIN
            or record.label_version != LABEL_VERSION or record.decision != "approve_limited_experimental_run"
            or record.execution != "owner_only" or record.annotation_review_scope != "corpus_procedural_labels_not_individual_field_truth"
            or record.pair_policy != CONFIG["pair_policy"]):
        raise ValueError("Review scope, protocol, dataset or label version does not match")
    if hashfile(candidate / "manifest.json") != record.manifest_sha256 or hashfile(candidate / "audit.json") != record.audit_sha256:
        raise ValueError("Reviewed candidate or audit has changed")
    audit = json.loads((candidate / "audit.json").read_text())
    if audit["manifest_sha256"] != MANIFEST_PIN or audit["status"] != "candidate_pending_review":
        raise ValueError("Reviewed audit does not establish the expected candidate")
    return record


def apply_review(sessions, record):
    """In-memory corpus acceptance overlay. Original pending annotations stay intact."""
    if record.decision != "approve_limited_experimental_run" or record.manifest_sha256 != MANIFEST_PIN:
        raise ValueError("Procedural proposals have not been accepted for this experiment")
    return [dict(s, targets=list(s["candidate_targets"]), provisional_only=False,
                 target_basis="owner-accepted procedural corpus; original annotations remain pending") for s in sessions]


def unique_pairs(sessions):
    groups = defaultdict(list)
    for session in sessions:
        groups[session["split"], session["group"], session["platform"], session["segment"]].append(session)
    primary = []
    for pair in groups.values():
        if len(pair) != 2 or {s["approved"] for s in pair} != {True, False}:
            raise ValueError("Expected exactly one approved/unapproved counterpart pair")
        if pair[0]["vectors"] != pair[1]["vectors"] or pair[0]["targets"] != pair[1]["targets"]:
            raise ValueError("Matched counterparts disagree on observable inputs/targets")
        primary.append(next(s for s in pair if s["approved"]))
    return primary


def evaluation(model, sessions, norm, *, context=False):
    """Primary activity metrics count matched X once; context retains both versions."""
    if len({s["split"] for s in sessions}) != 1:
        raise ValueError("Evaluate exactly one data split at a time")
    primary = unique_pairs(sessions)
    model.eval()
    cache, truth, predicted, rules, confidence, all_rows = {}, [], [], [], [], []
    total_loss = 0.
    for session in primary:
        x, targets = tensors([session], norm)
        with torch.no_grad():
            logits = model(x)
            score = logits.softmax(1)[0].transpose(0, 1).tolist()
            total_loss += F.cross_entropy(logits, targets, ignore_index=IGNORE_TARGET, reduction="sum").item()
        cache[session["group"], session["platform"], session["segment"]] = score
        for i, target in enumerate(session["targets"]):
            if target == IGNORE_TARGET:
                continue
            pred = max(range(4), key=score[i].__getitem__)
            rule = observable_rule(session["vectors"][max(0, i-4):i+1])
            if rule is None:
                raise ValueError("Mixed activity cannot have a four-class target")
            truth.append(target); predicted.append(pred); rules.append(rule)
            confidence.append(dict(truth=target, prediction=pred, scores=score[i], platform=session["platform"], volume=session["volumes"][i]))
    if not truth:
        raise ValueError("No eligible reviewed targets for evaluation")
    result = dict(loss=total_loss/len(truth), activity=metrics(truth, predicted), rule=metrics(truth, rules),
                  primary_segments=len(primary), primary_observed_windows=sum(len(s["vectors"]) for s in primary),
                  primary_supported_windows=len(truth),
                  primary_masked_windows=sum(len(s["vectors"]) for s in primary)-len(truth),
                  confidence=confidence_diagnostics(confidence),
                  subsets={f"{key}:{value}": metrics([r["truth"] for r in confidence if r[key] == value],
                                                       [r["prediction"] for r in confidence if r[key] == value])
                           for key in ("platform", "volume") for value in sorted({r[key] for r in confidence})})
    if not context:
        return result
    for session in sessions:
        scores = cache[session["group"], session["platform"], session["segment"]]
        sequence, rows = [], []
        for i, (score, annotation) in enumerate(zip(scores, session["annotations"], strict=True)):
            pred = max(range(4), key=score.__getitem__)
            # Only parser-derived coverage/history/evidence reaches backup checks.
            # Authorization, activity target and mask status are evaluation truth only.
            sequence.append(dict(host=session["host"], platform=session["platform"],
                session_id=f"{session['id']}:{session['segment']}", start_utc=session["starts_utc"][i],
                verification=dict(vector=session["vectors"][i], model_class=pred, probabilities=score,
                                  coverage=session["coverage_by_window"][i], history_windows=min(i,4),
                                  feature_version=FEATURE_VERSION, feature_schema_sha256=schema_hash(),
                                  evidence_ids=annotation.evidence_event_ids)))
            security = annotation.authorization.status
            rows.append(dict(source=session["id"], segment=session["segment"], window=i, group=session["group"],
                             platform=session["platform"], volume=session["volumes"][i], phase=session["phases"][i],
                             label_status=annotation.label_status, activity_truth=None if session["targets"][i] == IGNORE_TARGET else session["targets"][i],
                             truth=True if security == "simulated_unapproved" else False if security == "authorized" else None,
                             security_context=security, prediction=pred, scores=score,
                             cnn=dict(requires_review=pred != 0), evidence_ids=annotation.evidence_event_ids))
        for row, decision in zip(rows, verify_series(sequence), strict=True):
            row["combined"] = decision
        all_rows.extend(rows)
    result["simulated_context_review"] = {key: binary(all_rows, key) for key in ("cnn", "combined")}
    result["context_subsets"] = {status: binary([r for r in all_rows if r["label_status"] == status], "combined")
                                 for status in sorted({r["label_status"] for r in all_rows})}
    result["normal_activity_simulated_unapproved"] = binary([r for r in all_rows if r["activity_truth"] == 0 and r["truth"] is True], "combined")
    result["predictions"] = all_rows
    result["context_metric_note"] = "Both counterparts included for declared simulation context; correlated windows, not independent field accuracy. Review requests are not confirmed attacks."
    return result


def source_hashes():
    names = ("training/mixed_experiment.py", "training/mixed_data.py", "training/mixed_preflight.py",
             "training/mixed_candidate.py", "training/label_contract.py", "training/experiment_data.py",
             "training/experimental_cnn.py", "sentinel/features.py", "sentinel/ingest/windows.py",
             "sentinel/ingest/linux.py", "sentinel/ingest/common.py", "sentinel/detection/verification.py",
             "sentinel/detection/temporal_verification.py", "scripts/temporal_challenge.py")
    return {name: hashfile(ROOT/name) for name in names}


def prepare(review_path=REVIEW):
    record = load_review(review_path)
    sessions = apply_review(load(DATA, {"train", "validation"}, MANIFEST_PIN), record)
    training = [s for s in sessions if s["split"] == "train"]
    validation = [s for s in sessions if s["split"] == "validation"]
    primary = unique_pairs(training)
    norm = normalize_fit(primary)
    return record, training, validation, norm


def readiness(review_path=REVIEW):
    record, training, validation, norm = prepare(review_path)
    return dict(status="prepared_owner_run_not_started", review_sha256=hashfile(review_path), manifest_sha256=MANIFEST_PIN,
                train_primary_segments=len(unique_pairs(training)), validation_primary_segments=len(unique_pairs(validation)),
                train_unique_supported=sum(t != IGNORE_TARGET for s in unique_pairs(training) for t in s["targets"]),
                validation_unique_supported=sum(t != IGNORE_TARGET for s in unique_pairs(validation) for t in s["targets"]),
                normalization_fit_observed_train_windows=norm["fit_windows"],
                class_counts=dict(Counter(t for s in unique_pairs(training) for t in s["targets"] if t != IGNORE_TARGET)),
                test_inputs_loaded=False, optimizer_created=False, training_started=False)


def new_model():
    model = SentinelCNN()
    if sum(p.numel() for p in model.parameters()) != 4996:
        raise ValueError("Original architecture changed")
    return model


def run_claim(review_path):
    return ROOT / "training/runs" / ("v4-run-"+hashfile(review_path)+".json")


def owner_run(review_path=REVIEW):
    """Notebook re-entry: reuse a completed run; never silently restart a partial one."""
    load_review(review_path)
    claim = run_claim(review_path)
    if claim.exists():
        pointer = json.loads(claim.read_text())
        if pointer["review_sha256"] != hashfile(review_path):
            raise ValueError("Run pointer belongs to a different owner review")
        run = (ROOT/pointer["run_relative"]).resolve()
        if not run.is_relative_to(ROOT/"training/runs"):
            raise ValueError("Saved run pointer is outside the project")
        if not (run/"selection.json").exists():
            raise RuntimeError("This experiment already started but is incomplete; inspect its artifacts before any new run")
        if checked_run(run)[1]["review_sha256"] != hashfile(review_path):
            raise ValueError("Saved run does not belong to this owner review")
        print("Reusing completed run:", run, flush=True)
        return run
    return train(review_path)


def train(review_path=REVIEW):
    """Only explicit owner invocation starts optimization; never opens final test."""
    record, training, validation, norm = prepare(review_path)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    random.seed(CONFIG["seed"]); torch.manual_seed(CONFIG["seed"])
    primary = unique_pairs(training)
    x, y = tensors(primary, norm)
    if not (y != IGNORE_TARGET).any():
        raise ValueError("No supported training targets")
    run_root = (ROOT / "training/runs").resolve()
    if not run_root.is_relative_to(ROOT):
        raise ValueError("Run directory must stay inside V1")
    run = run_root / ("cnn-v4-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8])
    run_root.mkdir(parents=True, exist_ok=True)
    # Exclusive claim also protects concurrent notebook cells/processes.
    try:
        write(run_claim(review_path), dict(run_relative=run.relative_to(ROOT).as_posix(), review_sha256=hashfile(review_path)))
    except FileExistsError as error:
        raise RuntimeError("This approved experiment already started; use owner_run() or inspect the existing artifacts") from error
    run.mkdir(parents=True, exist_ok=False)
    hashes = source_hashes()
    config = dict(protocol=PROTOCOL, config=CONFIG, source_hashes=hashes, manifest_sha256=MANIFEST_PIN,
                  dataset_manifest=json.loads((DATA/"manifest.json").read_text()),
                  review_sha256=hashfile(review_path), review=record.model_dump(mode="json"),
                  review_source_relative=Path(review_path).resolve().relative_to(ROOT).as_posix(),
                  normalization=norm, python=platform.python_version(), torch=torch.__version__, platform=platform.platform(),
                  pair_policy=CONFIG["pair_policy"], label_version=LABEL_VERSION)
    write(run/"config.json", config)
    (run/"review.json").write_bytes(Path(review_path).read_bytes())
    write(run/"installed-packages.json", sorted([dict(name=d.metadata["Name"],version=d.version) for d in distributions()], key=lambda x:x["name"].lower()))
    for name in hashes:
        target = run/"source"/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT/name).read_bytes())
    model = new_model()
    torch.save(dict(state_dict=model.state_dict(), rng=torch.get_rng_state()), run/"initial.pt")
    optimizer = torch.optim.Adam(model.parameters(), lr=CONFIG["learning_rate"], weight_decay=CONFIG["weight_decay"])
    best, patience_reference, stale, best_epoch = float("inf"), float("inf"), 0, 0
    history = []
    for epoch in range(1, CONFIG["epochs"]+1):
        model.train()
        for batch in torch.randperm(len(primary)).split(CONFIG["batch_segments"]):
            if not (y[batch] != IGNORE_TARGET).any():
                continue
            optimizer.zero_grad()
            loss = masked_loss(model(x[batch]), y[batch])
            if not torch.isfinite(loss):
                raise ValueError("Nonfinite training loss")
            loss.backward(); optimizer.step()
        tr, va = evaluation(model, training, norm), evaluation(model, validation, norm)
        if not all(torch.isfinite(torch.tensor(r["loss"])) for r in (tr, va)):
            raise ValueError("Nonfinite selection loss")
        row = dict(epoch=epoch, train_loss=tr["loss"], validation_loss=va["loss"],
                   train_macro_f1=tr["activity"]["macro_f1"], validation_macro_f1=va["activity"]["macro_f1"])
        history.append(row)
        with (run/"history.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row)+"\n")
        checkpoint = dict(state_dict=model.state_dict(), optimizer=optimizer.state_dict(), epoch=epoch, rng=torch.get_rng_state())
        if va["loss"] < best:
            best, best_epoch = va["loss"], epoch
            torch.save(checkpoint, run/"best.pt")
        if va["loss"] < patience_reference-CONFIG["min_delta"]:
            patience_reference, stale = va["loss"], 0
        else:
            stale += 1
        if epoch == 1 or epoch % 10 == 0:
            print(row, flush=True)
        if stale >= CONFIG["patience"]:
            break
    torch.save(checkpoint, run/"last.pt")
    model.load_state_dict(torch.load(run/"best.pt", map_location="cpu", weights_only=True)["state_dict"])
    write(run/"train_metrics.json", evaluation(model, training, norm, context=True))
    write(run/"validation_metrics.json", evaluation(model, validation, norm, context=True))
    if source_hashes() != hashes or hashfile(review_path) != config["review_sha256"] or hashfile(DATA/"manifest.json") != MANIFEST_PIN:
        raise ValueError("Sources/review changed during the run; final test refused")
    write(run/"selection.json", dict(best_epoch=best_epoch, epochs_run=epoch, best_checkpoint_sha256=hashfile(run/"best.pt"),
                                     initial_checkpoint_sha256=hashfile(run/"initial.pt"), config_sha256=hashfile(run/"config.json"),
                                     test_evaluated=False, train_metrics_sha256=hashfile(run/"train_metrics.json"),
                                     validation_metrics_sha256=hashfile(run/"validation_metrics.json")))
    print("Artifacts:", run, "Selected epoch:", best_epoch, "Final test not evaluated.", flush=True)
    return run


def checked_run(run):
    run = Path(run).resolve()
    if not run.is_relative_to(ROOT/"training/runs"):
        raise ValueError("Run must stay inside V1/training/runs")
    config = json.loads((run/"config.json").read_text())
    selected = json.loads((run/"selection.json").read_text())
    if config["protocol"] != PROTOCOL or config["config"] != CONFIG or config["manifest_sha256"] != MANIFEST_PIN:
        raise ValueError("Wrong run protocol/config/dataset")
    if hashfile(run/"config.json") != selected["config_sha256"] or source_hashes() != config["source_hashes"]:
        raise ValueError("Run configuration or source code changed")
    checks = {"best.pt": "best_checkpoint_sha256", "initial.pt": "initial_checkpoint_sha256",
              "train_metrics.json": "train_metrics_sha256", "validation_metrics.json": "validation_metrics_sha256"}
    if any(hashfile(run/name) != selected[key] for name, key in checks.items()) or hashfile(DATA/"manifest.json") != MANIFEST_PIN:
        raise ValueError("Checkpoint, metrics or dataset changed")
    if hashfile(run/"review.json") != config["review_sha256"]:
        raise ValueError("Review snapshot changed")
    original_review = (ROOT/config["review_source_relative"]).resolve()
    if not original_review.is_relative_to(ROOT) or hashfile(original_review) != config["review_sha256"]:
        raise ValueError("Owner review changed or moved outside V1")
    load_review(run/"review.json")
    return run, config, selected


def final_test(run, *, accept_selected=False):
    """Explicit one-shot evaluation of selected weights. Marker claimed before loading test."""
    if accept_selected is not True:
        raise ValueError("Review train/validation first, then explicitly accept the selected checkpoint")
    run, config, selected = checked_run(run)
    if (run/"test-started.json").exists() or (run/"test_metrics.json").exists():
        raise RuntimeError("Final test already attempted; use saved results, not a retuned/repeated test")
    record = ExperimentReview(**config["review"])
    write(run/"test-started.json", dict(checkpoint_sha256=selected["best_checkpoint_sha256"], epoch=selected["best_epoch"]))
    sessions = apply_review(load(DATA, {"test"}, MANIFEST_PIN), record)
    model = new_model()
    model.load_state_dict(torch.load(run/"best.pt", map_location="cpu", weights_only=True)["state_dict"])
    result = evaluation(model, sessions, config["normalization"], context=True)
    write(run/"test_metrics.json", result)
    write(run/"SUMMARY.json", dict(best_epoch=selected["best_epoch"], test_activity=result["activity"],
        test_rule=result["rule"], test_confidence=result["confidence"], context_review=result["simulated_context_review"],
        primary_test_supported=result["primary_supported_windows"], full_context_windows=len(result["predictions"]),
        limitations=["Procedural synthetic activity labels, not field accuracy.", "Rule labels are reproducible by construction.",
                     "Matched counterpart dependence handled for activity metrics; context windows remain correlated.",
                     "Normal activity can have simulated-unapproved context. No calibrated security probability or zero-miss guarantee.",
                     "No production or scored-use deployment."]))
    print(json.dumps(json.loads((run/"SUMMARY.json").read_text()), indent=2))
    return result
