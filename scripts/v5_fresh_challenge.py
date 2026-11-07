"""Evaluate the frozen V5 checkpoint and an offline slow-auth prototype."""
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import uuid

import torch

from scripts.temporal_challenge import binary
from scripts.v4_broad_challenge import analyze, score_rows
from scripts.verification_v2_study import recheck
from sentinel.detection.slow_auth_review import VERSION as SLOW_VERSION, slow_auth_hits
from sentinel.features import canonical_hash
from training import diverse_experiment as v5
from training.experiment_data import ROOT, hashfile
from training.fresh_scenarios import FORMATS, emit
from training.v5_fresh_scenarios import RECIPES, RESERVED_SEEDS, SEEDS, VERSION, plan

RUN = ROOT / "training/runs/cnn-v5-20261105T052845Z-1baa855d"
BASE = ROOT / "data/private"
CANONICAL = {"windows-json", "linux-text"}
PHASES = {"challenge": SEEDS, "reserved": RESERVED_SEEDS}


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def signature(rows, policies):
    return canonical_hash([(row.get("slot"), row.get("vector"), row["context_sha256"], row["activity_truth"],
                            row["prediction"], row["scores"], [row[key]["requires_review"] for key in policies])
                           for row in rows])


def assess_source(episode, raw, expected, source, fmt, model, norm, prototype):
    base, decoded = analyze(raw, episode, fmt, expected, source, model, norm)
    extraction = decoded["extraction"]
    rows = recheck(base, {source: extraction})
    for row in rows:
        row.pop("previous_combined")
    if prototype:
        coverage = {row["window_id"]: row["coverage"] for row in rows if row.get("window_id")}
        hits = slow_auth_hits((window, extraction.members[window.window_id], coverage[window.window_id])
                              for window in extraction.windows) if extraction else {}
        for row in rows:
            evidence = hits.get(row.get("window_id"), [])
            row["slow"] = dict(requires_review=row["combined"]["requires_review"] or bool(evidence),
                               slow_auth_evidence_ids=evidence)
    return rows, decoded


def summarize(rows, policies, training_contexts):
    canonical = [row for row in rows if row["format"] in CANONICAL]
    unique = {}
    for row in canonical:
        if row["activity_truth"] is None:
            continue
        key = (row["platform"], row["context_sha256"])
        original = unique.setdefault(key, row)
        if original["activity_truth"] != row["activity_truth"]:
            raise ValueError("Exact causal input has conflicting activity labels")
    supported = [dict(row, truth=row["activity_truth"] != 0) for row in canonical if row["activity_truth"] is not None]
    misses = [row for row in canonical if row["truth"] is True and not row[policies[-1]]["requires_review"]]
    result = dict(canonical_units=len(canonical), supported_windows=sum(row["activity_truth"] is not None for row in canonical),
                  unique_supported=len(unique), exact_training_context_matches=len(unique.keys() & training_contexts),
                  context={key: binary(canonical, key) for key in policies},
                  activity_review={key: binary(supported, key) for key in policies},
                  unassessed_total=sum(row["activity_truth"] is None for row in canonical),
                  unassessed_reviewed={key: sum(row["activity_truth"] is None and row[key]["requires_review"]
                                                for row in canonical) for key in policies},
                  context_misses_by_case=dict(Counter(row["case"] for row in misses)),
                  context_misses_by_status=dict(Counter(row["label_status"] for row in misses)))
    scored = score_rows(list(unique.values()))
    result.update(activity=scored["activity"], confidence=scored["confidence"],
                  high_score_errors=sum(max(row["scores"]) >= .9 and row["activity_truth"] != row["prediction"] for row in unique.values()))
    result["cases"] = {name: {key: binary([row for row in canonical if row["case"] == name], key) for key in policies}
                       for name in RECIPES}
    if "slow" in policies:
        added = [row for row in canonical if row["slow"]["requires_review"] and not row["combined"]["requires_review"]]
        result["added_reviews_by_case"] = dict(Counter(row["case"] for row in added))
        result["added_reviews"] = dict(total=len(added), simulated_unapproved=sum(row["truth"] is True for row in added),
                                       benign=sum(row["truth"] is False for row in added), unknown=sum(row["truth"] is None for row in added))
    return result, misses


def projection_checks(rows, policies):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["case"], row["seed"], row["platform"], row["format"])].append(row)
    paired = {}
    count = 0
    for (case, seed, platform, fmt), projection in groups.items():
        if fmt not in CANONICAL:
            continue
        other = "windows-csv" if platform == "windows" else "linux-journal-json"
        digest = signature(projection, policies)
        if digest != signature(groups[case, seed, platform, other], policies):
            raise ValueError(f"Equivalent export formats disagree for {case}, {seed}, {platform}")
        count += 1
        if case in ("slow_same_identity", "benign_same_identity"):
            paired.setdefault((seed, platform), {})[case] = digest
    if any(len(pair) != 2 or len(set(pair.values())) != 1 for pair in paired.values()):
        raise ValueError("Matched retry inputs and decisions differ by simulated authorization")
    return dict(format_equivalence_pairs=count, matched_authorization_pairs=len(paired))


def existing_raw_hashes():
    hashes = set()
    for name in ("manifest.json", "sources.json", "holdout-sources.json", "challenge-sources.json", "reserved-sources.json"):
        for path in BASE.glob(f"*/{name}"):
            payload = read(path)
            sources = payload.get("sources", []) if isinstance(payload, dict) else payload
            hashes.update(source["raw_sha256"] for source in sources if "raw_sha256" in source)
    return hashes


def run_study():
    run, config, selection = v5.checked_run(RUN)
    test = read(run / "test-complete.json")
    if test["best_checkpoint_sha256"] != selection["files"]["best.pt"]:
        raise ValueError("Study checkpoint does not match the completed final test")
    if not BASE.resolve().is_relative_to(ROOT):
        raise ValueError("Study directory must stay inside V1")
    previous_raw = existing_raw_hashes()
    out = BASE / f"v5-fresh-{uuid.uuid4().hex[:12]}"
    out.mkdir()
    names = ("scripts/v5_fresh_challenge.py", "training/v5_fresh_scenarios.py", "training/fresh_scenarios.py",
             "scripts/v4_broad_challenge.py", "scripts/verification_v2_study.py", "scripts/audit_existing_dataset.py",
             "sentinel/detection/verification.py", "sentinel/detection/temporal_verification.py",
             "sentinel/detection/context_verification_v2.py", "sentinel/detection/slow_auth_review.py",
             "docs/V5_FRESH_CHALLENGE_PROTOCOL.md")
    hashes = {name: hashfile(ROOT / name) for name in names}
    write(out / "freeze.json", dict(version=VERSION, slow_policy=SLOW_VERSION, source_hashes=hashes,
                                     checkpoint_sha256=selection["files"]["best.pt"], phases=PHASES, recipes=RECIPES,
                                     manifest_sha256=v5.MANIFEST_PIN, config_sha256=selection["files"]["config.json"]))
    for name in names:
        snapshot = out / "source" / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes((ROOT / name).read_bytes())
    print("OUTPUT", out, flush=True)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    model = v5._model().eval()
    model.load_state_dict(torch.load(run / "best.pt", map_location="cpu", weights_only=True)["state_dict"])
    training = v5.load(v5.DATA, {"train"}, v5.MANIFEST_PIN)
    training_contexts = {(session["platform"], canonical_hash(session["vectors"][i-4:i+1]))
                         for session in training for i in range(4, len(session["vectors"]))}
    del training
    results = {}
    for phase, seeds in PHASES.items():
        prototype = phase == "reserved"
        policies = ("cnn", "combined", "slow") if prototype else ("cnn", "combined")
        ledger, rows = [], []
        for recipe in RECIPES:
            for seed in seeds:
                for fmt in FORMATS:
                    platform = fmt.split("-")[0]
                    episode = plan(recipe, seed, platform)
                    source = f"{phase}-{len(ledger):04d}"
                    raw, expected = emit(episode, fmt)
                    raw_path = out / f"{source}.raw"
                    raw_path.write_bytes(raw)
                    raw_hash = hashfile(raw_path)
                    if raw_hash in previous_raw:
                        raise ValueError("Fresh export duplicates a previous raw source")
                    previous_raw.add(raw_hash)
                    truth_path = out / f"{source}.truth.json"
                    write(truth_path, dict(episode=episode, expected_record_types=expected))
                    analyzed, decoded = assess_source(episode, raw, expected, source, fmt, model, config["normalization"], prototype)
                    if decoded["fatal"]:
                        raise ValueError(f"Unexpected source parse failure: {source}")
                    rows.extend(analyzed)
                    parsed = decoded["parsed"]
                    ledger.append(dict(id=source, recipe=recipe, seed=seed, format=fmt, raw=raw_path.name,
                                       raw_sha256=raw_hash, truth=truth_path.name, truth_sha256=hashfile(truth_path),
                                       accepted=len(parsed.events), rejected=len(parsed.rejected),
                                       warnings=sum(bool(event.parsing_errors) for event in parsed.events)))
            print(phase, recipe, len(ledger), "exports", flush=True)
        stats, misses = summarize(rows, policies, training_contexts)
        stats.update(projection_checks(rows, policies), exports=len(ledger),
                     accepted_events=sum(item["accepted"] for item in ledger), rejected=sum(item["rejected"] for item in ledger),
                     parser_warnings=sum(item["warnings"] for item in ledger))
        results[phase] = stats
        write(out / f"{phase}-sources.json", ledger)
        write(out / f"{phase}-misses.json", misses)
        with (out / f"{phase}-predictions.jsonl").open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, allow_nan=False) + "\n")
    write(out / "results.json", results)
    if any(hashfile(ROOT / name) != digest for name, digest in hashes.items()):
        raise ValueError("Study source changed during evaluation")
    v5.checked_run(RUN)
    artifacts = ["freeze.json", "results.json"] + [f"{phase}-{kind}" for phase in PHASES
                 for kind in ("sources.json", "misses.json", "predictions.jsonl")]
    write(out / "complete.json", {name: hashfile(out / name) for name in artifacts})
    print("COMPLETE", out, flush=True)
    return out


def verify_saved(folder):
    folder = folder.resolve()
    if not folder.is_relative_to(BASE.resolve()):
        raise ValueError("Study review must stay inside V1/data/private")
    for name, digest in read(folder / "complete.json").items():
        if hashfile(folder / name) != digest:
            raise ValueError(f"Changed artifact: {name}")
    freeze = read(folder / "freeze.json")
    _, _, selection = v5.checked_run(RUN)
    if freeze["checkpoint_sha256"] != selection["files"]["best.pt"]:
        raise ValueError("Changed checkpoint")
    for name, digest in freeze["source_hashes"].items():
        if hashfile(folder / "source" / name) != digest or hashfile(ROOT / name) != digest:
            raise ValueError(f"Changed source: {name}")
    results = read(folder / "results.json")
    review = {}
    for phase in PHASES:
        sources = read(folder / f"{phase}-sources.json")
        for source in sources:
            for kind in ("raw", "truth"):
                if hashfile(folder / source[kind]) != source[f"{kind}_sha256"]:
                    raise ValueError(f"Changed export: {source[kind]}")
        rows = [json.loads(line) for line in (folder / f"{phase}-predictions.jsonl").read_text(encoding="utf-8").splitlines()]
        canonical = [row for row in rows if row["format"] in CANONICAL]
        policies = tuple(results[phase]["context"])
        for policy in policies:
            counts = Counter((row["truth"], row[policy]["requires_review"]) for row in canonical)
            actual = {"TP": counts[True, True], "FP": counts[False, True], "FN": counts[True, False], "TN": counts[False, False]}
            if any(actual[key] != results[phase]["context"][policy][key] for key in actual):
                raise ValueError(f"Context counts disagree for {phase}, {policy}")
        if "slow" in policies and any(row["combined"]["requires_review"] and not row["slow"]["requires_review"] for row in rows):
            raise ValueError("Prototype suppressed an existing review")
        review[phase] = dict(exports=len(sources), canonical_units=len(canonical), **projection_checks(rows, policies))
    write(folder / "independent_review.json", review)
    print(json.dumps(review, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.run:
        run_study()
    else:
        verify_saved(args.verify)
