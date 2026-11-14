"""Hash-checked V4 candidate review loader/audit. Does not approve or train data."""
from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path

from sentinel.features import FEATURE_ORDER, canonical_hash, schema_hash
from training.experiment_data import ROOT, baseline, hashfile, metrics, normalize_fit
from training.label_contract import CLASS_ORDER, LABEL_VERSION, WindowAnnotation, conflicting_contexts
from training.mixed_candidate import VERSION, inspect_source

IGNORE_TARGET = -100


def proposal_target(annotation):
    """For candidate audit ONLY; pending owner review is not training approval."""
    return CLASS_ORDER.index(annotation.observable_activity) if annotation.label_status == "supported" else IGNORE_TARGET


def observable_rule(history):
    """Independent feature-side proxy baseline; ambiguity remains None."""
    rows = [dict(zip(FEATURE_ORDER, v, strict=True)) for v in history[-5:]]
    current = rows[-1]
    failures = [r["auth_failure_count"] for r in rows]
    classes = []
    if failures[-1] >= 5 or (failures[-1] > 0 and sum(failures) >= 5 and sum(n > 0 for n in failures) >= 2):
        classes.append(1)
    if current["account_created_count"] > 0:
        classes.append(2)
    if sum(current[k] for k in ("service_installed_count", "service_state_change_count", "service_activity_count")) > 0:
        classes.append(3)
    return classes[0] if len(classes) == 1 else 0 if not classes else None


def _local(folder, name):
    path = (folder / name).resolve()
    if not path.is_relative_to(folder) or not path.is_file():
        raise ValueError("Candidate artifact is missing or outside its directory")
    return path


def load(folder, splits, manifest_pin):
    folder = Path(folder).resolve()
    if not folder.is_relative_to(ROOT) or not splits or not set(splits) <= {"train", "validation", "test"}:
        raise ValueError("Explicit V1-local candidate and valid splits required")
    if hashfile(_local(folder, "manifest.json")) != manifest_pin:
        raise ValueError("Candidate manifest hash changed")
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest["version"] != VERSION or manifest["label_version"] != LABEL_VERSION or manifest["classes"] != list(CLASS_ORDER) or manifest["feature_schema_sha256"] != schema_hash():
        raise ValueError("Candidate feature/label contract changed")
    for name, digest in manifest["source_hashes"].items():
        if hashfile(_local(folder, "source/" + name)) != digest or hashfile(_local(ROOT, name)) != digest:
            raise ValueError("Candidate preparation code changed; review/version explicitly")
    lineage = {name: defaultdict(set) for name in ("group", "family", "seed", "raw_sha256")}
    identities = set()
    result = []
    for source in manifest["sources"]:
        if source["id"] in identities:
            raise ValueError("Duplicate source identity")
        identities.add(source["id"])
        for name in lineage:
            lineage[name][source[name]].add(source["split"])
        if source["split"] not in splits:
            continue  # Do not open raw/labels of unselected final-test sources.
        for name in ("raw", "labels"):
            if hashfile(_local(folder, source[name])) != source[name + "_sha256"]:
                raise ValueError("Raw source or annotations changed")
        side = json.loads((folder / source["labels"]).read_text())
        if any(side[k] != source[k] for k in ("group", "family", "seed", "split", "platform", "approved_counterpart")):
            raise ValueError("Scenario lineage does not match manifest")
        expanded = deepcopy(side)
        facts_by_index = {r["record_index"]: r for r in expanded["facts"]}
        if len(facts_by_index) != len(expanded["facts"]):
            raise ValueError("Duplicate event fact")
        for slot in expanded["slots"]:
            slot["facts"] = [facts_by_index[i] for i in slot["record_indices"]]
        annotations, parsed, extraction = inspect_source((folder / source["raw"]).read_bytes(), expanded, source["id"])
        if annotations != side["annotations"]:
            raise ValueError("Saved annotations disagree with raw facts, rubric or causal alignment")
        windows = extraction.windows
        if len(parsed.events) != source["events"] or len(windows) != source["windows"]:
            raise ValueError("Declared event/window counts changed")
        facts_flat = [i for slot in expanded["slots"] for i in slot["record_indices"]]
        if facts_flat != list(range(1, len(parsed.events) + 1)):
            raise ValueError("Scenario evidence references are incomplete or out of order")
        # Split on actual time gaps; never let convolutions bridge missing collection.
        blocks, current = [], []
        for i, window in enumerate(windows):
            if current and window.start_utc != windows[current[-1]].end_utc:
                blocks.append(current)
                current = []
            if window.host != windows[0].host or window.platform != side["platform"]:
                raise ValueError("Host/platform changed inside session")
            current.append(i)
        if current:
            blocks.append(current)
        decoded = [WindowAnnotation(**a) for a in annotations]
        for block_index, indices in enumerate(blocks):
            result.append(dict(id=source["id"], segment=block_index, group=side["group"], family=side["family"],
                               seed=side["seed"], split=side["split"], platform=side["platform"],
                               approved=side["approved_counterpart"],
                               auth_style=side["auth_style"],
                               vectors=[windows[i].vector for i in indices],
                               # Honest targets stay masked until annotation review is recorded.
                               targets=[decoded[i].training_target() if decoded[i].training_target() is not None else IGNORE_TARGET for i in indices],
                               candidate_targets=[proposal_target(decoded[i]) for i in indices],
                               annotations=[decoded[i] for i in indices],
                               phases=[side["slots"][i]["phase"] for i in indices],
                               volumes=[side["slots"][i]["volume"] for i in indices],
                               host=windows[0].host,
                               starts_utc=[windows[i].start_utc.isoformat() for i in indices],
                               coverage_by_window=[dict(collection_complete=True, rejected_records=0,
                                   unrecognized_events=sum(e.event_type is None for e in extraction.members[windows[i].window_id]),
                                   missing_timestamp=0, missing_host=0, excluded_records=0) for i in indices],
                               warning_events=sum(bool(e.parsing_errors) for i in indices for e in extraction.members[windows[i].window_id]),
                               events=sum(len(windows[i].event_ids) for i in indices),
                               provisional_only=True))
    if any(len(values) != 1 for collection in lineage.values() for values in collection.values()):
        raise ValueError("Related scenario lineage crosses data splits")
    return result


def audit(folder, manifest_pin):
    sessions = load(folder, {"train", "validation", "test"}, manifest_pin)
    counts, masked, contexts, event_counts, groups, families, seeds, sources = (Counter() for _ in range(8))
    vectors, causal, candidates, eligible = [], defaultdict(list), [], 0
    baseline_rows = defaultdict(list)
    auth_styles, tiny_windows = Counter(), Counter()
    gaps = Counter()
    trajectories = defaultdict(list)
    pairs = defaultdict(list)
    for session in sessions:
        split, platform = session["split"], session["platform"]
        event_counts[split, platform] += session["events"]
        groups[split, session["group"]] += 1
        families[split, session["family"]] += 1
        seeds[split, session["seed"]] += 1
        sources[session["id"]] += 1
        for i, (vector, annotation, target) in enumerate(zip(session["vectors"], session["annotations"], session["candidate_targets"], strict=True)):
            contexts[split, annotation.authorization.status] += 1
            eligible += session["targets"][i] != IGNORE_TARGET
            if vector[0] <= 3:
                tiny_windows[split, platform] += 1
            if target == IGNORE_TARGET:
                masked[split, platform, annotation.label_status] += 1
            else:
                counts[split, platform, target] += 1
                if target == 1:
                    auth_styles[split, platform, session["auth_style"]] += 1
                rule = observable_rule(session["vectors"][max(0, i-4):i+1])
                if rule is None:
                    raise ValueError("A supposedly supported target has mixed feature-side evidence")
                baseline_rows[split].append((target, baseline(vector), rule))
                if annotation.authorization.status == "simulated_unapproved" and target == 0:
                    gaps["simulated_unapproved_with_normal_activity"] += 1
                if annotation.authorization.status == "authorized" and target != 0:
                    gaps["authorized_with_non_normal_activity"] += 1
            vectors.append((split, platform, target, tuple(vector)))
            context = session["vectors"][max(0, i-4):i+1]
            causal[canonical_hash(context)].append((split, target, annotation.window_id, len(context)))
            # Check provisional label contradictions without forging saved reviewer status.
            reviewed_probe = annotation.model_copy(update={"review_status": "reviewed", "reviewer": "automated collision probe only"})
            candidates.append((reviewed_probe, context))
        signature = tuple(tuple(v) for v in session["vectors"])
        trajectories[signature].append((session["group"], split, session["id"], session["approved"]))
        pairs[session["group"], platform, session["segment"]].append(signature)
    norm = normalize_fit([s for s in sessions if s["split"] == "train"])
    scales = [max(1.0, v) for v in norm["scale"]]
    # All complete source trajectories, not just short post-gap segments.
    combined = defaultdict(list)
    for session in sessions:
        combined[session["id"]].append(session)
    full = []
    for source, segments in combined.items():
        segments.sort(key=lambda s: s["segment"])
        full.append(dict(id=source, group=segments[0]["group"], split=segments[0]["split"], platform=segments[0]["platform"],
                         vectors=[v for s in segments for v in s["vectors"]]))
    near = []
    for i, a in enumerate(full):
        for b in full[i+1:]:
            if a["platform"] != b["platform"] or a["group"] == b["group"]:
                continue
            distances = [abs(x-y)/scales[j] for va, vb in zip(a["vectors"], b["vectors"], strict=True) for j, (x, y) in enumerate(zip(va, vb, strict=True))]
            if max(distances) <= .25 and sum(distances)/len(distances) <= .02:
                near.append([a["id"], b["id"]])
    vector_counts = Counter(v for _, _, _, v in vectors)
    conflicts = conflicting_contexts(candidates)
    exact_cross_split_contexts = sum(len({split for split, _, _, _ in rows}) > 1 for rows in causal.values())
    cross_split_supported_contexts = sum(len({s for s, t, _, _ in rows if t != IGNORE_TARGET}) > 1 for rows in causal.values())
    cross_split_full_contexts = sum(len({s for s, _, _, length in rows if length == 5}) > 1 for rows in causal.values())
    recipe_coverage = []
    for split in ("train", "validation", "test"):
        for platform in ("windows", "linux"):
            for target, name in enumerate(CLASS_ORDER):
                selected = [s for s in sessions if s["split"] == split and s["platform"] == platform and target in s["candidate_targets"]]
                recipe_coverage.append(dict(split=split, platform=platform, activity=name, windows=counts[split, platform, target],
                                            groups=len({s["group"] for s in selected}), families=len({s["family"] for s in selected})))
    return dict(version=VERSION, manifest_sha256=manifest_pin, label_version=LABEL_VERSION,
                status="candidate_pending_review" if not conflicts and not cross_split_supported_contexts and not near else "structural_review_required",
                audit_source_sha256=hashfile(Path(__file__)),
                raw_events=sum(event_counts.values()), windows=len(vectors), sources=len(sources),
                contiguous_segments=len(sessions), independent_procedural_groups=len(groups), recipe_families=len(families), seeds=len(seeds),
                candidate_supported=sum(counts.values()), masked=sum(masked.values()), actual_reviewed_training_targets=eligible,
                class_counts=[dict(split=s, platform=p, activity=CLASS_ORDER[t], windows=n) for (s,p,t),n in sorted(counts.items())],
                masked_counts=[dict(split=s, platform=p, status=k, windows=n) for (s,p,k),n in sorted(masked.items())],
                coverage=recipe_coverage,
                event_counts=[dict(split=s, platform=p, events=n) for (s,p),n in sorted(event_counts.items())],
                authorization_counts=[dict(split=s, status=k, windows=n) for (s,k),n in sorted(contexts.items())],
                parser_rejected=0, expected_unrecognized_and_warning_events=sum(s["warning_events"] for s in sessions),
                independent_feature_mismatches=0, rubric_or_annotation_mismatches=0,
                all_pair_segments_identical=all(len(v)==2 and v[0]==v[1] for v in pairs.values()),
                matched_approval_pairs=len(pairs)//2, exact_repeated_current_vectors=sum(n-1 for n in vector_counts.values()),
                repeated_segment_signatures=sum(len(v)-1 for v in trajectories.values()),
                cross_group_exact_segment_signatures=sum(len({g for g,_,_,_ in rows})>1 for rows in trajectories.values()),
                exact_causal_target_conflict_groups=len(conflicts), exact_contexts_shared_across_splits=exact_cross_split_contexts,
                exact_supported_contexts_shared_across_splits=cross_split_supported_contexts,
                exact_full_five_window_contexts_shared_across_splits=cross_split_full_contexts,
                unique_supported_causal_inputs=len({signature for signature, rows in causal.items() if any(t != IGNORE_TARGET for _,t,_,_ in rows)}),
                auth_style_counts=[dict(split=s, platform=p, style=k, windows=n) for (s,p,k),n in sorted(auth_styles.items())],
                one_to_three_event_windows=[dict(split=s, platform=p, windows=n) for (s,p),n in sorted(tiny_windows.items())],
                context_activity_gaps=dict(gaps),
                proxy_baseline={split: {"old_thresholds": metrics([r[0] for r in rows], [r[1] for r in rows]),
                                         "observable_rubric": metrics([r[0] for r in rows], [r[2] for r in rows])}
                                for split, rows in baseline_rows.items()},
                feature_ranges={name: {"min": min(v[j] for _,_,_,v in vectors), "max": max(v[j] for _,_,_,v in vectors)}
                                for j, name in enumerate(FEATURE_ORDER)},
                near_duplicate_source_pairs=near,
                near_duplicate_definition="Same OS, different group, full 44 observed windows; training-only SD scale floored at 1; max absolute scaled distance <=0.25 and mean <=0.02. Not a universal similarity test.",
                train_only_normalization=norm, training_started=False, training_approved=False,
                test_inspection="Raw/labels/feature arithmetic structurally audited; no CNN final-test predictions or fitting performed.",
                limitations=["All labels are provisional procedural annotations, pending owner review; reviewed training target count is zero.",
                             "Related matched counterparts intentionally duplicate X within their own split; they are not independent extra examples.",
                             "Shared renderer/primitive log syntax across recipe families; no field generalization established.",
                             "Targets implement an observable rubric, not maliciousness. Rule agreement can be perfect by construction.",
                             "No fine-grained privilege/process detection or guaranteed zero false negatives."])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    report = audit(args.folder, args.manifest_sha256)
    output = args.folder.resolve() / "audit.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({k:v for k,v in report.items() if k not in ("train_only_normalization", "class_counts", "coverage", "event_counts", "authorization_counts", "masked_counts")}, indent=2))
    print("AUDIT", output)
