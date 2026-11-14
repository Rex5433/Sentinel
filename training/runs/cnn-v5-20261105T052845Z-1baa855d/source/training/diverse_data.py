"""V5 review loader and streaming audit. Does not approve data or train models."""
from collections import Counter, defaultdict
import json
import math
from pathlib import Path

from sentinel.features import FEATURE_ORDER, canonical_hash, schema_hash
from training.experiment_data import ROOT, hashfile
from training.label_contract import CLASS_ORDER, LABEL_VERSION, WindowAnnotation
from training.diverse_candidate import VERSION, inspect_source
from training.mixed_data import observable_rule

IGNORE_TARGET=-100


def _file(folder,name):
    path=(folder/name).resolve()
    if not path.is_relative_to(folder) or not path.is_file():
        raise ValueError("Missing or outside-candidate artifact")
    return path


def manifest_for(folder,pin):
    folder=Path(folder).resolve()
    if not folder.is_relative_to(ROOT): raise ValueError("Candidate must remain inside V1")
    if hashfile(_file(folder,"manifest.json"))!=pin: raise ValueError("Candidate manifest hash changed")
    manifest=json.loads((folder/"manifest.json").read_text())
    if (manifest["version"]!=VERSION or manifest["label_version"]!=LABEL_VERSION or
        manifest["feature_schema_sha256"]!=schema_hash() or manifest["classes"]!=list(CLASS_ORDER)):
        raise ValueError("Feature/label contract changed")
    for name,digest in manifest["source_hashes"].items():
        if hashfile(_file(folder,"source/"+name))!=digest or hashfile(_file(ROOT,name))!=digest:
            raise ValueError("Preparation source changed; version/review explicitly")
    lineage={key:defaultdict(set) for key in ("group","family","seed","host","raw_sha256")}
    ids=set()
    for source in manifest["sources"]:
        if source["id"] in ids: raise ValueError("Duplicate source identity")
        ids.add(source["id"])
        if source["split"] not in ("train","validation","test"): raise ValueError("Invalid split")
        for key in lineage: lineage[key][source[key]].add(source["split"])
    if any(len(splits)!=1 for values in lineage.values() for splits in values.values()):
        raise ValueError("Related scenario lineage crosses splits")
    return folder,manifest


def iter_sources(folder,splits,pin):
    if not splits or not set(splits)<={"train","validation","test"}: raise ValueError("Explicit valid splits required")
    folder,manifest=manifest_for(folder,pin)
    for source in manifest["sources"]:
        if source["split"] not in splits: continue  # Final-test raw is not opened for train/validation.
        for name in ("raw","labels"):
            if hashfile(_file(folder,source[name]))!=source[name+"_sha256"]: raise ValueError("Raw source or labels changed")
        side=json.loads((folder/source["labels"]).read_text())
        if any(source[key]!=side[key] for key in ("group","family","seed","platform","host","split","auth_style")):
            raise ValueError("Scenario lineage disagrees with manifest")
        annotations,parsed,extraction=inspect_source((folder/source["raw"]).read_bytes(),side,source["id"],source["format"])
        if annotations!=side["annotations"]: raise ValueError("Saved annotations disagree with causal facts")
        if len(parsed.events)!=source["events"] or len(extraction.windows)!=source["windows"]:
            raise ValueError("Declared counts disagree with observed data")
        anchors=Counter(a["observable_activity"] for a,s in zip(annotations,side["slots"],strict=True) if s["primary"])
        if anchors!=dict.fromkeys(CLASS_ORDER,8): raise ValueError("Balanced-anchor contract changed")
        yield source,side,parsed,extraction


def load(folder,splits,pin):
    """Future-run compatible sequences; all targets stay masked pending review.

    This loader performs no review overlay, optimizer construction or model import.
    Other supported windows remain visible as diagnostics but are not primary targets.
    """
    sessions=[]
    for source,side,_,extraction in iter_sources(folder,splits,pin):
        blocks=[];block=[]
        for i,window in enumerate(extraction.windows):
            if block and window.start_utc!=extraction.windows[block[-1]].end_utc:
                blocks.append(block);block=[]
            block.append(i)
        if block: blocks.append(block)
        for segment,indices in enumerate(blocks):
            annotations=[WindowAnnotation(**side["annotations"][i]) for i in indices]
            candidate=[CLASS_ORDER.index(a.observable_activity) if side["slots"][i]["primary"] and a.label_status=="supported" else IGNORE_TARGET for i,a in zip(indices,annotations,strict=True)]
            sessions.append(dict(**{key:source[key] for key in ("id","group","family","seed","platform","split","host")},
                segment=segment,vectors=[extraction.windows[i].vector for i in indices],candidate_targets=candidate,
                targets=[IGNORE_TARGET]*len(indices),annotations=annotations,
                starts_utc=[extraction.windows[i].start_utc.isoformat() for i in indices],provisional_only=True))
    return sessions


def _rows(counter,keys):
    return [dict(zip(keys,key,strict=True),count=count) for key,count in sorted(counter.items())]


def audit(folder,pin):
    folder,manifest=manifest_for(folder,pin)
    selected,natural,masked,authorization,loads,auth_counts=(Counter() for _ in range(6))
    counts=Counter(); event_types=Counter(); feature_min=[math.inf]*18; feature_max=[-math.inf]*18
    contexts=defaultdict(list); behavior=defaultdict(list); vectors=Counter(); trajectories=[]
    means=[0.]*18;m2=[0.]*18;ntrain=0; seen_raw=set(); full_signatures=Counter()
    for source,side,parsed,extraction in iter_sources(folder,{"train","validation","test"},pin):
        split,platform=source["split"],source["platform"]
        counts["events"]+=len(parsed.events);counts["windows"]+=len(extraction.windows)
        counts["rejected"]+=len(parsed.rejected);counts["unrecognized"]+=sum(e.event_type is None for e in parsed.events)
        counts["warnings"]+=sum(bool(e.parsing_errors) for e in parsed.events)
        counts["excluded"]+=extraction.coverage["excluded_records"];counts["sources"]+=1
        counts["missing_intervals"]+=len(side["missing_slots"])
        event_types.update(e.event_type or "unrecognized" for e in parsed.events)
        if source["raw_sha256"] in seen_raw: raise ValueError("Duplicate raw source")
        seen_raw.add(source["raw_sha256"])
        history=[];full=[]
        for window,annotation,slot in zip(extraction.windows,side["annotations"],side["slots"],strict=True):
            vector=window.vector
            if history and window.start_utc!=history[-1].end_utc: history=[]
            history=(history+[window])[-5:]
            context=[w.vector for w in history]
            for j,value in enumerate(vector):
                feature_min[j]=min(feature_min[j],value);feature_max[j]=max(feature_max[j],value)
            if split=="train":
                ntrain+=1
                for j,value in enumerate(vector):
                    delta=value-means[j];means[j]+=delta/ntrain;m2[j]+=delta*(value-means[j])
            vectors[canonical_hash(vector)]+=1
            target=CLASS_ORDER.index(annotation["observable_activity"]) if annotation["label_status"]=="supported" else IGNORE_TARGET
            if target!=IGNORE_TARGET:
                natural[split,platform,target]+=1
                if observable_rule(context)!=target: raise ValueError("Feature-side rubric disagrees with fact label")
            else: masked[split,platform,annotation["label_status"]]+=1
            authorization[split,platform,annotation["authorization"]["status"],target]+=1
            if slot["primary"]:
                selected[split,platform,target]+=1
                key=canonical_hash(context)
                contexts[key].append((split,target,source["id"],window.window_id))
                # Timing-free exact behavior is a stricter shortcut audit than raw X equality.
                signature=[[v for j,v in enumerate(w.vector) if j not in (14,15)] for w in history]
                behavior[canonical_hash(signature)].append((split,target,source["id"]))
                load=slot["background_events"]
                band=next(i for i,(lo,hi) in enumerate(((1,3),(4,9),(10,24),(25,59),(60,119),(120,249),(250,499),(500,850))) if lo<=load<=hi)
                loads[split,platform,target,band]+=1
                if target==1: auth_counts[split,platform,side["auth_style"]]+=1
            full.append(vector)
        full_signatures[canonical_hash(full)]+=1
        trajectories.append(dict(id=source["id"],group=source["group"],platform=platform,split=split,vectors=full))
        print(f"Audited {counts['sources']}/{len(manifest['sources'])} sources",flush=True)
    exact_cross=[rows for rows in contexts.values() if len({r[0] for r in rows})>1]
    conflicts=[rows for rows in contexts.values() if len({r[1] for r in rows})>1]
    if exact_cross or conflicts: raise ValueError("Cross-split duplicate or conflicting selected causal inputs")
    scales=[max(1.,math.sqrt(value/max(1,ntrain))) for value in m2]
    near=[]
    for i,a in enumerate(trajectories):
        for b in trajectories[i+1:]:
            if a["platform"]!=b["platform"] or a["group"]==b["group"]: continue
            total=0.;number=0;failed=False
            for va,vb in zip(a["vectors"],b["vectors"],strict=True):
                for j,(x,y) in enumerate(zip(va,vb,strict=True)):
                    distance=abs(x-y)/scales[j]
                    if distance>.25: failed=True;break
                    total+=distance;number+=1
                if failed: break
            if not failed and total/number<=.02: near.append([a["id"],b["id"]])
    sources=manifest["sources"]
    lineage={key:len({s[key] for s in sources}) for key in ("group","family","seed","host")}
    cross_behavior=[rows for rows in behavior.values() if len({r[0] for r in rows})>1]
    prior_raw=set()
    prior_manifests=0
    for path in (ROOT/"data/private").glob("candidate-*/manifest.json"):
        if path.parent==folder: continue
        old=json.loads(path.read_text())
        prior_raw.update(s["raw_sha256"] for s in old.get("sources",[]) if "raw_sha256" in s)
        prior_manifests+=1
    for path in ((ROOT/"data/private").glob("v4-fresh-*/sources.json")):
        prior_raw.update(s["raw_sha256"] for s in json.loads(path.read_text()))
    for path in ((ROOT/"data/private").glob("verification-v2-*/holdout-sources.json")):
        prior_raw.update(s["raw_sha256"] for s in json.loads(path.read_text()))
    prior_matches=len(seen_raw & prior_raw)
    if prior_matches: raise ValueError("Raw bytes reused from existing candidates/challenges")
    return dict(version=VERSION,manifest_sha256=pin,status="candidate_pending_review" if not near and max(full_signatures.values(),default=0)<=1 else "structural_review_required",
        **dict(counts),independent_procedural_groups=lineage["group"],recipe_parameter_families=lineage["family"],seeds=lineage["seed"],hosts=lineage["host"],
        by_split=[dict(split=split,sources=len(ss),groups=len({s["group"] for s in ss}),families=len({s["family"] for s in ss}),
                       events=sum(s["events"] for s in ss),windows=sum(s["windows"] for s in ss))
                  for split in ("train","validation","test") if (ss:=[s for s in sources if s["split"]==split])],
        selected_targets=sum(selected.values()),all_supported_windows=sum(natural.values()),masked_windows=sum(masked.values()),
        selected_class_counts=_rows(selected,("split","platform","target")),natural_class_counts=_rows(natural,("split","platform","target")),
        masked_counts=_rows(masked,("split","platform","status")),authorization_counts=_rows(authorization,("split","platform","status","target")),
        selected_background_loads=_rows(loads,("split","platform","target","band")),selected_auth_styles=_rows(auth_counts,("split","platform","style")),
        formats=dict(Counter(s["format"] for s in sources)),event_types=dict(event_types),
        feature_ranges={name:dict(min=feature_min[j],max=feature_max[j]) for j,name in enumerate(FEATURE_ORDER)},
        unique_single_vectors=len(vectors),repeated_single_vector_occurrences=sum(n-1 for n in vectors.values()),
        unique_selected_causal_inputs=len(contexts),duplicate_selected_context_occurrences=sum(len(rs)-1 for rs in contexts.values()),
        cross_split_exact_selected_contexts=len(exact_cross),conflicting_selected_contexts=len(conflicts),
        prior_candidate_manifests_checked=prior_manifests,prior_candidate_or_challenge_raw_matches=prior_matches,
        timing_free_behavior_unique=len(behavior),timing_free_behavior_cross_split_groups=len(cross_behavior),
        timing_free_behavior_cross_split_occurrences=sum(len(rs) for rs in cross_behavior),
        timing_free_behavior_conflict_groups=sum(len({r[1] for r in rs})>1 for rs in behavior.values()),
        duplicate_full_trajectory_occurrences=sum(n-1 for n in full_signatures.values()),near_duplicate_source_pairs=near,
        near_duplicate_definition="Same OS/different group, all 95 observed windows aligned: training-only SD floored at 1; maximum scaled difference <=0.25 and mean <=0.02. Limited metric, not universal independence.",
        actual_reviewed_training_targets=0,training_started=False,training_approved=False,model_inference_performed=False,
        test_inspection="Structural facts/labels/features only, no checkpoint predictions or model selection.",
        limitations=["Synthetic procedural labels; not confirmed real attack/authorization truth.",
            "Shared primitives and renderer; held-out cadence/identity families are not independent field domains.",
            "Balanced selected anchors change class prevalence; context and natural counts reported separately.",
            "Zero exact input matches does not eliminate all near duplicates or generator shortcuts.",
            "Targets mirror an observable count rubric; cannot prove added value over rules or zero incident misses."])
