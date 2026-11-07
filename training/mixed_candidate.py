"""Original team synthetic mixed sessions. Explicit preparation only; never trains."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import uuid

from sentinel.features import FEATURE_ORDER, FEATURE_VERSION, canonical_hash, extract_features, schema_hash
from sentinel.ingest import parse_linux, parse_windows
from sentinel.ingest.common import PARSER_VERSION
from training.experiment_data import ROOT, hashfile
from training.label_contract import CLASS_ORDER, LABEL_VERSION, WindowAnnotation

VERSION = "team-mixed-v4.2"
VOLUMES = {"sparse": (1, 9), "medium": (12, 35), "busy": (40, 80)}
FAMILIES = (
    "interactive", "batch", "helpdesk", "backup", "provisioning", "maintenance",
    "shared_terminal", "rotating_shift", "remote_branch", "scheduled_rollout", "recovery", "build_farm",
)
EVENT_NAMES = ("auth_failure", "auth_success", "session_open", "session_close", "sudo_command",
               "account_created", "service_installed", "service_state_change", "service_activity")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def split_for(family):
    return "train" if family < 8 else "validation" if family < 10 else "test"


def activity_categories(history):
    """Frozen v1 rubric from independent scenario facts; not model predictions."""
    current = history[-1]
    kinds = []
    failures = [sum(r["event_type"] == "auth_failure" for r in rows) for rows in history[-5:]]
    if failures[-1] >= 5 or (failures[-1] > 0 and sum(failures) >= 5 and sum(n > 0 for n in failures) >= 2):
        kinds.append(CLASS_ORDER[1])
    if any(r["event_type"] == "account_created" for r in current):
        kinds.append(CLASS_ORDER[2])
    if any(r["event_type"] in ("service_installed", "service_state_change", "service_activity") for r in current):
        kinds.append(CLASS_ORDER[3])
    return kinds or [CLASS_ORDER[0]]


def reference_vector(facts, platform):
    """Arithmetic from latent event facts, without reading parser output."""
    counts = Counter(r["event_type"] for r in facts)
    times = [datetime.fromisoformat(r["timestamp"]) for r in facts]
    values = {"event_count": len(facts), **{f"{k}_count": counts[k] for k in EVENT_NAMES},
              "other_event_count": sum(n for k, n in counts.items() if k not in EVENT_NAMES),
              "span_seconds": (max(times) - min(times)).total_seconds(),
              "auth_failure_fraction": counts["auth_failure"] / len(facts),
              "is_windows": int(platform == "windows"), "is_linux": int(platform == "linux")}
    for key in ("actor", "source_ip", "target"):
        values[f"distinct_{key}_count"] = len({r[key] for r in facts if r[key] is not None})
    return [float(values[k]) for k in FEATURE_ORDER]


def render(family, replicate, platform, approved):
    if family not in range(12) or replicate not in range(4) or platform not in ("linux", "windows"):
        raise ValueError("Unsupported recipe")
    group = f"{FAMILIES[family]}-{replicate}"
    seed = 5_840_000 + family * 107 + replicate * 1009
    # Approval is deliberately absent from RNG; matched X remains identical.
    rng = random.Random(f"{VERSION}/{seed}/{platform}")
    start = datetime(2026, 6, 1, tzinfo=timezone.utc) + timedelta(days=family * 4 + replicate)
    host = f"lab-{platform}-{seed}-{int(approved)}"
    order = list(range(4))
    rng.shuffle(order)
    raw, facts, slots = [], [], []
    users = [f"operator{i}" for i in range(2 + family % 5)]
    ips = [f"192.0.2.{30+i}" for i in range(1 + (family * 3 + replicate) % 6)]
    service_steps = {}
    for w in range(44):
        actual_slot = w + (w >= 36)  # One missing five-minute interval, never zero-filled.
        phase = "warmup" if w < 4 else "activity" if w < 32 else "mixed" if w < 34 else "parser_gap" if w == 34 else "unobservable" if w == 35 else "after_gap"
        mode = order[(w - 4) // 7] if 4 <= w < 32 else 0
        within = (w - 4) % 7
        volume = tuple(VOLUMES)[(rng.randrange(3) + replicate) % 3]
        n = rng.randint(*VOLUMES[volume])
        if phase == "mixed":
            n = max(2, n)
        background = ["success", "close"] + (["open", "sudo"] if platform == "linux" else ["privilege"])
        kinds = [rng.choice(background) for _ in range(n)]
        # Background includes success; a sparse foreground may replace all of it.
        kinds[0] = "success"
        if phase == "activity":
            if mode == 0:
                if within in (1, 4):
                    kinds[-1] = "failure"  # Benign mistakes below burst rubric.
            elif mode == 1:
                failures = min(n, (2, 1, 2, 1, 1, 3, 2)[within]) if (family + replicate) % 3 != 1 else min(n, rng.randint(5, 12))
                kinds[-failures:] = ["failure"] * failures
            else:
                number = rng.randint(1, min(4, n))
                kinds[-number:] = ["account" if mode == 2 else "service"] * number
        elif phase == "mixed":
            kinds[-2:] = ["account", "service"]
        elif phase == "parser_gap":
            kinds[-1] = "unknown"
        rng.shuffle(kinds)
        # Family-specific temporal shapes; random span is not selected by target.
        span = rng.randint(8, 295)
        if family % 3 == 0:
            offsets = sorted(rng.choices(range(span + 1), k=n))
        elif family % 3 == 1:
            offsets = sorted(rng.randint(0, min(span, 20)) if i < n // 2 else rng.randint(0, span) for i in range(n))
        else:
            offsets = sorted(int(i * span / max(1, n - 1)) for i in range(n))
        rows = []
        for i, (kind, delta) in enumerate(zip(kinds, offsets)):
            actor, ip = rng.choice(users), rng.choice(ips)
            target = f"member{rng.randrange(2 + replicate)}"
            service = f"worker{rng.randrange(1 + family % 4)}"
            stamp = (start + timedelta(seconds=actual_slot * 300 + delta)).isoformat()
            index = len(raw) + 1
            if kind == "account":
                target = f"member{replicate}_{index}"  # Successful creation never reuses a live account.
            event_type = {"success": "auth_success", "failure": "auth_failure", "close": "session_close",
                          "open": "session_open", "sudo": "sudo_command", "privilege": "privilege_assigned",
                          "account": "account_created", "unknown": None}.get(kind)
            if platform == "linux":
                if kind == "service":
                    step = service_steps.get(service, 0)
                    transition = ("Starting", "Started", "Stopping", "Stopped")[step % 4]
                    service_steps[service] = step + 1
                emitter, message = {
                    "success": ("sshd", f"Accepted publickey for {actor} from {ip} port 41000 ssh2"),
                    "failure": ("sshd", f"Failed password for {actor} from {ip} port 41000 ssh2"),
                    "close": ("sshd", f"pam_unix(sshd:session): session closed for user {actor}"),
                    "open": ("sshd", f"pam_unix(sshd:session): session opened for user {actor} by (uid=0)"),
                    "sudo": ("sudo", f"{actor} : TTY=pts/2 ; USER=root ; COMMAND=/usr/bin/id"),
                    "account": ("useradd", f"new user: name={target}, UID={7000+index}"),
                    "service": ("systemd", f"{transition if kind == 'service' else 'Started'} {service}.service"),
                    "unknown": ("teamapp", "configuration observation outside current parser coverage"),
                }[kind]
                raw.append(f"{stamp} {host} {emitter}[{12000+index}]: {message}")
                if kind == "service":
                    event_type = "service_activity"
                fact_actor = None if kind in ("account", "service", "unknown") else actor
                fact_target = target if kind == "account" else "root" if kind == "sudo" else "sshd" if kind in ("success", "failure", "open", "close") else None
            else:
                code = {"success": 4624, "failure": 4625, "close": 4634, "privilege": 4672,
                        "account": 4720, "service": rng.choice((7045, 7036)), "unknown": 9999}[kind]
                if code == 7045:
                    service = f"newworker{index}"  # Install records describe distinct new services.
                fields = {"ServiceName": service} if kind == "service" else {"SubjectUserName": actor, "TargetUserName": target} if kind == "account" else {"SubjectUserName": actor} if kind == "privilege" else {"TargetUserName": actor}
                if kind in ("success", "failure"):
                    fields["IpAddress"] = ip
                raw.append({"Id": code, "RecordId": index, "TimeCreated": stamp, "MachineName": host,
                            "LogName": "System" if kind == "service" else "Security",
                            "ProviderName": "Service Control Manager" if kind == "service" else "Microsoft-Windows-Security-Auditing",
                            "EventData": fields, "Message": "Original team synthetic export"})
                event_type = "service_installed" if code == 7045 else "service_state_change" if code == 7036 else event_type
                fact_actor = None if kind in ("service", "unknown") else actor
                # Unknown ID retains TargetUserName but has no recognized actor.
                fact_target = service if code == 7045 else None if code == 7036 or kind == "privilege" else target if kind == "account" else actor
            row = dict(record_index=index, event_type=event_type, timestamp=stamp, actor=fact_actor,
                       source_ip=ip if kind in ("success", "failure") else None, target=fact_target,
                       slot=w, kind=kind)
            facts.append(row)
            rows.append(row)
        slots.append(dict(index=w, actual_slot=actual_slot, phase=phase, volume=volume, mode=mode,
                          facts=rows, security_status="simulated_unapproved" if not approved and
                          (phase in ("mixed", "unobservable") or (phase == "activity" and (mode != 0 or within == 2))) else "authorized"))
    data = ("\n".join(raw) + "\n").encode() if platform == "linux" else encode(raw)
    side = dict(version=VERSION, family=FAMILIES[family], family_index=family, group=group, seed=seed,
                replicate=replicate, platform=platform, approved_counterpart=approved, split=split_for(family),
                auth_style="concentrated" if (family + replicate) % 3 == 1 else "distributed",
                origin="Original team-generated Codex-assisted synthetic; not field telemetry", facts=facts, slots=slots)
    return data, side


def inspect_source(raw, side, source_id):
    """Validate event facts/18 arithmetic values, then attach review-only truth."""
    parsed = (parse_linux(raw, file_format="text", source_file="episode.log", upload_id=source_id)
              if side["platform"] == "linux" else parse_windows(raw, file_format="json", source_file="episode.json", upload_id=source_id))
    extraction = extract_features(parsed.events)
    if parsed.rejected or len(parsed.events) != len(side["facts"]) or len(extraction.windows) != 44:
        raise ValueError("Unexpected parser/window coverage")
    for event, fact in zip(parsed.events, side["facts"], strict=True):
        if (event.event_type != fact["event_type"] or event.timestamp_utc.isoformat() != fact["timestamp"]
                or event.actor != fact["actor"] or event.target != fact["target"]
                or (str(event.source_ip) if event.source_ip else None) != fact["source_ip"]):
            raise ValueError("Parser disagrees with scenario event facts")
        if bool(event.parsing_errors) != (fact["event_type"] is None):
            raise ValueError("Unexpected parser warning outside the declared coverage challenge")
    annotations = []
    for i, (window, slot) in enumerate(zip(extraction.windows, side["slots"], strict=True)):
        if window.vector != reference_vector(slot["facts"], side["platform"]):
            raise ValueError("Independent 18-feature arithmetic mismatch")
        beginning = max(0, i - 4, 36 if i >= 36 else 0)
        ids = [w.window_id for w in extraction.windows[beginning:i+1]]
        categories = activity_categories([s["facts"] for s in side["slots"][beginning:i+1]])
        status = "supported"
        if len(categories) > 1:
            status = "mixed_activity"
        if i < 4 or 36 <= i < 40 or i == 34:
            status = "insufficient_evidence"
        if i == 35:
            status = "feature_unobservable"
        annotation = WindowAnnotation(
            label_version=LABEL_VERSION, feature_version=FEATURE_VERSION, feature_schema_sha256=schema_hash(),
            window_id=window.window_id, source_sha256=window.source_sha256, causal_window_ids=ids,
            origin="team_generated_synthetic", scenario_group=side["group"], split=side["split"],
            observed_categories=categories, observable_activity=categories[0] if status == "supported" else None,
            label_status=status, evidence_event_ids=window.event_ids,
            activity_evidence_refs=[f"scenario:slots/{i}/facts"],
            rationale="Frozen observable rubric applied to team scenario facts; unsupported cases retained and masked.",
            review_status="pending", reviewer=None,
            authorization=dict(status=slot["security_status"], basis="scenario_manifest",
                               evidence_refs=[f"scenario:slots/{i}/security_status"],
                               rationale="Declared simulation context only; no human-confirmed incident."))
        annotations.append(annotation.model_dump(mode="json"))
    return annotations, parsed, extraction


def generate(base=None, families=range(12), replicates=range(4)):
    base = (ROOT / "data/private" if base is None else Path(base)).resolve()
    if not base.is_relative_to(ROOT):
        raise ValueError("Output must stay inside V1")
    folder = base / ("candidate-v4-" + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True, exist_ok=False)
    sources = []
    for family in families:
        for replicate in replicates:
            for platform in ("linux", "windows"):
                for approved in (True, False):
                    raw, side = render(family, replicate, platform, approved)
                    source_id = canonical_hash([VERSION, family, replicate, platform, approved])[:24]
                    rawname = source_id + (".log" if platform == "linux" else ".json")
                    side["annotations"] = inspect_source(raw, side, source_id)[0]
                    # Facts remain in one location rather than duplicated per slot.
                    for slot in side["slots"]:
                        slot["record_indices"] = [r["record_index"] for r in slot.pop("facts")]
                    labelname = source_id + ".labels.json"
                    (folder / rawname).write_bytes(raw)
                    (folder / labelname).write_bytes(encode(side))
                    sources.append(dict(id=source_id, raw=rawname, labels=labelname,
                                        raw_sha256=hashfile(folder/rawname), labels_sha256=hashfile(folder/labelname),
                                        split=side["split"], group=side["group"], family=side["family"], platform=platform,
                                        seed=side["seed"], approved_counterpart=approved,
                                        events=len(side["facts"]), windows=len(side["annotations"])))
    provenance_files = (Path(__file__), ROOT/"training/label_contract.py", ROOT/"sentinel/features.py",
                        ROOT/"sentinel/ingest/windows.py", ROOT/"sentinel/ingest/linux.py", ROOT/"sentinel/ingest/common.py",
                        ROOT/"docs/OBSERVABLE_ACTIVITY_LABEL_CONTRACT.md")
    hashes = {}
    for path in provenance_files:
        relative = path.relative_to(ROOT).as_posix()
        target = folder / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        hashes[relative] = hashfile(path)
    manifest = dict(version=VERSION, label_version=LABEL_VERSION, feature_schema_sha256=schema_hash(),
                    parser_version=PARSER_VERSION, classes=CLASS_ORDER, source_hashes=hashes, sources=sources,
                    origin="Team-generated Codex-assisted; no public data or real telemetry",
                    review_status="pending_owner_review", training_approved=False,
                    split_policy="Whole recipe families: 0..7 train, 8..9 validation, 10..11 test; counterparts and replicates together",
                    warmup_policy="First four observed slots and first four after the deliberate gap are masked, never zero-filled")
    (folder / "manifest.json").write_bytes(encode(manifest))
    return folder


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    if args.generate:
        print(generate(), flush=True)
    else:
        print("Preparation only: explicit --generate required; no training.")
