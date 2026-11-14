"""Original deterministic window features. No learned weights, labels, or text embeddings."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from typing import Iterable, Literal

from pydantic import Field

from .schemas import Contract, EventRecord, Sha256, Text, UtcTimestamp

FEATURE_VERSION = "event-window-v1"
WINDOW_SECONDS = 300
MAX_EVENTS = 100_000
EVENT_TYPES = (
    "auth_failure", "auth_success", "session_open", "session_close", "sudo_command",
    "account_created", "service_installed", "service_state_change", "service_activity",
)
FEATURE_ORDER = (
    "event_count", *(f"{name}_count" for name in EVENT_TYPES), "other_event_count",
    "distinct_actor_count", "distinct_source_ip_count", "distinct_target_count",
    "span_seconds", "auth_failure_fraction", "is_windows", "is_linux",
)


def feature_schema() -> dict:
    return {
        "version": FEATURE_VERSION, "window_seconds": WINDOW_SECONDS,
        "alignment": "UTC epoch-aligned non-overlapping [start,end) buckets",
        "group_by": ["upload_id", "platform", "host"],
        "feature_order": list(FEATURE_ORDER), "dtype": "finite unscaled floats",
        "event_types": list(EVENT_TYPES),
        "excluded": ["missing_timestamp", "missing_host", "window_out_of_range"],
        "duplicate_policy": "identical upload_id/event_id counted once; conflicting duplicates rejected",
        "feature_definitions": {
            "event_count": "all unique eligible records in the bucket",
            "event_type_counts": "exact equality to each listed normalized event_type",
            "other_event_count": "null or unlisted event_type",
            "distinct_counts": "distinct non-null values; IP addresses use canonical schema values",
            "span_seconds": "last timestamp minus first timestamp; singleton=0",
            "auth_failure_fraction": "auth_failure_count divided by event_count",
            "platform_bits": "one-hot indicators for the bucket platform",
        },
        "excluded_from_vector": ["IDs", "absolute timestamps", "literal hosts/accounts/IPs/targets",
                                 "filenames", "messages", "labels", "parsing warnings", "baseline outcomes"],
    }


def canonical_hash(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("utf-8")).hexdigest()


def schema_hash() -> str:
    return canonical_hash(feature_schema())


class FeatureWindow(Contract):
    window_id: Sha256
    upload_id: Text
    host: Text
    platform: Literal["windows", "linux"]
    start_utc: UtcTimestamp
    end_utc: UtcTimestamp
    feature_version: Literal["event-window-v1"] = FEATURE_VERSION
    feature_schema_sha256: Sha256
    source_sha256: Sha256 | None = None
    event_ids: list[Text] = Field(min_length=1)
    vector: list[float] = Field(min_length=len(FEATURE_ORDER), max_length=len(FEATURE_ORDER))
    quality: dict[str, int]

    def feature_values(self) -> dict[str, float]:
        return dict(zip(FEATURE_ORDER, self.vector, strict=True))

    def summary(self) -> dict:
        value = self.model_dump(mode="json", exclude={"event_ids"})
        value.update(feature_values=self.feature_values(), evidence_count=len(self.event_ids),
                     evidence_preview_ids=self.event_ids[:5])
        return value


@dataclass
class Extraction:
    windows: list[FeatureWindow] = field(default_factory=list)
    members: dict[str, list[EventRecord]] = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)


def extract_features(events: Iterable[EventRecord]) -> Extraction:
    groups = defaultdict(list)
    seen = {}
    exclusions = Counter()
    total = duplicates = 0
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    width = timedelta(seconds=WINDOW_SECONDS)
    for event in events:
        total += 1
        if total > MAX_EVENTS:
            raise ValueError("Feature extraction exceeds the 100000-record limit.")
        identity = (event.upload_id, event.event_id)
        if identity in seen:
            if seen[identity].model_dump(mode="json") != event.model_dump(mode="json"):
                raise ValueError("Conflicting duplicate event identities; analysis refused.")
            duplicates += 1
            continue
        seen[identity] = event
        if event.timestamp_utc is None:
            exclusions["missing_timestamp"] += 1
            continue
        if event.host is None:
            exclusions["missing_host"] += 1
            continue
        try:
            start = epoch + ((event.timestamp_utc - epoch) // width) * width
            end = start + width
        except OverflowError:
            exclusions["window_out_of_range"] += 1
            continue
        groups[(event.upload_id, event.platform, event.host, start, end)].append(event)
    result = Extraction()
    for (upload_id, platform, host, start, end), members in sorted(groups.items(), key=lambda item: (item[0][3], *item[0][:3])):
        members.sort(key=lambda event: (event.timestamp_utc, event.event_id))
        hashes = {event.source_sha256 for event in members if event.source_sha256 is not None}
        if len(hashes) > 1:
            raise ValueError("Conflicting source hashes within one window; analysis refused.")
        counts = Counter(event.event_type for event in members)
        count = len(members)
        values = {
            "event_count": count,
            **{f"{kind}_count": counts[kind] for kind in EVENT_TYPES},
            "other_event_count": sum(n for kind, n in counts.items() if kind not in EVENT_TYPES),
            "distinct_actor_count": len({event.actor for event in members if event.actor is not None}),
            "distinct_source_ip_count": len({str(event.source_ip) for event in members if event.source_ip is not None}),
            "distinct_target_count": len({event.target for event in members if event.target is not None}),
            "span_seconds": (members[-1].timestamp_utc - members[0].timestamp_utc).total_seconds(),
            "auth_failure_fraction": counts["auth_failure"] / count,
            "is_windows": int(platform == "windows"), "is_linux": int(platform == "linux"),
        }
        schema = schema_hash()
        window_id = canonical_hash([schema, upload_id, platform, host, start.isoformat()])
        window = FeatureWindow(
            window_id=window_id, upload_id=upload_id, host=host, platform=platform,
            start_utc=start, end_utc=end, feature_schema_sha256=schema,
            source_sha256=next(iter(hashes)) if hashes else None,
            event_ids=[event.event_id for event in members],
            vector=[float(values[name]) for name in FEATURE_ORDER],
            quality={"missing_actor_count": sum(event.actor is None for event in members),
                     "missing_source_ip_count": sum(event.source_ip is None for event in members),
                     "warning_event_count": sum(bool(event.parsing_errors) for event in members),
                     "missing_source_hash_count": sum(event.source_sha256 is None for event in members)},
        )
        result.windows.append(window)
        result.members[window_id] = members
    used = sum(len(window.event_ids) for window in result.windows)
    result.coverage = {
        "input_records": total, "used_records": used, "duplicate_records": duplicates,
        "excluded_records": sum(exclusions.values()), "exclusion_counts": dict(sorted(exclusions.items())),
        "window_count": len(result.windows),
    }
    return result
