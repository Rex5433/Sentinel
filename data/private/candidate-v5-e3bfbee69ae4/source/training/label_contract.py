"""Review-only activity annotations. No dataset migration, inference or training.

Authorization is metadata, never a learned target or a numeric input. Future
loaders must explicitly adopt this contract; legacy loaders are unchanged.
"""
from collections import defaultdict
import math
from typing import Literal, Self

from pydantic import Field, model_validator

from sentinel.features import FEATURE_ORDER, FEATURE_VERSION, canonical_hash, schema_hash
from sentinel.schemas import Contract, Sha256, Text

LABEL_VERSION = "observable-activity-v1.0"
CLASS_ORDER = (
    "normal_or_unremarkable", "authentication_burst",
    "account_or_privilege_change", "process_or_service_anomaly",
)
Activity = Literal[
    "normal_or_unremarkable", "authentication_burst",
    "account_or_privilege_change", "process_or_service_anomaly",
]


class AuthorizationContext(Contract):
    status: Literal["authorized", "simulated_unapproved", "confirmed_unapproved", "unknown", "mixed"]
    basis: Literal["scenario_manifest", "human_review", "unavailable"]
    evidence_refs: list[Text]
    rationale: Text
    reviewer: Text | None = None

    @model_validator(mode="after")
    def evidence_matches_claim(self) -> Self:
        if (self.status != "unknown" or self.basis != "unavailable") and not self.evidence_refs:
            raise ValueError("Known authorization context requires independent evidence references")
        if self.basis == "unavailable" and self.status != "unknown":
            raise ValueError("Unavailable authorization evidence must remain unknown")
        if self.basis == "human_review" and not self.reviewer:
            raise ValueError("Human confirmation requires a named reviewer")
        if self.status == "confirmed_unapproved" and self.basis != "human_review":
            raise ValueError("A synthetic scenario is not human-confirmed field truth")
        if self.status == "simulated_unapproved" and self.basis != "scenario_manifest":
            raise ValueError("Simulated context requires scenario provenance")
        return self


class WindowAnnotation(Contract):
    label_version: Literal["observable-activity-v1.0"]
    feature_version: Literal["event-window-v1"]
    feature_schema_sha256: Sha256
    window_id: Sha256
    source_sha256: Sha256
    # Current window last; up to four prior windows. IDs are audit metadata.
    causal_window_ids: list[Sha256] = Field(min_length=1, max_length=5)
    origin: Literal["team_generated_synthetic", "team_collected"]
    scenario_group: Text
    split: Literal["train", "validation", "test", "review_only"]
    observed_categories: list[Activity]
    observable_activity: Activity | None
    label_status: Literal["supported", "mixed_activity", "insufficient_evidence", "feature_unobservable"]
    evidence_event_ids: list[Text] = Field(min_length=1)
    activity_evidence_refs: list[Text] = Field(min_length=1)
    rationale: Text
    review_status: Literal["pending", "reviewed"]
    reviewer: Text | None = None
    authorization: AuthorizationContext

    @model_validator(mode="after")
    def enforce_target_boundary(self) -> Self:
        if self.feature_schema_sha256.lower() != schema_hash():
            raise ValueError("Annotation feature schema does not match the frozen 18 features")
        if self.causal_window_ids[-1] != self.window_id:
            raise ValueError("Current window must be last in causal context")
        if len(set(self.causal_window_ids)) != len(self.causal_window_ids):
            raise ValueError("Repeated causal window identity")
        categories = set(self.observed_categories)
        if len(categories) != len(self.observed_categories):
            raise ValueError("Duplicate observed activity category")
        if "normal_or_unremarkable" in categories and len(categories) > 1:
            raise ValueError("Normal cannot override supported activity")
        if self.label_status == "supported":
            if self.observable_activity is None or categories != {self.observable_activity}:
                raise ValueError("A supported target requires exactly one matching observed category")
        elif self.observable_activity is not None:
            raise ValueError("Ambiguous/unobservable labels have no four-class training target")
        if self.label_status == "mixed_activity" and len(categories) < 2:
            raise ValueError("Mixed activity requires multiple observed categories")
        if self.review_status == "reviewed" and not self.reviewer:
            raise ValueError("Reviewed annotations require a named reviewer")
        if self.origin == "team_generated_synthetic" and self.authorization.status == "confirmed_unapproved":
            raise ValueError("Synthetic provenance cannot establish a real unauthorized incident")
        return self

    def training_target(self) -> int | None:
        """Target proposal only; caller must also pass split/coverage/collision gates."""
        if self.label_status != "supported" or self.review_status != "reviewed":
            return None
        return CLASS_ORDER.index(self.observable_activity)


def conflicting_contexts(samples: list[tuple[WindowAnnotation, list[list[float]]]]) -> list[list[str]]:
    """Return exact same-input/different-target groups for quarantine, not relabeling.

    Inputs are unscaled ordered causal vectors, with the same prefix/reset policy.
    This checks exact collisions only, not near duplicates or source independence.
    """
    groups = defaultdict(list)
    for annotation, vectors in samples:
        if len(vectors) != len(annotation.causal_window_ids):
            raise ValueError("Causal vectors and annotation references do not align")
        if any(len(vector) != len(FEATURE_ORDER) for vector in vectors):
            raise ValueError("Each window requires all 18 features")
        if any(type(value) not in (int, float) or not math.isfinite(value)
               for vector in vectors for value in vector):
            raise ValueError("Context features must be finite numbers")
        # Normalize numeric representation so 1 and 1.0 cannot hide a collision.
        identity = canonical_hash([FEATURE_VERSION, annotation.feature_schema_sha256.lower(),
                                   [[float(value) for value in vector] for vector in vectors]])
        target = annotation.training_target()
        if target is not None:
            groups[identity].append((annotation.window_id, target))
    return [sorted({window for window, _ in group}) for _, group in sorted(groups.items())
            if len({target for _, target in group}) > 1]
