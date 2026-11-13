"""Version 1 contracts. These types validate records; they do not parse or detect."""

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

Text = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]


def _explicit_datetime(value: object) -> object:
    if not isinstance(value, (str, datetime)):
        raise ValueError("use an ISO 8601 timestamp with timezone, not epoch numbers")
    if isinstance(value, str):
        # Pydantic also accepts numeric strings as epochs; this contract does not.
        return datetime.fromisoformat(value)
    return value


UtcTimestamp = Annotated[
    AwareDatetime,
    BeforeValidator(_explicit_datetime),
    AfterValidator(lambda value: value.astimezone(timezone.utc)),
]

ActivityClass = Literal[
    "normal_or_unremarkable",
    "authentication_burst",
    "account_or_privilege_change",
    "process_or_service_anomaly",
    "network_activity_anomaly",
    "unknown/insufficient_evidence",
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class EventRecord(Contract):
    """Common Windows/Linux event; unknown observed facts stay null.

    event_id is a stable local reference, not the Windows numeric event code.
    Raw evidence is inert JSON/text. Never strip or rewrite original evidence.
    """

    event_id: Text
    platform: Literal["windows", "linux"]
    source: Text
    upload_id: Text
    timestamp_utc: UtcTimestamp | None = None
    original_timestamp: Text | None = None
    host: Text | None = None
    event_type: Text | None = None
    actor: Text | None = None
    source_ip: IPvAnyAddress | None = None
    target: Text | None = None
    message: str | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    raw_record: JsonValue = None
    source_file: Text | None = None
    source_sha256: Sha256 | None = None
    record_index: Annotated[int, Field(strict=True, ge=1)] | None = None
    parsing_errors: list[Text] = Field(default_factory=list)

    @field_validator("source_ip", mode="before")
    @classmethod
    def explicit_ip(cls, value: object) -> object:
        if value is not None and not isinstance(value, (str, IPv4Address, IPv6Address)):
            raise ValueError("source_ip must be an IPv4 or IPv6 address")
        return value


class WindowsEventRecord(EventRecord):
    platform: Literal["windows"] = "windows"
    windows_event_id: Annotated[int, Field(strict=True, ge=0, le=65535)] | None = None
    channel: Text | None = None
    provider: Text | None = None


class LinuxEventRecord(EventRecord):
    platform: Literal["linux"] = "linux"
    service: Text | None = None
    process_id: Annotated[int, Field(strict=True, ge=0)] | None = None


class Finding(Contract):
    """Evidence-backed triage contract; priority is not compromise probability."""

    finding_id: Text
    timestamp_utc: UtcTimestamp
    activity_class: ActivityClass
    triage_priority: Annotated[int, Field(strict=True, ge=0, le=100)]
    evidence_event_ids: Annotated[list[Text], Field(min_length=1)]
    explanation: Text
    method: Literal["deterministic", "statistical", "model"]
    confidence: Annotated[float, Field(strict=True, ge=0, le=1)] | None = None
    model_version: Text | None = None
    limitations: list[Text] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_model_provenance(self) -> Self:
        if self.method == "model" and self.model_version is None:
            raise ValueError("model findings require model_version")
        if self.method != "model" and self.model_version is not None:
            raise ValueError("model_version applies only to model findings")
        return self
