"""Windows projected CSV/JSON exports; no EVTX/XML or localized-message guesses."""

from typing import Literal

from pydantic import ValidationError

from sentinel.schemas import WindowsEventRecord
from .common import (
    PARSER_VERSION, ParseInputError, ParseResult, RejectedRecord, address, bounded, choose,
    csv_records, integer, json_records, prepare, text_value, timestamp,
)

SECURITY_TYPES = {
    4624: "auth_success",
    4625: "auth_failure",
    4720: "account_created",
    4697: "service_installed",
    4634: "session_close",
    4672: "privilege_assigned",
}


def _event(record: dict, index: int, result: ParseResult) -> WindowsEventRecord:
    errors: list[str] = []

    def read(*names: str) -> str | None:
        return text_value(choose(record, names, errors), names[0], errors)

    code = integer(choose(record, ("Id", "EventID"), errors), "EventID", errors, 65535)
    original_time = read("TimeCreated", "Timestamp")
    channel = read("LogName", "Channel")
    provider = read("ProviderName", "Provider")
    message = record.get("Message")
    if message is not None and not isinstance(message, str):
        errors.append("Message: expected text; raw value retained")
        message = None
    details = record.get("EventData")
    if details is None:
        details = {}
    if not isinstance(details, dict):
        errors.append("EventData: expected an object; raw value retained")
        details = {}

    def detail(name: str) -> str | None:
        # Conflicting flat and nested values are not silently resolved.
        values = {"flat": record.get(name), "nested": details.get(name)}
        return text_value(choose(values, ("flat", "nested"), errors), name, errors)

    event_type = None
    if channel == "Security" and provider == "Microsoft-Windows-Security-Auditing":
        event_type = SECURITY_TYPES.get(code)
    elif channel == "System" and provider == "Service Control Manager" and code == 7036:
        event_type = "service_state_change"
    elif channel == "System" and provider == "Service Control Manager" and code == 7045:
        event_type = "service_installed"
    subject = detail("SubjectUserName")
    account = detail("TargetUserName")
    actor = account if event_type in ("auth_success", "auth_failure", "session_close") else subject
    target = detail("ServiceName") if event_type == "service_installed" else account
    attrs = {"parser_version": PARSER_VERSION}
    if "RecordId" in record:
        attrs["windows_record_id"] = record["RecordId"]
    if details:
        attrs["event_data"] = details
    if event_type is None:
        errors.append("event_type: unsupported event/provider/channel; no activity inferred")
    return WindowsEventRecord(
        **result.provenance(index), source=channel or result.source_file,
        windows_event_id=code, channel=channel, provider=provider,
        original_timestamp=original_time, timestamp_utc=timestamp(original_time, errors),
        host=read("MachineName", "Computer"), event_type=event_type,
        actor=actor, target=target, source_ip=address(detail("IpAddress"), errors),
        message=message, raw_record=record, attributes=attrs, parsing_errors=errors,
    )


def parse_windows(
    data: bytes, *, file_format: Literal["json", "csv"], source_file: str, upload_id: str
) -> ParseResult:
    if file_format not in ("json", "csv"):
        raise ParseInputError("Windows format must be json or csv")
    text, result = prepare(data, source_file, upload_id, f"windows-{file_format}")
    records = json_records(text) if file_format == "json" else csv_records(text)
    for index, record in bounded(records):
        if not isinstance(record, dict) or not set(record) & {"Id", "EventID", "TimeCreated", "Timestamp", "Message"}:
            result.rejected.append(RejectedRecord(index, "not a supported Windows record", record))
            continue
        try:
            result.events.append(_event(record, index, result))
        except ValidationError:
            result.rejected.append(RejectedRecord(index, "record cannot satisfy event contract", record))
    return result
