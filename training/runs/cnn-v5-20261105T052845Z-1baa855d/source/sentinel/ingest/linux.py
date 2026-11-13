"""Narrow Linux auth/syslog text and journal JSON parsers with explicit gaps."""

from datetime import datetime, timedelta, timezone
import re
from typing import Literal

from pydantic import ValidationError

from sentinel.schemas import LinuxEventRecord
from .common import (
    PARSER_VERSION, ParseInputError, ParseResult, RejectedRecord, address, bounded,
    integer, load_json, prepare, text_records, text_value, timestamp,
)

PREFIX = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[Tt]\S+|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<service>[A-Za-z0-9_./@-]+)(?:\[(?P<pid>\d+)\])?: ?(?P<message>.*)$"
)
SSH = re.compile(
    r"^(?P<outcome>Failed|Accepted) (?:password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?:\s|$)"
)
SESSION = re.compile(
    r"^pam_unix\((?:sshd|login|sudo|su):session\): session "
    r"(?P<state>opened|closed) for user (?P<user>[^\s(]+)"
)
SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<fields>TTY=.*)$")


def _activity(service: str | None, message: str | None, errors: list[str]) -> dict:
    fields = {"event_type": None, "actor": None, "target": None, "source_ip": None, "attributes": {}}
    if message is None:
        return fields
    if service in ("sshd", "sshd-session") and (match := SSH.match(message)):
        fields.update(
            event_type="auth_failure" if match["outcome"] == "Failed" else "auth_success",
            actor=match["user"], target=service, source_ip=address(match["ip"], errors),
        )
    elif service in ("sshd", "sshd-session", "login", "sudo", "su") and (match := SESSION.match(message)):
        fields.update(event_type="session_open" if match["state"] == "opened" else "session_close",
                      actor=match["user"], target=service)
    elif service == "sudo" and (match := SUDO.match(message)):
        command = re.search(r"(?:^|;\s*)COMMAND=(.*)$", match["fields"])
        metadata = match["fields"][:command.start()] if command else ""
        target = re.search(r"(?:^|;\s*)USER=([^ ;]+)", metadata)
        if target and command:
            fields.update(event_type="sudo_command", actor=match["user"], target=target[1])
            fields["attributes"]["command_text"] = command[1]
    elif service == "useradd" and (match := re.match(r"^new user: name=([^,\s]+), UID=\d+(?:,|$)", message)):
        fields.update(event_type="account_created", target=match[1])
    elif service == "systemd-logind" and re.fullmatch(r"Removed session [A-Za-z0-9_-]+\.", message):
        fields.update(event_type="session_close")
    elif service == "systemd" and re.match(r"^(?:Started|Starting|Stopped|Stopping) .+", message):
        fields["event_type"] = "service_activity"
    if fields["event_type"] is None:
        errors.append("event_type: unrecognized message retained without inferred activity")
    return fields


def _text_event(line: str, index: int, result: ParseResult) -> LinuxEventRecord | None:
    # Only delimiters are removed for matching; raw_record keeps the original line.
    match = PREFIX.match(line.rstrip("\r\n"))
    if match is None:
        return None
    errors: list[str] = []
    original = match["stamp"]
    if original[0].isdigit():
        utc = timestamp(original, errors)
    else:
        utc = None
        errors.append("timestamp: legacy syslog omits year/timezone; no time inferred")
    activity = _activity(match["service"], match["message"], errors)
    activity["attributes"]["parser_version"] = PARSER_VERSION
    return LinuxEventRecord(
        **result.provenance(index), source=result.source_file,
        timestamp_utc=utc, original_timestamp=original, host=match["host"],
        service=match["service"], process_id=integer(match["pid"], "PID", errors),
        message=match["message"], raw_record=line, parsing_errors=errors, **activity,
    )


def _journal_event(record: dict, index: int, result: ParseResult) -> LinuxEventRecord:
    errors: list[str] = []

    def read(name: str) -> str | None:
        return text_value(record.get(name), name, errors)

    message = read("MESSAGE")
    # These are distinct journal fields, not aliases: prefer explicit tag/trusted PID.
    service = read("SYSLOG_IDENTIFIER") or read("_COMM")
    pid_value = record.get("_PID") if record.get("_PID") is not None else record.get("SYSLOG_PID")
    pid = integer(pid_value, "PID", errors)
    original = read("__REALTIME_TIMESTAMP")
    micros = integer(original, "__REALTIME_TIMESTAMP", errors)
    utc = None
    if micros is not None:
        try:
            utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
        except OverflowError:
            errors.append("timestamp: journal microseconds out of range; raw value retained")
    else:
        errors.append("timestamp: journal microseconds missing or invalid; no time inferred")
    activity = _activity(service, message, errors)
    activity["attributes"]["parser_version"] = PARSER_VERSION
    if "_SYSTEMD_UNIT" in record:
        activity["attributes"]["emitter_systemd_unit"] = record["_SYSTEMD_UNIT"]
    if activity["event_type"] == "service_activity":
        activity["target"] = read("UNIT")
    return LinuxEventRecord(
        **result.provenance(index), source=result.source_file,
        timestamp_utc=utc, original_timestamp=original, host=read("_HOSTNAME"),
        service=service, process_id=pid, message=message, raw_record=record,
        parsing_errors=errors, **activity,
    )


def parse_linux(
    data: bytes, *, file_format: Literal["text", "journal-json"], source_file: str, upload_id: str
) -> ParseResult:
    if file_format not in ("text", "journal-json"):
        raise ParseInputError("Linux format must be text or journal-json")
    text, result = prepare(data, source_file, upload_id, f"linux-{file_format}")
    records = text_records(text)
    for index, line in bounded(records):
        if file_format == "text":
            event = _text_event(line, index, result)
            if event is None:
                result.rejected.append(RejectedRecord(index, "unsupported syslog/auth line", line))
                continue
        else:
            try:
                record = load_json(line)
            except (ValueError, RecursionError):
                result.rejected.append(RejectedRecord(index, "invalid journal JSON line", line))
                continue
            if not isinstance(record, dict) or not set(record) & {"MESSAGE", "__REALTIME_TIMESTAMP", "_HOSTNAME", "SYSLOG_IDENTIFIER", "_COMM"}:
                result.rejected.append(RejectedRecord(index, "not a supported journal object", record))
                continue
            try:
                event = _journal_event(record, index, result)
            except ValidationError:
                result.rejected.append(RejectedRecord(index, "record cannot satisfy event contract", record))
                continue
        result.events.append(event)
    return result
