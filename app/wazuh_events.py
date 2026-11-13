"""Bounded Wazuh evidence and deduplication receipts in the local evidence store."""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from math import isfinite
import re


MAX_ALERT_BYTES = 64 * 1024
MAX_ALERTS = 500
MAX_HEALTH_EVENTS = 250
MAX_RECEIPTS = 4096
ALERT = "security_alert"
TRANSITIONS = {("active", "disconnected"): "agent_disconnected", ("disconnected", "active"): "agent_recovered"}
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])"
)


class EventValidationError(ValueError):
    pass


class EventTooLarge(EventValidationError):
    pass


class EventConflict(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EventValidationError("Wazuh JSON contains a duplicate member.")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise EventValidationError("Wazuh JSON numbers must be finite.")


def _finite_float(value):
    number = float(value)
    if not isfinite(number):
        _invalid_constant(value)
    return number


def decode_alert(body: bytes) -> dict:
    if len(body) > MAX_ALERT_BYTES:
        raise EventTooLarge("The Wazuh alert exceeds 64 KiB.")
    try:
        raw = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_invalid_constant, parse_float=_finite_float)
    except EventValidationError:
        raise
    except (ValueError, RecursionError):
        raise EventValidationError("The Wazuh body must be valid UTF-8 JSON.") from None
    if not isinstance(raw, dict):
        raise EventValidationError("A single Wazuh JSON alert object is required.")
    return raw


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise EventValidationError("The Wazuh object contains invalid JSON data.") from None


def _timestamp(value) -> str:
    if isinstance(value, str) and len(value) <= 40 and TIMESTAMP.fullmatch(value):
        try:
            return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat(timespec="microseconds")
        except (ValueError, OverflowError):
            pass
    raise EventValidationError("Wazuh timestamps require an explicit time zone.")


def _text(value, field: str, maximum: int, *, required=False) -> str | None:
    if value is None and not required:
        return None
    if (not isinstance(value, str) or len(value) > maximum or not value.strip() or "\x00" in value):
        raise EventValidationError(f"Invalid Wazuh {field}.")
    return value


def _identifier(value, field: str, *, required=False) -> str | None:
    if type(value) is int and 0 <= value < 10**20:
        value = str(value)
    return _text(value, field, 128, required=required)


def _ip(value) -> str | None:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _normalize(manager_id, raw, *, event_type, source_event_id, timestamp, agent_id, agent_name, agent_ip):
    manager_id = _text(manager_id, "manager identifier", 128, required=True)
    encoded = _canonical(raw)
    if len(encoded) > MAX_ALERT_BYTES:
        raise EventTooLarge("The Wazuh event exceeds 64 KiB.")
    identity = ["native", source_event_id] if source_event_id is not None else ["content", sha256(encoded).hexdigest()]
    event_id = sha256(_canonical(["sentinel-wazuh-v1", manager_id, event_type, identity])).hexdigest()
    return {
        "id": event_id, "manager_id": manager_id, "source": "wazuh", "event_type": event_type,
        "source_event_id": source_event_id, "timestamp": _timestamp(timestamp),
        "agent_id": agent_id, "agent_name": agent_name, "agent_ip": _ip(agent_ip), "raw_event": raw,
    }


def normalize_alert(manager_id: str, raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise EventValidationError("A single Wazuh JSON alert object is required.")
    rule = raw.get("rule")
    agent = raw.get("agent")
    if not isinstance(rule, dict) or (agent is not None and not isinstance(agent, dict)):
        raise EventValidationError("Wazuh rule and agent fields must be objects when supplied, with rule required.")
    agent = agent or {}
    level = rule.get("level")
    if type(level) is not int or not 0 <= level <= 16:
        raise EventValidationError("Wazuh rule level must be an integer from 0 through 16.")
    groups = rule.get("groups", [])
    if not isinstance(groups, list) or len(groups) > 64:
        raise EventValidationError("Wazuh rule groups must be a list of up to 64 labels.")
    description = _text(rule.get("description"), "rule description", 4096)
    event = _normalize(
        manager_id, raw, event_type=ALERT, source_event_id=_identifier(raw.get("id"), "alert ID"),
        timestamp=raw.get("timestamp"), agent_id=_identifier(agent.get("id"), "agent ID"),
        agent_name=_text(agent.get("name"), "agent name", 255), agent_ip=agent.get("ip"),
    )
    event.update(
        rule_id=_identifier(rule.get("id"), "rule ID", required=True),
        rule_level=level, rule_description=description,
        rule_groups=[_text(group, "rule group", 128, required=True) for group in groups],
        message=description or "Wazuh reported an alert.",
    )
    return event


def normalize_transition(manager_id: str, *, agent_id: str, agent_name: str | None, timestamp: str,
                         previous_status: str, status: str, ip: str | None = None) -> dict:
    event_type = TRANSITIONS.get((previous_status, status))
    if not event_type:
        raise EventValidationError("Unsupported Wazuh agent transition.")
    agent_id = _identifier(agent_id, "agent ID", required=True)
    agent_name = _text(agent_name, "agent name", 255)
    timestamp = _timestamp(timestamp)
    raw = {
        "agent": {"id": agent_id, "name": agent_name, "ip": ip},
        "previous_status": previous_status, "status": status, "observed_at": timestamp,
    }
    event = _normalize(
        manager_id, raw, event_type=event_type, source_event_id=None, timestamp=timestamp,
        agent_id=agent_id, agent_name=agent_name, agent_ip=ip,
    )
    message = ("The manager reported an agent disconnection. Investigate agent, host, and network health."
               if status == "disconnected" else "The manager reported that the agent is active again.")
    event.update(previous_status=previous_status, status=status, message=message)
    return event


def initialize(store):
    with store.connect() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS wazuh_events (
                id TEXT PRIMARY KEY,
                manager_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                agent_name TEXT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS wazuh_event_time ON wazuh_events(manager_id,timestamp DESC,id DESC);
            CREATE INDEX IF NOT EXISTS wazuh_event_type ON wazuh_events(event_type);
            CREATE TABLE IF NOT EXISTS wazuh_event_receipts (
                id TEXT PRIMARY KEY,
                digest TEXT NOT NULL
            );
        """)


def record_event(connection, event: dict) -> bool:
    """Insert an event and its receipt inside the caller's write transaction."""
    event_id = event["id"]
    digest = sha256(_canonical(event["raw_event"])).hexdigest()
    receipt = connection.execute("SELECT digest FROM wazuh_event_receipts WHERE id=?", (event_id,)).fetchone()
    if receipt:
        if digest != receipt[0]:
            raise EventConflict("A different Wazuh payload already uses this source event identity.")
        return False
    # The separate receipt window may have rolled past a still-visible health event.
    existing = connection.execute("SELECT payload FROM wazuh_events WHERE id=?", (event_id,)).fetchone()
    if existing:
        if digest != sha256(_canonical(json.loads(existing[0])["raw_event"])).hexdigest():
            raise EventConflict("A different Wazuh payload already uses this source event identity.")
        return False
    connection.execute("INSERT INTO wazuh_event_receipts(id,digest) VALUES (?,?)", (event_id, digest))
    connection.execute(
        "INSERT INTO wazuh_events(id,manager_id,timestamp,agent_name,event_type,payload) VALUES (?,?,?,?,?,?)",
        (event_id, event["manager_id"], event["timestamp"], event["agent_name"], event["event_type"], _canonical(event).decode("utf-8")),
    )
    is_alert = event["event_type"] == ALERT
    connection.execute(
        "DELETE FROM wazuh_events WHERE rowid IN (SELECT rowid FROM wazuh_events WHERE (event_type=?)=? "
        "ORDER BY rowid DESC LIMIT -1 OFFSET ?)",
        (ALERT, is_alert, MAX_ALERTS if is_alert else MAX_HEALTH_EVENTS),
    )
    connection.execute(
        "DELETE FROM wazuh_event_receipts WHERE rowid IN (SELECT rowid FROM wazuh_event_receipts "
        "ORDER BY rowid DESC LIMIT -1 OFFSET ?)",
        (MAX_RECEIPTS,),
    )
    return True


def save_event(store, event: dict) -> bool:
    with store.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        return record_event(connection, event)


def read_event(store, event_id: str, *, manager_id: str | None = None) -> dict | None:
    with store.connect() as connection:
        row = connection.execute(
            "SELECT payload FROM wazuh_events WHERE id=? AND (? IS NULL OR manager_id=?)",
            (event_id, manager_id, manager_id),
        ).fetchone()
    return json.loads(row[0]) if row else None


def page_events(store, *, offset: int = 0, limit: int = 25, event_type: str | None = None,
                manager_id: str | None = None) -> dict:
    if not 0 <= offset or not 1 <= limit <= 100:
        raise ValueError("Wazuh page bounds are invalid.")
    clauses, parameters = [], []
    for field, value in (("manager_id", manager_id), ("event_type", event_type)):
        if value is not None:
            clauses.append(f"{field}=?")
            parameters.append(value)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with store.connect() as connection:
        connection.execute("BEGIN")
        total = connection.execute(f"SELECT COUNT(*) FROM wazuh_events {where}", parameters).fetchone()[0]
        rows = connection.execute(
            f"SELECT payload FROM wazuh_events {where} ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
    return {"items": [json.loads(row[0]) for row in rows], "total": total, "offset": offset, "limit": limit}
