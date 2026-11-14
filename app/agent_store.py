"""Local agent profiles, checkpoints and bounded evidence in the Sentinel store."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from uuid import uuid4

from sentinel.detection.windows_review import SECURITY_PROVIDER, field as windows_field
from .event_activity import parse_linux, parse_windows_jsonl
from sentinel.schemas import Finding, LinuxEventRecord, WindowsEventRecord
from .agent_collectors import collection_plan
from .log_context import load_roster, roster_labels, with_live_context
from .log_review import event_flags, review_events


MAX_AGENTS = 32
MAX_EVENTS = 50_000
MAX_PER_AGENT = 8_000
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
REVIEW_EVENTS = 2_000


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def parse_records(raw, source, agent_id, format):
    if format == "windows-jsonl":
        return parse_windows_jsonl(raw, source_file=source, upload_id=agent_id)
    return parse_linux(raw, file_format="text" if format == "linux-text" else "journal-json",
                       source_file=source, upload_id=agent_id)


def managed_findings(rows):
    for row in rows:
        timestamp = row["timestamp_utc"]
        if not timestamp:
            continue
        kind = row["event_type"]
        if kind == "integrity_change":
            title, severity, priority = "Selected file differs from baseline", "context", 45
            activity = "process_or_service_anomaly"
        elif kind == "listener_change":
            title, severity, priority = "New listening endpoint observed", "context", 45
            activity = "network_activity_anomaly"
        elif (row.get("windows_event_id") in {4728, 4732, 4756}
              and (row.get("channel") or "").casefold() == "security"
              and (row.get("provider") or "").casefold() == SECURITY_PROVIDER
              and isinstance(row["raw_record"], dict)
              and not any(error.startswith(("LogName:", "ProviderName:", "EventID:", "EventData:"))
                          for error in row["parsing_errors"])):
            group = windows_field(row["raw_record"], "TargetSid")
            if group != "S-1-5-32-544" and not (group.startswith("S-1-5-21-") and group.endswith(("-512", "-519"))):
                continue
            title, severity, priority = "Member added to a privileged Windows group", "warning", 75
            activity = "account_or_privilege_change"
        else:
            continue
        finding = Finding(
            finding_id=sha256(f"ssh-managed-v1:{title}:{row['event_id']}".encode()).hexdigest(),
            timestamp_utc=timestamp, activity_class=activity, triage_priority=priority,
            evidence_event_ids=[row["event_id"]], explanation=title + ". Compare the observation with authorized work.",
            method="deterministic", limitations=["The source reports the observation. Verify authorization and context."],
        )
        yield {"finding": finding.model_dump(mode="json"), "window_id": None, "title": title,
               "rule_version": "ssh-managed-v1", "severity": severity}


class AgentStore:
    def __init__(self, store):
        self.store = store

    def initialize(self):
        with self.store.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS ssh_agents (
                    id TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL,
                    profile TEXT NOT NULL, pins BLOB NOT NULL, health TEXT NOT NULL,
                    UNIQUE(host,port)
                );
                CREATE TABLE IF NOT EXISTS ssh_agent_streams (
                    agent_id TEXT NOT NULL REFERENCES ssh_agents(id) ON DELETE CASCADE,
                    stream TEXT NOT NULL, position TEXT, detail TEXT NOT NULL,
                    PRIMARY KEY(agent_id,stream)
                );
                CREATE TABLE IF NOT EXISTS ssh_agent_events (
                    seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL,
                    platform TEXT NOT NULL, host TEXT, timestamp_utc TEXT, event_type TEXT, source TEXT,
                    actor TEXT, source_ip TEXT, windows_event_id INTEGER, service TEXT,
                    raw BLOB NOT NULL, source_format TEXT NOT NULL, payload TEXT NOT NULL,
                    bytes INTEGER NOT NULL, severity TEXT
                );
                CREATE INDEX IF NOT EXISTS ssh_agent_event_host ON ssh_agent_events(agent_id,seq);
                CREATE INDEX IF NOT EXISTS ssh_agent_event_time ON ssh_agent_events(timestamp_utc);
                CREATE TABLE IF NOT EXISTS ssh_agent_findings (
                    agent_id TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ssh_agent_review_pending (agent_id TEXT PRIMARY KEY);
            """)

    def get(self, id):
        with self.store.connect() as connection:
            row = connection.execute("SELECT * FROM ssh_agents WHERE id=?", (id,)).fetchone()
        if not row:
            return None
        return json.loads(row["profile"]), row["pins"], json.loads(row["health"])

    def list(self):
        with self.store.connect() as connection:
            rows = connection.execute("""SELECT profile,health,
                (SELECT MAX(timestamp_utc) FROM ssh_agent_events AS e WHERE e.agent_id=a.id),
                (SELECT COUNT(*) FROM ssh_agent_events AS e WHERE e.agent_id=a.id AND severity IN ('warning','critical')),
                EXISTS(SELECT 1 FROM ssh_agent_captures AS c WHERE c.agent_id=a.id)
                FROM ssh_agents AS a ORDER BY host,port""").fetchall()
        return [json.loads(profile) | json.loads(health) | {"last_event_at": last_event, "alert_count": alerts,
                                                            "live_capture": bool(capture)}
                for profile, health, last_event, alerts, capture in rows]

    def put(self, profile, pins):
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT 1 FROM ssh_agents WHERE id=?", (profile["id"],)).fetchone()
            if not existing and connection.execute("SELECT COUNT(*) FROM ssh_agents").fetchone()[0] >= MAX_AGENTS:
                raise ValueError(f"Up to {MAX_AGENTS} managed SSH hosts are supported.")
            connection.execute("""INSERT INTO ssh_agents(id,host,port,profile,pins,health) VALUES (?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET profile=excluded.profile,pins=excluded.pins""",
                               (profile["id"], profile["host"], profile["port"], encode(profile), pins, "{}"))

    def remove(self, id):
        with self.store.connect() as connection:
            return connection.execute("DELETE FROM ssh_agents WHERE id=?", (id,)).rowcount

    def purge(self, id):
        with self.store.connect() as connection:
            connection.execute("DELETE FROM ssh_agent_events WHERE agent_id=?", (id,))
            connection.execute("DELETE FROM ssh_agent_findings WHERE agent_id=?", (id,))
            connection.execute("DELETE FROM ssh_agent_review_pending WHERE agent_id=?", (id,))

    def set_health(self, id, status, error=None, **details):
        with self.store.connect() as connection:
            row = connection.execute("SELECT health FROM ssh_agents WHERE id=?", (id,)).fetchone()
            if row is None:
                return
            health = json.loads(row[0])
            history = health.get("history", [])
            if (status, error) != (health.get("status"), health.get("error")):
                history = (history + [{"status": status, "error": error, "observed_at": utc_now()}])[-24:]
            health.update(status=status, error=error, history=history, **details)
            connection.execute("UPDATE ssh_agents SET health=? WHERE id=?", (encode(health), id))

    def streams(self, id):
        with self.store.connect() as connection:
            rows = connection.execute("SELECT stream,position,detail FROM ssh_agent_streams WHERE agent_id=?",
                                      (id,)).fetchall()
        return {name: (position, json.loads(detail)) for name, position, detail in rows}

    def stream_status(self, id, stream, position, detail):
        with self.store.connect() as connection:
            self.write_stream(connection, id, stream, position, detail)

    @staticmethod
    def write_stream(connection, id, stream, position, detail):
        connection.execute("""INSERT INTO ssh_agent_streams(agent_id,stream,position,detail) VALUES(?,?,?,?)
            ON CONFLICT(agent_id,stream) DO UPDATE SET position=excluded.position, detail=excluded.detail""",
                           (id, stream, position, encode(detail)))

    def page(self, profile, stream, page, detail, *, emit_change=False):
        """Advance the checkpoint in the same transaction as native evidence."""
        id = profile["id"]
        source = f"ssh-agent-{id[:8]}-{stream.id}"
        entries = []
        if page.records:
            batch = list(page.records.items())
            result = parse_records(b"".join(line for _, line in batch), source, id, stream.source_format)
            if result.rejected or len(result.events) != len(batch):
                raise ValueError("The source page contains invalid log records. The checkpoint was held.")
            for record, (identity, raw) in zip(result.events, batch):
                values = record.model_dump(mode="json")
                native = f"{id}:{'files:' + stream.id if stream.kind == 'file' else stream.kind}:{identity}"
                event_id = sha256(native.encode()).hexdigest()
                values.update(event_id=event_id, source_sha256=sha256(id.encode()).hexdigest())
                entries.append(self.entry(profile, stream, detail, values, raw, stream.source_format))
        if emit_change:
            kind = "integrity_change" if stream.module == "integrity" else "listener_change"
            raw = encode({"collector": stream.id, "changes": detail["changes"]}).encode()
            schema = WindowsEventRecord if profile["platform"] == "windows" else LinuxEventRecord
            values = schema(event_id=sha256(id.encode() + raw + detail["observed_at"].encode()).hexdigest(),
                            upload_id=id, source=stream.id, host=profile["host"], source_file=source,
                            timestamp_utc=detail["observed_at"], event_type=kind, raw_record=json.loads(raw),
                            message="Observed differences from the initial snapshot.",
                            source_sha256=sha256(id.encode()).hexdigest(), record_index=1).model_dump(mode="json")
            entries.append(self.entry(profile, stream, detail, values, raw, "agent-snapshot"))
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            before = connection.total_changes
            connection.executemany("""INSERT OR IGNORE INTO ssh_agent_events
                (event_id,agent_id,platform,host,timestamp_utc,event_type,source,actor,source_ip,windows_event_id,
                 service,raw,source_format,payload,bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", entries)
            inserted = connection.total_changes - before
            self.write_stream(connection, id, stream.id, page.bookmark, detail)
            if inserted:
                connection.execute("INSERT OR IGNORE INTO ssh_agent_review_pending(agent_id) VALUES (?)", (id,))
                connection.execute("DELETE FROM ssh_agent_events WHERE seq IN (SELECT seq FROM ssh_agent_events "
                                   "WHERE agent_id=? ORDER BY seq DESC LIMIT -1 OFFSET ?)", (id, MAX_PER_AGENT))
                count, size = connection.execute("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM ssh_agent_events").fetchone()
                if count > MAX_EVENTS or size > MAX_EVIDENCE_BYTES:
                    connection.execute("""DELETE FROM ssh_agent_events WHERE seq IN (
                        SELECT seq FROM (SELECT seq, ROW_NUMBER() OVER (ORDER BY seq DESC) AS n,
                            SUM(bytes) OVER (ORDER BY seq DESC) AS size FROM ssh_agent_events)
                        WHERE n > ? OR size > ?)""", (MAX_EVENTS, MAX_EVIDENCE_BYTES))
        return inserted

    @staticmethod
    def entry(profile, stream, detail, values, raw, format):
        payload = encode(values | {"agent_id": profile["id"], "agent_name": profile["name"], "collector": stream.id,
                                   "collected_at": detail["observed_at"], "collector_version": "ssh-agents-v1"})
        stamp = values.get("timestamp_utc")
        if stamp:
            stamp = datetime.fromisoformat(stamp).isoformat(timespec="microseconds")
        return (values["event_id"], profile["id"], values["platform"], values["host"], stamp, values["event_type"],
                values["source"], values["actor"], values.get("source_ip"), values.get("windows_event_id"),
                values.get("service"), raw, format, payload, len(raw) + len(payload))

    def review_pending(self, id):
        with self.store.connect() as connection:
            return connection.execute("SELECT 1 FROM ssh_agent_review_pending WHERE agent_id=?", (id,)).fetchone() is not None

    def recent(self, id, limit=50):
        with self.store.connect() as connection:
            return [json.loads(payload) | {"agent_severity": severity} for payload, severity in connection.execute(
                "SELECT payload,severity FROM ssh_agent_events WHERE agent_id=? ORDER BY seq DESC LIMIT ?", (id, limit)
            )]

    def analyze(self, profile):
        id = profile["id"]
        rows = self.recent(id, REVIEW_EVENTS)
        if not rows:
            return
        schema = WindowsEventRecord if profile["platform"] == "windows" else LinuxEventRecord
        review = review_events([schema.model_validate({key: row[key] for key in schema.model_fields if key in row})
                                for row in reversed(rows)], profile["platform"])
        findings = review.findings + list(managed_findings(rows))
        flags = event_flags(findings)
        severity_order = {"critical": 3, "warning": 2, "lead": 1, "context": 0}
        ranked = sorted(findings, key=lambda row: (
            severity_order.get(row.get("severity"), 2), row["finding"]["timestamp_utc"] or ""), reverse=True)
        with self.store.connect() as connection:
            connection.executemany("UPDATE ssh_agent_events SET severity=? WHERE event_id=?",
                                   ((severity, event) for event, severity in flags.items()))
            connection.execute("""INSERT INTO ssh_agent_findings(agent_id,payload) VALUES(?,?)
                ON CONFLICT(agent_id) DO UPDATE SET payload=excluded.payload""", (id, encode(ranked[:50])))
            connection.execute("DELETE FROM ssh_agent_review_pending WHERE agent_id=?", (id,))

    def detail(self, id):
        found = self.get(id)
        if found is None:
            return None
        profile, _, health = found
        with self.store.connect() as connection:
            finding = connection.execute("SELECT payload FROM ssh_agent_findings WHERE agent_id=?", (id,)).fetchone()
            stamp = connection.execute("SELECT MAX(timestamp_utc) FROM ssh_agent_events WHERE agent_id=?", (id,)).fetchone()[0]
            alerts = connection.execute("SELECT COUNT(*) FROM ssh_agent_events WHERE agent_id=? "
                                        "AND severity IN ('warning','critical')", (id,)).fetchone()[0]
            roster = load_roster(connection)
        active = {stream.id for stream in collection_plan(profile["platform"], profile.get("modules", []),
                                                          profile.get("integrity_paths", []))}
        streams = [value[1] for key, value in self.streams(id).items() if key in active]
        events = self.recent(id)
        return profile | health | roster_labels(events, roster) | {
            "last_event_at": stamp, "alert_count": alerts, "streams": streams,
            "events": events, "findings": json.loads(finding[0]) if finding else [],
        }

    def finding_evidence(self, id, finding_id):
        with self.store.connect() as connection:
            stored = connection.execute("SELECT payload FROM ssh_agent_findings WHERE agent_id=?", (id,)).fetchone()
            finding = next((row["finding"] for row in json.loads(stored[0])
                            if row["finding"]["finding_id"] == finding_id), None) if stored else None
            if finding is None:
                return None
            ids = finding["evidence_event_ids"]
            rows = [json.loads(payload) | {"agent_severity": severity} for payload, severity in connection.execute(
                "SELECT payload,severity FROM ssh_agent_events WHERE agent_id=? "
                "AND event_id IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT 5", (id, encode(ids))
            )]
            roster = load_roster(connection)
        return {"events": rows, "total_cited": len(ids), **roster_labels(rows, roster)}

    def live(self, detail):
        rows = list(reversed(self.recent(detail["id"], 100)))
        flags = {row["event_id"]: row["agent_severity"] for row in rows if row["agent_severity"]}
        review = {"events": rows, "findings": detail["findings"], "finding_count": len(detail["findings"]),
                  "flagged": flags, "windows_reviewed_event_ids": []}
        return {"source": detail["name"], "review": with_live_context(self.store, review)}

    def export(self, id, name):
        with self.store.connect() as connection:
            rows = connection.execute("SELECT raw,source_format FROM ssh_agent_events WHERE agent_id=? "
                                      "AND source_format <> 'agent-snapshot' ORDER BY seq DESC LIMIT 1000", (id,)).fetchall()
        if not rows:
            raise ValueError("Collect records before saving a Logs snapshot.")
        preferred = rows[0]["source_format"]
        data = b"".join(raw for raw, format in reversed(rows) if format == preferred)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("This snapshot exceeds 16 MiB. Export a narrower scope.")
        source = f"ssh-agent-{id[:8]}-{name[:64]}" + (".log" if preferred == "linux-text" else ".jsonl")
        return self.store.save(data, parse_records(data, source, uuid4().hex, preferred))
