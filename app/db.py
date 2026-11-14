"""Local evidence storage. Upload names never become filesystem paths."""

from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3

from sentinel.ingest.common import ParseResult
from sentinel.ingest.pcap import CaptureResult
from sentinel.snapshots import SnapshotResult

RETENTION_DAYS = 7
MAX_UPLOADS = 250


class StorageFull(ValueError):
    pass


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.raw_dir = self.root / "raw"
        self.db_path = self.root / "sentinel.sqlite3"

    @contextmanager
    def connect(self):
        # Streaming generators can resume on another ASGI worker thread. Each
        # connection still belongs to one serial operation and is always closed.
        connection = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self):
        self.raw_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.root.chmod(0o700)
        self.raw_dir.chmod(0o700)
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                    filename TEXT NOT NULL, format TEXT NOT NULL, sha256 TEXT NOT NULL,
                    byte_count INTEGER NOT NULL, accepted_count INTEGER NOT NULL,
                    rejected_count INTEGER NOT NULL, warning_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    record_index INTEGER NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY (upload_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS rejected (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    record_index INTEGER NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY (upload_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rehearsal_reviews (
                    upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL,
                    confirmations TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feature_windows (
                    upload_id TEXT NOT NULL REFERENCES analyses(upload_id) ON DELETE CASCADE,
                    window_id TEXT NOT NULL, start_utc TEXT NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(upload_id, window_id)
                );
                CREATE TABLE IF NOT EXISTS baseline_findings (
                    upload_id TEXT NOT NULL REFERENCES analyses(upload_id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL, priority INTEGER NOT NULL, timestamp_utc TEXT NOT NULL,
                    payload TEXT NOT NULL, PRIMARY KEY(upload_id, finding_id)
                );
                CREATE TABLE IF NOT EXISTS captured_critical_events (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL, timestamp_utc TEXT, reviewed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(upload_id,event_id)
                );
                CREATE TABLE IF NOT EXISTS finding_maintenance_notes (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL, note TEXT NOT NULL, username TEXT NOT NULL,
                    updated_at TEXT NOT NULL, PRIMARY KEY(upload_id, finding_id)
                );
                CREATE TABLE IF NOT EXISTS blue_team_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT NOT NULL, host TEXT NOT NULL, account TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'blue-team' CHECK(category IN ('blue-team', 'user')),
                    UNIQUE(platform, host, account)
                );
                CREATE TABLE IF NOT EXISTS live_bookmarks (
                    scope TEXT PRIMARY KEY, position TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_summaries (
                    upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_flows (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    flow_id TEXT NOT NULL, protocol TEXT NOT NULL, source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL, destination_port INTEGER NOT NULL,
                    packet_count INTEGER NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(upload_id, flow_id)
                );
                CREATE TABLE IF NOT EXISTS network_packets (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    record_index INTEGER NOT NULL, flow_id TEXT, status TEXT NOT NULL,
                    payload TEXT NOT NULL, PRIMARY KEY(upload_id, record_index)
                );
                CREATE INDEX IF NOT EXISTS network_evidence ON network_packets(upload_id,flow_id,record_index);
                CREATE TABLE IF NOT EXISTS snapshots (
                    upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL
                );
            """)
            if "category" not in {row["name"] for row in connection.execute("PRAGMA table_info(blue_team_accounts)")}:
                connection.execute("ALTER TABLE blue_team_accounts ADD COLUMN category TEXT NOT NULL DEFAULT 'blue-team' "
                                   "CHECK(category IN ('blue-team', 'user'))")
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(events)")}
            additions = ("timestamp_utc", "host", "platform", "event_type", "source", "event_id",
                         "actor", "source_ip", "windows_event_id", "service")
            for name in additions:
                if name not in columns:
                    connection.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
            if any(name not in columns for name in additions):
                rows = connection.execute("SELECT upload_id, record_index, payload FROM events").fetchall()
                for row in rows:
                    event = json.loads(row["payload"])
                    value = event.get("timestamp_utc")
                    stamp = datetime.fromisoformat(value).astimezone(timezone.utc).isoformat(timespec="microseconds") if value else None
                    connection.execute(
                        "UPDATE events SET timestamp_utc=?, host=?, platform=?, event_type=?, source=?, event_id=?, actor=?, source_ip=?, windows_event_id=?, service=? WHERE upload_id=? AND record_index=?",
                        (stamp, event.get("host"), event.get("platform"), event.get("event_type"), event.get("source"), event.get("event_id"),
                         event.get("actor"), event.get("source_ip"), event.get("windows_event_id"), event.get("service"), row["upload_id"], row["record_index"]),
                    )
            connection.execute("CREATE INDEX IF NOT EXISTS event_time ON events(timestamp_utc)")
            connection.execute("CREATE INDEX IF NOT EXISTS event_reference ON events(upload_id,event_id)")
            for name in ("actor", "source_ip", "windows_event_id"):
                connection.execute(f"CREATE INDEX IF NOT EXISTS event_{name} ON events({name})")
        self.db_path.chmod(0o600)
        self.prune_expired()

    def blob_path(self, upload_id: str) -> Path:
        if re.fullmatch(r"[a-f0-9]{32}", upload_id) is None:
            raise ValueError("invalid local upload identifier")
        return self.raw_dir / f"{upload_id}.bin"

    def prune_expired(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        with self.connect() as connection:
            expired = connection.execute("SELECT id FROM uploads WHERE created_at < ?", (cutoff,)).fetchall()
            for row in expired:
                self.blob_path(row["id"]).unlink(missing_ok=True)
                connection.execute("DELETE FROM uploads WHERE id = ?", (row["id"],))

    def save(self, data: bytes, result: ParseResult | CaptureResult) -> dict:
        self.prune_expired()
        capture = isinstance(result, CaptureResult)
        snapshot = isinstance(result, SnapshotResult)
        if snapshot:
            accepted = sum(len(section.items) for section in result.snapshot.sections.values())
            rejected = 0
            warnings = sum(not section.complete for section in result.snapshot.sections.values())
        else:
            accepted = result.summary["decoded_packets"] if capture else len(result.events)
            rejected = len(result.packets) - accepted if capture else len(result.rejected)
            warnings = result.summary["packets_with_warnings"] if capture else sum(bool(e.parsing_errors) for e in result.events)
        path = self.blob_path(result.upload_id)
        created_blob = False
        try:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT COUNT(*) FROM uploads").fetchone()[0] >= MAX_UPLOADS:
                    raise StorageFull("Import limit reached. Delete an older import first.")
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created_blob = True
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                connection.execute(
                    "INSERT INTO uploads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (result.upload_id, datetime.now(timezone.utc).isoformat(), result.source_file,
                     result.parser, result.source_sha256, len(data), accepted, rejected, warnings),
                )
                if snapshot:
                    connection.execute("INSERT INTO snapshots VALUES (?,?)", (result.upload_id, result.snapshot.model_dump_json()))
                elif capture:
                    connection.execute("INSERT INTO network_summaries VALUES (?,?)", (result.upload_id, json.dumps(result.summary, allow_nan=False)))
                    connection.executemany("INSERT INTO network_flows VALUES (?,?,?,?,?,?,?,?)", (
                        (result.upload_id, flow["flow_id"], flow["protocol"], flow["source_ip"], flow["destination_ip"],
                         flow["destination_port"], flow["packet_count"], json.dumps(flow, allow_nan=False)) for flow in result.flows
                    ))
                    connection.executemany("INSERT INTO network_packets VALUES (?,?,?,?,?)", (
                        (result.upload_id, packet["record_index"], packet["flow_id"], packet["status"],
                         json.dumps(packet, allow_nan=False)) for packet in result.packets
                    ))
                else:
                    self._save_log_records(connection, result)
        except Exception:
            if created_blob:
                path.unlink(missing_ok=True)
            raise
        return self.get(result.upload_id)

    @staticmethod
    def _save_log_records(connection, result):
        connection.executemany("INSERT INTO events (upload_id, record_index, payload, timestamp_utc, host, platform, event_type, source, event_id, actor, source_ip, windows_event_id, service) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                    (result.upload_id, event.record_index, event.model_dump_json(),
                     event.timestamp_utc.isoformat(timespec="microseconds") if event.timestamp_utc else None,
                     event.host, event.platform, event.event_type, event.source, event.event_id,
                     event.actor, str(event.source_ip) if event.source_ip is not None else None,
                     getattr(event, "windows_event_id", None), getattr(event, "service", None)) for event in result.events
                ))
        connection.executemany("INSERT INTO rejected VALUES (?, ?, ?)", (
                    (result.upload_id, item.record_index, json.dumps(vars(item), allow_nan=False))
                    for item in result.rejected
                ))

    def get(self, upload_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
        return dict(row) if row else None

    def uploads(self, offset: int, limit: int) -> dict:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM uploads").fetchone()[0]
            rows = connection.execute(
                "SELECT * FROM uploads ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "offset": offset, "limit": limit}

    def records(self, upload_id: str, kind: str, offset: int, limit: int) -> dict:
        if kind not in ("events", "rejected"):
            raise ValueError("unknown record kind")
        with self.connect() as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM {kind} WHERE upload_id = ?", (upload_id,)).fetchone()[0]
            rows = connection.execute(
                f"SELECT payload FROM {kind} WHERE upload_id = ? ORDER BY record_index LIMIT ? OFFSET ?",
                (upload_id, limit, offset),
            ).fetchall()
        return {"items": [json.loads(row["payload"]) for row in rows], "total": total,
                "offset": offset, "limit": limit, "upload_id": upload_id}

    def delete(self, upload_id: str) -> bool:
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM uploads WHERE id = ?", (upload_id,)).fetchone() is None:
                return False
            self.blob_path(upload_id).unlink(missing_ok=True)
            connection.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
        return True

    def timeline(self, offset: int, limit: int, *, upload_id=None, host=None, platform=None,
                 event_type=None, source=None, start=None, end=None, actor=None, source_ip=None,
                 windows_event_id=None, service=None, event_types=None, services=None, evidence_ids=None,
                 include_logs=True, wazuh_manager=None, wazuh_event=None, include_agents=False, agent_id=None,
                 collector=None, severity=None, include_scans=False) -> dict:
        clauses, values = [], []
        if evidence_ids is not None:
            clauses.append("event_id IN (SELECT value FROM json_each(?))")
            values.append(json.dumps(evidence_ids))
        for name, value in (("upload_id", upload_id), ("host", host), ("platform", platform),
                            ("event_type", event_type), ("source", source), ("actor", actor),
                            ("source_ip", source_ip), ("windows_event_id", windows_event_id), ("service", service)):
            if value is not None:
                clauses.append(f"{name} = ?")
                values.append(value)
        for name, options in (("event_type", event_types), ("service", services)):
            if options is not None:
                if not options:
                    clauses.append("0")
                else:
                    clauses.append(f"{name} IN ({','.join('?' for _ in options)})")
                    values.extend(options)
        for operator, value in ((">=", start), ("<=", end)):
            if value is not None:
                clauses.append(f"timestamp_utc {operator} ?")
                values.append(value.astimezone(timezone.utc).isoformat(timespec="microseconds"))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        if wazuh_manager is not None or not include_logs or include_agents or include_scans:
            return self.combined_timeline(offset, limit, where, values, include_logs=include_logs,
                                          manager=wazuh_manager, wazuh_event=wazuh_event,
                                          host=host, event_type=event_type, start=start, end=end,
                                          include_agents=include_agents, agent_id=agent_id, collector=collector,
                                          severity=severity, include_scans=include_scans)
        with self.connect() as connection:
            connection.execute("BEGIN")
            total = connection.execute("SELECT COUNT(*) FROM events" + where, values).fetchone()[0]
            rows = connection.execute(
                "SELECT payload FROM events" + where +
                " ORDER BY timestamp_utc IS NULL, timestamp_utc, upload_id, record_index LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        return {"items": [json.loads(row["payload"]) for row in rows], "total": total,
                "offset": offset, "limit": limit, "order": "UTC ascending; unknown times last"}

    def combined_timeline(self, offset, limit, log_where, log_values, *, include_logs, manager,
                          wazuh_event, host, event_type, start, end, include_agents, agent_id, collector, severity,
                          include_scans=False):
        # Keep the native event payload contracts and join only their ordering keys.
        sources, values = [], []
        if include_logs:
            sources.append("SELECT payload,timestamp_utc,0 AS stream,upload_id AS evidence,record_index FROM events" + log_where)
            values.extend(log_values)
        if include_agents:
            agent_where = log_where
            values.extend(log_values)
            for clause, value in (("agent_id = ?", agent_id), ("json_extract(payload,'$.collector') = ?", collector),
                                  ("severity IS NULL" if severity == "neutral" else "severity = ?", severity)):
                if value is not None:
                    agent_where += (" AND " if agent_where else " WHERE ") + clause
                    if "?" in clause:
                        values.append(value)
            sources.append("SELECT json_set(payload,'$.agent_severity',severity) AS payload,timestamp_utc,"
                           "2 AS stream,agent_id AS evidence,seq AS record_index FROM ssh_agent_events" + agent_where)
        if manager is not None:
            clauses = ["manager_id = ?"]
            values.append(manager)
            for column, value in (("id", wazuh_event), ("event_type", event_type)):
                if value is not None:
                    clauses.append(f"{column} = ?")
                    values.append(value)
            if host is not None:
                clauses.append("(agent_name = ? OR json_extract(payload,'$.agent_ip') = ? OR "
                               "json_extract(payload,'$.raw_event.agentless.host') = ? OR "
                               "json_extract(payload,'$.raw_event.predecoder.hostname') = ?)")
                values.extend((host, host, host, host))
            for operator, value in ((">=", start), ("<=", end)):
                if value is not None:
                    clauses.append(f"timestamp {operator} ?")
                    values.append(value.astimezone(timezone.utc).isoformat(timespec="microseconds"))
            sources.append("SELECT payload,timestamp AS timestamp_utc,1 AS stream,id AS evidence,0 AS record_index "
                           "FROM wazuh_events WHERE " + " AND ".join(clauses))
        if include_scans and event_type in {None, "port_state_change"}:
            clauses = ["1=1"]
            if host is not None:
                clauses.append("(address = ? OR json_extract(payload,'$.target') = ?)")
                values.extend((host, host))
            for operator, value in ((">=", start), ("<=", end)):
                if value is not None:
                    clauses.append(f"stamp {operator} ?")
                    values.append(value.astimezone(timezone.utc).isoformat(timespec="microseconds"))
            sources.append("SELECT payload,stamp AS timestamp_utc,3 AS stream,id AS evidence,0 AS record_index "
                           "FROM nmap_observations WHERE " + " AND ".join(clauses))
        total, rows = 0, []
        if sources:
            query = " UNION ALL ".join(sources)
            with self.connect() as connection:
                connection.execute("BEGIN")
                total = connection.execute("SELECT COUNT(*) FROM (" + query + ")", values).fetchone()[0]
                rows = connection.execute(
                    "SELECT payload FROM (" + query + ") "
                    "ORDER BY timestamp_utc IS NULL,timestamp_utc,stream,evidence,record_index LIMIT ? OFFSET ?",
                    (*values, limit, offset),
                ).fetchall()
        return {"items": [json.loads(row["payload"]) for row in rows], "total": total, "offset": offset, "limit": limit,
                "order": "UTC ascending; unknown times last"}

    def overview(self, upload_id: str) -> dict | None:
        """One snapshot of observed counts; top values are frequency, never risk."""
        with self.connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
            if row is None:
                return None
            source = dict(row)
            stats = connection.execute("""
                SELECT COUNT(*) AS event_count, COUNT(timestamp_utc) AS timed_records,
                       MIN(timestamp_utc) AS first_utc, MAX(timestamp_utc) AS last_utc,
                       COUNT(DISTINCT host) AS host_count, COUNT(DISTINCT actor) AS actor_count,
                       COUNT(DISTINCT source_ip) AS source_ip_count,
                       COUNT(*)-COUNT(host) AS missing_host,
                       COUNT(*)-COUNT(actor) AS missing_actor,
                       COUNT(*)-COUNT(source_ip) AS missing_source_ip,
                       COUNT(*)-COUNT(event_type) AS unknown_activity
                FROM events WHERE upload_id=?
            """, (upload_id,)).fetchone()
            result = {**dict(stats), "source": source, "version": "observed-overview-v1"}
            for field in ("host", "actor", "source_ip", "event_type"):
                groups = connection.execute(
                    f"SELECT {field} AS value, COUNT(*) AS count FROM events WHERE upload_id=? AND {field} IS NOT NULL "
                    f"GROUP BY {field} ORDER BY count DESC, {field} LIMIT 8", (upload_id,)).fetchall()
                result[field + "s"] = [dict(group) for group in groups]
        result["unknown_time"] = result["event_count"] - result["timed_records"]
        result["limitations"] = "Observed parsed records only; rejected records are excluded. Top eight known values by frequency, not risk. Duplicate exports can inflate counts. No threat verdict or complete host/account inventory is inferred."
        return result

    def iter_records(self, upload_id: str, kind: str):
        if kind not in ("events", "rejected"):
            raise ValueError("unknown record kind")
        with self.connect() as connection:
            cursor = connection.execute(
                f"SELECT payload FROM {kind} WHERE upload_id = ? ORDER BY record_index", (upload_id,)
            )
            while rows := cursor.fetchmany(100):
                for row in rows:
                    yield json.loads(row["payload"])
