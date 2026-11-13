"""Save opted-in managed SSH evidence as immutable, bounded Logs imports."""

from hashlib import sha256
from time import time
from uuid import uuid4

from .agent_store import parse_records
from .analysis import run_analysis


INTERVAL = 300
BATCH = 256
MAX_BYTES = 4 * 1024 * 1024


class AgentCapture:
    def __init__(self, store):
        self.store = store

    def initialize(self):
        with self.store.connect() as connection:
            connection.executescript("""CREATE TABLE IF NOT EXISTS ssh_agent_captures (
                agent_id TEXT PRIMARY KEY REFERENCES ssh_agents(id) ON DELETE CASCADE,
                token TEXT NOT NULL, position INTEGER NOT NULL, cutoff INTEGER,
                next_save REAL NOT NULL, last_upload_id TEXT, error TEXT
            );
            CREATE TABLE IF NOT EXISTS ssh_agent_capture_records (
                agent_id TEXT NOT NULL REFERENCES ssh_agent_captures(agent_id) ON DELETE CASCADE,
                event_id TEXT NOT NULL, upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                saved_event_id TEXT NOT NULL, PRIMARY KEY(agent_id,event_id)
            );
            CREATE INDEX IF NOT EXISTS ssh_agent_capture_upload ON ssh_agent_capture_records(upload_id);
            """)

    def mark_critical(self, connection, id):
        connection.execute("""INSERT OR IGNORE INTO captured_critical_events(upload_id,event_id,timestamp_utc)
            SELECT saved.upload_id,saved.saved_event_id,event.timestamp_utc FROM ssh_agent_capture_records AS saved
            JOIN ssh_agent_events AS event ON saved.event_id=event.event_id
            WHERE saved.agent_id=? AND event.severity='critical'""", (id,))

    def refresh_saved_review(self, id):
        with self.store.connect() as connection:
            self.mark_critical(connection, id)
            pending = connection.execute("""SELECT DISTINCT mark.upload_id FROM captured_critical_events AS mark
                JOIN ssh_agent_capture_records AS saved ON mark.upload_id=saved.upload_id
                WHERE saved.agent_id=? AND mark.reviewed=0""", (id,)).fetchall()
        for (upload_id,) in pending:
            if item := self.store.get(upload_id):
                run_analysis(self.store, item)

    def status(self, id):
        with self.store.connect() as connection:
            row = connection.execute("SELECT last_upload_id,error FROM ssh_agent_captures WHERE agent_id=?", (id,)).fetchone()
        return dict(row) if row else None

    def start(self, id):
        with self.store.connect() as connection:
            # Seed the capture with up to 50 retained native records for incident context.
            position = connection.execute("""SELECT COALESCE((SELECT seq FROM ssh_agent_events
                WHERE agent_id=? AND source_format <> 'agent-snapshot' ORDER BY seq DESC LIMIT 1 OFFSET 50),0)""",
                (id,)).fetchone()[0]
            connection.execute("""INSERT OR IGNORE INTO ssh_agent_captures
                (agent_id,token,position,next_save) VALUES (?,?,?,0)""", (id, uuid4().hex, position))

    def stop(self, id):
        with self.store.connect() as connection:
            connection.execute("DELETE FROM ssh_agent_captures WHERE agent_id=?", (id,))

    def flush(self, profile, *, force=False):
        id = profile["id"]
        self.refresh_saved_review(id)
        with self.store.connect() as connection:
            state = connection.execute("SELECT * FROM ssh_agent_captures WHERE agent_id=?", (id,)).fetchone()
            if state is None:
                return None
            position, cutoff = state["position"], state["cutoff"]
            if cutoff is None:
                count, newest, critical = connection.execute("""SELECT COUNT(*), MAX(seq), MAX(severity='critical')
                    FROM ssh_agent_events WHERE agent_id=? AND seq>? AND source_format <> 'agent-snapshot'""",
                    (id, position)).fetchone()
                if not count or (not force and count < BATCH and not critical and state["next_save"] > time()):
                    return state["last_upload_id"]
                cutoff = newest
                connection.execute("UPDATE ssh_agent_captures SET cutoff=? WHERE agent_id=?", (cutoff, id))
        last = state["last_upload_id"]
        while True:
            records = bytearray()
            source_format = None
            event_ids = []
            with self.store.connect() as connection:
                rows = connection.execute("""SELECT seq,source_format,raw,event_id FROM ssh_agent_events
                    WHERE agent_id=? AND seq>? AND seq<=? AND source_format <> 'agent-snapshot' ORDER BY seq LIMIT ?""",
                    (id, position, cutoff, BATCH))
                for row in rows:
                    if source_format is None:
                        source_format = row["source_format"]
                    if row["source_format"] != source_format or len(records) + len(row["raw"]) > MAX_BYTES:
                        break
                    records.extend(row["raw"])
                    position = row["seq"]
                    event_ids.append(row["event_id"])
            if not records:
                if source_format is not None:
                    raise ValueError("A retained record exceeds the live capture limit.")
                break
            last = sha256(f"agent-capture:{state['token']}:{position}".encode()).hexdigest()[:32]
            extension = ".log" if source_format == "linux-text" else ".jsonl"
            name = f"ssh-live-{profile['name'][:64]}-{id[:8]}-{position}{extension}"
            data = bytes(records)
            parsed = parse_records(data, name, last, source_format)
            if parsed.rejected or len(parsed.events) != len(event_ids):
                raise ValueError("A live batch could not map each native record.")
            item = self.store.get(last)
            if item is None:
                item = self.store.save(data, parsed)
            elif item["sha256"] != sha256(data).hexdigest():
                raise ValueError("Retained evidence changed before this live batch could be saved.")
            with self.store.connect() as connection:
                connection.executemany("""INSERT OR IGNORE INTO ssh_agent_capture_records
                    (agent_id,event_id,upload_id,saved_event_id) VALUES (?,?,?,?)""",
                    ((id, origin, last, event.event_id) for origin, event in zip(event_ids, parsed.events)))
                self.mark_critical(connection, id)
            run_analysis(self.store, item)
            with self.store.connect() as connection:
                connection.execute("""UPDATE ssh_agent_captures SET position=?,last_upload_id=?
                    WHERE agent_id=?""", (position, last, id))
        with self.store.connect() as connection:
            connection.execute("""UPDATE ssh_agent_captures SET cutoff=NULL, next_save=?, error=NULL
                WHERE agent_id=?""", (time() + INTERVAL, id))
        return last

    def set_error(self, id, message):
        with self.store.connect() as connection:
            connection.execute("UPDATE ssh_agent_captures SET error=? WHERE agent_id=?", (message, id))
