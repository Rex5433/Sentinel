"""Local roster and maintenance labels for displayed events."""

import json

from sentinel.detection.windows_review import AUDIT_PROVIDER, SECURITY_PROVIDER
from sentinel.ingest.common import choose, text_value

from .analysis import IMPLEMENTATION_SHA256


def account_key(platform, host, account, *, all_hosts=False):
    host = host.strip().lower()
    account = account.strip()
    if (bool(host) == all_hosts or not account or "\\" in host
            or any(char.isspace() for char in host)
            or (platform == "linux" and any(char.isspace() for char in account))
            or any(not char.isprintable() or char in "*/?" for char in host + account)):
        raise ValueError("Enter a reporting hostname or select all hosts, and enter the exact account without wildcards.")
    parts = account.split("\\")
    if any(not part or part == "-" for part in parts) or len(parts) > (2 if platform == "windows" else 1):
        raise ValueError("Enter a Linux account name or a Windows account such as DOMAIN\\user.")
    return platform, host, account.lower() if platform == "windows" else account


def event_account(record):
    host = record.get("host")
    platform = record["platform"]
    if not host:
        return None
    if platform == "linux":
        actor = record.get("actor")
        activity = record.get("event_type")
        if activity in {"session_open", "session_close"} and record.get("service") not in {"sshd", "sshd-session", "login"}:
            return None
        if not actor:
            return None
        return actor, "target" if activity in {"auth_failure", "ssh_invalid_account", "ssh_pam_failure"} else "account"

    raw = record.get("raw_record")
    code = record.get("windows_event_id")
    provider = AUDIT_PROVIDER if code == 1102 else SECURITY_PROVIDER
    if (not isinstance(raw, dict) or (record.get("channel") or "").casefold() != "security"
            or (record.get("provider") or "").casefold() != provider or code is None
            or any(error.startswith(("EventID:", "EventData:")) for error in record.get("parsing_errors", ()))):
        return None
    nested = raw.get("EventData") or {}
    prefix = "Target" if code in {4624, 4625, 4634} else "Subject"
    errors = []
    name_field, domain_field = prefix + "UserName", prefix + "DomainName"
    name = text_value(choose({"flat": raw.get(name_field), "nested": nested.get(name_field)}, ("flat", "nested"), errors),
                      name_field, errors)
    domain = text_value(choose({"flat": raw.get(domain_field), "nested": nested.get(domain_field)}, ("flat", "nested"), errors),
                        domain_field, errors)
    if errors or not name or (domain and ("\\" in domain or "\\" in name)):
        return None
    return f"{domain}\\{name}" if domain else name, "target" if code == 4625 else "account"


def with_log_context(store, page):
    rows = page["items"]
    page.update(maintenance_note_events={}, blue_team_events={}, user_account_events={})
    if not rows:
        return page
    visible = {(row["upload_id"], row["event_id"]) for row in rows}
    with store.connect() as connection:
        roster = load_roster(connection)
        matches = connection.execute("""
            SELECT DISTINCT note.upload_id, evidence.value
            FROM finding_maintenance_notes AS note
            JOIN baseline_findings AS f USING (upload_id, finding_id)
            JOIN analyses AS a USING (upload_id)
            JOIN uploads AS u ON u.id = note.upload_id
            JOIN json_each(f.payload, '$.finding.evidence_event_ids') AS evidence
            WHERE note.upload_id IN (SELECT value FROM json_each(?))
              AND evidence.value IN (SELECT value FROM json_each(?))
              AND json_extract(a.payload, '$.implementation_sha256') = ?
              AND json_extract(a.payload, '$.source_sha256') = u.sha256
        """, (json.dumps(list({row["upload_id"] for row in rows})),
              json.dumps([row["event_id"] for row in rows]), IMPLEMENTATION_SHA256))
        for upload_id, event_id in matches:
            if (upload_id, event_id) in visible:
                page["maintenance_note_events"].setdefault(upload_id, []).append(event_id)
    page.update(roster_labels(rows, roster))
    return page


def load_roster(connection):
    return {(row["platform"], row["host"], row["account"]): row["category"] for row in connection.execute(
        "SELECT platform,host,account,category FROM blue_team_accounts")}


def roster_labels(rows, roster):
    labels = {"blue-team": {}, "user": {}}
    for row in rows:
        observed = event_account(row)
        if observed is None:
            continue
        account, role = observed
        try:
            key = account_key(row["platform"], row["host"], account)
        except ValueError:
            continue
        category = roster.get(key) or roster.get((key[0], "", key[2]))
        if category:
            labels[category][row["event_id"]] = {"account": account, "role": role}
    return {"blue_team_events": labels["blue-team"], "user_account_events": labels["user"]}


def with_live_context(store, review, snapshot_id=None):
    """Annotate only current live events. Never load a saved-log list/feed.

    Maintenance notes may come only from this watch's explicitly saved,
    unchanged snapshot, with exact matching raw event records. A note about a
    historical account/host never authorizes new live events.
    """
    from sentinel.features import canonical_hash
    from .analysis import analysis_summary
    rows = review["events"]
    with store.connect() as connection:
        roster = load_roster(connection)
    result = dict(review, **roster_labels(rows, roster), maintenance_note_event_ids=[])
    result["findings"] = [{k: v for k, v in entry.items() if k != "maintenance_note"} for entry in review["findings"]]
    if not snapshot_id or not rows:
        return result
    snapshot = store.get(snapshot_id)
    if not snapshot or analysis_summary(store, snapshot)["status"] != "current":
        return result
    saved = store.records(snapshot_id, "events", 0, len(rows))
    if saved["total"] != len(rows):
        return result
    def key(row):
        return (row["record_index"], row["platform"], row["host"], canonical_hash(row["raw_record"]))
    saved_rows = {key(row): row for row in saved["items"]}
    if set(saved_rows) != {key(row) for row in rows}:
        return result
    live_ids = {saved_rows[key(row)]["event_id"]: row["event_id"] for row in rows}
    context = with_log_context(store, saved)
    noted = context["maintenance_note_events"].get(snapshot_id, [])
    result["maintenance_note_event_ids"] = [live_ids[id] for id in noted if id in live_ids]
    with store.connect() as connection:
        sets = connection.execute("""SELECT f.payload FROM finding_maintenance_notes AS n
            JOIN baseline_findings AS f USING (upload_id,finding_id) WHERE n.upload_id=?""", (snapshot_id,)).fetchall()
    exact = [{live_ids[id] for id in json.loads(row[0])["finding"]["evidence_event_ids"] if id in live_ids} for row in sets]
    for entry in result["findings"]:
        if set(entry["finding"]["evidence_event_ids"]) in exact:
            entry["maintenance_note"] = True
    return result
