"""Local roster and maintenance labels for displayed events."""

import json

from sentinel.detection.windows_review import AUDIT_PROVIDER, SECURITY_PROVIDER
from sentinel.ingest.common import choose, text_value

from .analysis import IMPLEMENTATION_SHA256


def account_key(platform, host, account):
    host = host.strip().lower()
    account = account.strip()
    if (not host or not account or "\\" in host
            or any(char.isspace() for char in host)
            or (platform == "linux" and any(char.isspace() for char in account))
            or any(not char.isprintable() or char in "*/?" for char in host + account)):
        raise ValueError("Enter an exact hostname and account without wildcards.")
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
        return actor, "target" if activity == "auth_failure" else "account"

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
    page.update(maintenance_note_events={}, blue_team_events={})
    if not rows:
        return page
    visible = {(row["upload_id"], row["event_id"]) for row in rows}
    with store.connect() as connection:
        roster = {tuple(entry) for entry in connection.execute("SELECT platform,host,account FROM blue_team_accounts")}
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
    if roster:
        for row in rows:
            observed = event_account(row)
            if observed is None:
                continue
            account, role = observed
            try:
                key = account_key(row["platform"], row["host"], account)
            except ValueError:
                continue
            if key in roster:
                page["blue_team_events"][row["event_id"]] = {"account": account, "role": role}
    return page
