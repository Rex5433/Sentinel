import json

from app.log_review import review_events
from sentinel.ingest.windows_jsonl import parse_windows_jsonl


def test_windows_success_requires_same_domain_and_logon_type_with_distinct_failures():
    def row(number, event_id=4625, *, domain="LAB", logon="3", second=None):
        return {"LogName": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing", "Id": event_id,
                "RecordId": number, "MachineName": "test-host", "TimeCreated": f"2026-11-10T12:00:{second or number:02}Z",
                "EventData": {"TargetUserName": "nora", "TargetDomainName": domain, "IpAddress": "192.0.2.25",
                              "LogonType": logon}}

    rows = [row(1), row(1), row(2), row(3, 4624, second=3),
            row(4), row(5), row(6), row(7, 4624, domain="OTHER"), row(8, 4624, logon="10"),
            row(9, 4624)]
    raw = ("\n".join(map(json.dumps, rows)) + "\n").encode()
    events = parse_windows_jsonl(raw, source_file="fixture.jsonl", upload_id="sample").events
    review = review_events(events, "windows")
    finding, = [entry["finding"] for entry in review.findings if entry.get("rule_version") == "sign-in-after-failures-v1"]
    assert finding["evidence_event_ids"] == [event.event_id for event in [*events[4:7], events[-1]]]
