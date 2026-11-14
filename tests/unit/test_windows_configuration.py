import json

from app.log_review import event_flags, review_events
from app.windows_live import TASK_SCHEDULER
from sentinel.ingest.windows_jsonl import parse_windows_jsonl


def test_windows_change_warnings_require_evidence_and_matching_sources():
    security = "Microsoft-Windows-Security-Auditing"
    task = "Microsoft-Windows-TaskScheduler"
    run_key = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    user_image = r"C:\Users\lab\AppData\Roaming\sample.exe"
    ordinary_image = r"C:\Program Files\Maintenance\sample.exe"
    rows = [
        ("Security", security, 4657, {"ObjectName": run_key, "NewValue": f'"{user_image}" --silent'}),
        ("Security", security, 4657, {"ObjectName": run_key, "NewValue": f'"{ordinary_image}" --silent'}),
        ("Security", security, 4702, {"TaskContentNew": f"<Task><Actions><Exec><Command>{user_image}</Command></Exec></Actions></Task>"}),
        ("System", "Service Control Manager", 7040, {"ServiceName": "Maintenance"}),
        (TASK_SCHEDULER, task, 200, {"ActionName": ordinary_image}),
        (TASK_SCHEDULER, task, 200, {"ActionName": user_image}),
        ("Application", task, 200, {"ActionName": user_image}),
        ("Security", "Unrelated provider", 4657, {"ObjectName": run_key, "NewValue": user_image}),
        ("System", "Microsoft-Windows-Eventlog", 104, {}),
        ("System", "Unrelated provider", 104, {}),
    ]
    raw = "".join(json.dumps({"Id": event_id, "LogName": log, "ProviderName": provider, "EventData": fields,
                              "MachineName": "lab-win", "TimeCreated": "2026-11-10T12:00:00Z", "RecordId": index}) + "\n"
                  for index, (log, provider, event_id, fields) in enumerate(rows, start=1)).encode()
    parsed = parse_windows_jsonl(raw, source_file="fixture.jsonl", upload_id="fixture")
    review = review_events(parsed.events, "windows")
    flags = event_flags(review.findings)
    assert [flags.get(event.event_id) for event in parsed.events] == [
        "warning", "context", "warning", "context", None, "warning", None, None, "critical", None,
    ]
    assert [event.record_index for event in parsed.events if event.event_id in review.windows_reviewed_event_ids] == [1, 2, 3, 4, 5, 6, 9]
