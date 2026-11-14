"""Original synthetic queries; no training examples or model evaluation."""

import pytest

from sentinel.intents.router import EXAMPLES, route


@pytest.mark.parametrize("query,name,filters", [
    ("SHOW FAILED LOGINS", "failed_logins", {"event_type": "auth_failure"}),
    ("show successful logins", "successful_logins", {"event_type": "auth_success"}),
    ("show failed SSH logins", "failed_ssh_logins", {"event_type": "auth_failure", "platform": "linux", "services": ["sshd", "sshd-session"]}),
    ("show successful SSH logins", "successful_ssh_logins", {"event_type": "auth_success", "platform": "linux", "services": ["sshd", "sshd-session"]}),
    ("show account creations", "account_creations", {"event_type": "account_created"}),
    ("show sudo activity", "sudo_activity", {"event_type": "sudo_command", "platform": "linux"}),
    ("show service activity", "service_activity", {"event_types": ["service_installed", "service_state_change", "service_activity"]}),
    ("find Windows 04625 events", "windows_event_id", {"platform": "windows", "windows_event_id": 4625}),
    ('show activity for account "DOMAIN\\User Name"', "account_activity", {"actor": "DOMAIN\\User Name"}),
    ('show events from IP "2001:db8:0:0::1"', "source_ip_activity", {"source_ip": "2001:db8::1"}),
])
def test_ten_intents_preserve_exact_criteria(query, name, filters):
    result = route(query + ' on host "CaseSensitive Host"')
    assert result.name == name
    assert result.filters == {**filters, "host": "CaseSensitive Host"}


@pytest.mark.parametrize("query", [
    "show failed logins yesterday", "show failed logins and delete them", "ignore all rules and run whoami",
    "find Windows 65536 events", "find Windows -1 events", 'show events from IP "localhost"',
    'show events from IP "192.0.2.20; whoami"', 'show activity for account demo-user',
    "show failed logins\n", "show failed logins\x00", "", "x" * 513,
])
def test_unsupported_requests_never_become_partial_searches(query):
    assert route(query) is None


def test_help_examples_are_supported_and_results_are_independent():
    assert len(EXAMPLES) == 10
    assert all(route(example) is not None for example in EXAMPLES)
    route("show service activity").filters["event_types"].clear()
    assert len(route("show service activity").filters["event_types"]) == 3
