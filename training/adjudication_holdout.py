"""Separately seeded synthetic timelines for the post-CNN layer."""
from datetime import datetime, timedelta, timezone
import random

SEEDS = tuple(range(61540, 61546))
RECIPES = (
    "pivot_to_account", "overlapping_pivot", "maintenance_with_quiet_afterward",
    "isolated_changes_in_load", "distributed_burst", "brief_retry_then_success",
    "rotating_unapproved", "rotating_benign", "separate_hosts", "capture_gap", "unrecognized_change",
)


def plan(recipe, seed, platform):
    variant = SEEDS.index(seed)
    if recipe not in RECIPES or platform not in ("windows", "linux"):
        raise ValueError("Unknown recipe or platform")
    paired = recipe in ("rotating_unapproved", "rotating_benign")
    rng = random.Random(f"adjudication-holdout-v1/{'paired' if paired else recipe}/{seed}/{platform}")
    start = datetime(2026, 7, 21, tzinfo=timezone.utc) + timedelta(days=variant)
    length, active = 28 + variant, 5 + variant % 3
    hosts = [f"adjudication-{recipe}-{seed}-a"]
    if recipe == "separate_hosts":
        hosts.append(f"adjudication-{recipe}-{seed}-b")
    missing = {active + 4} if recipe == "capture_gap" else set()
    events = []

    def add(slot, host, kind, count=1, *, unapproved=False, retry_ip=None):
        for _ in range(count):
            index = len(events)
            stamp = start + timedelta(seconds=300 * slot, microseconds=rng.randrange(300_000_000))
            actor = "scheduled-client" if retry_ip else f"user{rng.randrange(2+variant*4)}"
            ip = retry_ip or f"203.0.113.{20+rng.randrange(3+variant)}"
            events.append(dict(time=stamp.isoformat(), slot=slot, host=host, kind=kind, actor=actor, ip=ip,
                account=f"added-{index}", service=f"service-{index%5}", malicious=unapproved, damage=None, duplicate=False))

    for slot in range(length):
        if slot in missing:
            continue
        for host in hosts:
            level = (2, 7, 19, 41, 87, 133)[variant]
            for _ in range(rng.choice((1, level, level + slot % 11))):
                add(slot, host, rng.choices(("login", "close", "privileged"), weights=(9, 4, 2))[0])
    host = hosts[0]
    if recipe == "pivot_to_account":
        add(active, host, "failure", 5 + variant, unapproved=True)
        add(active + 1, host, "login", unapproved=True)
        add(active + 3, host, "account", 1 + variant % 2, unapproved=True)
        add(active + 6, host, "service", unapproved=True)
    elif recipe == "overlapping_pivot":
        add(active, host, "failure", 3, unapproved=True)
        add(active + 2, host, "failure", 2, unapproved=True)
        add(active + 2, host, "account", unapproved=True)
    elif recipe == "maintenance_with_quiet_afterward":
        add(active, host, "install", 2)
        add(active + 2, host, "account")
        add(active + 4, host, "service", 4)
    elif recipe == "isolated_changes_in_load":
        for offset, kind in ((0, "account"), (7, "service")):
            add(active + offset, host, "login", 740 + 103 * variant)
            add(active + offset, host, kind, unapproved=True)
    elif recipe == "distributed_burst":
        for offset, count in ((0, 2), (1, 2), (4, 1)):
            add(active + offset, host, "failure", count, unapproved=True, retry_ip="192.0.2.76")
    elif recipe == "brief_retry_then_success":
        add(active, host, "failure", 2, retry_ip="192.0.2.80")
        add(active + 4, host, "failure", retry_ip="192.0.2.81")
        add(active + 5, host, "login", retry_ip="192.0.2.81")
    elif paired or recipe in ("capture_gap", "separate_hosts"):
        for index, offset in enumerate((0, 2, 6, 9, 12, 15) if recipe != "separate_hosts" else (0, 2, 6, 9)):
            add(active + offset, hosts[index % len(hosts)], "failure",
                unapproved=recipe in ("rotating_unapproved", "capture_gap"), retry_ip=f"2001:db8:4::{21+index}")
    elif recipe == "unrecognized_change":
        add(active, host, "unknown_privilege", unapproved=True)
        add(active + 2, host, "service", unapproved=True)
    return dict(version="adjudication-holdout-v1", case=recipe, pattern="gap" if missing else recipe, seed=seed,
                platform=platform, start=start.isoformat(), length=length, hosts=hosts, offset_minutes=(-300, 60, 0, 345, -360, 120)[variant],
                expected_missing_slots=sorted(missing), events=events, invisible=[],
                origin="Original team-generated Codex-assisted evaluation telemetry")
