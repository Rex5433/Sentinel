"""Team synthetic evaluation timelines with new seeds and paired retry controls."""
from datetime import datetime, timedelta, timezone
import random

VERSION = "v5-fresh-timelines-v1"
SEEDS = tuple(range(38021, 38027))
RESERVED_SEEDS = tuple(range(41031, 41037))
FIXTURE_SEED = 57001
RECIPES = (
    "clean_load_swings", "approved_maintenance", "single_account_under_load",
    "single_service_under_load", "mixed_change_under_load", "authentication_pivot",
    "five_window_boundary", "slow_same_identity", "benign_same_identity",
    "slow_rotating_origin", "split_hosts", "interrupted_history",
    "unrecognized_change", "invisible_change", "brief_benign_retries",
    "unapproved_success", "routine_privilege",
)


def plan(recipe, seed, platform):
    if recipe not in RECIPES or seed not in (*SEEDS, *RESERVED_SEEDS, FIXTURE_SEED):
        raise ValueError("Unknown fresh recipe or seed")
    if platform not in ("windows", "linux"):
        raise ValueError("Unknown platform")
    pair = recipe in ("slow_same_identity", "benign_same_identity")
    rng = random.Random(f"{VERSION}/{seed}/{platform}/{'paired-retries' if pair else recipe}")
    variant = (seed - (RESERVED_SEEDS[0] if seed in RESERVED_SEEDS else SEEDS[0])) % 6
    start = datetime(2026, 9, 8, tzinfo=timezone.utc) + timedelta(days=seed % 47)
    length = 30 + variant
    active = 6 + variant % 3
    hosts = [f"v5-{recipe}-{seed}-a"]
    if recipe == "split_hosts":
        hosts.append(f"v5-{recipe}-{seed}-b")
    missing = {active + 5} if recipe == "interrupted_history" else set()
    events, invisible = [], []

    def add(slot, host, kind, count=1, *, malicious=False, identity=None, edge=None):
        for _ in range(count):
            index = len(events)
            when = start + timedelta(seconds=slot * 300, microseconds=rng.randrange(300_000_000) if edge is None else edge)
            actor, address = identity or (f"staff{rng.randrange(2 + variant * 3)}", f"203.0.113.{20+rng.randrange(1+variant*4)}")
            events.append(dict(time=when.isoformat(), slot=slot, host=host, kind=kind, actor=actor, ip=address,
                               account=f"new-user-{seed}-{index}", service=f"change-{index}" if kind == "install" else "agent-service",
                               malicious=malicious, damage=None, duplicate=False))

    for slot in range(length):
        if slot in missing:
            continue
        for host in hosts:
            base = (1, 4, 11, 27, 53, 89)[variant]
            load = rng.choice((1, base, base + slot % 9, 2 * base))
            for _ in range(load):
                add(slot, host, rng.choices(("login", "close", "privileged"), weights=(13, 4, 1))[0])
    host = hosts[0]
    slow_slots = (0, 4, 8, 11, 15, 18) if seed in RESERVED_SEEDS else (0, 3, 7, 10, 13, 16)
    principal = ("service-retry", "2001:db8::77") if seed % 2 else ("service-retry", "192.0.2.77")
    if recipe == "clean_load_swings":
        add(active, host, "login", 700 + variant * 101)
    elif recipe == "approved_maintenance":
        add(active, host, "account", 1 + variant % 3)
        add(active + 3, host, "install")
        add(active + 5, host, "service", 3)
    elif recipe in ("single_account_under_load", "single_service_under_load", "mixed_change_under_load"):
        add(active, host, "login", 630 + variant * 137)
        if recipe != "single_service_under_load":
            add(active, host, "account", malicious=True)
        if recipe != "single_account_under_load":
            add(active, host, "install" if variant % 2 else "service", malicious=True)
    elif recipe == "authentication_pivot":
        add(active, host, "failure", 5 + variant, malicious=True, identity=principal)
        add(active + 1, host, "login", malicious=True, identity=principal)
        add(active + 2, host, "account", malicious=True)
        add(active + 5, host, "service", malicious=True)
    elif recipe == "five_window_boundary":
        for offset in range(5):
            add(active + offset, host, "failure", malicious=True, identity=principal,
                edge=0 if offset % 2 else 299_999_999)
    elif pair or recipe in ("slow_rotating_origin", "split_hosts"):
        for i, offset in enumerate(slow_slots):
            identity = (principal[0], f"198.51.100.{40+i}") if recipe == "slow_rotating_origin" else principal
            # Each split host receives only two attempts, so pooling would give a spurious review.
            if recipe == "split_hosts" and i >= 4:
                break
            add(active + offset, hosts[i % 2] if recipe == "split_hosts" else host, "failure",
                malicious=recipe in ("slow_same_identity", "slow_rotating_origin"), identity=identity)
    elif recipe == "interrupted_history":
        for offset in (0, 3, 7, 10, 14):
            add(active + offset, host, "failure", malicious=True, identity=principal)
    elif recipe == "unrecognized_change":
        add(active, host, "unknown_privilege", malicious=True)
        add(active + 2, host, "unknown_process", malicious=True)
        add(active + 4, host, "service", malicious=True)
    elif recipe == "invisible_change":
        invisible.append(dict(host=host, slot=active, malicious=True, note="Scenario action absent from captured telemetry"))
    elif recipe == "brief_benign_retries":
        add(active, host, "failure", 2, identity=principal)
        add(active + 3, host, "failure", identity=principal)
        add(active + 4, host, "login", identity=principal)
    elif recipe == "unapproved_success":
        add(active, host, "login", malicious=True, identity=principal)
    elif recipe == "routine_privilege":
        add(active, host, "privileged", 6 + variant * 3)
    return dict(version=VERSION,case=recipe,pattern="gap" if missing else recipe,seed=seed,platform=platform,
                start=start.isoformat(),length=length,hosts=hosts,expected_missing_slots=sorted(missing),
                offset_minutes=(0,330,-360,345,60,-210)[variant],events=events,invisible=invisible,
                origin="Original team-generated Codex-assisted evaluation telemetry")
