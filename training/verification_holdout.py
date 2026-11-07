"""New targeted evaluation episodes for context verifier v2; no old plan/render calls."""
from datetime import datetime,timedelta,timezone
import random

VERSION="verification-holdout-v1"
FIXTURE_SEEDS=(18400,18401,18402,18403,18404,18405)
SEEDS=(29410,29411,29412,29413,29414,29415)
RECIPES=("clean_reference","five_window_failures","spread_with_quiet_window","harmless_retries",
         "stale_failures_expire","interrupted_capture","unknown_then_clean","two_unknown_records",
         "late_unknown","interleaved_hosts","busy_small_change","unlogged_change")


def plan_holdout(recipe,seed,platform):
    if recipe not in RECIPES or seed not in FIXTURE_SEEDS+SEEDS or platform not in ("linux","windows"):
        raise ValueError("Unsupported holdout case")
    variant=(FIXTURE_SEEDS+SEEDS).index(seed)%6
    rng=random.Random(f"{VERSION}/{recipe}/{seed}/{platform}")
    start=datetime(2026,4,6,tzinfo=timezone.utc)+timedelta(days=variant)
    length=21+variant
    active=5+variant%3
    hosts=[f"v2-{recipe}-{seed}-a"]
    if recipe=="interleaved_hosts":hosts.append(f"v2-{recipe}-{seed}-b")
    missing={active+1} if recipe=="interrupted_capture" else set()
    events=[];invisible=[]

    def add(slot,host,kind,n=1,malicious=False):
        for i in range(n):
            index=len(events)
            events.append(dict(time=(start+timedelta(seconds=slot*300,microseconds=rng.randrange(300_000_000))).isoformat(),
                slot=slot,host=host,kind=kind,actor=f"operator{rng.randrange((2,3,7,11,19,31)[variant])}",
                ip=f"2001:db8:{variant:x}::{1+rng.randrange(1+variant*3)}" if seed%2 else f"203.0.113.{70+rng.randrange(1+variant*3)}",
                account=f"holdout_{seed}_{index}",service=f"createdsvc{index}" if kind=="install" else f"existing{i%2}",
                malicious=malicious,damage=None,duplicate=False))
    for slot in range(length):
        if slot in missing:continue
        for host in hosts:
            for _ in range((2,5,13,29,77,151)[variant]):
                add(slot,host,rng.choices(("login","close","privileged"),weights=(10,3,1))[0])
    host=hosts[0]
    if recipe=="five_window_failures":
        for slot in range(active,active+5):add(slot,host,"failure",malicious=True)
    elif recipe=="spread_with_quiet_window":
        for offset,count in ((0,2),(2,1),(4,2)):add(active+offset,host,"failure",count,True)
    elif recipe=="harmless_retries":
        for offset,count in ((0,2),(2,1),(4,1)):add(active+offset,host,"failure",count)
    elif recipe=="stale_failures_expire":
        add(active,host,"failure",3,True);add(active+5,host,"failure",2,True)
    elif recipe=="interrupted_capture":
        add(active,host,"failure",3,True);add(active+2,host,"failure",3,True)
    elif recipe in ("unknown_then_clean","two_unknown_records","late_unknown"):
        first=length-2 if recipe=="late_unknown" else active
        add(first,host,"unknown_privilege",malicious=True)
        if recipe=="two_unknown_records":add(first+3,host,"unknown_process",malicious=True)
    elif recipe=="interleaved_hosts":
        add(active,host,"unknown_task",malicious=True)
        add(active+1,host,"failure",3,True);add(active+1,hosts[1],"failure",3)
    elif recipe=="busy_small_change":
        add(active,host,"login",500+variant*23)
        add(active,host,"account",malicious=True)
        add(active+4,host,"service",malicious=True)
    elif recipe=="unlogged_change":
        invisible.append(dict(host=host,slot=active,malicious=True,note="Oracle scenario fact absent from exported telemetry"))
    return dict(version=VERSION,case=recipe,pattern="gap" if missing else recipe,seed=seed,platform=platform,
        start=start.isoformat(),length=length,hosts=hosts,expected_missing_slots=sorted(missing),
        offset_minutes=(0,330,-360,60,345,-210)[variant],events=events,invisible=invisible,
        origin="Original team-generated Codex-assisted targeted holdout; not training or field capture")
