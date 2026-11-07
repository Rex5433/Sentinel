from copy import deepcopy
from datetime import datetime,timedelta,timezone

import pytest

from sentinel.features import FEATURE_VERSION,schema_hash
from sentinel.detection.temporal_verification import verify_series as old_verify
from sentinel.detection.context_verification_v2 import verify_series,HISTORY


def row(index,failures=0,*,host="host-a",session="import-a",platform="linux"):
    vector=[0.]*18
    vector[0]=max(1,failures);vector[1]=failures;vector[2]=0 if failures else 1
    vector[11]=vector[12]=vector[13]=1
    vector[15]=failures/vector[0];vector[16:]=[1,0] if platform=="windows" else [0,1]
    return dict(platform=platform,host=host,session_id=session,
                start_utc=(datetime(2026,11,4,tzinfo=timezone.utc)+timedelta(minutes=5*index)).isoformat(),
                verification=dict(vector=vector,model_class=0,probabilities=[1.,0.,0.,0.],history_windows=min(index,4),
                    coverage=dict(collection_complete=True,rejected_records=0,unrecognized_events=0,missing_timestamp=0,missing_host=0,excluded_records=0),
                    feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),evidence_ids=[f"event-{host}-{session}-{index}"]))


@pytest.mark.parametrize("platform",["windows","linux"])
def test_fifth_failure_is_caught_even_with_perfect_normal_score(platform):
    rows=[row(i,1,platform=platform) for i in range(5)]
    assert not old_verify(rows)[-1]["requires_review"]
    result=verify_series(rows)[-1]
    assert result["requires_review"] and result["disposition"]=="alert"
    assert "five_window_authentication" in result["rule_hits"] and len(result["evidence_ids"])==5
    assert HISTORY==5


@pytest.mark.parametrize("key",["rejected_records","unrecognized_events","missing_timestamp","missing_host","excluded_records","collection_complete"])
def test_parser_gap_propagates_exactly_four_following_windows(key):
    rows=[row(i) for i in range(13)]
    rows[5]["verification"]["coverage"][key]=False if key=="collection_complete" else 1
    output=verify_series(rows)
    for i in range(6,10):
        assert any(r["code"]=="causal_input_unassessed" for r in output[i]["reasons"])
        assert "event-host-a-import-a-5" in output[i]["evidence_ids"]
    assert not output[10]["requires_review"]


@pytest.mark.parametrize("field,value",[("vector",None),("feature_schema_sha256","0"*64),("evidence_ids",[])])
def test_invalid_input_or_untraceable_evidence_remains_a_context_gap(field,value):
    rows=[row(i) for i in range(13)];rows[5]["verification"][field]=value
    output=verify_series(rows)
    assert all(output[i]["requires_review"] for i in range(5,10))
    assert not output[10]["requires_review"]


def test_unknown_coverage_types_and_missing_report_are_not_treated_as_clean():
    rows=[row(i) for i in range(11)];rows[4]["verification"]["coverage"]={"collection_complete":True,"rejected_records":False}
    output=verify_series(rows)
    assert all(output[i]["requires_review"] for i in range(4,9))
    assert not output[9]["requires_review"]


def test_uncertain_prediction_does_not_poison_parser_quality_history():
    rows=[row(i) for i in range(10)];rows[4]["verification"]["probabilities"]=[.6,.2,.1,.1]
    output=verify_series(rows)
    assert output[4]["requires_review"] and not output[5]["requires_review"]


def test_multiple_gaps_expire_from_last_gap_without_lookahead():
    rows=[row(i) for i in range(16)]
    for i in (5,8):rows[i]["verification"]["coverage"]["unrecognized_events"]=1
    output=verify_series(rows)
    assert all(output[i]["requires_review"] for i in range(5,13))
    assert not output[13]["requires_review"]
    altered=deepcopy(rows);altered[14]["verification"]["coverage"]["unrecognized_events"]=1
    assert verify_series(altered)[:14]==output[:14]


@pytest.mark.parametrize("identity",["host","session_id","platform"])
def test_histories_are_isolated_by_host_source_and_platform(identity):
    rows=[]
    for i in range(5):
        a=row(i,1)
        b=row(i,0)
        if identity=="platform":b=row(i,0,platform="windows")
        else:b[identity]="other"
        rows.extend([a,b])
    output=verify_series(rows)
    assert "five_window_authentication" in output[-2]["rule_hits"]
    assert "five_window_authentication" not in output[-1]["rule_hits"]


def test_quality_gap_does_not_contaminate_another_valid_host():
    rows=[]
    for i in range(10):
        a,b=row(i),row(i,host="host-b")
        if i==5:a["verification"]["coverage"]["unrecognized_events"]=1
        rows.extend([a,b])
    result=verify_series(rows)
    assert result[12]["requires_review"] and not result[13]["requires_review"]


def test_time_gap_resets_failures_and_derives_missing_history():
    rows=[row(i,1) for i in (0,1,2,3,8,9,10,11,12)]
    result=verify_series(rows)
    assert result[4]["derived_prior_windows"]==0 and result[4]["requires_review"]
    assert "five_window_authentication" not in result[4]["rule_hits"]
    assert "five_window_authentication" in result[-1]["rule_hits"]


@pytest.mark.parametrize("bad_time",[None,"not-a-date","2026-11-04T00:25:00","2026-11-04T00:26:00+00:00","2026-11-04T00:20:00+00:00"])
def test_invalid_or_repeated_time_fails_closed_and_resets(bad_time):
    rows=[row(i) for i in range(12)];rows[5]["start_utc"]=bad_time
    result=verify_series(rows)
    assert all(result[i]["requires_review"] for i in range(5,10))
    assert not result[10]["requires_review"]


@pytest.mark.parametrize("bad",[None,{}, {"verification":{}}, {"verification":{"vector":[float("nan")]*18,"model_class":2}},
                                {"verification":{"vector":[10**400]*18,"model_class":2}}])
def test_malformed_rows_never_raise_or_return_no_review(bad):
    result=verify_series([bad])[0]
    assert result["requires_review"]
    if isinstance(bad,dict) and bad.get("verification",{}).get("model_class")==2:
        assert result["disposition"]=="alert"


def test_inputs_unchanged_and_existing_flags_cannot_be_suppressed():
    rows=[row(i) for i in range(10)];rows[6]["verification"].update(model_class=2,probabilities=[0.,0.,1.,0.])
    before=deepcopy(rows);old=old_verify(rows);new=verify_series(rows)
    assert rows==before
    assert all(not a["requires_review"] or b["requires_review"] for a,b in zip(old,new))
    assert new[6]["disposition"]=="alert"


def test_five_window_aggregation_does_not_include_expired_failures():
    rows=[row(i) for i in range(11)];rows[4]=row(4,3);rows[9]=row(9,2)
    result=verify_series(rows)
    assert "five_window_authentication" not in result[9]["rule_hits"]
