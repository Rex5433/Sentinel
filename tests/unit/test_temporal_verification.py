from copy import deepcopy
import pytest
from sentinel.detection.temporal_verification import verify_series
from sentinel.features import FEATURE_VERSION,schema_hash

def row(minute,failures,host='host'):
    v=[0.]*18;v[0]=10;v[1]=failures;v[2]=10-failures;v[11]=1;v[12]=1;v[13]=1;v[14]=100;v[15]=failures/10;v[17]=1
    return {'host':host,'platform':'linux','session_id':'test','start_utc':f'2026-11-04T12:{minute:02d}:00+00:00',
            'verification':dict(vector=v,model_class=0,probabilities=[1,0,0,0],history_windows=4,
                feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),evidence_ids=[f'event-{minute}'],
                coverage={'collection_complete':True,'rejected_records':0,'unrecognized_events':0,'missing_timestamp':0,'missing_host':0,'excluded_records':0})}

def test_slow_failures_correlate_without_looking_forward():
    results=verify_series([row(0,2),row(5,2),row(10,2)])
    assert not results[0]['requires_review'] and not results[1]['requires_review']
    assert results[2]['rule_hits']==['cross_window_authentication']
    assert len(results[2]['evidence_ids'])==3

@pytest.mark.parametrize('case',['host','gap','session'])
def test_no_correlation_across_boundaries(case):
    rows=[row(0,3),row(5,3)]
    if case=='host': rows[1]['host']='other'
    if case=='gap': rows[1]['start_utc']='2026-11-04T12:15:00+00:00'
    if case=='session': rows[1]['session_id']='other'
    assert not verify_series(rows)[1]['requires_review']

def test_out_of_order_and_missing_time_are_reviewed():
    assert verify_series([row(5,0),row(0,0)])[1]['requires_review']
    value=row(0,0);value['start_utc']='bad'
    assert verify_series([value])[0]['requires_review']
