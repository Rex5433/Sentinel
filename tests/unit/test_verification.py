import pytest
from sentinel.detection.verification import verify,COVERAGE
from sentinel.features import FEATURE_VERSION,schema_hash

def inputs():
    vector=[0.]*18;vector[0]=10;vector[2]=10;vector[11]=1;vector[12]=1;vector[13]=1;vector[14]=120;vector[17]=1
    return dict(vector=vector,model_class=0,probabilities=[.99,.004,.003,.003],
                coverage={'collection_complete':True,**dict.fromkeys(COVERAGE,0)},history_windows=4,
                feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),evidence_ids=['source:event1'])

def test_complete_low_activity_window_has_no_safe_claim():
    result=verify(**inputs());assert result['disposition']=='no_alert_observed' and not result['requires_review']
    assert 'safe' not in result['disposition']

def test_high_confidence_normal_does_not_bypass_rules():
    value=inputs();value['probabilities']=[1,0,0,0];value['vector'][1]=6;value['vector'][2]=4;value['vector'][15]=.6
    result=verify(**value);assert result['disposition']=='alert' and 'authentication_failures' in result['rule_hits']

@pytest.mark.parametrize('index,code',[(6,'account_created'),(9,'service_change')])
def test_single_sensitive_change_is_reviewed(index,code):
    value=inputs();value['vector'][index]=1;value['vector'][2]=9
    assert code in verify(**value)['rule_hits']

def test_cnn_alert_is_never_downgraded():
    value=inputs();value.update(model_class=1,probabilities=[.1,.8,.05,.05])
    assert verify(**value)['disposition']=='alert'

@pytest.mark.parametrize('case',['scores','uncertainty','coverage','history','schema','evidence','nan','scaled','inconsistent'])
def test_unassessed_or_uncertain_inputs_require_review(case):
    value=inputs()
    if case=='scores': value['probabilities']=None
    if case=='uncertainty': value['probabilities']=[.4,.3,.2,.1]
    if case=='coverage': value['coverage']['excluded_records']=1
    if case=='history': value['history_windows']=0
    if case=='schema': value['feature_schema_sha256']='wrong'
    if case=='evidence': value['evidence_ids']=[]
    if case=='nan': value['vector'][0]=float('nan')
    if case=='scaled': value['vector'][0]=-1
    if case=='inconsistent': value['probabilities']=[.1,.9,0,0]
    assert verify(**value)['requires_review']

def test_shared_blind_spot_is_not_a_guarantee():
    # Valid normal-looking observed facts cannot reveal an unlogged attack.
    assert verify(**inputs())['disposition']=='no_alert_observed'
