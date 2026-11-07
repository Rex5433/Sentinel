"""Copy-free post-model triage checks. No commands, model fitting or safe verdicts."""
from math import isfinite, isclose
from sentinel.features import FEATURE_ORDER, FEATURE_VERSION, schema_hash

VERSION='post-model-verification-v1'
CLASSES=('normal_or_unremarkable','authentication_burst','account_or_privilege_change','process_or_service_anomaly')
COVERAGE=('rejected_records','unrecognized_events','missing_timestamp','missing_host','excluded_records')
MIN_SCORE=.90
MIN_MARGIN=.20


def verify(*,vector,model_class,probabilities=None,coverage=None,history_windows=None,
           feature_version=None,feature_schema_sha256=None,evidence_ids=()):
    """Always run backup checks, including for high-score normal predictions.

    Input is one UNSCALED raw 18-feature window, four softmax scores, explicit
    collection coverage, available prior history (0..4), and original evidence IDs.
    Thresholds are provisional triage policy, not calibrated compromise estimates.
    """
    reasons=[]; rule_hits=[]
    def reason(code,message): reasons.append({'code':code,'message':message})
    if feature_version!=FEATURE_VERSION or feature_schema_sha256!=schema_hash():
        reason('feature_contract','Feature schema missing or incompatible; manual review required.')
    valid=isinstance(vector,(list,tuple)) and len(vector)==18 and all(type(x) in (int,float) and isfinite(x) and x>=0 for x in vector)
    if valid:
        f=dict(zip(FEATURE_ORDER,vector)); count_keys=[k for k in FEATURE_ORDER if k.endswith('_count')]
        valid=(f['event_count']>0 and all(float(f[k]).is_integer() for k in count_keys)
               and all(f[k]<=f['event_count'] for k in count_keys)
               and f['span_seconds']<300 and f['auth_failure_fraction']<=1
               and (f['is_windows'],f['is_linux']) in ((1,0),(0,1))
               and isclose(sum(f[k] for k in FEATURE_ORDER[1:11]),f['event_count'])
               and isclose(f['auth_failure_fraction'],f['auth_failure_count']/f['event_count'],abs_tol=1e-9))
    if not valid: reason('invalid_features','Raw feature window is invalid; model output is unassessed.')
    else:
        checks=(('authentication_failures',f['auth_failure_count']>=5,'At least five observed authentication failures.'),
                ('account_created',f['account_created_count']>=1,'Account creation requires review, including legitimate administration.'),
                ('service_change',sum(f[k] for k in ('service_installed_count','service_state_change_count','service_activity_count'))>=1,'Observed service activity requires review; may be benign.'))
        for code,hit,message in checks:
            if hit:
                rule_hits.append(code); reason(code,message)
    if type(model_class) is not int or model_class not in range(4):
        reason('model_unavailable','Valid four-class model prediction unavailable.')
    elif model_class!=0:
        reason('model_flag','CNN predicted non-normal activity; verification cannot suppress it.')
    scores_valid=(isinstance(probabilities,(list,tuple)) and len(probabilities)==4
                  and all(type(x) in (int,float) and isfinite(x) and 0<=x<=1 for x in probabilities)
                  and isclose(sum(probabilities),1.,abs_tol=1e-5))
    if not scores_valid: reason('scores_unavailable','Model scores missing/invalid; confidence cannot be assessed.')
    else:
        ordered=sorted(probabilities,reverse=True)
        if type(model_class) is int and model_class in range(4) and probabilities[model_class]!=ordered[0]:
            reason('prediction_inconsistent','Predicted class disagrees with scores.')
        if ordered[0]<MIN_SCORE or ordered[0]-ordered[1]<MIN_MARGIN:
            reason('uncertain_model','Low top score or close competing scores; request manual review.')
    if not isinstance(coverage,dict) or coverage.get('collection_complete') is not True:
        reason('collection_unknown','Collection completeness is unknown or false.')
    for key in COVERAGE:
        value=coverage.get(key) if isinstance(coverage,dict) else None
        if type(value) is not int or value<0: reason('coverage_unknown',f'{key} coverage is missing/invalid.')
        elif value: reason('coverage_gap',f'{key}: {value}; some input is not fully assessed.')
    if type(history_windows) is not int or not 0<=history_windows<=4:
        reason('history_unknown','Available prior history is not established.')
    elif history_windows<4: reason('short_history','CNN has fewer than four preceding windows; padded-history review required.')
    if not isinstance(evidence_ids,(list,tuple)) or not evidence_ids or any(not isinstance(x,str) or not x.strip() for x in evidence_ids):
        reason('evidence_missing','Original event references are unavailable.')
        evidence_ids=[]
    alert=bool(rule_hits) or (type(model_class) is int and model_class in (1,2,3))
    return {'version':VERSION,'model_class':CLASSES[model_class] if type(model_class) is int and model_class in range(4) else None,
            'disposition':'alert' if alert else 'manual_review' if reasons else 'no_alert_observed',
            'requires_review':bool(reasons),'reasons':reasons,'rule_hits':rule_hits,'evidence_ids':list(evidence_ids),
            'policy':{'minimum_top_score':MIN_SCORE,'minimum_margin':MIN_MARGIN,'calibrated':False},
            'limitations':['No safety verdict or zero-miss guarantee.','Shared model/rule blind spots remain possible.',
                           'No alert is evidence about this observed window only.','No action executed.']}
