"""Offline bounded host/session correlation layered on frozen verification v1."""
from datetime import datetime, timedelta
from math import isfinite
from sentinel.detection.verification import verify

VERSION='temporal-verification-v1'
HISTORY=4
FAILURES=5

def verify_series(rows):
    """Rows in chronological order; no future data, cross-host or gap bridging.

    Each row: host, platform, session_id, start_utc and kwargs for verify().
    Correlates unscaled host-level counts, not proof of a particular attacker.
    """
    histories={}; output=[]
    for row in rows:
        result=verify(**row['verification'])
        try:
            identity=tuple(row[k] for k in ('platform','host','session_id'))
            if any(not isinstance(x,str) or not x.strip() for x in identity): raise ValueError()
            start=datetime.fromisoformat(row['start_utc'])
            if start.tzinfo is None or start.utcoffset() is None: raise ValueError()
            previous=histories.get(identity,[])
            if previous and start<=previous[-1]['time']: raise ValueError()
            if previous and start-previous[-1]['time']!=timedelta(seconds=300): previous=[]
            vector=row['verification'].get('vector')
            valid=(isinstance(vector,(list,tuple)) and len(vector)==18 and not any(r['code']=='invalid_features' for r in result['reasons']))
            if not valid:
                histories.pop(identity,None); output.append(result); continue
            failures=vector[1]
            previous.append({'time':start,'failures':failures,'evidence':list(result['evidence_ids'])})
            previous=previous[-HISTORY:]; histories[identity]=previous
            count=sum(w['failures'] for w in previous)
            active=sum(w['failures']>0 for w in previous)
            if active>=2 and count>=FAILURES:
                result['disposition']='alert'; result['requires_review']=True
                result['rule_hits'].append('cross_window_authentication')
                result['reasons'].append({'code':'cross_window_authentication',
                    'message':f'{int(count)} authentication failures across {len(previous)} consecutive windows in this host/session; may be benign retries.'})
                result['evidence_ids']=list(dict.fromkeys(e for w in previous for e in w['evidence']))
        except (KeyError,TypeError,ValueError):
            result['requires_review']=True
            if result['disposition']=='no_alert_observed': result['disposition']='manual_review'
            result['reasons'].append({'code':'correlation_context_invalid','message':'Correlation identity or chronological context is invalid; manual review required.'})
        result['temporal_policy']={'version':VERSION,'maximum_windows':HISTORY,'failure_threshold':FAILURES}
        output.append(result)
    return output
