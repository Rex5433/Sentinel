"""Fresh evaluation-only cases; freeze policy before inference, never train/tune."""
from datetime import datetime,timedelta,timezone
from collections import Counter
import json
from pathlib import Path
import uuid
import torch
from training.experiment_data import ROOT,hashfile,metrics
from training.experimental_cnn import SentinelCNN
from sentinel.ingest import parse_linux,parse_windows
from sentinel.features import extract_features,FEATURE_VERSION,schema_hash
from sentinel.detection.verification import verify
from sentinel.detection.temporal_verification import verify_series

RUN=ROOT/'training/runs/cnn-20261104T162845Z-4d452e71'
CASES=(('routine',0),('legitimate_retries',0),('maintenance',0),('occasional_typo',0),
       ('slow_campaign',1),('very_slow_campaign',1),('stolen_login',1),('account_campaign',2),
       ('service_campaign',3),('unsupported_activity',3),('gapped_unknown',None),('malformed_unknown',None))

def render(name,os,index):
    start=datetime(2026,11,5,tzinfo=timezone.utc)+timedelta(hours=index)
    entries=[]; kinds_by_window=[]
    for w in range(6):
        if name=='gapped_unknown' and w in (1,3): continue
        kinds=['success','close','success','success']
        failure=([1,2,1,3,2,1][w] if name in ('legitimate_retries','slow_campaign') else
                 1 if name=='very_slow_campaign' else int(w in (1,4)) if name=='occasional_typo' else 0)
        kinds+=['failure']*failure
        if name in ('maintenance','account_campaign'): kinds+=['account']*(1+w%2)
        if name in ('maintenance','service_campaign'): kinds+=['service']*(1+w%2)
        if name=='unsupported_activity': kinds+=['unknown']
        for i,kind in enumerate(kinds):
            stamp=(start+timedelta(seconds=300*w+15+i*23)).isoformat();user=f'operator{i%3}';ip=f'203.0.113.{30+i%3}'
            if os=='linux':
                emitter,message={
                    'success':('sshd',f'Accepted publickey for {user} from {ip} port 45000 ssh2'),
                    'failure':('sshd',f'Failed password for {user} from {ip} port 45000 ssh2'),
                    'close':('sshd',f'pam_unix(sshd:session): session closed for user {user}'),
                    'account':('useradd',f'new user: name=account{i}, UID={3100+i}'),
                    'service':('systemd','Started scheduled-report.service'),
                    'unknown':('audit-probe','Unmapped activity requires investigation')}[kind]
                entries.append(f'{stamp} probe-{index} {emitter}[{7000+len(entries)}]: {message}')
            else:
                is_service=kind=='service'
                code={'success':4624,'failure':4625,'close':4634,'account':4720,'service':7045,'unknown':4688}[kind]
                fields={'ServiceName':'scheduled-report'} if is_service else {'TargetUserName':user,'SubjectUserName':user}
                if kind in ('failure','success'): fields['IpAddress']=ip
                entries.append({'Id':code,'MachineName':f'probe-{index}','TimeCreated':stamp,'RecordId':len(entries)+1,
                                'LogName':'System' if is_service else 'Security',
                                'ProviderName':'Service Control Manager' if is_service else 'Microsoft-Windows-Security-Auditing',
                                'EventData':fields,'Message':'Original synthetic event'})
            kinds_by_window.append({'record':len(entries),'window':w,'kind':kind})
        if name=='malformed_unknown':entries.append('inert malformed line' if os=='linux' else {'invalid_export_record':True})
    raw=('\n'.join(entries)+'\n').encode() if os=='linux' else json.dumps(entries).encode()
    return raw,start,kinds_by_window

def binary(rows,key):
    tp=fp=tn=fn=unknown_review=unknown=0
    for r in rows:
        review=r[key]['requires_review']
        if r['truth'] is None:
            unknown+=1; unknown_review+=review;continue
        if r['truth']:
            tp+=review;fn+=not review
        else:fp+=review;tn+=not review
    p=tp/(tp+fp) if tp+fp else 0.;rec=tp/(tp+fn) if tp+fn else 0.
    return {'TP':tp,'FP':fp,'TN':tn,'FN':fn,'precision':p,'recall':rec,
            'f1':2*p*rec/(p+rec) if p+rec else 0.,'f2':5*p*rec/(4*p+rec) if p+rec else 0.,
            'false_positive_rate':fp/(fp+tn) if fp+tn else None,'unknown_review':unknown_review,'unknown':unknown,
            'total_review':sum(r[key]['requires_review'] for r in rows),'total_slots':len(rows)}

def confidence_diagnostics(rows):
    known=[r for r in rows if r['truth'] is not None and r['scores'] is not None]
    result=metrics([r['truth'] for r in known],[r['prediction'] for r in known])
    bins=[];ece=0.;brier=0.
    for i in range(10):
        selected=[r for r in known if min(int(max(r['scores'])*10),9)==i]
        if not selected:continue
        confidence=sum(max(r['scores']) for r in selected)/len(selected)
        accuracy=sum(r['prediction']==r['truth'] for r in selected)/len(selected)
        ece+=len(selected)/len(known)*abs(confidence-accuracy)
        bins.append({'range':[i/10,(i+1)/10],'count':len(selected),'mean_top_score':confidence,'accuracy':accuracy})
    brier=sum(sum((score-int(i==r['truth']))**2 for i,score in enumerate(r['scores'])) for r in known)/len(known)
    return {'classification':result,'bins':bins,'ece_10_bins':ece,'multiclass_brier_mean_sum_squared':brier,
            'calibrated':False,'warning':'Descriptive synthetic correlated sample; scores are not correctness probabilities or confidence intervals.'}

def main():
    torch.set_num_threads(1)
    selection=json.loads((RUN/'selection.json').read_text());config=json.loads((RUN/'config.json').read_text())
    assert hashfile(RUN/'best.pt')==selection['best_checkpoint_sha256'] and hashfile(RUN/'config.json')==selection['config_sha256']
    policies=[ROOT/'sentinel/detection/verification.py',ROOT/'sentinel/detection/temporal_verification.py',Path(__file__).resolve()]
    frozen={str(p.relative_to(ROOT)):hashfile(p) for p in policies}
    out=ROOT/'data/private'/('temporal-challenge-'+uuid.uuid4().hex[:12]);out.mkdir(exist_ok=False)
    (out/'freeze.json').write_text(json.dumps({'source_hashes':frozen,'checkpoint':selection['best_checkpoint_sha256'],
        'cases':CASES,'evaluation_only':True,'training':False,'origin':'Team-generated Codex-assisted, not field telemetry'},indent=2))
    for p in policies:(out/p.name).write_bytes(p.read_bytes())
    model=SentinelCNN();model.load_state_dict(torch.load(RUN/'best.pt',map_location='cpu',weights_only=True)['state_dict']);model.eval()
    rows=[];sources=[]
    for index,(name,truth) in enumerate(CASES):
        for os in ('linux','windows'):
            raw,start,provenance=render(name,os,index)
            filename=f'{index:02d}-{os}'+('.log' if os=='linux' else '.json');(out/filename).write_bytes(raw)
            parsed=(parse_linux(raw,file_format='text',source_file=filename,upload_id=filename) if os=='linux'
                    else parse_windows(raw,file_format='json',source_file=filename,upload_id=filename))
            extraction=extract_features(parsed.events);windows={int((w.start_utc-start).total_seconds()/300):w for w in extraction.windows}
            coverage={'collection_complete':name not in ('gapped_unknown','malformed_unknown'),'rejected_records':len(parsed.rejected),
                      'unrecognized_events':sum(e.event_type is None for e in parsed.events),'missing_timestamp':0,'missing_host':0,
                      'excluded_records':extraction.coverage['excluded_records']}
            sequence=[];case_rows=[];history=[]
            for pos in range(6):
                w=windows.get(pos);prior=len(history)
                if w:
                    history.append(w.vector);history=history[-5:]
                    x=torch.tensor([history],dtype=torch.float32);x=(x-torch.tensor(config['normalization']['mean']))/torch.tensor(config['normalization']['scale'])
                    with torch.no_grad():scores=model(x.transpose(1,2))[0,:,-1].softmax(0).tolist()
                    prediction=max(range(4),key=lambda i:scores[i])
                else: history=[];scores=None;prediction=None
                args=dict(vector=w.vector if w else None,model_class=prediction,probabilities=scores,coverage=coverage,
                          history_windows=min(prior,4) if w else 0,feature_version=FEATURE_VERSION,feature_schema_sha256=schema_hash(),evidence_ids=w.event_ids if w else [])
                sequence.append({'host':f'probe-{index}','platform':os,'session_id':filename,
                                 'start_utc':(start+timedelta(seconds=pos*300)).isoformat(),'verification':args})
                case_rows.append({'case':name,'platform':os,'slot':pos,'truth':truth,'prediction':prediction,'scores':scores,'v1':verify(**args)})
            for r,decision in zip(case_rows,verify_series(sequence)):r['v2']=decision
            rows.extend(case_rows);sources.append({'file':filename,'sha256':hashfile(out/filename),'records':provenance,'truth':truth})
    assert all(hashfile(ROOT/path)==digest for path,digest in frozen.items()) and hashfile(RUN/'best.pt')==selection['best_checkpoint_sha256']
    report={'comparison':{key:binary(rows,key) for key in ('v1','v2')},'confidence':confidence_diagnostics(rows),
            'rows':rows,'sources':sources,'limitations':['Evaluation only, no training or field evidence.','Manual review counts as escalation, not confirmed detection.','Policy developed after prior challenge: this fresh test is not the original held-out test.']}
    (out/'results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('OUTPUT',out);print(json.dumps({'comparison':report['comparison'],'confidence':report['confidence']},indent=2))

if __name__=='__main__':main()
