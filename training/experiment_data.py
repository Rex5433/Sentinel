"""Approved Candidate V2 loading, training-only scaling and transparent metrics."""
from collections import Counter, defaultdict
from hashlib import sha256
import json
import math
from pathlib import Path
from sentinel.ingest import parse_linux, parse_windows
from sentinel.features import extract_features, FEATURE_ORDER, schema_hash

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data/private/candidate-v2-f6f255127117'
APPROVED_MANIFEST_SHA256='836b2f938e0b7d9f0698a09ea7a4ecf36ca199767aad3f761ada95b56b5ebf80'
CLASSES=('normal_or_unremarkable','authentication_burst','account_or_privilege_change','process_or_service_anomaly')

def hashfile(path): return sha256(Path(path).read_bytes()).hexdigest()

def load(splits):
    if hashfile(DATA/'manifest.json')!=APPROVED_MANIFEST_SHA256: raise ValueError('Approved dataset manifest changed')
    manifest=json.loads((DATA/'manifest.json').read_text())
    if manifest['feature_schema_sha256']!=schema_hash(): raise ValueError('Feature schema changed')
    result=[]; groups=defaultdict(set)
    for source in manifest['sources']:
        sidepath=DATA/source['labels']
        if hashfile(sidepath)!=source['labels_sha256']: raise ValueError('Labels changed')
        side=json.loads(sidepath.read_text()); groups[side['group_id']].add(side['split'])
        if side['split'] not in splits: continue
        rawpath=DATA/source['raw']
        if hashfile(rawpath)!=source['raw_sha256']: raise ValueError('Source changed')
        raw=rawpath.read_bytes()
        parsed=(parse_linux(raw,file_format='text',source_file=source['raw'],upload_id=source['id']) if side['platform']=='linux'
                else parse_windows(raw,file_format='json',source_file=source['raw'],upload_id=source['id']))
        windows=extract_features(parsed.events).windows
        if parsed.rejected or len(windows)!=6: raise ValueError('Unexpected parser coverage')
        for w,truth in zip(windows,side['windows']):
            if w.start_utc.isoformat()!=truth['start'] or truth['class_target']!=side['target']: raise ValueError('Window/label mismatch')
        result.append({'id':source['id'],'group':side['group_id'],'split':side['split'],'platform':side['platform'],
                       'vectors':[w.vector for w in windows], 'targets':[CLASSES.index(w['class_target']) for w in side['windows']],
                       'contexts':[w['scenario_context'] for w in side['windows']]})
    if any(len(s)>1 for s in groups.values()): raise ValueError('Group crosses splits')
    expected={'train':192,'validation':96,'test':96}
    for split in splits:
        selected=[s for s in result if s['split']==split]
        if sum(len(s['targets']) for s in selected)!=expected[split]: raise ValueError('Split size changed')
    return result

def normalize_fit(sessions):
    if not sessions or any(s['split']!='train' for s in sessions): raise ValueError('Fit requires training sessions only')
    rows=[v for s in sessions for v in s['vectors']]
    mean=[sum(v[i] for v in rows)/len(rows) for i in range(18)]
    scale=[math.sqrt(sum((v[i]-mean[i])**2 for v in rows)/len(rows)) or 1. for i in range(18)]
    return {'mean':mean,'scale':scale,'fit_windows':len(rows),'feature_order':FEATURE_ORDER}

def baseline(vector):
    f=dict(zip(FEATURE_ORDER,vector))
    if f['account_created_count']>=2: return 2
    if sum(f[k] for k in ('service_installed_count','service_state_change_count','service_activity_count'))>=4: return 3
    if f['auth_failure_count']>=5: return 1
    return 0

def metrics(truth,prediction):
    if len(truth)!=len(prediction) or not truth: raise ValueError('Invalid prediction count')
    matrix=[[0]*4 for _ in range(4)]
    for a,b in zip(truth,prediction): matrix[a][b]+=1
    rows=[]
    for i,name in enumerate(CLASSES):
        tp=matrix[i][i]; support=sum(matrix[i]); predicted=sum(r[i] for r in matrix)
        precision=tp/predicted if predicted else 0.; recall=tp/support if support else 0.
        rows.append({'class':name,'support':support,'precision':precision,'recall':recall,'f1':2*precision*recall/(precision+recall) if precision+recall else 0.})
    return {'accuracy':sum(matrix[i][i] for i in range(4))/len(truth),'macro_f1':sum(r['f1'] for r in rows)/4,
            'confusion_matrix_rows_truth':matrix,'class_order':CLASSES,'per_class':rows}
