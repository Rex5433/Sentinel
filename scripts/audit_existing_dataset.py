"""Read-only audit of existing review data. Writes only a new audit report."""
from collections import Counter, defaultdict
from hashlib import sha256
from itertools import combinations
import json
import math
from pathlib import Path
import sqlite3
import uuid

from sentinel.features import extract_features, FEATURE_ORDER, EVENT_TYPES
from sentinel.ingest import parse_linux, parse_windows, ParseInputError

ROOT=Path(__file__).resolve().parents[1]


def independent_vector(events):
    times=[e.timestamp_utc for e in events]
    return [float(len(events)), *[float(sum(e.event_type==kind for e in events)) for kind in EVENT_TYPES],
            float(sum(e.event_type not in EVENT_TYPES for e in events)),
            *[float(len({str(getattr(e,key)) for e in events if getattr(e,key) is not None})) for key in ('actor','source_ip','target')],
            (max(times)-min(times)).total_seconds(),sum(e.event_type=='auth_failure' for e in events)/len(events),
            float(events[0].platform=='windows'),float(events[0].platform=='linux')]


def main():
    inventory=Counter(); inventory_files=[]
    def walk(folder):
        for p in folder.iterdir():
            if p.name in ('.venv','.git','__pycache__','.pytest_cache') or p.is_symlink() or p.is_junction():
                continue
            if p.is_dir(): walk(p)
            elif p.is_file():
                relative=p.relative_to(ROOT).as_posix()
                inventory[relative.split('/')[0]]+=1
                inventory_files.append({'path':relative,'bytes':p.stat().st_size})
    walk(ROOT)
    rows=[]; integrity=[]; raw_lines=[]; raw_hashes=[]; vectors=[]
    # Only existing manifests with actual generator source identities define candidate sessions.
    for p in sorted((ROOT/'data').rglob('manifests/*.json')):
        m=json.loads(p.read_text()); base=next(parent for parent in p.parents if parent.name.startswith('kit-review-'))
        rawpath=(base/m['raw_relative']).resolve(); labelpath=(base/m['labels_relative']).resolve()
        if not rawpath.is_relative_to(ROOT) or not labelpath.is_relative_to(ROOT):
            raise ValueError('Source outside workspace')
        raw=rawpath.read_bytes(); labelbytes=labelpath.read_bytes(); lab=json.loads(labelbytes)
        checks={'raw_hash':sha256(raw).hexdigest()==m['raw_sha256']==lab['raw_sha256'],
                'labels_hash':sha256(labelbytes).hexdigest()==m['labels_sha256'],
                'record_alignment':[r['physical_line'] for r in lab['records']]==list(range(1,len(raw.splitlines())+1))}
        integrity.append({'source_id':m['source_id'],**checks})
        platform=m['platform']; direct=True
        try:
            parsed=(parse_linux(raw,file_format='text',source_file=rawpath.name,upload_id=m['source_id']) if platform=='linux'
                    else parse_windows(raw,file_format='json',source_file=rawpath.name,upload_id=m['source_id']))
        except ParseInputError:
            if platform!='windows': raise
            direct=False
            parsed=parse_windows(json.dumps([json.loads(line) for line in raw.splitlines()]).encode(),file_format='json',source_file='diagnostic.json',upload_id=m['source_id'])
        extraction=extract_features(parsed.events)
        mismatches=[]
        for window in extraction.windows:
            members=extraction.members[window.window_id]
            assert independent_vector(members)==window.vector
            vectors.append({'source_id':m['source_id'],'scenario':m['scenario_id'],'platform':platform,
                            'label':lab['class_target'],'vector':window.vector})
        for event, record in zip(parsed.events,lab['records']):
            expected={'success':'auth_success','failure':'auth_failure','account':'account_created',
                      'close':'session_close','sudo':'sudo_command','service':'service_activity'}[record['event_kind']]
            if event.event_type is None: mismatches.append({'kind':record['event_kind'],'reason':'unrecognized'})
            elif event.event_type!=expected: mismatches.append({'kind':record['event_kind'],'reason':'different normalized category'})
        rows.append({'source_id':m['source_id'],'platform':platform,'scenario':m['scenario_id'],'seed':m['seed'],'run':m['run'],
                     'generator':m['generator_version'],'split':m['split'],'label':lab['class_target'],
                     'raw_records':len(raw.splitlines()),'raw_sha256':sha256(raw).hexdigest(),
                     'direct':direct,'accepted_diagnostic':len(parsed.events),'rejected':len(parsed.rejected),
                     'windows_diagnostic':len(extraction.windows),'windows_direct':len(extraction.windows) if direct else 0,
                     'unrecognized':sum(e.event_type is None for e in parsed.events),
                     'missing':{key:sum(getattr(e,key) is None for e in parsed.events) for key in ('timestamp_utc','host','actor','source_ip','target')},
                     'hosts':sorted({e.host for e in parsed.events if e.host}),
                     'mismatches':mismatches,'coverage':extraction.coverage})
        raw_hashes.append(sha256(raw).hexdigest()); raw_lines.extend(raw.splitlines())
    all_vectors=[v['vector'] for v in vectors]
    exact=[(a['source_id'],b['source_id']) for a,b in combinations(vectors,2) if a['vector']==b['vector']]
    # Descriptive distance only: per-feature observed-range normalization, not a fitted model transform.
    ranges=[max(v[i] for v in all_vectors)-min(v[i] for v in all_vectors) for i in range(18)]
    active=[i for i,r in enumerate(ranges) if r]
    near=[]
    for a,b in combinations(vectors,2):
        if a['platform']!=b['platform']: continue
        distance=sum(abs(a['vector'][i]-b['vector'][i])/ranges[i] for i in active)/len(active)
        near.append({'a':a['scenario'],'b':b['scenario'],'platform':a['platform'],'labels':[a['label'],b['label']], 'mean_range_scaled_distance':distance,
                     'equal_features':sum(x==y for x,y in zip(a['vector'],b['vector']))})
    fixtures=[]
    for name,platform,fmt in [('windows_events.json','windows','json'),('windows_events.csv','windows','csv'),('windows_auth_burst.json','windows','json'),('linux_auth.txt','linux','text'),('linux_journal.jsonl','linux','journal-json')]:
        data=(ROOT/'tests/fixtures'/name).read_bytes()
        parsed=(parse_windows(data,file_format=fmt,source_file=name,upload_id=name) if platform=='windows' else parse_linux(data,file_format=fmt,source_file=name,upload_id=name))
        fixtures.append({'file':name,'accepted':len(parsed.events),'rejected':len(parsed.rejected),'windows':len(extract_features(parsed.events).windows),'sha256':sha256(data).hexdigest()})
    uploads=[]
    db=ROOT/'storage/sentinel.sqlite3'
    if db.exists():
        with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as conn:
            conn.row_factory=sqlite3.Row
            for row in conn.execute('SELECT id,format,accepted_count,rejected_count,sha256 FROM uploads'):
                uploads.append(dict(row))
    report={'status':'not_training_ready','inventory':dict(inventory),'inventory_files':inventory_files,
            'feature_order':FEATURE_ORDER,'sessions':rows,'vectors':vectors,'integrity':integrity,
            'exact_vector_pairs':exact,'nearest_pairs':sorted(near,key=lambda p:p['mean_range_scaled_distance'])[:12],
            'constant_features':[FEATURE_ORDER[i] for i,r in enumerate(ranges) if not r],
            'duplicate_file_hashes':len(raw_hashes)-len(set(raw_hashes)), 'duplicate_raw_lines':len(raw_lines)-len(set(raw_lines)),
            'fixtures_excluded_from_training':fixtures,'unlabeled_saved_uploads':uploads}
    out=ROOT/'docs'/('dataset-audit-'+uuid.uuid4().hex[:12]+'.json')
    with out.open('x',encoding='utf-8') as f: json.dump(report,f,indent=2)
    print('REPORT',out)
    print('TOTALS',json.dumps({'raw':sum(r['raw_records'] for r in rows),'diagnostic_windows':sum(r['windows_diagnostic'] for r in rows),'direct_windows':sum(r['windows_direct'] for r in rows),'sessions':len(rows),'hosts':len({h for r in rows for h in r['hosts']}),'labels':dict(Counter(r['label'] or 'unknown' for r in rows)),'constants':report['constant_features'],'duplicate_files':report['duplicate_file_hashes'],'duplicate_lines':report['duplicate_raw_lines']}))
    for platform in ('linux','windows'):
        selected=[r for r in rows if r['platform']==platform]
        print(platform,json.dumps({'raw':sum(r['raw_records'] for r in selected),'labels':dict(Counter(r['label'] or 'unknown' for r in selected)),'unknown':sum(r['unrecognized'] for r in selected),'missing':{k:sum(r['missing'][k] for r in selected) for k in selected[0]['missing']},'mismatches':dict(Counter((e['kind']+':'+e['reason']) for r in selected for e in r['mismatches']))}))
    print('NEAREST',json.dumps(report['nearest_pairs'][:6]));print('FIXTURES',json.dumps(fixtures));print('UPLOADS',json.dumps(uploads));print('INVENTORY',json.dumps(dict(inventory)))


if __name__=='__main__': main()
