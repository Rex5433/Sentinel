"""Owner-run original causal CNN. No dashboard integration or pretrained weights."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import random
import uuid
from importlib.metadata import distributions
import torch
from torch import nn
from torch.nn import functional as F
from training.experiment_data import ROOT, DATA, CLASSES, load, normalize_fit, baseline, metrics, hashfile

CONFIG={'seed':84,'epochs':200,'patience':25,'min_delta':.0001,'learning_rate':.001,
        'weight_decay':.0001,'batch_sessions':8,'device':'cpu',
        'architecture':'causal-18-32-32-k3-dropout0.1-linear4-v1'}

class SentinelCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1=nn.Conv1d(18,32,3); self.conv2=nn.Conv1d(32,32,3)
        self.dropout=nn.Dropout(.1); self.head=nn.Linear(32,4)
    def forward(self,x):
        x=F.relu(self.conv1(F.pad(x,(2,0))))
        x=F.relu(self.conv2(F.pad(x,(2,0))))
        return self.head(self.dropout(x).transpose(1,2)).transpose(1,2)

def tensors(sessions,norm):
    x=torch.tensor([s['vectors'] for s in sessions],dtype=torch.float32)
    x=(x-torch.tensor(norm['mean']))/torch.tensor(norm['scale'])
    return x.transpose(1,2),torch.tensor([s['targets'] for s in sessions],dtype=torch.long)

def evaluate(model,sessions,norm):
    x,y=tensors(sessions,norm); model.eval()
    with torch.no_grad():
        logits=model(x); loss=F.cross_entropy(logits,y).item(); pred=logits.argmax(1).reshape(-1).tolist()
    truth=y.reshape(-1).tolist(); rules=[baseline(v) for s in sessions for v in s['vectors']]
    records=[]
    for i,s in enumerate(sessions):
        for t in range(6): records.append({'source':s['id'],'group':s['group'],'platform':s['platform'],'window':t,
                                          'context':s['contexts'][t],'truth':truth[i*6+t],'cnn':pred[i*6+t],'rule':rules[i*6+t]})
    subsets={}
    for field in ('platform','context'):
        for value in sorted({r[field] for r in records}):
            selected=[r for r in records if r[field]==value]
            subsets[f'{field}:{value}']={'cnn':metrics([r['truth'] for r in selected],[r['cnn'] for r in selected]),
                                       'rule':metrics([r['truth'] for r in selected],[r['rule'] for r in selected])}
    return {'loss':loss,'cnn':metrics(truth,pred),'rule':metrics(truth,rules),'subsets':subsets,'predictions':records}

def write(path,value):
    with path.open('x',encoding='utf-8') as f: json.dump(value,f,indent=2)

def self_check():
    torch.manual_seed(84); model=SentinelCNN().eval(); x=torch.randn(2,18,6)
    with torch.no_grad():
        before=model(x); changed=x.clone(); changed[:,:,3:]+=100
        assert before.shape==(2,4,6)
        assert torch.equal(before[:,:,:3],model(changed)[:,:,:3]),'Future leakage'
    sessions=load({'train','validation'}); norm=normalize_fit([s for s in sessions if s['split']=='train'])
    assert norm['fit_windows']==192
    return {'status':'passed','causality':'verified','shape':[2,4,6],'parameters':sum(p.numel() for p in model.parameters())}

def train():
    """One fixed run; notebook must call explicitly. Does not load test raw inputs."""
    torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
    random.seed(CONFIG['seed']); torch.manual_seed(CONFIG['seed'])
    all_sessions=load({'train','validation'}); training=[s for s in all_sessions if s['split']=='train']; validation=[s for s in all_sessions if s['split']=='validation']
    norm=normalize_fit(training); x,y=tensors(training,norm)
    run=ROOT/'training/runs'/('cnn-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(ROOT)):hashfile(p) for p in (Path(__file__),ROOT/'training/experiment_data.py',ROOT/'sentinel/features.py',ROOT/'sentinel/ingest/windows.py',ROOT/'sentinel/ingest/linux.py',ROOT/'sentinel/ingest/common.py')}
    snapshot={'config':CONFIG,'source_hashes':sources,'manifest_sha256':hashfile(DATA/'manifest.json'),
              'dataset_manifest':json.loads((DATA/'manifest.json').read_text()),'torch':torch.__version__,
              'python':platform.python_version(),'platform':platform.platform(),'normalization':norm}
    write(run/'config.json',snapshot)
    write(run/'installed-packages.json',sorted([{'name':d.metadata['Name'],'version':d.version} for d in distributions()],key=lambda x:x['name'].lower()))
    for path in sources:
        target=run/'source'/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes((ROOT/path).read_bytes())
    model=SentinelCNN(); optimizer=torch.optim.Adam(model.parameters(),lr=CONFIG['learning_rate'],weight_decay=CONFIG['weight_decay'])
    torch.save({'state_dict':model.state_dict(),'rng':torch.get_rng_state()},run/'initial.pt')
    best=float('inf'); reference=float('inf'); stale=0; best_epoch=0; history=[]
    for epoch in range(1,CONFIG['epochs']+1):
        model.train(); order=torch.randperm(len(training))
        for batch in order.split(CONFIG['batch_sessions']):
            optimizer.zero_grad(); loss=F.cross_entropy(model(x[batch]),y[batch]); loss.backward(); optimizer.step()
        tr=evaluate(model,training,norm); val=evaluate(model,validation,norm)
        entry={'epoch':epoch,'train_loss':tr['loss'],'validation_loss':val['loss'],
               'train_accuracy':tr['cnn']['accuracy'],'validation_accuracy':val['cnn']['accuracy']}
        history.append(entry)
        with (run/'history.jsonl').open('a',encoding='utf-8') as f: f.write(json.dumps(entry)+'\n')
        checkpoint={'state_dict':model.state_dict(),'optimizer':optimizer.state_dict(),'epoch':epoch,'rng':torch.get_rng_state()}
        if val['loss']<best:
            best=val['loss']; best_epoch=epoch; torch.save(checkpoint,run/'best.pt')
        if val['loss']<reference-CONFIG['min_delta']: reference=val['loss']; stale=0
        else: stale+=1
        if epoch==1 or epoch%10==0: print(entry,flush=True)
        if stale>=CONFIG['patience']: break
    torch.save(checkpoint,run/'last.pt')
    model.load_state_dict(torch.load(run/'best.pt',map_location='cpu',weights_only=True)['state_dict'])
    write(run/'train_metrics.json',evaluate(model,training,norm)); write(run/'validation_metrics.json',evaluate(model,validation,norm))
    selection={'best_epoch':best_epoch,'best_checkpoint_sha256':hashfile(run/'best.pt'),'config_sha256':hashfile(run/'config.json'),
               'epochs_run':epoch,'test_evaluated':False,'history':history}
    write(run/'selection.json',selection)
    print('Selected epoch',best_epoch,'Artifacts:',run)
    return run

def final_test(run):
    run=Path(run).resolve()
    if not run.is_relative_to(ROOT/'training/runs'): raise ValueError('Run outside V1')
    if (run/'test_metrics.json').exists() or (run/'test-started.json').exists(): raise RuntimeError('Final test already attempted; inspect saved artifacts, do not retune/retest')
    config=json.loads((run/'config.json').read_text()); selection=json.loads((run/'selection.json').read_text())
    if config['config']!=CONFIG or hashfile(run/'config.json')!=selection['config_sha256'] or hashfile(DATA/'manifest.json')!=config['manifest_sha256']:
        raise ValueError('Run or dataset changed')
    if hashfile(run/'best.pt')!=selection['best_checkpoint_sha256']: raise ValueError('Checkpoint changed')
    for path,digest in config['source_hashes'].items():
        if hashfile(ROOT/path)!=digest: raise ValueError('Code changed since selection')
    write(run/'test-started.json',{'selected_epoch':selection['best_epoch'],'checkpoint_hash':selection['best_checkpoint_sha256']})
    test=load({'test'}); model=SentinelCNN(); model.load_state_dict(torch.load(run/'best.pt',map_location='cpu',weights_only=True)['state_dict'])
    result=evaluate(model,test,config['normalization']); write(run/'test_metrics.json',result)
    write(run/'SUMMARY.json',{'best_epoch':selection['best_epoch'],'train':json.loads((run/'train_metrics.json').read_text())['cnn'],
          'validation':json.loads((run/'validation_metrics.json').read_text())['cnn'],'test':result['cnn'],'test_rule':result['rule'],
          'limitations':['Synthetic renderer shared across splits; not field accuracy.','Context authorization not present in X.','Test descriptive summaries were reviewed before training.','No deployment or competition authorization.']})
    print(json.dumps(json.loads((run/'SUMMARY.json').read_text()),indent=2)); return result
