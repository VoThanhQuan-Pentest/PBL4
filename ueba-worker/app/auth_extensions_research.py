"""Staged, no-admission extension campaign: eight classifier fits at most."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import time

import numpy as np
from scipy.special import logsumexp

from . import auth_extensions_core as core
from .auth_extensions_diagnostics import fit_temperature,calibration_pass,DriftReference
from .auth_shadow_contract import RECIPES,SEEDS,FEATURE_NAMES
from .auth_shadow_research import ResourceGuard,threshold_for,nonregression,ci
from .postlogin_serving import ProjectPostloginModel
from .auth_extensions_http import BASELINE_SHA

QUOTAS={'train':40000,'calibration':15000,'development':10000,'evaluation':25000,'controls':10000}
CLASS_QUOTAS={'train':(32000,6000,2000),'calibration':(12000,2400,600),'development':(8000,1500,500),'evaluation':(20000,3000,2000)}
CASES=('case3','case4','case5')
CONTEXTS=np.asarray(['ROUTINE_CONTEXT','BEHAVIOR_REVIEW_CONTEXT','SERVICE_DEGRADATION_CONTEXT'])


def admit(data,cohort,splits):
    manifest=core.read_json(data/'manifest.json');protocol=core.read_json(data/'protocol.json');parity=core.read_json(data/'producer-parity.json')
    if (manifest.get('format')!='AUTH_EXTENSIONS_DATA_V1' or manifest.get('status')!='SOURCE_CAPTURE_COMPLETE'
            or manifest.get('records')!=100000 or manifest.get('cohort')!=cohort
            or manifest.get('protocol_sha256')!=core.sha(data/'protocol.json')
            or protocol.get('format')!='AUTH_EXTENSIONS_SOURCE_V1' or protocol.get('seed')!=20261028
            or protocol.get('smoke_only') is not False
            or protocol.get('cohort')!=cohort or protocol.get('model_width')!=(81 if cohort=='READY' else 42)
            or protocol.get('classifier_total_cap')!=8 or protocol.get('cold_false_positive_cap')!=0
            or protocol.get('recipes')!=list(RECIPES) or protocol.get('seeds')!=list(SEEDS)):
        raise ValueError('sealed extension protocol required')
    if (parity.get('status')!='HARNESS_REEXPORT_PARITY_PASS' or parity.get('records')!=100000
            or parity.get('manifest_sha256')!=core.sha(data/'manifest.json')
            or parity.get('protocol_sha256')!=core.sha(data/'protocol.json')):raise ValueError('source-bound parity required')
    code=Path(__file__).parent
    if protocol.get('code_sha256')!={p.name:core.sha(p) for p in sorted([*code.glob('auth_extensions_*.py'),code/'auth_shadow_research.py'])}:
        raise ValueError('campaign code changed after sealing')
    if set(manifest.get('splits',{}))!=set(QUOTAS):raise ValueError('split inventory differs')
    groups=set()
    for split,n in QUOTAS.items():
        item=manifest['splits'][split]
        if item.get('records')!=n or item.get('file')!=split+'.jsonl.gz' or item.get('raw_file')!=split+'-raw.jsonl.gz':raise ValueError('quota/path differs')
        current=set(item.get('account_groups',[]))
        if len(current)<256 or current&groups:raise ValueError('account overlap or insufficient groups')
        groups|=current
        if split in splits:
            path=data/item['file']
            if path.is_symlink() or core.sha(path)!=item['sha256']:raise ValueError('split checksum differs')
    return manifest,{'manifest_sha256':core.sha(data/'manifest.json'),'protocol_sha256':core.sha(data/'protocol.json'),
                     'parity_sha256':core.sha(data/'producer-parity.json'),'cohort':cohort}


def rows(data,split,manifest,cohort,guard):
    values=np.empty((QUOTAS[split],81 if cohort=='READY' else 42));labels=np.empty(len(values),dtype=np.uint8)
    metadata=[];seen=set();sessions=set();allowed=set(manifest['splits'][split]['account_groups'])
    with gzip.open(data/(split+'.jsonl.gz'),'rt') as source:
        for i in range(len(values)):
            if i%1000==0:guard.check()
            line=source.readline(65537)
            if not line or len(line)>=65537:raise ValueError('bounded source rows required')
            row=json.loads(line)
            if row['split']!=split or row['status']!='OBSERVED' or row['cohort']!=cohort:raise ValueError('source scope mismatch')
            if row['episode_id'] in seen or row['session_group'] in sessions or row['account_group'] not in allowed:raise ValueError('identity mismatch')
            seen.add(row['episode_id']);sessions.add(row['session_group'])
            label=row['context_label']
            if type(label) is not int or label not in (0,1,2):raise ValueError('explicit label required')
            if row['family'] not in (('routine',) if label==0 else CASES if label==1 else ('operational',)):raise ValueError('scenario/label differs')
            if row['snapshot']['snapshot_id']!=row['episode_id']:raise ValueError('snapshot differs')
            values[i]=core.project(row['snapshot'],cohort);labels[i]=label
            count=row['snapshot']['trusted_window_count']
            stratum='0' if count==0 else '1-9' if count<10 else '10-29' if count<30 else 'READY'
            if row['history_stratum']!=stratum:raise ValueError('observed history stratum differs')
            metadata.append({k:row[k] for k in ('episode_id','account_group','session_group','family','recipe','history_stratum')})
        if source.read(1):raise ValueError('extra rows')
    if tuple(int((labels==x).sum()) for x in range(3))!=CLASS_QUOTAS[split]:raise ValueError('class quota differs')
    return values,labels,metadata


def metrics(flags,contexts,labels,metadata):
    family=np.asarray([m['family'] for m in metadata]);recipe=np.asarray([m['recipe'] for m in metadata])
    normal,review,ops=labels==0,labels==1,labels==2
    result={'normal':int(normal.sum()),'false_review':int(flags[normal].sum()),'behavior':int(review.sum()),
        'true_review':int(flags[review].sum()),'operations':int(ops.sum()),
        'recall_by_case':{case:float(flags[review&(family==case)].mean()) for case in CASES},
        'false_review_by_legitimate_control':{x:int(flags[normal&(recipe==x)].sum()) for x in sorted(set(recipe[normal]))},
        'operational_false_review':int(flags[ops].sum()),'operational_correct':int((ops&(contexts==2)).sum()),
        'confusion_matrix_context':[[int(((labels==a)&(contexts==b)).sum()) for b in range(3)] for a in range(3)],
        'precision_review':float(flags[review].sum()/flags.sum()) if flags.any() else 0.,
        'false_review_ci95_episode_naive':ci(int(flags[normal].sum()),int(normal.sum())),
        'episode_ci_method':'WILSON_ASSUMES_EPISODE_INDEPENDENCE','assessment_coverage':1.0}
    strata=np.asarray([m['history_stratum'] for m in metadata]);result['strata']={}
    for key in sorted(set(strata)):
        mask=strata==key;n=normal&mask;p=review&mask;o=ops&mask
        result['strata'][key]={'normal':int(n.sum()),'false_review':int(flags[n].sum()),'review':int(p.sum()),
            'true_review':int(flags[p].sum()),'operations':int(o.sum()),'operational_correct':int((o&(contexts==2)).sum())}
    return result


def cold_gate(result):
    if (set(result['strata'])!={'0','1-9','10-29'} or result['false_review']!=0 or result['operational_false_review']!=0
            or result['operational_correct']<.95*result['operations']
            or min(result['recall_by_case'].values())<.9 or result['assessment_coverage']<.9):return False
    return all(s['false_review']==0 and s['true_review']>=.9*s['review']
               and s['operational_correct']>=.95*s['operations'] for s in result['strata'].values())


def score(state,values,baseline,cohort,guard):
    raw=np.empty(len(values));contexts=np.empty(len(values),dtype=np.uint8);all_logits=np.empty((len(values),3))
    for start in range(0,len(values),32):
        guard.check();batch=values[start:start+32];result=core.logits(state,batch)
        margin=logsumexp(result[:,1:],axis=1)-result[:,0]
        if cohort=='READY':margin=np.maximum(margin,np.log(baseline.model._normal.anomaly_scores(batch[:,:37])+1e-12))
        raw[start:start+len(batch)]=margin;contexts[start:start+len(batch)]=result.argmax(axis=1);all_logits[start:start+len(batch)]=result
    return raw,contexts,all_logits


def reference(directory):
    receipt=core.read_json(directory/'research-receipt.json');selection=core.read_json(directory/'selection.json')
    if receipt.get('status')!='RESEARCH_PASS' or core.sha(directory/'selection.json')!=receipt['selection_sha256']:
        raise ValueError('READY reference receipt chain differs')
    name=receipt['selected_trial']
    if name!='A-42':raise ValueError('fixed READY reference required')
    path=directory/(name+'-state.json')
    if core.sha(path)!=core.REFERENCE_SHA or receipt['selected_state_sha256']!=core.REFERENCE_SHA:raise ValueError('READY reference state differs')
    return core.validate_state(core.read_json(path)),receipt['threshold']


def calibrate(ledger,out,cohort,identity,raw_logits,labels,binding):
    ledger.reserve('calibrator',cohort,identity,binding)
    value=fit_temperature(raw_logits,labels);core.write_new(out/(identity+'-temperature.json'),value)
    return value


def select(data,out,ledger_dir,reference_dir,baseline_dir,cohort):
    if any(p.name!='operation.lock' for p in out.iterdir()):raise ValueError('fresh result directory required')
    guard=ResourceGuard(data,out);manifest,binding=admit(data,cohort,('train','calibration','development'))
    baseline=ProjectPostloginModel(baseline_dir,BASELINE_SHA);ref,ref_threshold=reference(reference_dir)
    binding.update(reference_ready_sha256=core.REFERENCE_SHA,baseline_manifest_sha256=BASELINE_SHA)
    core.write_new(out/'selection-started.json',{'binding':binding,'at':time.time()})
    ledger=core.Ledger(ledger_dir)
    train,y,_=rows(data,'train',manifest,cohort,guard)
    cal,cy,_=rows(data,'calibration',manifest,cohort,guard)
    dev,dy,dm=rows(data,'development',manifest,cohort,guard)
    names=FEATURE_NAMES if cohort=='READY' else core.COLD_NAMES
    drift_state,drift_result=drift_gate(cal,names,dev)
    core.write_new(out/'drift-reference.json',drift_state)
    core.write_new(out/'drift-development.json',drift_result)
    if cohort=='READY':
        rr,rc,ref_cal_logits=score(ref,cal,baseline,cohort,guard);ref_cal=(rc==1)&(rr>=ref_threshold)
        rr,rc,_=score(ref,dev,baseline,cohort,guard);ref_dev=metrics((rc==1)&(rr>=ref_threshold),rc,dy,dm)
    else:ref_cal=np.zeros(len(cal),dtype=bool);ref_dev=None
    trials=[]
    for recipe in RECIPES:
        for seed in SEEDS:
            guard.check(force=True);name=recipe['name']+'-'+str(seed)
            ledger.reserve('classifier',cohort,name,binding)
            core.write_new(out/(name+'-fit-reserved.json'),{'at':time.time(),'binding':binding})
            model=core.fit_classifier(train,y,cohort,recipe,seed)
            state=core.export_classifier(model,cohort,recipe,seed)
            from .normal_support import _signed_log
            np.testing.assert_allclose(core.logits(state,train[:32]),model._raw_predict(_signed_log(train[:32])),rtol=1e-12,atol=1e-12)
            del model;core.write_new(out/(name+'-state.json'),state)
            raw,ctx,_=score(state,cal,baseline,cohort,guard)
            threshold=threshold_for(raw,ctx,cy,ref_cal)
            raw,ctx,_=score(state,dev,baseline,cohort,guard)
            measured=metrics((ctx==1)&(raw>=threshold),ctx,dy,dm)
            eligible=nonregression(measured,ref_dev) if cohort=='READY' else cold_gate(measured)
            record={'id':name,'state_sha256':core.sha(out/(name+'-state.json')),'threshold':threshold,
                    'development':measured,'eligible':eligible}
            core.write_new(out/(name+'-completed.json'),record);trials.append(record)
            print(json.dumps({'phase':'FIT_COMPLETE','cohort':cohort,'trial':name,'eligible':eligible}),flush=True)
    eligible=[x for x in trials if x['eligible']]
    selected=min(eligible,key=lambda x:(x['development']['false_review'],-x['development']['true_review'],x['id'])) if eligible else None
    if cohort=='READY':
        core.write_new(out/'reference-state.json',ref)
        calibrate(ledger,out,cohort,'reference',ref_cal_logits,cy,binding)
    if selected:
        state=core.read_json(out/(selected['id']+'-state.json'));_,_,cal_logits=score(state,cal,baseline,cohort,guard)
        calibrate(ledger,out,cohort,'selected',cal_logits,cy,binding)
    core.write_new(out/'selection.json',{'status':'SELECTED' if selected else 'REFERENCE_RETAINED' if cohort=='READY' else 'NO_ADMISSION',
        'cohort':cohort,'binding':binding,'candidate':selected,'reference_threshold':ref_threshold,
        'reference_development':ref_dev,'classifier_fits':4,'evaluation_opened':False})
    baseline.verify_identity()


def paired_bootstrap(candidate,reference_flags,labels,metadata):
    _,group=np.unique([m['account_group'] for m in metadata],return_inverse=True);n=int(group.max())+1
    normal=labels==0;review=labels==1
    totals=lambda a:np.bincount(group,weights=np.asarray(a,dtype=float),minlength=n)
    nd,pd=totals(normal),totals(review)
    fp=totals(candidate&normal)-totals(reference_flags&normal)
    tp=totals(candidate&review)-totals(reference_flags&review)
    rng=np.random.default_rng(20261028);a=[];b=[]
    for start in range(0,2000,32):
        choices=rng.integers(0,n,size=(min(32,2000-start),n))
        normal_count=nd[choices].sum(axis=1);review_count=pd[choices].sum(axis=1)
        if (normal_count==0).any() or (review_count==0).any():raise ValueError('bootstrap population incomplete')
        a.extend((fp[choices].sum(axis=1)/normal_count).tolist());b.extend((tp[choices].sum(axis=1)/review_count).tolist())
    return {'method':'PAIRED_ACCOUNT_BOOTSTRAP_DESCRIPTIVE_LAB','groups':n,'resamples':2000,'seed':20261028,
            'fpr_difference_ci95':np.quantile(a,[.025,.975]).tolist(),'recall_difference_ci95':np.quantile(b,[.025,.975]).tolist()}


def controls(data,cohort):
    counts=Counter()
    with gzip.open(data/'controls.jsonl.gz','rt') as f:
        for line in f:
            if len(line)>65536:raise ValueError('oversized control')
            row=json.loads(line);kind=row['family']
            if kind=='missing':
                if row['status']!='UNDETERMINED' or row['snapshot']:raise ValueError('missing data padded')
            else:
                other='COLD' if cohort=='READY' else 'READY';core.project(row['snapshot'],other)
                if kind!=other.lower():raise ValueError('control routing differs')
            counts[kind]+=1
    if counts!={('cold' if cohort=='READY' else 'ready'):5000,'missing':5000}:raise ValueError('control quotas differ')
    return dict(counts)


def drift_gate(values,names,development=None):
    rng=np.random.default_rng(20261028);population=values if development is None else development
    operation_column=list(names).index('current_operation_password_change');references={};results={}
    for operation,flag in (('PASSWORD_CHANGE',1),('EMAIL_CHANGE',0)):
        original=values[values[:,operation_column]==flag];dev=population[population[:,operation_column]==flag]
        reference=DriftReference.fit(original,names);references[operation]=reference.state
        # Reweight complete real feature rows, never invent out-of-domain numbers.
        column=max(range(values.shape[1]),key=lambda i:len(np.unique(dev[:,i])))
        pool=dev[dev[:,column]>=np.quantile(dev[:,column],.8)]
        false=detected=0
        for i in range(100):
            sample=dev[rng.integers(0,len(dev),size=2000)]
            monitor=DriftReference(reference.state);monitor.window(sample[:1000])
            false+=monitor.window(sample[1000:])['status']=='DRIFT'
            shifted=pool[rng.integers(0,len(pool),size=2000)]
            monitor=DriftReference(reference.state);monitor.window(shifted[:1000])
            detected+=monitor.window(shifted[1000:])['status']=='DRIFT'
        results[operation]={'stable_false_alarms':false,'detected_shift_trials':detected,'trials':100,
                            'reweighted_feature':names[column]}
    passed=all(v['stable_false_alarms']<=1 and v['detected_shift_trials']>=90 for v in results.values())
    return {'format':'AUTH_CONTEXT_DRIFT_OPERATIONS_V1','operations':references}, {
        'status':'DRIFT_LAB_PASS' if passed else 'DRIFT_NO_ADMISSION','operations':results,
        'scope':'CONDITIONAL_DEVELOPMENT_RESAMPLING_NOT_REAL_USER_WINDOWS'}


def evaluate(data,out,reference_dir,baseline_dir,cohort):
    guard=ResourceGuard(data,out);selection=core.read_json(out/'selection.json')
    manifest,binding=admit(data,cohort,('evaluation','controls'))
    binding.update(reference_ready_sha256=core.REFERENCE_SHA,baseline_manifest_sha256=BASELINE_SHA)
    if binding!=selection['binding']:raise ValueError('selection identity changed')
    core.write_new(out/'evaluation-started.json',{'selection_sha256':core.sha(out/'selection.json'),'binding':binding})
    if cohort=='COLD' and selection['candidate'] is None:
        core.write_new(out/'receipt.json',{'status':'NO_ADMISSION','cohort':cohort,'classifier_fits':4,'evaluation_opened':False,'binding':binding});return
    baseline=ProjectPostloginModel(baseline_dir,BASELINE_SHA);ref,ref_threshold=reference(reference_dir)
    values,y,metadata=rows(data,'evaluation',manifest,cohort,guard)
    chosen=selection['candidate'];candidate_result=None;accepted=False;reference_result=None;reference_cal=None
    if cohort=='READY':
        raw,ctx,ref_logits=score(ref,values,baseline,cohort,guard);ref_flags=(ctx==1)&(raw>=ref_threshold)
        reference_result=metrics(ref_flags,ctx,y,metadata)
        reference_cal=calibration_pass(ref_logits,y,core.read_json(out/'reference-temperature.json'))
    if chosen:
        path=out/(chosen['id']+'-state.json')
        if core.sha(path)!=chosen['state_sha256']:raise ValueError('selected state changed')
        state=core.validate_state(core.read_json(path));raw,ctx,L=score(state,values,baseline,cohort,guard)
        flags=(ctx==1)&(raw>=chosen['threshold']);candidate_result=metrics(flags,ctx,y,metadata)
        accepted=(nonregression(candidate_result,reference_result,evaluation=True)
                  and (candidate_result['false_review']<reference_result['false_review'] or candidate_result['true_review']>reference_result['true_review'])) if cohort=='READY' else cold_gate(candidate_result)
        candidate_cal=calibration_pass(L,y,core.read_json(out/'selected-temperature.json'))
    else:candidate_cal=None
    if accepted:
        final_state=state;threshold=chosen['threshold'];calibrator=core.read_json(out/'selected-temperature.json');cal_result=candidate_cal
    elif cohort=='READY':
        final_state=ref;threshold=ref_threshold;calibrator=core.read_json(out/'reference-temperature.json');cal_result=reference_cal
    else:final_state=None;threshold=None;calibrator=None;cal_result=candidate_cal
    if final_state is not None:core.write_new(out/'selected-state.json',final_state)
    drift_result=core.read_json(out/'drift-development.json')
    baseline.verify_identity()
    receipt={'status':('READY_RESEARCH_PASS' if accepted else 'READY_REFERENCE_RETAINED') if cohort=='READY' else ('COLD_RESEARCH_PASS' if accepted else 'NO_ADMISSION'),
        'scope':'OFFLINE_RESEARCH_ONLY','cohort':cohort,'binding':binding,'selection_sha256':core.sha(out/'selection.json'),
        'selected_trial':chosen['id'] if accepted else 'READY_R2_REFERENCE' if cohort=='READY' else None,
        'selected_state_sha256':core.sha(out/'selected-state.json') if final_state is not None else None,
        'threshold':threshold,'calibrator':calibrator,'calibration':cal_result,
        'reference':reference_result,'candidate':candidate_result,'drift':drift_result,
        'controls':controls(data,cohort),'classifier_fits':4,'normal_fits':0,
        'maximum_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'automatic_enforcement':False,'strict_production_qualified':False}
    if cohort=='READY' and chosen:receipt['paired_account_comparison']=paired_bootstrap(flags,ref_flags,y,metadata)
    core.write_new(out/'receipt.json',receipt)


def smoke(data,out,reference_dir,baseline_dir,cohort):
    guard=ResourceGuard(data,out);manifest=core.read_json(data/'manifest.json');parity=core.read_json(data/'producer-parity.json')
    if (manifest.get('status')!='SMOKE_ONLY' or parity.get('status')!='SMOKE_PARITY_PASS'
            or parity['manifest_sha256']!=core.sha(data/'manifest.json')
            or parity['protocol_sha256']!=core.sha(data/'protocol.json')):raise ValueError('smoke parity required')
    baseline=ProjectPostloginModel(baseline_dir,BASELINE_SHA);ref,_=reference(reference_dir)
    projected=Counter();count=0
    for split in QUOTAS:
        with gzip.open(data/(split+'.jsonl.gz'),'rt') as source:
            for line in source:
                row=json.loads(line);packet=row.get('snapshot')
                if not packet:continue
                role='READY' if packet['baseline_established'] else 'COLD';value=core.project(packet,role)
                if role=='READY':
                    raw,_,_=score(ref,value.reshape(1,-1),baseline,role,guard)
                    if not np.isfinite(raw).all():raise ValueError('smoke inference failed')
                projected[role]+=1;count+=1
    baseline.verify_identity()
    core.write_new(out/'smoke-receipt.json',{'status':'SMOKE_ONLY','observed':count,'projected':dict(projected),
        'classifier_fits':0,'calibrator_fits':0,'automatic_enforcement':False})


def main():
    if os.environ.get('AUTH_RESEARCH_SUPERVISED')!='1':raise SystemExit('bounded supervisor required')
    p=argparse.ArgumentParser();p.add_argument('stage',choices=('select','evaluate','smoke'));p.add_argument('--cohort',choices=core.COHORTS,required=True)
    for name in ('data','output','ledger','reference','baseline'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    with core.lock(a.output):
        if a.stage=='smoke':smoke(a.data,a.output,a.reference,a.baseline,a.cohort)
        elif a.stage=='select':select(a.data,a.output,a.ledger,a.reference,a.baseline,a.cohort)
        else:evaluate(a.data,a.output,a.reference,a.baseline,a.cohort)


if __name__=='__main__':main()
