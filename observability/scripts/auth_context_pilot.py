#!/usr/bin/env python3
"""One preregistered, quota-bound PILOT_ONLY experiment; never installs/adopts a model.

Run inside the pinned worker environment. Dataset evaluation is scored only after
selection is committed. Baseline normal support/calibration/thresholds are read-only.
"""
import argparse
from collections import Counter
import fcntl
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import time
import numpy as np
from app.auth_shadow_contract import FEATURE_NAMES,RECIPES,SEEDS,pilot_protocol,validate
from app.auth_shadow_model import fit_classifier,export_classifier,score_components
from app.postlogin_contract import FEATURE_NAMES as BASE_NAMES
from app.postlogin_serving import configured_model

QUOTAS={'train':40000,'calibration':15000,'development':10000,'evaluation':25000,'controls':10000}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def put(path,value,*,replace=False):
    if path.exists() and not replace:raise RuntimeError('Immutable receipt exists: '+path.name)
    pending=path.with_suffix(path.suffix+'.partial')
    with pending.open('wb') as out:os.chmod(pending,0o600);out.write(canonical(value));out.flush();os.fsync(out.fileno())
    pending.replace(path)
def usage(root):return sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
def budget(data,out):
    if usage(data)+usage(out)>4*1024**3:raise RuntimeError('STOP_RESOURCE:4GiB pilot quota')

def admit(data,out):
    source=json.loads((data/'manifest.json').read_bytes())
    if source.get('status')!='SOURCE_CAPTURE_COMPLETE' or source.get('records')!=100000 or source.get('data_provenance')!='CONTROLLED_CLOCK_LAB' or source.get('feature_schema_version')!=7:raise RuntimeError('INSUFFICIENT_DATA: exact fresh controlled source required')
    groups=set()
    for split,count in QUOTAS.items():
        item=source['splits'][split]
        if item['records']!=count or item['file']!=split+'.jsonl.gz' or item['raw_file']!=split+'-raw.jsonl.gz':raise RuntimeError('Source quota/path differs')
        for name,key in [(item['file'],'sha256'),(item['raw_file'],'raw_sha256')]:
            file=data/name
            if file.is_symlink() or sha(file)!=item[key]:raise RuntimeError('Source checksum differs')
        current=set(item['account_groups'])
        if not current or groups&current:raise RuntimeError('Account groups overlap across splits')
        groups|=current
    parity=json.loads((data/'producer-parity.json').read_bytes())
    if parity.get('status')!='DEPLOYED_PRODUCER_REEXPORT_PARITY_PASS' or parity.get('records')!=100000 or parity.get('feature_count')!=81:raise RuntimeError('Deployed JDK21 producer parity required')
    compatible=json.loads((data/'producer-compatible-release.json').read_bytes())
    if compatible.get('status')!='PRODUCER_CLASSES_BYTE_IDENTICAL' or compatible.get('reference_jar_sha256')!=parity['application_jar_sha256']:raise RuntimeError('Release producer compatibility proof required')
    baseline=configured_model();baseline.verify_identity()
    protocol=pilot_protocol()|{'dataset_id':source['dataset_id'],'source_manifest_sha256':sha(data/'manifest.json'),
        'source_generator_sha256':source['generator_sha256'],'producer_parity_sha256':sha(data/'producer-parity.json'),'application_jar_sha256':compatible['application_jar_sha256'],'producer_compatible_release_sha256':sha(data/'producer-compatible-release.json'),'baseline_manifest_sha256':baseline.manifest_sha256,
        'model_code_sha256':sha(Path('/service/app/auth_shadow_model.py')),'source_transport':source['source_transport'],
        'comparison_target':'REVIEW_CONTEXT_PLUS_MODEL_THRESHOLD; NOT_ACTOR_OWNERSHIP_OR_APPLICATION_HOLD',
        'selection':'development macro recall subject to paired FP/operational nonregression; tie A then lower seed',
        'evaluation_opened_after_selection_only':True}
    path=out/'protocol.json'
    if path.exists():
        if path.read_bytes()!=canonical(protocol):raise RuntimeError('Protocol binding changed; no refit allowed')
    else:put(path,protocol)
    budget(data,out);return source,baseline,protocol

def load(data,split):
    count=QUOTAS[split];values=np.empty((count,81),dtype=np.float64);labels=np.empty(count,dtype=np.uint8)
    metadata=[];seen=set();counts=Counter()
    with gzip.open(data/(split+'.jsonl.gz'),'rt',encoding='utf-8') as file:
        for index in range(count):
            line=file.readline(65537)
            if not line or len(line)>=65537:raise RuntimeError('Bounded complete source row required')
            row=json.loads(line);identifier=row['episode_id']
            if identifier in seen or row['split']!=split:raise RuntimeError('Duplicate episode or split mismatch')
            seen.add(identifier);counts[row['family']]+=1
            if type(row['context_label']) is not int or row['context_label'] not in (0,1,2):raise RuntimeError('Independent context labels required')
            if row['status']!='OBSERVED':raise RuntimeError('Covered source required outside controls')
            packet=row['snapshot'];values[index]=validate(packet)
            if packet['snapshot_id']!=identifier:raise RuntimeError('Snapshot/reference differs')
            labels[index]=row['context_label'];metadata.append({k:row[k] for k in ('episode_id','account_group','session_group','family','recipe')}|{'as_of':packet['as_of'],'trusted':packet['trusted_window_count']})
        if file.read(1):raise RuntimeError('Source exceeds split quota')
    if split=='evaluation' and (int((labels==0).sum())!=20000 or any(counts[name]!=1000 for name in ('case3','case4','case5'))):raise RuntimeError('Evaluation coverage differs from predeclared groups')
    return values,labels,metadata

def baseline_flags(model,rows,metadata):
    scores=[];contexts=[];flags=[]
    for start in range(0,len(rows),32):
        packets=[]
        for i in range(start,min(start+32,len(rows))):
            meta=metadata[i];packets.append({'snapshot_id':meta['episode_id'],'evaluation_unit':'SENSITIVE_ACTION_ATTEMPT','feature_schema_version':6,
                'feature_names':list(BASE_NAMES),'features':rows[i,:65].tolist(),'as_of':meta['as_of'],'baseline_established':True,'trusted_window_count':meta['trusted']})
        result=model.score(packets)['assessments']
        for item in result:scores.append(item['raw_score']);contexts.append(item['context']);flags.append(item['above_threshold'] and item['context']=='BEHAVIOR_REVIEW_CONTEXT')
    return np.asarray(flags,dtype=bool),np.asarray(contexts)

def candidate_scores(state,rows,model):
    raw=[];contexts=[]
    for start in range(0,len(rows),32):
        result=score_components(state,rows[start:start+32],model);raw.extend(result['raw_score'].tolist());contexts.extend(result['context_index'].tolist())
    return np.asarray(raw),np.asarray(contexts)

def threshold_for(raw,context,labels,baseline):
    budget=int(baseline[labels==0].sum());normal=np.sort(raw[(labels==0)&(context==1)])[::-1]
    return float(np.nextafter(normal[budget],np.inf)) if len(normal)>budget else float(raw.min())

def metrics(flags,contexts,labels,metadata):
    families=np.asarray([m['family'] for m in metadata]);recipes=np.asarray([m['recipe'] for m in metadata]);normal=labels==0;behavior=labels==1;ops=labels==2
    recalls={family:float(flags[families==family].mean()) for family in ('case3','case4','case5')}
    by_control={name:int(flags[normal&(recipes==name)].sum()) for name in sorted(set(recipes[normal]))}
    return {'normal':int(normal.sum()),'false_review':int(flags[normal].sum()),'behavior':int(behavior.sum()),'true_review':int(flags[behavior].sum()),
        'recall_by_case':recalls,'macro_recall':float(np.mean(list(recalls.values()))),'false_review_by_legitimate_control':by_control,
        'operational_false_review':int(flags[ops].sum()),'operational_correct':int(np.sum(ops&(contexts=='SERVICE_DEGRADATION_CONTEXT')))}

def ci(success,total):
    if total==0:return [0.,1.]
    p=success/total;z=1.959963984540054;denom=1+z*z/total;center=(p+z*z/(2*total))/denom;spread=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denom
    return [max(0.,center-spread),min(1.,center+spread)]

def run(data,out,fit):
    out.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (out/'pilot.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        source,baseline,protocol=admit(data,out)
        protocol_hash=sha(out/'protocol.json')
        if not fit:print(json.dumps({'status':'PILOT_PREPARED_NO_FITS','protocol_sha256':protocol_hash}));return
        admission=json.loads(Path(os.environ['AUTH_PILOT_TRAINING_ADMISSION']).read_bytes())
        if admission.get('status')!='TRAINING_RESOURCE_ADMITTED' or admission.get('protocol_sha256')!=protocol_hash or admission.get('source_manifest_sha256')!=sha(data/'manifest.json') or admission.get('scope')!='PILOT_ONLY':raise RuntimeError('Private resource admission binding required')
        if (out/'fit-ledger.json').exists():raise RuntimeError('Fit ledger already reserved; inspect receipt, never replay fits')
        ledger={'protocol_sha256':protocol_hash,'classifier_fits':0,'normal_fits':0,'entries':[]};put(out/'fit-ledger.json',ledger)
        started=time.monotonic();normal_state_hash=hashlib.sha256(canonical(baseline.model._normal.to_state())).hexdigest()
        train,train_labels,_=load(data,'train');cal,cal_labels,cal_meta=load(data,'calibration');dev,dev_labels,dev_meta=load(data,'development')
        baseline_cal,_=baseline_flags(baseline,cal,cal_meta);baseline_dev_flags,baseline_dev_context=baseline_flags(baseline,dev,dev_meta);baseline_dev=metrics(baseline_dev_flags,baseline_dev_context,dev_labels,dev_meta)
        trials=[]
        for recipe in RECIPES:
            for seed in SEEDS:
                budget(data,out);trial=recipe['name']+'-'+str(seed)
                ledger['classifier_fits']+=1;ledger['entries'].append({'id':trial,'status':'RESERVED_BEFORE_FIT','at':time.time()});put(out/'fit-ledger.json',ledger,replace=True)
                fit_started=time.monotonic();classifier=fit_classifier(train,train_labels,recipe,seed)
                state=export_classifier(classifier,recipe,seed);del classifier
                if time.monotonic()-fit_started>1800:raise RuntimeError('Fit deadline exceeded; reservation remains spent')
                put(out/(trial+'-state.json'),state)
                raw,context=candidate_scores(state,cal,baseline);threshold=threshold_for(raw,context,cal_labels,baseline_cal)
                dev_raw,dev_context=candidate_scores(state,dev,baseline);flags=(dev_context==1)&(dev_raw>=threshold)
                context_names=np.asarray(['ROUTINE_CONTEXT','BEHAVIOR_REVIEW_CONTEXT','SERVICE_DEGRADATION_CONTEXT'])[dev_context]
                measured=metrics(flags,context_names,dev_labels,dev_meta)
                eligible=measured['false_review']<=baseline_dev['false_review'] and measured['operational_false_review']<=baseline_dev['operational_false_review'] and measured['operational_correct']>=baseline_dev['operational_correct']
                record={'id':trial,'recipe':recipe['name'],'seed':seed,'threshold':threshold,'development':measured,'eligible':eligible,'state_sha256':sha(out/(trial+'-state.json'))}
                trials.append(record);ledger['entries'][-1].update(status='COMPLETED',state_sha256=record['state_sha256']);put(out/'fit-ledger.json',ledger,replace=True);put(out/(trial+'-development.json'),record)
                print(json.dumps({'phase':'FIT_COMPLETE','trial':trial,'classifier_fits':ledger['classifier_fits'],'eligible':eligible}),flush=True)
        eligible=[v for v in trials if v['eligible']]
        if not eligible:
            put(out/'offline-receipt.json',{'status':'STOP_NO_IMPROVEMENT','reason':'No development candidate satisfies paired false-review/operational nonregression','classifier_fits':4,'normal_fits':0,'evaluation_opened':False,'strict_production_qualified':False});return
        selected=sorted(eligible,key=lambda v:(-v['development']['macro_recall'],v['recipe'],v['seed']))[0];put(out/'selection.json',selected)
        evaluation,labels,metadata=load(data,'evaluation')
        baseline_eval_flags,baseline_eval_context=baseline_flags(baseline,evaluation,metadata);baseline_result=metrics(baseline_eval_flags,baseline_eval_context,labels,metadata)
        state=json.loads((out/(selected['id']+'-state.json')).read_bytes());raw,context=candidate_scores(state,evaluation,baseline)
        flags=(context==1)&(raw>=selected['threshold']);context_names=np.asarray(['ROUTINE_CONTEXT','BEHAVIOR_REVIEW_CONTEXT','SERVICE_DEGRADATION_CONTEXT'])[context]
        result=metrics(flags,context_names,labels,metadata)
        controls_ok=all(n<=baseline_result['false_review_by_legitimate_control'].get(k,0) for k,n in result['false_review_by_legitimate_control'].items())
        benefit=result['true_review']>baseline_result['true_review']
        passed=result['false_review']<=baseline_result['false_review'] and result['operational_false_review']<=baseline_result['operational_false_review'] and result['operational_correct']>=baseline_result['operational_correct'] and min(result['recall_by_case'].values())>=.9 and controls_ok and benefit
        if hashlib.sha256(canonical(baseline.model._normal.to_state())).hexdigest()!=normal_state_hash:raise RuntimeError('Frozen baseline normal component changed')
        baseline.verify_identity()
        control_counts=Counter()
        with gzip.open(data/'controls.jsonl.gz','rt',encoding='utf-8') as stream:
            for row in map(json.loads,stream):
                if row['family']=='cold':
                    validate(row['snapshot'],require_ready=False)
                    if row['snapshot']['baseline_established']:raise RuntimeError('COLD source invented READY')
                elif row['status']!='UNDETERMINED' or row['snapshot']:raise RuntimeError('Missing coverage was padded')
                control_counts[row['family']]+=1
        if control_counts!={'cold':5000,'missing':5000}:raise RuntimeError('Control population differs')
        receipt={'status':'OFFLINE_PILOT_PASS' if passed else 'STOP_NO_IMPROVEMENT','scope':'PILOT_ONLY','evaluation_mode':'SHADOW','protocol_sha256':protocol_hash,
            'source_manifest_sha256':sha(data/'manifest.json'),'data_provenance':'CONTROLLED_CLOCK_LAB','source_transport':source['source_transport'],
            'baseline_manifest_sha256':baseline.manifest_sha256,'baseline':baseline_result,'candidate':result,'classifier_fits':4,'normal_fits':0,'evaluation_opened':True,
            'selected_state_sha256':selected['state_sha256'],'selected_trial':selected['id'],'threshold':selected['threshold'],'controls_undetermined':dict(control_counts),
            'candidate_normal_false_review_ci95':ci(result['false_review'],result['normal']),'baseline_normal_false_review_ci95':ci(baseline_result['false_review'],baseline_result['normal']),
            'maximum_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,'seconds':round(time.monotonic()-started,2),
            'automatic_enforcement':False,'strict_production_qualified':False}
        put(out/'offline-receipt.json',receipt);budget(data,out);print(json.dumps({'status':receipt['status'],'classifier_fits':4,'normal_fits':0,'seconds':receipt['seconds']}),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--data',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--fit',action='store_true');args=parser.parse_args();run(args.data,args.output,args.fit)
