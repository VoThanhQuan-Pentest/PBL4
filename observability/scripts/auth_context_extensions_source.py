#!/usr/bin/env python3
"""New, sealed READY/COLD corpora using the existing isolated Java extractor."""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import time
import urllib.request
import urllib.error

import auth_context_research_v2 as legacy
from auth_context_research_runner import WORKER_IMAGE,PRODUCER_IMAGE

QUOTAS=legacy.QUOTAS
ANCHORS={s:datetime(2026,7,1,tzinfo=timezone.utc)+timedelta(days=21*i) for i,s in enumerate(QUOTAS)}


def protocol(cohort,classpath,smoke=False):
    code=legacy.ROOT/'ueba-worker/app'
    return {'format':'AUTH_EXTENSIONS_SOURCE_V1','seed':20261028,'cohort':cohort,'smoke_only':bool(smoke),
        'provenance':'CONTROLLED_CLOCK_LAB','quotas':QUOTAS,'feature_schema_version':7,
        'model_width':81 if cohort=='READY' else 42,'normal_recipes':legacy.KINDS,
        'class_names':['ROUTINE_CONTEXT','BEHAVIOR_REVIEW_CONTEXT','SERVICE_DEGRADATION_CONTEXT'],
        'recipes':[{'name':'A','max_iter':100,'max_leaf_nodes':15},{'name':'B','max_iter':200,'max_leaf_nodes':31}],
        'seeds':[42,43],'max_ready_fits':4,'max_cold_fits':4,'max_calibrator_fits':3,
        'classifier_total_cap':8,'cold_false_positive_cap':0,
        'expected_worker_image':WORKER_IMAGE,'expected_producer_image':PRODUCER_IMAGE,
        'anchors':{s:legacy.source.stamp(t) for s,t in ANCHORS.items()},
        'variants':'SINGLE_ACCOUNT_EPISODE_CURRENT_WINDOW_CONTEXT_HISTORY_COHERENT_V1',
        'classpath':legacy.classpath_fingerprint(classpath),'generator_sha256':legacy.sha(Path(__file__)),
        'adapter_sha256':legacy.sha(Path(legacy.__file__)),
        'code_sha256':{p.name:legacy.sha(p) for p in sorted([*code.glob('auth_extensions_*.py'),code/'auth_shadow_research.py'])}}


def entries(cohort,split):
    if split=='controls':
        values=[('cold' if cohort=='READY' else 'ready','control')]*5000+[('missing','control')]*5000
    else:
        normal,review,ops=QUOTAS[split]
        values=[('routine',legacy.KINDS[i%8]) for i in range(normal)]
        values += [(('case3','case4','case5')[i%3],('case3','case4','case5')[i%3]) for i in range(review)]
        values += [('operational','operational')]*ops
    random.Random(legacy.source.digest([20261028,cohort,split,'order'])).shuffle(values)
    return values


def stamp(at):return at.isoformat().replace('+00:00','Z')
def at(value):return datetime.fromisoformat(value.replace('Z','+00:00'))


def frame(cohort,split,index,kind,recipe,stratum,smoke=False):
    # The legacy adapter's mutable seed is scoped to this one-cohort process.
    legacy.SEED=f'20261028-{cohort}'+('-smoke' if smoke else '')
    source_kind='routine' if kind in ('cold','ready') else kind
    source_recipe='browse' if recipe=='control' else recipe
    raw,meta=legacy.frame(split,index,source_kind,source_recipe)
    rng=random.Random(legacy.source.digest([20261028,cohort,split,index,'variant']))
    account='lab-account-'+legacy.source.digest([20261028,cohort,split,index,'actor',bool(smoke)])[:24]
    raw=legacy.replace_account(raw,meta['account_group'],account);meta['account_group']=account
    old_at=at(raw['attempt']['event_timestamp']);old_issued=at(raw['attempt']['session_issued_at'])
    start=ANCHORS[split]+timedelta(days=index%3,hours=(index//3)%24)
    target=start+timedelta(minutes=14,seconds=45);issued=start+timedelta(seconds=rng.randint(240,720))
    for event in raw['context']:
        point=at(event['event_timestamp'])
        if point<old_issued:new=issued+(point-old_issued)
        else:new=issued+(target-issued)*((point-old_issued).total_seconds()/(old_at-old_issued).total_seconds())
        event['event_timestamp']=stamp(new)
        if 'session_issued_at' in event:event['session_issued_at']=stamp(issued)
    raw['attempt']['event_timestamp']=stamp(target);raw['attempt']['session_issued_at']=stamp(issued)
    if kind=='case4':
        # Observable repeated sources within one session, rather than actor intent.
        http=[e for e in raw['context'] if e['event_type']=='HTTP_REQUEST']
        original=raw['attempt']['session_pseudonym']
        for i,e in enumerate(http):
            e['session_pseudonym']=original;e['source_ip']='172.28.0.'+str(10+i%4)
    if kind=='routine' and split!='controls':
        http=[e for e in raw['context'] if e['event_type']=='HTTP_REQUEST']
        # Held-out composition of benign source/browser changes; labels remain presealed.
        if recipe in ('browser_update','mobile') and index%2:
            for e in http:
                e['source_ip']='172.29.0.8';e['user_agent_family']='FIREFOX'
            raw['attempt'].update(source_ip='172.29.0.8',user_agent_family='FIREFOX')
        if recipe=='transient_4xx':
            for i,e in enumerate(http):
                e['http_status']=404 if i%(4 if split=='development' else 5)==0 else 200
                e['outcome']='FAILURE' if e['http_status']>=400 else 'SUCCESS'
    cold=(cohort=='COLD' and kind!='ready') or kind=='cold'
    history_count=(0 if stratum==0 else rng.randint(1,9) if stratum==1 else rng.randint(10,29)) if cold else (30 if index%2 else 48)
    template=raw['baseline_frames'][0] if raw['baseline_frames'] else None
    if template is None:
        template=legacy.source.frame('history-template','train',0,'routine')[0]['baseline_frames'][0]
    histories=[]
    for offset in range(history_count,0,-1):
        window=start-timedelta(minutes=15*offset);item=deepcopy(template)
        item.update(frame_id='history-'+legacy.source.digest([account,stamp(window)])[:40],
            account_id=account,window_start=stamp(window),day=100-offset)
        session=legacy.source.digest([account,stamp(window),'history-session'])
        observations=[]
        for i in range(5+rng.randrange(6)):
            e=deepcopy(template['events'][i%len(template['events'])])
            e.update(event_timestamp=stamp(window+timedelta(seconds=30+i*50)),session_pseudonym=session,
                     session_issued_at=stamp(window-timedelta(seconds=20)))
            observations.append(e)
        item['events']=observations;histories.append(item)
    raw['baseline_frames']=histories
    raw['context'].sort(key=lambda e:(e['event_timestamp'],e['event_id']))
    meta.update(cohort=cohort,family=kind,recipe=source_recipe,history_stratum='0' if history_count==0 else '1-9' if history_count<10 else '10-29' if history_count<30 else 'READY')
    if kind in ('cold','ready'):meta['context_label']=0
    return raw,meta


def capture(cohort,output,classpath,smoke=0):
    output=legacy.safe_output(output);legacy.budget(output,admission=True)
    proto=protocol(cohort,classpath,bool(smoke));output.mkdir(mode=0o700);legacy.put(output/'protocol.json',proto)
    manifest={'format':'AUTH_EXTENSIONS_DATA_V1','cohort':cohort,'status':'CAPTURING',
              'records':0,'data_provenance':'CONTROLLED_CLOCK_LAB','splits':{},
              'protocol_sha256':legacy.sha(output/'protocol.json')}
    process=log=token_path=None;started=time.monotonic();last_check=0.;total=0
    episodes=set();sessions=set();accounts=set()
    try:
        process,log,token_path,token,url=legacy.producer(classpath,output)
        for split in QUOTAS:
            items=entries(cohort,split);items=items[:smoke] if smoke else items
            numeric=output/(split+'.jsonl.gz');rawpath=output/(split+'-raw.jsonl.gz')
            counts=Counter();groups=[];strata=Counter();class_ordinal=Counter()
            with gzip.open(numeric,'xt',encoding='utf-8') as rows,gzip.open(rawpath,'xt',encoding='utf-8') as raws:
                numeric.chmod(0o600);rawpath.chmod(0o600)
                for index,(kind,recipe) in enumerate(items):
                    now=time.monotonic()
                    if now-started>5400:raise RuntimeError('capture deadline')
                    if now-last_check>=2:legacy.budget(output);last_check=now
                    stratum=class_ordinal[kind]%3;class_ordinal[kind]+=1
                    raw,meta=frame(cohort,split,index,kind,recipe,stratum,bool(smoke))
                    if meta['episode_id'] in episodes or meta['session_group'] in sessions or meta['account_group'] in accounts:
                        raise ValueError('source identities overlap')
                    episodes.add(meta['episode_id']);sessions.add(meta['session_group']);accounts.add(meta['account_group'])
                    body=json.dumps(raw,separators=(',',':'),allow_nan=False).encode()
                    request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-Lab-Token':token},method='POST')
                    with urllib.request.urlopen(request,timeout=15) as response:answer=json.loads(response.read(65536))
                    if answer.get('before_current_outcome') is not True:raise ValueError('future outcome leakage')
                    expected='UNDETERMINED' if kind=='missing' else 'OBSERVED'
                    if answer.get('status')!=expected:raise ValueError('unexpected coverage '+str(answer))
                    if kind!='missing':
                        packet=answer['snapshot'];legacy.validate(packet,require_ready=False)
                        is_cold=meta['history_stratum']!='READY'
                        if packet['baseline_established']==is_cold:raise ValueError('history cohort differs')
                        if packet['snapshot_id']!=meta['episode_id']:raise ValueError('snapshot id differs')
                    elif answer.get('snapshot'):raise ValueError('missing coverage padded')
                    row=meta|{'status':answer['status'],'snapshot':answer['snapshot'],'reason':answer['reason'],
                              'source_sha256':hashlib.sha256(body).hexdigest()}
                    rows.write(json.dumps(row,separators=(',',':'))+'\n')
                    raws.write(json.dumps({'episode_id':meta['episode_id'],'raw':raw},separators=(',',':'))+'\n')
                    counts[kind]+=1;groups.append(meta['account_group']);strata[meta['history_stratum']]+=1;total+=1
                    if total%1000==0:print(json.dumps({'phase':'CAPTURE','cohort':cohort,'records':total}),flush=True)
            manifest['splits'][split]={'records':len(items),'counts':dict(counts),'strata':dict(strata),
                'file':numeric.name,'raw_file':rawpath.name,'sha256':legacy.sha(numeric),
                'raw_sha256':legacy.sha(rawpath),'account_groups':groups}
        manifest.update(status='SMOKE_ONLY' if smoke else 'SOURCE_CAPTURE_COMPLETE',records=total,
                        seconds=round(time.monotonic()-started,2))
        legacy.put(output/'manifest.json',manifest)
    finally:
        if process:
            process.terminate()
            try:process.wait(timeout=15)
            except Exception:process.kill();process.wait(timeout=10)
            log.close();token_path.unlink(missing_ok=True)


def parity(cohort,data,classpath,smoke=0):
    manifest=json.loads((data/'manifest.json').read_bytes());stored=json.loads((data/'protocol.json').read_bytes())
    expected=smoke*5 if smoke else 100000
    if manifest['status']!=('SMOKE_ONLY' if smoke else 'SOURCE_CAPTURE_COMPLETE') or manifest['records']!=expected:
        raise ValueError('complete sealed source required')
    if not legacy.same_protocol(protocol(cohort,classpath,bool(smoke)),stored):raise ValueError('source protocol changed')
    if legacy.sha(data/'protocol.json')!=manifest['protocol_sha256']:raise ValueError('protocol checksum differs')
    legacy.budget(data,admission=True);process=log=token_path=None;started=time.monotonic();count=0
    try:
        process,log,token_path,token,url=legacy.producer(classpath,data)
        for split,item in manifest['splits'].items():
            for name,key in ((item['file'],'sha256'),(item['raw_file'],'raw_sha256')):
                if data.joinpath(name).is_symlink() or legacy.sha(data/name)!=item[key]:raise ValueError('source checksum differs')
            with gzip.open(data/item['file'],'rt') as rows,gzip.open(data/item['raw_file'],'rt') as raws:
                for line in rows:
                    row=json.loads(line);raw=json.loads(next(raws))
                    if row['episode_id']!=raw['episode_id']:raise ValueError('raw reference differs')
                    body=json.dumps(raw['raw'],separators=(',',':'),allow_nan=False).encode()
                    request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-Lab-Token':token},method='POST')
                    with urllib.request.urlopen(request,timeout=15) as response:answer=json.loads(response.read(65536))
                    if answer['snapshot']!=row['snapshot'] or answer['status']!=row['status']:raise ValueError('Java parity differs')
                    count+=1
                    if count%1000==0:legacy.budget(data);print(json.dumps({'phase':'PARITY','cohort':cohort,'records':count}),flush=True)
                    if time.monotonic()-started>5400:raise RuntimeError('parity deadline')
                if raws.read(1):raise ValueError('extra raw rows')
        if count!=expected:raise ValueError('incomplete parity')
        legacy.put(data/'producer-parity.json',{'status':'SMOKE_PARITY_PASS' if smoke else 'HARNESS_REEXPORT_PARITY_PASS','records':count,
             'manifest_sha256':legacy.sha(data/'manifest.json'),'protocol_sha256':legacy.sha(data/'protocol.json'),
             'seconds':round(time.monotonic()-started,2),'cohort':cohort})
    finally:
        if process:
            process.terminate()
            try:process.wait(timeout=15)
            except Exception:process.kill();process.wait(timeout=10)
            log.close();token_path.unlink(missing_ok=True)


def fault(cohort,data,classpath):
    manifest=json.loads((data/'manifest.json').read_bytes())
    if manifest.get('status')!='SMOKE_ONLY':raise ValueError('fault tests require smoke source')
    selected=None
    with gzip.open(data/'train-raw.jsonl.gz','rt') as f:
        selected=json.loads(next(f))['raw']
    process=log=token_path=None
    try:
        process,log,token_path,token,url=legacy.producer(classpath,data)
        def send(raw):
            body=json.dumps(raw,separators=(',',':')).encode()
            req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-Lab-Token':token},method='POST')
            try:
                with urllib.request.urlopen(req,timeout=15) as response:return json.loads(response.read(65536))
            except urllib.error.HTTPError as error:
                if error.code!=400:raise
                return {'status':'REFUSED','snapshot':None}
        original=send(selected)
        if original['status']!='OBSERVED':raise ValueError('covered fault fixture required')
        cases={}
        shuffled=deepcopy(selected);random.Random(20261028).shuffle(shuffled['context'])
        answer=send(shuffled)
        cases['event_order']={'pass':answer['status']=='REFUSED' or answer['snapshot']==original['snapshot']}
        duplicate=deepcopy(selected);event=next(e for e in duplicate['context'] if e['event_type']=='HTTP_REQUEST')
        duplicate['context'].append(deepcopy(event));answer=send(duplicate)
        cases['duplicate_event']={'pass':answer['status']=='REFUSED' or answer['snapshot']==original['snapshot'],
            'finding':'DUPLICATE_EVENT_MULTIPLICATION' if answer['status']!='REFUSED' and answer['snapshot']!=original['snapshot'] else None}
        future=deepcopy(selected);event=deepcopy(future['context'][0]);event['event_timestamp']=future['attempt']['event_timestamp'];future['context'].append(event)
        cases['current_outcome_excluded']={'pass':send(future)['status']=='REFUSED'}
        missing=deepcopy(selected);missing['context']=[e for e in missing['context'] if not (e['action']=='LOGIN' and e['outcome']=='SUCCESS')]
        cases['missing_login']={'pass':send(missing)['status']=='UNDETERMINED'}
        oversized=deepcopy(selected);oversized['oversized']='x'*(2*1024**2)
        cases['bounded_payload']={'pass':send(oversized)['status']=='REFUSED'}
        result={'status':'PRODUCER_FAULT_PASS' if all(x['pass'] for x in cases.values()) else 'PRODUCER_FINDING',
                'cohort':cohort,'cases':cases,'scope':'OFFLINE_HARNESS','new_fits':0,
                'runtime_integration_blocked':not all(x['pass'] for x in cases.values())}
        legacy.put(data.parent/('producer-fault-'+cohort.lower()+'.json'),result)
    finally:
        if process:
            process.terminate()
            try:process.wait(timeout=15)
            except Exception:process.kill();process.wait(timeout=10)
            log.close();token_path.unlink(missing_ok=True)


def main():
    if os.environ.get('AUTH_RESEARCH_SUPERVISED')!='1':raise SystemExit('bounded supervisor required')
    p=argparse.ArgumentParser();p.add_argument('stage',choices=('capture','parity','fault'));p.add_argument('--cohort',choices=('READY','COLD'),required=True)
    p.add_argument('--data',type=Path,required=True);p.add_argument('--java-classpath',required=True);p.add_argument('--smoke',type=int,default=0)
    a=p.parse_args()
    if not 0<=a.smoke<=100:raise ValueError('smoke limit')
    if a.stage=='capture':capture(a.cohort,a.data,a.java_classpath,a.smoke)
    elif a.stage=='parity':parity(a.cohort,a.data,a.java_classpath,a.smoke)
    else:fault(a.cohort,a.data,a.java_classpath)


if __name__=='__main__':main()
