#!/usr/bin/env python3
"""Fresh controlled-clock observations -> loopback HTTP -> real Java feature extractors.

This is an explicitly synthetic feature harness, not ELK evidence or a production qualification.
Full JWT/OTP/DB HTTP guards are verified separately by the integration/operational gates.
No prior training corpus, validation, holdout or model-fitting API is read here.
"""
import argparse
from collections import Counter
from datetime import datetime,timedelta,timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import select
import subprocess
import time
import urllib.request

QUOTAS={'train':(32000,6000,2000),'calibration':(12000,2400,600),'development':(8000,1500,500),'evaluation':(20000,3000,2000),'controls':(5000,5000,0)}
ANCHORS={'train':datetime(2026,8,3,tzinfo=timezone.utc),'calibration':datetime(2026,8,24,tzinfo=timezone.utc),'development':datetime(2026,9,7,tzinfo=timezone.utc),'evaluation':datetime(2026,9,28,tzinfo=timezone.utc),'controls':datetime(2026,10,12,tzinfo=timezone.utc)}
MAX_BYTES=4*1024**3

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def stamp(at):return at.isoformat().replace('+00:00','Z')
def allocated(root):return sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
def private_json(path,value):
    temporary=path.with_suffix(path.suffix+'.partial')
    with temporary.open('w') as out:os.chmod(temporary,0o600);json.dump(value,out,indent=2);out.flush();os.fsync(out.fileno())
    temporary.replace(path)

def kinds(split,seed):
    a,b,c=QUOTAS[split]
    rows=(['cold']*a+['missing']*b) if split=='controls' else ['routine']*a+['case3','case4','case5']*(b//3)+['operational']*c
    random.Random(seed).shuffle(rows);return rows

def frame(dataset,split,index,kind):
    rng=random.Random(digest([dataset,split,index,'execution']))
    episode='authlab-'+digest([dataset,split,index])[:40];account='lab-account-'+digest([dataset,split,index%20])[:24]
    at=ANCHORS[split]+timedelta(hours=index%24,seconds=(index//24)%3600)
    start=at.replace(minute=at.minute//15*15,second=0,microsecond=0)
    ip='172.25.1.'+str(10+index%180);novel='172.25.2.'+str(10+index%180);ua='CHROMIUM';other='FIREFOX'
    session=digest([dataset,split,index,'session']);issued=at-timedelta(seconds=rng.randint(180,900));serial=0
    context=[]
    def event(type,action,outcome,when,*,actor=account,target=account,source=ip,agent=ua,sess=session,operation=None,challenge=None,status=None,endpoint=None):
        nonlocal serial
        serial+=1
        value={'event_id':'event-'+digest([episode,serial])[:40],'actor_user_id':actor,'target_user_id':target,'event_type':type,'action':action,'outcome':outcome,'event_timestamp':stamp(when),'telemetry_contract_version':4 if type!='HTTP_REQUEST' else 3,'source_ip':source,'user_agent_family':agent,'route_group':operation or ('profile' if endpoint=='PROFILE_READ' else 'products' if type=='HTTP_REQUEST' else 'auth' if type=='AUTH' else 'account')}
        if actor is not None and sess is not None:value.update(session_pseudonym=sess,session_issued_at=stamp(issued))
        if type=='HTTP_REQUEST':value.update(http_method='GET',http_status=status or 200,endpoint_category=endpoint or 'PRODUCT_LIST')
        if challenge:value['challenge_reference']=challenge
        return value
    operation='PASSWORD_CHANGE' if index%2==0 else 'EMAIL_CHANGE'
    current_ip,current_ua=ip,ua
    recipe=rng.choice(['browse','forgot_otp','mobile','two_devices','reset_return']) if kind in ('routine','cold','missing') else kind
    if kind=='case3':current_ip,current_ua=novel,other
    elif kind=='case4':current_ip,current_ua=novel,other
    if recipe=='mobile':current_ip=novel
    if kind=='case3':
        for i in range(rng.randint(2,8)):context.append(event('AUTH','LOGIN','FAILURE',issued-timedelta(seconds=50+i*15),actor=None,source=current_ip,agent=current_ua,sess=None))
        if rng.random()<.7:context.append(event('DOMAIN_ACTION','PASSWORD_RESET','SUCCESS',issued-timedelta(seconds=180),actor=None,source=current_ip,agent=current_ua,sess=None))
    if recipe=='reset_return':context.append(event('DOMAIN_ACTION','PASSWORD_RESET','SUCCESS',issued-timedelta(seconds=180),actor=None,sess=None))
    login_ip,login_ua=(current_ip,current_ua) if kind=='case3' else (ip,ua)
    if kind!='missing':context.append(event('AUTH','LOGIN','SUCCESS',issued,source=login_ip,agent=login_ua))
    count=rng.randint(40,80) if kind=='operational' else rng.randint(3,24)
    second=digest([episode,'second-session'])
    for i in range(count):
        when=issued+timedelta(seconds=(i+1)*(at-issued).total_seconds()/(count+2))
        alternate=(kind=='case4' or recipe=='two_devices') and i%2==1
        source=novel if alternate else current_ip;agent=other if alternate else current_ua
        status=503 if kind=='operational' and i%3!=0 else 200
        context.append(event('HTTP_REQUEST','READ','SUCCESS' if status<400 else 'FAILURE',when,source=source,agent=agent,sess=second if alternate else session,status=status,endpoint='PROFILE_READ' if i%4==0 else 'PRODUCT_LIST'))
    if kind=='case5' or recipe=='forgot_otp':
        wrong=rng.randint(2,7) if kind=='case5' else rng.randint(1,4)
        for i in range(wrong):
            challenge='challenge-'+digest([episode,'challenge',i%3 if kind=='case5' else 0])[:24]
            when=at-timedelta(seconds=40+i*5)
            context.append(event('AUTH_INVESTIGATION','OTP_CHECK','FAILURE',when,operation=operation,challenge=challenge))
            if kind=='case5':context.append(event('AUTH_INVESTIGATION','SENSITIVE_REJECTED','FAILURE',when+timedelta(seconds=1),operation=operation,challenge=challenge))
        if recipe=='forgot_otp':context.append(event('DOMAIN_ACTION',operation,'SUCCESS',at-timedelta(seconds=10)))
        if kind=='case5':
            for i in range(rng.randint(3,9)):context.append(event('SENSITIVE_ACTION_ATTEMPT',operation,'ATTEMPT',at-timedelta(seconds=80+i*3),operation=operation))
    context.sort(key=lambda value:(value['event_timestamp'],value['event_id']))
    attempt=event('SENSITIVE_ACTION_ATTEMPT',operation,'ATTEMPT',at,source=current_ip,agent=current_ua,operation=operation)
    histories=[]
    if kind!='cold':
        for offset in range(30,0,-1):
            window=start-timedelta(minutes=15*offset);history_session=digest([dataset,account,stamp(window),'history-session'])
            observations=[]
            for i in range(5+rng.randrange(6)):
                observations.append({'event_type':'HTTP_REQUEST','action':'READ','outcome':'SUCCESS','event_timestamp':stamp(window+timedelta(seconds=30+i*50)),'http_method':'GET','http_status':200,'route_group':'products','source_ip':ip,'user_agent_family':ua,'endpoint_category':'PRODUCT_LIST','session_pseudonym':history_session,'session_issued_at':stamp(window-timedelta(seconds=20))})
            histories.append({'frame_id':'history-'+digest([account,stamp(window)])[:40],'account_id':account,'day':31-offset,'cohort':'DEVELOPMENT','window_start':stamp(window),'demo_label':'NORMAL','family':'normal','events':observations,'telemetry_contract_version':3})
    return {'frame_id':episode,'attempt':attempt,'context':context,'baseline_frames':histories},{'episode_id':episode,'account_group':account,'session_group':session,'context_label':2 if kind=='operational' else 1 if kind.startswith('case') else 0,'family':kind,'recipe':recipe,'split':split}

def capture(output,classpath,smoke):
    output.mkdir(mode=0o700,parents=True,exist_ok=True)
    if (output/'manifest.json').exists():raise RuntimeError('Capture already exists; do not overwrite a sealed source')
    dataset='auth-context-'+secrets.token_hex(12);token=secrets.token_hex(24);token_file=output/'capture-token.private'
    token_file.write_text(token);token_file.chmod(0o600)
    manifest={'format':'AUTH_CONTEXT_LAB_SOURCE_V1','status':'CAPTURING','dataset_id':dataset,'data_provenance':'CONTROLLED_CLOCK_LAB','source_transport':'LOOPBACK_FEATURE_HARNESS','backend_auth_guard_validation':'SEPARATE_REAL_HTTP_MYSQL_REDIS_GATE_REQUIRED','labels_basis':'PREDECLARED_OBSERVABLE_CONTEXT_SCENARIO; NOT_ACTOR_OWNERSHIP_OR_RULE_OUTPUT','generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'feature_schema_version':7,'maximum_snapshots':100000,'strict_production_qualified':False,'splits':{}}
    private_json(output/'manifest.json',manifest);started=time.monotonic();total=0
    with (output/'java-capture.private.log').open('w') as error:
        process=subprocess.Popen(['java','-Xmx384m','-XX:ActiveProcessorCount=2','-cp',classpath,'com.flarefitness.backend.ops.AuthShadowLabCaptureServer',str(token_file)],stdout=subprocess.PIPE,stderr=error,text=True)
        try:
            if not select.select([process.stdout],[],[],20)[0]:raise RuntimeError('Java feature producer startup deadline')
            ready=json.loads(process.stdout.readline());url='http://127.0.0.1:'+str(ready['port'])+'/capture'
            for split in QUOTAS:
                labels=kinds(split,int(digest([dataset,split,'ordering'])[:16],16));labels=labels[:smoke] if smoke else labels
                numeric=output/(split+'.jsonl.gz');rawfile=output/(split+'-raw.jsonl.gz');counts=Counter();accounts=set();sessions=set()
                with gzip.open(numeric,'xt',encoding='utf-8') as rows,gzip.open(rawfile,'xt',encoding='utf-8') as raw:
                    numeric.chmod(0o600);rawfile.chmod(0o600)
                    for index,kind in enumerate(labels):
                        if time.monotonic()-started>5400:raise RuntimeError('Capture wall-clock budget exhausted')
                        if total%200==0:
                            if allocated(output.parent)>MAX_BYTES:raise RuntimeError('Pilot4GiB artifact quota exceeded')
                            available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
                            if available<3*1024**3:raise RuntimeError('STOP_RESOURCE: preserve3GiB host memory reserve')
                        source,metadata=frame(dataset,split,index,kind);body=json.dumps(source,separators=(',',':')).encode()
                        request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-Lab-Token':token},method='POST')
                        try:
                            with urllib.request.urlopen(request,timeout=15) as response:answer=json.loads(response.read(65536))
                        except Exception as refused:raise RuntimeError('Java capture failed at '+split+':'+str(index)) from refused
                        if answer['before_current_outcome'] is not True or answer['producer']!='REAL_JAVA_EXTRACTOR_LOOPBACK_HARNESS':raise RuntimeError('Producer contract differs')
                        expected='UNDETERMINED' if kind=='missing' else 'OBSERVED'
                        if answer['status']!=expected:raise RuntimeError('Observed coverage differs for '+kind+': '+answer.get('reason',''))
                        row=metadata|{'status':answer['status'],'snapshot':answer['snapshot'],'reason':answer['reason'],'source_event_id':answer['source_event_id'],'source_sha256':hashlib.sha256(body).hexdigest()}
                        rows.write(json.dumps(row,separators=(',',':'))+'\n');raw.write(json.dumps({'episode_id':metadata['episode_id'],'raw':source},separators=(',',':'))+'\n')
                        counts[kind]+=1;accounts.add(metadata['account_group']);sessions.add(metadata['session_group']);total+=1
                        if total%1000==0:private_json(output/'capture-progress.private.json',{'status':'CAPTURING','records':total,'split':split,'seconds':round(time.monotonic()-started,1)})
                manifest['splits'][split]={'records':len(labels),'counts':dict(counts),'file':numeric.name,'sha256':hashlib.sha256(numeric.read_bytes()).hexdigest(),'raw_file':rawfile.name,'raw_sha256':hashlib.sha256(rawfile.read_bytes()).hexdigest(),'account_groups':sorted(accounts),'session_groups_sha256':digest(sorted(sessions))}
                private_json(output/'manifest.json',manifest)
            manifest.update(status='SMOKE_ONLY' if smoke else 'SOURCE_CAPTURE_COMPLETE',records=total,seconds=round(time.monotonic()-started,1),artifact_bytes=allocated(output))
            private_json(output/'manifest.json',manifest);print(json.dumps({'status':manifest['status'],'records':total,'seconds':manifest['seconds'],'artifact_mib':round(manifest['artifact_bytes']/1024**2,2)}))
        except Exception as failure:
            manifest.update(status='SOURCE_CAPTURE_FAILED',records=total,reason=type(failure).__name__,fits=0)
            private_json(output/'manifest.json',manifest)
            raise
        finally:
            process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
            token_file.unlink(missing_ok=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--java-classpath',required=True);parser.add_argument('--smoke-per-split',type=int,default=0);args=parser.parse_args()
    if args.smoke_per_split and not 1<=args.smoke_per_split<=100:parser.error('Smoke1–100 per split')
    capture(args.output,args.java_classpath,args.smoke_per_split)
