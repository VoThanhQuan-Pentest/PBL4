#!/usr/bin/env python3
"""Upgrade only the existing local app/worker after immutable image/clone receipts.

Preserves database/Redis/ELK volumes, current signature mode, fixed baseline model,
OTP/mail/JWT configuration and protected lecturer cases. No seed, restore, prune,
training, watermark changes or duplicate log writers.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'observability/scripts'/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
ops=module('workspace_release_ops','siem-upgrade-local.py');compose=module('workspace_release_compose','siem-validate-compose.py')

def save(path,value):
    pending=path.with_suffix('.partial')
    with pending.open('w') as out:os.chmod(pending,0o600);json.dump(value,out,indent=2);out.flush();os.fsync(out.fileno())
    pending.replace(path)

def healthy(name,seconds=240):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        current=ops.inspect(name)['State']
        if current['Running'] and current.get('Health',{}).get('Status','healthy')=='healthy':return
        time.sleep(2)
    raise RuntimeError('Service health deadline: '+name)

def execute(folder,args,env):
    with (folder/'workspace-deploy.private.log').open('ab') as log:subprocess.run(args,env=env,stdout=log,stderr=log,check=True,timeout=240)

def main(folder,apply):
    folder=folder.resolve()
    if not folder.is_relative_to((ROOT/'observability/runtime/private-backups').resolve()):raise ValueError('Private release directory required')
    with (folder/'workspace-release.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        candidate=json.loads((folder/'candidate-images.private.json').read_text());backup=json.loads((folder/'backup.receipt.private.json').read_text())
        images=candidate['images'];clone_path=folder/('clone-'+images['app']['id'].split(':')[1][:12]+'.receipt.private.json');clone=json.loads(clone_path.read_text())
        if clone['image_id']!=images['app']['id'] or clone['schema_version']!=42 or clone['backup_sha256']!=backup['sha256'] or clone['migration_v42_sha256']!=ops.digest((ROOT/'backend/src/main/resources/db/migration/V42__add_auth_investigation_and_shadow_assessments.sql').read_bytes()):raise RuntimeError('Exact image/backup/V42 rehearsal required')
        for image in images.values():
            if json.loads(ops.run(['docker','image','inspect',image['tag']]))[0]['Id']!=image['id']:raise RuntimeError('Release tag changed')
        current=ops.fingerprint()
        if current!=backup['protected']:raise RuntimeError('Protected live state changed since backup; reconcile with a fresh backup/clone, never overwrite it')
        admission=ops.admission()
        print(json.dumps({'phase':'WORKSPACE_RELEASE_ADMISSION_PASS','free_gib':round(admission['filesystem_available_bytes']/1024**3,2),'apply':apply}),flush=True)
        if not apply:return
        receipt=folder/'workspace-deployed.receipt.private.json'
        if receipt.exists():raise RuntimeError('Deployment already committed; use verification, not replay')
        old_app=ops.inspect(ops.APP);old_worker=ops.inspect('flare-otp-local-postlogin-worker-1')
        database_id=ops.inspect(ops.DB)['Id'];redis_id=ops.inspect('flare-otp-local-redis-1')['Id']
        nginx=ops.inspect('flare-otp-local-nginx-1')['Config']['Image'];gateway=ops.inspect('flare-otp-local-gateway-1')['Config']['Image']
        args,env,existing=compose.context(images['app']['tag'],nginx,gateway)
        env['FLARE_POSTLOGIN_WORKER_IMAGE']=images['worker']['tag'];env['FLARE_SIEM_RECURRENCE_MODE']=existing['SIEM_PREVENTION_RECURRENCE_MODE']
        env['FLARE_SIEM_PROTECTED_IPS']=existing['SIEM_PREVENTION_PROTECTED_IPS']
        key=ROOT/'.secrets/siem-auth/fingerprint.key';key.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if key.is_symlink() or key.resolve()!=key.absolute():raise RuntimeError('Refuse symlinked fingerprint key path')
        if not key.exists():
            with key.open('xb') as out:os.chmod(key,0o640);out.write(secrets.token_bytes(32));out.flush();os.fsync(out.fileno())
        if key.stat().st_size!=32 or key.stat().st_mode&0o027:raise RuntimeError('Private32-byte fingerprint key required')
        override=folder/'workspace-override.private.json'
        save(override,{'services':{'app':{'environment':{'SIEM_AUTH_FINGERPRINT_KEY_FILE':'/run/siem-auth/fingerprint.key','SIEM_AUTH_SHADOW_ENABLED':'false'},'volumes':[{'type':'bind','source':str(key),'target':'/run/siem-auth/fingerprint.key','read_only':True}]},'postlogin-worker':{'image':images['worker']['tag']}}})
        args=args+['-f',str(override)]
        config=json.loads(subprocess.check_output(args+['config','--format','json'],env=env))
        app_env=config['services']['app']['environment']
        for key_name,value in existing.items():
            if key_name.startswith(('APP_MAIL','SPRING_MAIL','APP_SENSITIVE_ACTION','APP_JWT','SIEM_POSTLOGIN')) and app_env.get(key_name,'')!=value:raise RuntimeError('Existing protected configuration changed: '+key_name)
        if app_env['SIEM_PREVENTION_RECURRENCE_MODE']!=existing['SIEM_PREVENTION_RECURRENCE_MODE']:raise RuntimeError('Existing signature mode changed')
        checkpoint=folder/'workspace-deploy.checkpoint.private.json'
        def phase(name):save(checkpoint,{'phase':name,'status':'RUNNING','updated_at':time.time(),'app_image':images['app']['id'],'worker_image':images['worker']['id'],'database_id':database_id,'redis_id':redis_id});print(json.dumps({'phase':name}),flush=True)
        phase('REPLACE_READ_ONLY_WORKER_BASELINE_PIN_UNCHANGED')
        execute(folder,args+['up','-d','--no-build','--pull','never','--no-deps','postlogin-worker'],env);healthy('flare-otp-local-postlogin-worker-1')
        phase('MIGRATE_AND_REPLACE_MAIN_APPLICATION')
        execute(folder,args+['up','-d','--no-build','--pull','never','--no-deps','app'],env);healthy(ops.APP)
        execute(folder,args+['restart','nginx'],env)
        phase('VERIFY_PRIMARY_TOPOLOGY_AND_PROTECTED_DATA')
        deadline=time.monotonic()+30
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:8089/api/health',timeout=5) as response:
                    if response.status==200:break
            except OSError:pass
            if time.monotonic()>deadline:raise RuntimeError('Recovery front door not healthy')
            time.sleep(.5)
        if ops.inspect(ops.DB)['Id']!=database_id or ops.inspect('flare-otp-local-redis-1')['Id']!=redis_id:raise RuntimeError('Primary database/Redis replaced unexpectedly')
        if ops.fingerprint()!=backup['protected']:raise RuntimeError('Protected state changed; no destructive rollback attempted')
        version=ops.sql('SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1;').decode().strip()
        if version!='42':raise RuntimeError('Primary migration not V42')
        if ops.inspect(ops.APP)['Image']!=images['app']['id'] or ops.inspect('flare-otp-local-postlogin-worker-1')['Image']!=images['worker']['id']:raise RuntimeError('Deployed image identity differs')
        ops.run(['docker','exec',ops.APP,'sh','-ceu','test -r /run/siem-auth/fingerprint.key && test $(wc -c < /run/siem-auth/fingerprint.key) -eq 32'])
        # Explicitly audited local operator transition. Application policy writes remain Admin-only.
        mode='OBSERVE';reason='Authorized local workspace release; observe auth correlations before alert acceptance.'
        row=ops.sql('SELECT mode,version FROM siem_auth_correlation_policy WHERE id=1;').decode().strip().split('\t')
        old_mode,version=row[0],int(row[1]);request=str(uuid.uuid4());digest=hashlib.sha256((mode+'|'+str(version)+'|'+reason).encode()).hexdigest()
        if old_mode=='OFF':
            sql="START TRANSACTION; SELECT id FROM siem_auth_correlation_policy WHERE id=1 FOR UPDATE; UPDATE siem_auth_correlation_policy SET mode='OBSERVE',version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=1 AND version="+str(version)+"; SET @workspace_changed=ROW_COUNT(); INSERT INTO siem_auth_policy_requests(request_id,actor_user_id,request_hash,reason,mode,resulting_version,created_at) SELECT '"+request+"','LOCAL_OPERATOR','"+digest+"','"+reason+"','OBSERVE',"+str(version+1)+",UTC_TIMESTAMP(6) WHERE @workspace_changed=1; COMMIT;"
            ops.sql(sql)
        actual_mode=ops.sql('SELECT mode FROM siem_auth_correlation_policy WHERE id=1;').decode().strip()
        if actual_mode!='OBSERVE':raise RuntimeError('Auth policy changed externally; no overwrite performed')
        value={'status':'DEPLOYED_AUTH_OBSERVE_SHADOW_OFF','images':images,'schema_version':42,'protected':ops.fingerprint(),'signature_mode':existing['SIEM_PREVENTION_RECURRENCE_MODE'],'model_baseline_unchanged':True,'candidate_mode':'OFF','database_id':database_id,'redis_id':redis_id,'auth_policy_actor':'LOCAL_OPERATOR','new_model_fits':0,'previous_app_image':old_app['Image'],'previous_worker_image':old_worker['Image']}
        ops.publish(folder,'workspace-deployed',value);save(checkpoint,{'phase':'DEPLOYED_AUTH_OBSERVE_SHADOW_OFF','status':'COMMITTED','updated_at':time.time()});print(json.dumps({'status':value['status'],'schema_version':42,'signature_mode':value['signature_mode']}),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--apply',action='store_true');a=p.parse_args();main(a.output,a.apply)
