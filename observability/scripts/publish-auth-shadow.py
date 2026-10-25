#!/usr/bin/env python3
"""Publish only the qualified numeric candidate to read-only SHADOW; never changes baseline enforcement."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]

def module(name,file):
    s=importlib.util.spec_from_file_location(name,ROOT/'observability/scripts'/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
ops=module('shadow_publish_ops','siem-upgrade-local.py');compose=module('shadow_publish_compose','siem-validate-compose.py')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def write(path,value):
    data=canonical(value)
    if path.exists():
        if path.read_bytes()!=data:raise RuntimeError('Immutable model publication differs: '+path.name)
        return
    with path.open('xb') as out:os.chmod(path,0o640);out.write(data);out.flush();os.fsync(out.fileno())
def healthy(name,seconds=180):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        state=ops.inspect(name)['State']
        if state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy':return
        time.sleep(2)
    raise RuntimeError('Shadow rollout health deadline')

def main(folder):
    folder=folder.resolve()
    if not folder.is_relative_to((ROOT/'observability/runtime/private-backups').resolve()):raise ValueError('Private task folder required')
    with (folder/'shadow-publication.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (folder/'shadow-activated.receipt.private.json').exists():raise RuntimeError('Shadow already committed; verify instead of replay')
        result=folder/'pilot-result';offline=json.loads((result/'offline-receipt.json').read_text());resource=json.loads((result/'resource-probe.json').read_text())
        guard=json.loads((folder/'operational-gate-1.receipt.private.json').read_text());desktop=json.loads((folder/'live-ui/desktop-soak-result.private.json').read_text())
        assert offline['status']=='OFFLINE_PILOT_PASS' and resource['status']=='SHADOW_RESOURCE_PASS'
        assert guard['status']=='SIEM_ONE_HOUR_HTTP_GATE_PASS' and guard['compiled_class_parity'] and guard['continuous_seconds']>=3600 and guard['evaluations']>=30
        assert desktop['status']=='LIVE_NEW_DESKTOP_ONE_HOUR_PASS' and desktop['seconds']>=3600
        before=ops.fingerprint();directory=Path(json.loads((folder/'candidate-publication-path.private.json').read_text())['directory'])
        assert sha(directory/'model-state.json')==offline['selected_state_sha256']==resource['state_sha256']
        for source,target in [(result/'resource-probe.json',directory/'resource-receipt.json')]:
            if target.exists():assert target.read_bytes()==source.read_bytes()
            else:shutil.copyfile(source,target);target.chmod(0o640)
        admission={'status':'SHADOW_READY','strict_production_qualified':False,'automatic_enforcement':False,'baseline_manifest_sha256':offline['baseline_manifest_sha256'],'offline_receipt_sha256':sha(directory/'offline-receipt.json'),'resource_receipt_sha256':sha(directory/'resource-receipt.json')}
        write(directory/'admission.json',admission)
        names=json.loads((result/'protocol.json').read_text())['feature_names']
        manifest={'format':'AUTH_SHADOW_MANIFEST_V1','scope':'PILOT_ONLY','mode':'SHADOW','feature_schema_version':7,'feature_names':names,'state_sha256':offline['selected_state_sha256'],'baseline_manifest_sha256':offline['baseline_manifest_sha256'],'threshold':offline['threshold'],'admission_sha256':sha(directory/'admission.json')}
        write(directory/'manifest.json',manifest);pin=sha(directory/'manifest.json')
        scope=ops.sql("SELECT account_allowlist_json FROM siem_postlogin_policy WHERE id='postlogin-project-limited-v1';").decode().strip();accounts=json.loads(scope)
        if accounts!=['e2e-customer']:raise RuntimeError('Accepted baseline population changed; do not expand it silently')
        current=ops.inspect(ops.APP);app=current['Config']['Image'];worker=ops.inspect('flare-otp-local-postlogin-worker-1')['Config']['Image'];nginx=ops.inspect('flare-otp-local-nginx-1')['Config']['Image'];gateway=ops.inspect('flare-otp-local-gateway-1')['Config']['Image']
        args,env,existing=compose.context(app,nginx,gateway);env['FLARE_POSTLOGIN_WORKER_IMAGE']=worker;env['FLARE_SIEM_RECURRENCE_MODE']=existing['SIEM_PREVENTION_RECURRENCE_MODE'];env['FLARE_SIEM_PROTECTED_IPS']=existing['SIEM_PREVENTION_PROTECTED_IPS']
        override=folder/'shadow-override.private.json';config=json.loads((folder/'workspace-override.private.json').read_text())
        config['services']['app']['environment'].update(SIEM_AUTH_SHADOW_ENABLED='true',SIEM_AUTH_SHADOW_MANIFEST_SHA256=pin,SIEM_AUTH_SHADOW_ACCOUNT_ALLOWLIST=','.join(accounts))
        config['services']['postlogin-worker'].update(environment={'UEBA_AUTH_SHADOW_MODEL_DIR':'/run/auth-shadow','UEBA_AUTH_SHADOW_MANIFEST_SHA256':pin},volumes=[{'type':'bind','source':str(directory),'target':'/run/auth-shadow','read_only':True}])
        with override.open('w') as out:os.chmod(override,0o600);json.dump(config,out,indent=2)
        args+=['-f',str(override)]
        validated=json.loads(subprocess.check_output(args+['config','--format','json'],env=env));application=validated['services']['app']['environment']
        for key,value in existing.items():
            if key.startswith(('APP_MAIL','SPRING_MAIL','APP_SENSITIVE_ACTION','APP_JWT','SIEM_POSTLOGIN')) and application.get(key,'')!=value:raise RuntimeError('Protected configuration changed')
        with (folder/'shadow-rollout.private.log').open('ab') as log:
            subprocess.run(args+['up','-d','--no-build','--pull','never','--no-deps','postlogin-worker'],env=env,check=True,stdout=log,stderr=log,timeout=180);healthy('flare-otp-local-postlogin-worker-1')
            subprocess.run(['docker','exec','flare-otp-local-postlogin-worker-1','python','-c','from app.auth_shadow_serving import configured_shadow; from app.postlogin_serving import configured_model; s=configured_shadow(); configured_model().verify_identity(); assert s.manifest["scope"]=="PILOT_ONLY"; print("PINNED_SHADOW_LOADER_PASS")'],check=True,stdout=log,stderr=log,timeout=30)
            subprocess.run(args+['up','-d','--no-build','--pull','never','--no-deps','app'],env=env,check=True,stdout=log,stderr=log,timeout=180);healthy(ops.APP)
            subprocess.run(args+['restart','nginx'],env=env,check=True,stdout=log,stderr=log,timeout=60)
        if ops.fingerprint()!=before:raise RuntimeError('Protected state changed; no destructive rollback attempted')
        value={'status':'QUALIFIED_LAB_CANDIDATE_SHADOW_ACTIVATED','candidate_manifest_sha256':pin,'state_sha256':offline['selected_state_sha256'],'feature_schema_version':7,'feature_count':81,'scope':'PILOT_ONLY','mode':'SHADOW','source_accounts':accounts,'baseline_manifest_sha256':offline['baseline_manifest_sha256'],'baseline_enforcement_population_unchanged':True,'maximum_existing_hold_seconds':600,'candidate_automatic_enforcement':False,'protected':ops.fingerprint(),'published_directory':str(directory),'worker_image_id':ops.inspect('flare-otp-local-postlogin-worker-1')['Image'],'app_image_id':ops.inspect(ops.APP)['Image'],'strict_production_qualified':False}
        ops.publish(folder,'shadow-activated',value);print(json.dumps({key:value[key] for key in ['status','candidate_manifest_sha256','mode','feature_count','strict_production_qualified']}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();main(a.output)
