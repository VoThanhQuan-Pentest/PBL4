#!/usr/bin/env python3
"""Advance only the local signature recurrence mode after qualified gates/recovery.

Keeps the same backend image, fixed model, OTP/mail, account allowlist and schema.
Never trains, seeds, restores or modifies credentials. Modes are staged in order.
"""
import importlib.util
import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def module(name,file):
    sp=importlib.util.spec_from_file_location(name,ROOT/'observability/scripts'/file);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

control=module('mode_control','siem-cutover-local.py');live=module('mode_live','siem-live-acceptance.py');ops=control.ops
FOLDER=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'

def healthy(name,seconds=180):
    begin=time.monotonic()
    while time.monotonic()-begin<seconds:
        state=ops.inspect(name)['State']
        if state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy':return
        time.sleep(2)
    raise RuntimeError('Staged-mode health deadline')

def main(epoch=1):
    suffix="" if epoch==1 else "-v"+str(epoch)
    gates=[json.loads(p.read_text()) for p in FOLDER.glob('operational-gate-*.receipt.private.json')]
    qualified=[v for v in gates if v.get('status')=='SIEM_ONE_HOUR_HTTP_GATE_PASS' and v.get('continuous_seconds',0)>=3600 and v.get('evaluations',0)>=30 and v.get('new_fits')==0 and v.get('compiled_class_parity') is True]
    assert qualified,'Exact deployed-class continuous HTTP gate required'
    gate=max(qualified,key=lambda v:v['started_at_utc'])
    for name in ['live-primary-monitor-contract.json','live-policy-outbox-recovery-contract.json','live-customer-containment-contract.json']:
        assert (ROOT/'audit-results/siem-upgrade-20261023'/name).is_file()
    receipt,_=control.effective_release(FOLDER);assert ops.inspect(ops.APP)['Image']==receipt['image_ids']['app'],'Refuse an image downgrade during mode changes';before=ops.fingerprint();stages=[]
    for mode in ['TEMPORARY','ENFORCE']:
        args,env,_=control.compose.context(receipt['images']['app'],receipt['images']['nginx'],receipt['images']['gateway']);env['FLARE_SIEM_RECURRENCE_MODE']=mode
        config=json.loads(subprocess.check_output(args+['config','--format','json'],env=env))
        assert config['services']['app']['environment']['SIEM_PREVENTION_RECURRENCE_MODE']==mode
        with (FOLDER/'enable-recurrence.private.log').open('ab') as log:
            subprocess.run(args+['up','-d','--no-build','--pull','never','--no-deps','app'],env=env,stdout=log,stderr=log,check=True,timeout=180)
            healthy('flare-otp-local-app-1')
            subprocess.run(args+['restart','nginx'],env=env,stdout=log,stderr=log,check=True,timeout=90)
        ready_until=time.monotonic()+30
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:8089/api/health',timeout=5) as response:
                    if response.status==200:break
            except OSError:pass
            if time.monotonic()>ready_until:raise RuntimeError('Gateway/Nginx recovery health deadline')
            time.sleep(.5)
        c=live.client('l2')
        try:
            workspace=c.request('GET','/api/siem/workspace');blocks=c.request('GET','/api/siem/prevention/blocks?size=1')
            assert blocks['recurrence_mode']==mode
            assert workspace['postlogin']['scope']=='PROJECT_LIMITED' and workspace['postlogin']['maximum_hold_seconds']==600 and workspace['postlogin']['otp_required'] is True
            assert workspace['pipeline']['elasticsearch_available'] is True
            assert workspace['policy']['gateway_state']=='APPLIED'
            assert ops.inspect('flare-otp-local-app-1')['Image']==receipt['image_ids']['app']
            assert ops.fingerprint()==before
            stages.append({'mode':mode,'gateway_state':'APPLIED','model_scope':'PROJECT_LIMITED','otp_required':True,'maximum_hold_seconds':600,'images_unchanged':True})
            ops.publish(FOLDER,'recurrence-'+mode.lower()+suffix,{'status':'LOCAL_RECURRENCE_'+mode+'_PASS','mode':mode,'protected':ops.fingerprint(),'model_fits':0,'qualified_http_gate':True,'strict_production_qualified':False})
        finally:c.request('POST','/api/auth/logout',{})
        if mode=='TEMPORARY':time.sleep(15)
    live.publish('live-staged-enforcement'+suffix+'-contract.json',{'status':'LOCAL_STAGED_RECURRENCE_ENFORCE_PASS','stages':stages,'qualified_http_evaluations':gate['evaluations'],'continuous_gate_seconds':gate['continuous_seconds'],'compiled_classes_checked':gate['compiled_classes_checked'],'new_fits':0,'until_revoked_requires_active_tested_approved_signature_episodes':True,'gateway_schema_and_durable_capability_required':True,'private_loopback_test_net_protected_ips_excluded':True,'model_does_not_create_until_revoked_blocks':True,'strict_production_qualified':False})

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--epoch',type=int,default=1);args=parser.parse_args()
    if not 1<=args.epoch<=10:parser.error('Explicit epoch must be 1–10')
    main(args.epoch)
