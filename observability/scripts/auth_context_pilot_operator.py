#!/usr/bin/env python3
"""Run the authorized bounded pilot with live memory supervision and unconditional local ELK recovery."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'observability/scripts'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
ops=module('pilot_operator_ops','siem-upgrade-local.py')

def available():return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024

def save(path,value):
    temp=path.with_suffix('.partial')
    with temp.open('w') as out:os.chmod(temp,0o600);json.dump(value,out,indent=2);out.flush();os.fsync(out.fileno())
    temp.replace(path)

def healthy(name,seconds=300):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        state=ops.inspect(name)['State']
        if state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy':return
        time.sleep(2)
    raise RuntimeError('Recovery health deadline: '+name)

def run(folder):
    folder=folder.resolve()
    if not folder.is_relative_to((ROOT/'observability/runtime/private-backups').resolve()):raise ValueError('Private task directory required')
    with (folder/'pilot-operation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        out=folder/'pilot-result';data=folder/'pilot-data/capture-2'
        if (out/'fit-ledger.json').exists():raise RuntimeError('A fit reservation exists; inspect it, never replay training')
        baseline=json.loads((folder/'resource-current-r3/baseline-resource.receipt.private.json').read_text())
        if baseline.get('status')!='BASELINE_RESOURCE_PASS' or baseline.get('continuous_seconds',0)<900:raise RuntimeError('Fresh full-stack resource gate required')
        before=ops.fingerprint();ops.admission();stopped=[];container='flare-auth-context-pilot-'+uuid.uuid4().hex[:10];started=time.monotonic();reason=None;minimum=available();created=False
        try:
            for name in ['flare-otp-local-kibana-1','flare-otp-local-logstash-1','flare-otp-local-elasticsearch-1']:
                if available()>=int(5.5*1024**3):break
                if not ops.inspect(name)['State']['Running']:raise RuntimeError('Service already stopped before maintenance; reconcile first')
                subprocess.run(['docker','stop','--time','30',name],check=True,stdout=subprocess.DEVNULL,timeout=60);stopped.append(name);time.sleep(2)
            if available()<int(5.5*1024**3):raise RuntimeError('STOP_RESOURCE:5.5GiB pre-train admission not met')
            protocol=hashlib.sha256((out/'protocol.json').read_bytes()).hexdigest();manifest=hashlib.sha256((data/'manifest.json').read_bytes()).hexdigest()
            admission=folder/'training-admission.private.json';save(admission,{'status':'TRAINING_RESOURCE_ADMITTED','scope':'PILOT_ONLY','protocol_sha256':protocol,'source_manifest_sha256':manifest,'host_available_bytes':available(),'maximum_memory_bytes':2*1024**3,'maximum_cpus':2,'main_baseline_resource_receipt_sha256':hashlib.sha256((folder/'resource-current-r3/baseline-resource.receipt.private.json').read_bytes()).hexdigest(),'services_temporarily_stopped':stopped})
            args=['docker','run','-d','--name',container,'--label','flare.siem-workspace.pilot=20261024-r1','--network','none','--memory','2g','--cpus','2','--pids-limit','256','--user','1000:1000','--read-only','--tmpfs','/tmp:rw,nosuid,size=64m',
                '-e','PYTHONPATH=/service','-e','OPENBLAS_NUM_THREADS=2','-e','OMP_NUM_THREADS=2','-e','PYTHONDONTWRITEBYTECODE=1','-e','AUTH_PILOT_TRAINING_ADMISSION=/run/training-admission.json','-e','UEBA_POSTLOGIN_MODEL_DIR=/run/model','-e','UEBA_POSTLOGIN_MANIFEST_SHA256=7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784',
                '-v',str(ROOT/'observability/runtime/postlogin-project-runtime/model-v1')+':/run/model:ro','-v',str(data)+':/data:ro','-v',str(out)+':/result','-v',str(ROOT/'observability/scripts/auth_context_pilot.py')+':/pilot.py:ro','-v',str(admission)+':/run/training-admission.json:ro','flare/postlogin-worker:auth-shadow-20261024-r2','python','/pilot.py','--data','/data','--output','/result','--fit']
            subprocess.run(args,check=True,stdout=subprocess.DEVNULL,timeout=30);created=True
            while True:
                state=ops.inspect(container)['State'];minimum=min(minimum,available())
                if not state['Running']:break
                if available()<3*1024**3:reason='STOP_RESOURCE_HOST_RESERVE';break
                if time.monotonic()-started>5400:reason='STOP_DEADLINE_RESTORE_SERVICES';break
                ledger=out/'fit-ledger.json'
                if ledger.exists():
                    journal=json.loads(ledger.read_text());entries=journal.get('entries',[])
                    if entries and entries[-1]['status']=='RESERVED_BEFORE_FIT' and time.time()-entries[-1]['at']>1800:reason='STOP_TRIAL_DEADLINE';break
                if sum(p.stat().st_size for p in (folder/'pilot-data').rglob('*') if p.is_file())+sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>4*1024**3:reason='STOP_ARTIFACT_QUOTA';break
                time.sleep(2)
            if reason:subprocess.run(['docker','stop','--time','15',container],check=True,stdout=subprocess.DEVNULL,timeout=30)
            final=ops.inspect(container)['State'];logs=subprocess.check_output(['docker','logs',container],stderr=subprocess.STDOUT,timeout=15)
            (folder/'pilot-fit.private.log').write_bytes(logs);(folder/'pilot-fit.private.log').chmod(0o600)
            if final.get('OOMKilled'):reason='STOP_CONTAINER_OOM'
            elif final.get('ExitCode')!=0 and reason is None:reason='PILOT_PROCESS_FAILED'
            save(folder/'pilot-process.private.json',{'status':reason or 'PILOT_PROCESS_COMPLETE','exit_code':final.get('ExitCode'),'oom_killed':final.get('OOMKilled',False),'minimum_host_available_bytes':minimum,'services_temporarily_stopped':stopped,'seconds':round(time.monotonic()-started,1)})
        finally:
            if created:
                state=ops.inspect(container)['State']
                if state['Running']:subprocess.run(['docker','stop','--time','15',container],stdout=subprocess.DEVNULL,timeout=30)
            for name in reversed(stopped):subprocess.run(['docker','start',name],check=True,stdout=subprocess.DEVNULL,timeout=30)
            for name in reversed(stopped):healthy(name)
            after=ops.fingerprint()
            save(folder/'pilot-recovery.private.json',{'status':'PILOT_SERVICES_RESTORED' if before==after else 'PROTECTED_STATE_CHANGED_RECONCILE','restored_services':stopped,'protected_unchanged':before==after,'baseline_model_unchanged':before['model']==after['model'],'model_not_adopted':True})
        receipt=out/'offline-receipt.json';value=json.loads(receipt.read_text()) if receipt.exists() else {'status':reason or 'PILOT_PROCESS_FAILED'}
        print(json.dumps({'status':value['status'],'classifier_fits':value.get('classifier_fits'),'normal_fits':value.get('normal_fits'),'model_adopted':False,'services_restored':True}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();run(a.output)
