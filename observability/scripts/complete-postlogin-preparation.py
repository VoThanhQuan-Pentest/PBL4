#!/usr/bin/env python3
"""Bounded completion of the live real-clock preparation; never opens training."""
import argparse
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import time

from ueba_research_artifacts import publish,commit,private_directory,digest
from postlogin_research_step import process_start

IMAGE='sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f'


def witness_closed_history(root):
    """Bind real DB window IDs to the already committed raw/Java wave.

    This observer only SELECTs the dedicated lab DB; it cannot invent history
    or change the frozen capture producer while that producer is running.
    """
    from postlogin_preparation_audit import checked
    child=root/'capture-real-v1'
    run=hashlib.sha256(str(child).encode()).hexdigest()[:12]
    database='flare-prep-'+run+'-mysql'
    markers=list(child.glob('warmup-window-*.commit.private.json'))+list(child.glob('resume-history-*.commit.private.json'))
    for marker in sorted(markers):
        phase=marker.name.removesuffix('.commit.private.json')
        witness=phase+'-db-witness'
        if (root/(witness+'.commit.private.json')).exists():
            old=checked(root,witness)
            assert old['source_receipt_sha256']==digest(child/(phase+'.receipt.private.json'))
            continue
        raw=checked(child,phase)
        value=json.loads(subprocess.check_output(['docker','inspect',database,'--format','{{json .Config.Labels}}'],text=True,timeout=15))
        assert value.get('flare.preparation.run')==run and value.get('flare.preparation.scope')=='zero-fit-lab'
        at=datetime.fromisoformat(raw['window_start']).strftime('%Y-%m-%d %H:%M:%S')
        sql=("SELECT SHA2(id,256),account_id,window_start,window_end,session_endpoint_feature_vector_json "
             "FROM siem_account_behavior_windows WHERE window_start='"+at+"' ORDER BY account_id")
        output=subprocess.check_output(['docker','exec','--env','MYSQL_PWD=flare-preparation-only',database,
            'mysql','-u','flare','--batch','--raw','--skip-column-names','flare_fitness','-e',sql],text=True,timeout=20)
        expected={r['account_id']:r for r in raw['rows']};retained=[]
        for line in output.splitlines():
            identity,account,start,end,features=line.split('\t',4)
            if account not in expected:continue
            vector=json.loads(features)
            if vector!=expected[account]['features']:raise ValueError('PERSISTED_HISTORY_DIFFERS_FROM_COMMITTED_JAVA_WAVE')
            if expected[account].get('window_id_sha256',identity)!=identity:
                raise ValueError('RECOVERED_HISTORY_ID_DIFFERS_FROM_DATABASE')
            retained.append({'window_id_sha256':identity,'account_id':account,'window_start':start.replace(' ','T')+'Z',
                             'window_end':end.replace(' ','T')+'Z'})
        if len(retained)!=len(expected):raise ValueError('INCOMPLETE_REAL_HISTORY_WITNESS')
        commit(root,{'status':'REAL_DB_HISTORY_READBACK_PASS','source_receipt_sha256':digest(child/(phase+'.receipt.private.json')),
                     'rows':retained,'database_mutated':False},phase=witness)

def audit(a):
    root=a.output
    from postlogin_preparation_audit import cases,summarize
    if a.mode=='check-smoke':
        rows=cases(root/'capture-smoke-v2');assert len(rows)==6
        result={'status':'ACTUAL_PRECOMMIT65_SMOKE_VERIFIED','rows':6,'new_fits':0,
            'shared_mailbox_controls_committed':sum(r['shared_mailbox_limit'] and r['account_mutated'] for r in rows),
            'labels_outside_features':True,'all_oracles_presealed':True,'training_admitted':False}
        commit(root,result,phase='capture-smoke-verification-v1')
    else:result=summarize(root)
    print(json.dumps({k:v for k,v in result.items() if k in ('status','rows','benchmark_rows','p1_pairs','new_fits','capture_projection_seconds_50_percent_margin')}),flush=True)
    return 0


def wait_and_finish(a):
    root=a.output
    from postlogin_preparation_audit import verify_pipeline
    verify_pipeline(root)
    with (root/'preparation-controller.lock').open('a+') as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state={'status':'WAIT_LIVE_REAL_CLOCK_CAPTURE','pid':os.getpid(),'process_start':process_start(os.getpid()),'new_fit_cap':0,'quota_policy':'NOT_USED'}
        publish(root/'preparation-controller.private.json',state)
        started=time.monotonic()
        while True:
            secret=root/'capture-real-v1/lab-client-secret.private.txt'
            if secret.exists() and not (root/'lab-client-secret-durability-v1.commit.private.json').exists():
                fd=os.open(secret,os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    info=os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_nlink!=1:
                        raise ValueError('PRIVATE_LAB_RECOVERY_SECRET_REQUIRED')
                    os.fsync(fd)
                finally:os.close(fd)
                directory_fd=os.open(secret.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory_fd)
                finally:os.close(directory_fd)
                commit(root,{'status':'LAB_RECOVERY_SECRET_FSYNCED','secret_contents_exported':False},phase='lab-client-secret-durability-v1')
            hold=root/'operator-hold.private.json'
            if hold.exists() and json.loads(hold.read_text()).get('hold_new_units'):
                child=root/'capture-real-v1'
                if child.is_dir():
                    publish(child/'operator-hold.private.json',{'hold_new_units':True,'reason':'EXPLICIT_OPERATOR_HOLD'})
                state['status']='STOP_OPERATOR_HOLD';publish(root/'preparation-controller.private.json',state);return 2
            b=json.loads((root/'budget.private.json').read_text());active=b['active_unit']
            if not active:break
            if active['id']!=getattr(a,'capture_unit','real-clock-history-and-capture-v1'):raise RuntimeError('UNEXPECTED_ACTIVE_UNIT_DO_NOT_OVERLAP')
            alive=active.get('pid') and process_start(active['pid'])==active.get('process_start')
            if not alive:
                # An absent supervisor is not permission to replay source or
                # mutate its budget. The operator must reconcile its deadline.
                state['status']='WAIT_OPERATOR_RECONCILIATION_OF_MISSING_JOB';publish(root/'preparation-controller.private.json',state);return 3
            witness_closed_history(root)
            if time.monotonic()-started>a.maximum_seconds:raise RuntimeError('CONTROLLER_DEADLINE')
            time.sleep(45)
        source=root/'capture-real-v1/preparation-capture-result-v1.commit.private.json'
        if not source.exists():
            state['status']='STOP_CAPTURE_INCOMPLETE_NO_RETRY';publish(root/'preparation-controller.private.json',state);return 4
        script=Path(__file__).resolve();repo=script.parents[2]
        args=['docker','run','--rm','--name','flare-prep-final-audit-'+hashlib.sha256(str(root).encode()).hexdigest()[:8],'--workdir','/work','--network','none','--cpus','2','--memory','2g','--pids-limit','128',
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.geteuid()}:{os.getegid()}',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--env','PYTHONDONTWRITEBYTECODE=1','--env','OPENBLAS_NUM_THREADS=2',
            '--env','PYTHONPATH=/work/ueba-worker:/work/observability/scripts',
            '--mount',f'type=bind,src={repo}/ueba-worker,dst=/work/ueba-worker,readonly',
            '--mount',f'type=bind,src={repo}/observability/scripts,dst=/work/observability/scripts,readonly',
            '--mount',f'type=bind,src={root},dst=/preparation','--entrypoint','/usr/bin/timeout',IMAGE,'--signal=TERM','--kill-after=5s','90',
            'python','/work/observability/scripts/complete-postlogin-preparation.py','--output','/preparation','--mode','audit']
        command=[sys.executable,str(repo/'observability/scripts/postlogin_research_step.py'),'--output',str(root),
            '--unit','measured-preparation-audit-v1','--group','verification','--maximum-seconds','120',
            '--input',str(script),'--input',str(script.with_name('postlogin_preparation_audit.py')),
            '--input',str(repo/'ueba-worker/app/postlogin_contract.py'),'--',*args]
        result=subprocess.run(command,cwd=repo,timeout=145)
        state['status']='STOP_PREPARATION_AUDIT_FAILURE'
        if result.returncode==0:
            measured=json.loads((root/'measured-preparation-result-v1.receipt.private.json').read_text())
            state['status']=('MEASUREMENTS_READY_AWAIT_CAMPAIGN_BUDGET' if measured['status']=='ZERO_FIT_PREPARATION_MEASUREMENTS_COMPLETE'
                             else 'SOURCE_CORRECTION_REQUIRED_BEFORE_TRAINING')
        state['finished_at_utc']=datetime.now(timezone.utc).isoformat()
        publish(root/'preparation-controller.private.json',state)
        operator=json.loads((root/'operator-state.private.json').read_text());operator.update(status=state['status'],next_action='Review measured-preparation-result-v1 before any full campaign; no training authorization in this preparation.')
        publish(root/'operator-state.private.json',operator)
        return result.returncode

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mode',choices=('check-smoke','audit','wait'),required=True)
    p.add_argument('--maximum-seconds',type=int,default=57000)
    p.add_argument('--capture-unit',choices=tuple('real-clock-history-and-capture-v'+str(i) for i in range(1,10)),default='real-clock-history-and-capture-v1')
    a=p.parse_args();a.output=private_directory(a.output.resolve())
    raise SystemExit(wait_and_finish(a) if a.mode=='wait' else audit(a))
