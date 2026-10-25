#!/usr/bin/env python3
"""Wait for the committed OBSERVE result, then run only the already-authorized local gates."""
import argparse
import fcntl
import json
import os
import subprocess
import time

from postlogin_impl_control import OUTPUT,REPO,FIT_LEDGER,held,read,runtime_hold,now,process_start,boot_id
from postlogin_preparation_audit import checked
from postlogin_project_release import verify_source
from ueba_research_artifacts import commit,digest,publish

def update(status,phase,next_action):
    state=read('operator-state.private.json');state.update(status=status,phase=phase,next_action=next_action)
    publish(OUTPUT/'operator-state.private.json',state)
    public=read('implementation-state.private.json');public.update(status=status,phase=phase,updated_at_utc=now())
    publish(OUTPUT/'implementation-state.private.json',public)

def step(name,seconds,pause_mode,argv):
    if held():raise InterruptedError('EXPLICIT_OPERATOR_PAUSE')
    if read('budget.private.json')['active_unit']:raise RuntimeError('ANOTHER_ACTIVE_JOB_NO_DUPLICATE')
    command=['python3',str(REPO/'observability/scripts/postlogin_impl_control.py'),'run','--unit',name,
        '--group','verification','--maximum-seconds',str(seconds),'--pause-mode',pause_mode]
    for path in ['observability/scripts/postlogin_project_site.py','observability/tests/test_postlogin_project_site.py',
                 'docker-compose.postlogin-project.yml']:
        command+=['--input',str(REPO/path)]
    command+=['--input',str(OUTPUT/'project-release-v1.receipt.private.json'),'--',*argv]
    result=subprocess.run(command,cwd=REPO)
    proof=checked(OUTPUT,name)
    if result.returncode or proof.get('status')!='COMMAND_PASS':
        if pause_mode=='boundary':
            state=read('operator-state.private.json');state.update(boundary_audit_required=True,interrupted_unit_id=name,
                runtime_revalidation_required=True)
            publish(OUTPUT/'operator-state.private.json',state)
        raise RuntimeError('GATE_FAILED_RECONCILE_'+name)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observe-unit',default='job-project-observe-epoch2-v1')
    parser.add_argument('--observe-phase',default='project-one-hour-observe-v2')
    parser.add_argument('--gate-revision',type=int,default=1)
    args=parser.parse_args()
    if args.gate_revision not in (1,2,3):raise RuntimeError('BOUNDED_GATE_REVISION_REQUIRED')
    import re
    identity=re.fullmatch(r'job-project-observe-epoch([1-9]|10)-v1',args.observe_unit)
    if identity is None or args.observe_phase!='project-one-hour-observe-v'+identity.group(1):
        raise RuntimeError('MATCHING_BOUNDED_EXPLICIT_OBSERVE_EPOCH_REQUIRED')
    with (OUTPUT/'completion-controller.lock').open('a+') as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        publish(OUTPUT/'completion-controller.private.json',{'pid':os.getpid(),'process_start':process_start(os.getpid()),
            'boot_id':boot_id(),'observe_unit':args.observe_unit,'started_at_utc':now()})
        if (OUTPUT/'implementation-result-v1.commit.private.json').exists():
            checked(OUTPUT,'implementation-result-v1');print('IMPLEMENTATION_ALREADY_COMPLETE');return
        release=checked(OUTPUT,'project-release-v1');verify_source(release)
        deadline=time.monotonic()+4300
        try:
            while True:
                if held():raise InterruptedError('EXPLICIT_OPERATOR_PAUSE')
                active=read('budget.private.json')['active_unit']
                if active:
                    if active['id']!=args.observe_unit:raise RuntimeError('UNEXPECTED_ACTIVE_JOB')
                elif (OUTPUT/(args.observe_unit+'.commit.private.json')).exists():
                    receipt=checked(OUTPUT,args.observe_unit)
                    if receipt.get('status')!='COMMAND_PASS':raise RuntimeError('OBSERVE_JOB_FAILED_NO_DEPLOY')
                    break
                if time.monotonic()>deadline:raise RuntimeError('OBSERVE_COMPLETION_DEADLINE_NO_REPLAY')
                time.sleep(10)
            observe=checked(OUTPUT,args.observe_phase)
            if (observe.get('status')!='PROJECT_ONE_HOUR_OBSERVE_PASS' or observe.get('continuous_seconds',0)<3600
                    or observe.get('evaluations',0)<30 or observe.get('release_receipt_sha256')!=digest(OUTPUT/'project-release-v1.receipt.private.json')):
                raise RuntimeError('OBSERVE_RESULT_OR_SOURCE_GATE_FAILED')
            # Normal JVM shutdown may take a moment to stop its disposable DB/Redis. Never overlap the clone with it.
            for attempt in range(12):
                running=subprocess.check_output(['docker','ps','-q','--filter','label=flare.postlogin.implementation=legacy-20261022',
                    '--filter','label=flare.postlogin.unit=project-observe'],text=True).strip()
                if not running:break
                if held():raise InterruptedError('EXPLICIT_OPERATOR_PAUSE')
                time.sleep(5)
            else:raise RuntimeError('OBSERVE_RESOURCES_NOT_QUIESCED')
            update('ROLLOUT_GATE_TESTS','P6','Verify rollout failure/pause/rollback contracts before clone or deployment.')
            step('job-local-rollout-controls-v'+str(args.gate_revision),120,'interruptible',
                ['python3','-m','unittest','discover','-s','observability/tests','-p','test_postlogin_project_site.py','-v'])
            update('MIGRATION_CLONE_CHECK','P6','Upgrade an isolated private database copy; keep website unchanged.')
            step('job-project-migration-clone-v'+str(args.gate_revision),600,'boundary',
                ['python3','observability/scripts/postlogin_project_site.py','clone-check'])
            if held():raise InterruptedError('EXPLICIT_OPERATOR_PAUSE')
            update('LOCAL_LIMITED_ROLLOUT','P6','Apply the source-bound local release, verify OTP/SOC/protected state, then limited policy.')
            step('job-project-local-rollout-v'+str(args.gate_revision),600,'boundary',
                ['python3','observability/scripts/postlogin_project_site.py','deploy'])
            result=checked(OUTPUT,'project-local-rollout-v1')
            if result.get('status')!='LOCAL_PROJECT_ENFORCE_LIMITED_PASS':raise RuntimeError('ROLLOUT_NOT_COMMITTED')
            if held():raise InterruptedError('EXPLICIT_OPERATOR_PAUSE')
            original=checked(OUTPUT,'implementation-authorization-v1')
            if digest(FIT_LEDGER)!=original['historical_fit_ledger_sha256']:raise RuntimeError('FIT_LEDGER_CHANGED')
            verify_source(release)
            budget=read('budget.private.json')
            commit(OUTPUT,{'status':'PROJECT_LIMITED_IMPLEMENTATION_COMPLETE','completed_at_utc':now(),
                'scope':'LAB_PROJECT_ONLY','qualification_scope':'PROJECT_LIMITED','data_provenance':'DEMO_ONLY_RULE_DISTILLATION',
                'observe_phase':args.observe_phase,'observe_evaluations':observe['evaluations'],
                'observe_continuous_seconds':observe['continuous_seconds'],'new_fits':0,'aws_changed':False,
                'strict_production_qualified':False,'rollout_receipt_sha256':digest(OUTPUT/'project-local-rollout-v1.receipt.private.json'),
                'new_job_seconds':budget['elapsed_seconds']-budget['inherited_job_seconds'],
                'otp_required':True,'allowlist':['e2e-customer'],'maximum_hold_seconds':600},phase='implementation-result-v1')
            state=read('operator-state.private.json');state.update(active_handle=None,runtime_revalidation_required=False)
            publish(OUTPUT/'operator-state.private.json',state)
            public=read('implementation-state.private.json');public.update(active_handle=None,in_progress=[],pending=[],
                final_receipt='implementation-result-v1')
            publish(OUTPUT/'implementation-state.private.json',public)
            update('PROJECT_LIMITED_IMPLEMENTATION_COMPLETE','COMPLETE','No remaining authorized implementation work. Stop the heartbeat and notify the user with lab scope and runbook.')
            print('PROJECT_LIMITED_IMPLEMENTATION_COMPLETE',flush=True)
        except InterruptedError:
            runtime_hold(True);update('PAUSED','P5_P6','Await explicit resume; preserve receipts and audit any interrupted boundary before another mutation.')
            print('PAUSED_WITH_RUNTIME_HELD',flush=True)
        except BaseException:
            runtime_hold(True)
            update('LOCAL_CORRECTION_REQUIRED','P5_P6','Read the failed gate/receipts and actual resources. Diagnose within the authorized budget; do not replay a business boundary blindly.')
            raise

if __name__=='__main__':main()
