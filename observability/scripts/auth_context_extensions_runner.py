#!/usr/bin/env python3
"""Registered extension stages using the existing resource supervisor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import uuid

import auth_context_research_runner as base

REFERENCE=Path('/home/quan/.codex/research/model-capability-assessment/auth-context-v2-20261027-r2/result')


def command(stage,cohort,job,classpath=None,smoke=0):
    name='auth-research-'+uuid.uuid4().hex
    small=stage in ('http-test','benchmark','soak')
    threads='1' if small else '2'
    args=['docker','run','--rm','--name',name,'--label','auth.research.owner='+name,
          '--network','none','--memory','512m' if small else '2g','--cpus',threads,
          '--pids-limit','256','--user',f'{os.getuid()}:{os.getgid()}','--read-only',
          '--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,size=64m',
          '--workdir','/service','-e','AUTH_RESEARCH_SUPERVISED=1','-e','PYTHONDONTWRITEBYTECODE=1',
          '-e','OMP_NUM_THREADS='+threads,'-e','OPENBLAS_NUM_THREADS='+threads]
    if stage in ('capture','parity','fault'):
        base.verify_classpath(job,classpath,None)
        args+=base.bind(base.ROOT,'/workspace')+base.bind(job,str(job),writable=True)
        data=job/('corpus-'+cohort.lower()+('-smoke' if smoke or stage=='fault' else ''))
        args += [base.WORKER_IMAGE,'python','-B','/workspace/observability/scripts/auth_context_extensions_source.py',stage,
                 '--cohort',cohort,'--data',str(data),'--java-classpath',classpath]
        if smoke:args+=['--smoke',str(smoke)]
        return args
    for module in sorted((base.ROOT/'ueba-worker/app').glob('auth_extensions_*.py')):
        args+=base.bind(module,'/service/app/'+module.name)
    args+=base.bind(base.ROOT/'ueba-worker/app/auth_shadow_research.py','/service/app/auth_shadow_research.py')
    args+=base.bind(base.BASELINE,'/run/model')
    if stage in ('select','evaluate','smoke'):
        data=job/('corpus-'+cohort.lower()+('-smoke' if stage=='smoke' else ''))
        out=job/('smoke-'+cohort.lower() if stage=='smoke' else cohort.lower())
        splits=('train','calibration','development') if stage=='select' else ('evaluation','controls') if stage=='evaluate' else ('train','calibration','development','evaluation','controls')
        for file in base.METADATA+tuple(s+'.jsonl.gz' for s in splits):
            path=base.safe_path(data/file,data)
            if not path.is_file():raise ValueError('split file missing')
            args+=base.bind(path,'/data/'+file)
        args+=base.bind(out,'/output',writable=True)+base.bind(job/'ledger','/ledger',writable=True)
        args+=base.bind(REFERENCE,'/reference')
        args += [base.WORKER_IMAGE,'python','-B','-m','app.auth_extensions_research',stage,
                 '--cohort',cohort,'--data','/data','--output','/output','--ledger','/ledger',
                 '--reference','/reference','--baseline','/run/model']
        return args
    if stage in ('http-test','benchmark','soak'):
        args+=base.bind(job/'bundle','/bundle')+base.bind(job/'http-results','/results',writable=True)
        bundle=json.loads((job/'bundle/manifest.json').read_bytes())
        for role in ('ready','cold'):
            source=job/('corpus-'+role)/'evaluation.jsonl.gz'
            if role=='cold' and 'COLD' not in bundle['models']:source=job/'corpus-ready/controls.jsonl.gz'
            args+=base.bind(source,'/samples/'+role+'.jsonl.gz')
        args += [base.WORKER_IMAGE,'python','-B','-m','app.auth_extensions_benchmark',stage,
                 '--bundle','/bundle/manifest.json','--baseline','/run/model','--samples','/samples','--output','/results']
        return args
    raise ValueError('unknown extension stage')


def package(job):
    folder=job/'bundle';folder.mkdir(mode=0o700)
    manifest={'format':'AUTH_EXTENSIONS_BUNDLE_V1','scope':'OFFLINE_RESEARCH_ONLY','models':{},
              'automatic_enforcement':False,'strict_production_qualified':False,'receipts':{},
              'runtime_integration_blocked':True,'integration_findings':[]}
    for cohort in ('ready','cold'):
        fault=json.loads((job/('producer-fault-'+cohort+'.json')).read_bytes())
        if fault.get('runtime_integration_blocked'):
            manifest['integration_findings'].append({'cohort':cohort,'producer':fault})
    for cohort in ('READY','COLD'):
        out=job/cohort.lower();receipt=json.loads((out/'receipt.json').read_bytes())
        manifest['receipts'][cohort]={'status':receipt['status'],'sha256':base.file_sha(out/'receipt.json',16*1024**2)}
        allowed=('READY_RESEARCH_PASS','READY_REFERENCE_RETAINED') if cohort=='READY' else ('COLD_RESEARCH_PASS',)
        if receipt['status'] not in allowed:continue
        source=out/'selected-state.json';expected=receipt['selected_state_sha256']
        if source.is_symlink() or base.file_sha(source,16*1024**2)!=expected:raise ValueError('selected model state differs')
        name=cohort.lower()+'-state.json'
        with (folder/name).open('xb') as output:os.chmod(folder/name,0o600);output.write(source.read_bytes())
        drift_name=cohort.lower()+'-drift.json';drift_source=out/'drift-reference.json'
        with (folder/drift_name).open('xb') as output:os.chmod(folder/drift_name,0o600);output.write(drift_source.read_bytes())
        manifest['models'][cohort]={'state_file':name,'state_sha256':expected,'threshold':receipt['threshold'],
            'calibrator':receipt['calibrator'],'calibration_pass':receipt['calibration']['status']=='CALIBRATION_PASS',
            'drift_status':receipt['drift']['status'],
            'drift_file':drift_name,'drift_sha256':base.file_sha(drift_source,2*1024**2)}
    if 'READY' not in manifest['models']:raise ValueError('no READY fallback')
    with (folder/'manifest.json').open('x') as f:
        os.chmod(folder/'manifest.json',0o600);json.dump(manifest,f,sort_keys=True,allow_nan=False);f.flush();os.fsync(f.fileno())
    print(json.dumps({'status':'OFFLINE_BUNDLE_CREATED','cohorts':list(manifest['models'])}))


def main():
    p=argparse.ArgumentParser();p.add_argument('stage',choices=('capture','parity','fault','smoke','select','evaluate','package','http-test','benchmark','soak'))
    p.add_argument('--cohort',choices=('READY','COLD'));p.add_argument('--job',type=Path,required=True)
    p.add_argument('--smoke',type=int,default=0)
    a=p.parse_args();job=base.safe_path(a.job,base.RESEARCH_ROOT)
    if a.stage in ('capture','parity','fault','smoke','select','evaluate') and not a.cohort:p.error('cohort required')
    if not 0<=a.smoke<=100 or a.smoke and a.stage not in ('capture','parity'):p.error('smoke capture/parity only')
    if a.stage=='package':package(job);return
    base.resource_check(job,admission=True)
    cp=None
    if a.stage in ('capture','parity','fault'):cp=json.loads((job/'classpath-receipt.json').read_bytes())['classpath']
    if a.stage in ('select','smoke'):
        (job/('smoke-'+a.cohort.lower() if a.stage=='smoke' else a.cohort.lower())).mkdir(mode=0o700)
        (job/'ledger').mkdir(mode=0o700,exist_ok=True)
    if a.stage in ('http-test','benchmark','soak'):(job/'http-results').mkdir(mode=0o700,exist_ok=True)
    args=command(a.stage,a.cohort,job,cp,a.smoke)
    stage=a.stage+('-'+a.cohort.lower() if a.cohort else '')+('-smoke' if a.smoke else '')
    base.run_command(args,job,stage,fit_result=job/a.cohort.lower() if a.stage=='select' else None)


if __name__=='__main__':main()
