#!/usr/bin/env python3
"""Inspect the preparation or request an explicit safe hold; never starts fits."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import subprocess
from postlogin_research_step import process_start
from ueba_research_artifacts import private_directory,publish

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
p.add_argument('action',choices=('status','hold'));a=p.parse_args();root=private_directory(a.output.resolve())
if a.action=='hold':
    hold={'hold_new_units':True,'reason':'EXPLICIT_OPERATOR_REQUEST','requested_at_utc':datetime.now(timezone.utc).isoformat()}
    publish(root/'operator-hold.private.json',hold)
    child=root/'capture-real-v1'
    if child.is_dir():publish(child/'operator-hold.private.json',hold)
    print(json.dumps({'status':'HOLD_REQUESTED','new_fits':0}));raise SystemExit(0)
b=json.loads((root/'budget.private.json').read_text());active=b['active_unit']
live=bool(active and active.get('pid') and process_start(active['pid'])==active.get('process_start'))
progress=root/'capture-real-v1/preparation-progress.private.json'
controller=root/'preparation-controller.private.json'
c=json.loads(controller.read_text()) if controller.exists() else None
print(json.dumps({'status':json.loads((root/'operator-state.private.json').read_text())['status'],
    'job_alive':live,'active_unit':active['id'] if active else None,'deadline_utc':active['deadline_utc'] if active else None,
    'new_preparation_job_seconds_committed':b['elapsed_seconds']-b['inherited_job_seconds'],
    'new_fit_cap':0,'quota_policy':'NOT_USED','progress':json.loads(progress.read_text()) if progress.exists() else None,
    'completion_controller_alive':bool(c and process_start(c['pid'])==c['process_start']),
    'completion_controller_status':c['status'] if c else None}))
