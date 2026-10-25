#!/usr/bin/env python3
"""Read-only one-hour baseline+candidate probe; does not need or create an activation receipt."""
import argparse
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import resource
import time
import numpy as np
from app.auth_shadow_contract import validate
from app.auth_shadow_model import validate_state,score_components
from app.postlogin_serving import configured_model

def rss():return int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmRSS:')))*1024
def available():return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024

def main(data,result,seconds):
    receipt=json.loads((result/'offline-receipt.json').read_bytes())
    if receipt['status']!='OFFLINE_PILOT_PASS':raise RuntimeError('No qualified offline candidate')
    baseline=configured_model();baseline.verify_identity();before=rss()
    state=validate_state(json.loads((result/(receipt['selected_trial']+'-state.json')).read_bytes()))
    if hashlib.sha256((result/(receipt['selected_trial']+'-state.json')).read_bytes()).hexdigest()!=receipt['selected_state_sha256']:raise RuntimeError('Candidate bytes differ')
    with gzip.open(data/'development.jsonl.gz','rt',encoding='utf-8') as source:rows=[validate(json.loads(next(source))['snapshot']) for _ in range(32)]
    latencies=[];peak=before;minimum=available();started=time.monotonic()
    while time.monotonic()-started<seconds:
        at=time.perf_counter();components=score_components(state,rows,baseline);latencies.append((time.perf_counter()-at)*1000)
        assert np.isfinite(components['raw_score']).all()
        baseline.verify_identity();peak=max(peak,rss());minimum=min(minimum,available())
        if peak-before>128*1024**2 or minimum<1.5*1024**3:raise RuntimeError('STOP_RESOURCE:serving memory admission failed')
        (result/'probe-progress.private.json').write_text(json.dumps({'status':'RUNNING','seconds':round(time.monotonic()-started,1),'candidate_incremental_rss_bytes':peak-before,'host_available_bytes':minimum}))
        time.sleep(min(5,max(.01,seconds-(time.monotonic()-started))))
    memory_peak=int(Path('/sys/fs/cgroup/memory.peak').read_text().strip());latencies.sort();p95=latencies[max(0,int(np.ceil(.95*len(latencies)))-1)]
    passed=memory_peak<=448*1024**2 and peak-before<=128*1024**2 and minimum>=1.5*1024**3 and p95<=1000
    value={'status':'SHADOW_RESOURCE_PASS' if passed else 'STOP_RESOURCE','scope':'FULL_STACK_WITH_ISOLATED_SHADOW_PROBE','state_sha256':receipt['selected_state_sha256'],'continuous_seconds':round(time.monotonic()-started,1),'worker_memory_peak_bytes':memory_peak,'incremental_rss_bytes':peak-before,'minimum_host_available_bytes':minimum,'no_oom':True,'batch_size':32,'p95_batch_latency_ms':round(p95,3),'new_model_fits':0,'strict_production_qualified':False}
    with (result/'resource-probe.json').open('x') as output:json.dump(value,output,indent=2)
    print(json.dumps(value))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',type=Path,required=True);p.add_argument('--result',type=Path,required=True);p.add_argument('--seconds',type=int,default=3600);a=p.parse_args()
    if not 3600<=a.seconds<=3900:p.error('Continuous one-hour probe required')
    main(a.data,a.result,a.seconds)
