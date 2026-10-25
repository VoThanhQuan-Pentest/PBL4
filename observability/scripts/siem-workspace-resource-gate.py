#!/usr/bin/env python3
"""Measure a healthy full-stack baseline. Never starts/stops services or trains a model."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
SERVICES=['app','gateway','nginx','filebeat','logstash','kibana','elasticsearch','postlogin-worker','db','redis']

def available():
    return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024

def main(output,seconds):
    output=output.resolve();private=(ROOT/'observability/runtime/private-backups').resolve()
    if not output.is_relative_to(private):raise ValueError('Private receipt directory required')
    output.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (output/'resource-gate.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=output/'baseline-resource.receipt.private.json'
        if result.exists():raise RuntimeError('Receipt exists; inspect it instead of replaying')
        started=time.monotonic();minimum=available();healthy=True;samples=0;last_check=-30
        with (output/'baseline-resource.private.jsonl').open('x') as log:
            os.chmod(log.name,0o600)
            while True:
                elapsed=time.monotonic()-started;memory=available();minimum=min(minimum,memory);free=shutil.disk_usage(ROOT).free
                if elapsed-last_check>=30:
                    rows=json.loads(subprocess.check_output(['docker','inspect',*[f'flare-otp-local-{service}-1' for service in SERVICES]],timeout=15))
                    healthy=healthy and all(row['State']['Running'] and row['State'].get('Health',{}).get('Status','healthy')=='healthy' for row in rows)
                    last_check=elapsed
                entry={'seconds':round(elapsed,1),'available_gib':round(memory/1024**3,3),'free_gib':round(free/1024**3,3),'healthy':healthy}
                log.write(json.dumps(entry)+'\n');log.flush();samples+=1
                if memory<1*1024**3 or free<30*1024**3 or not healthy:break
                if elapsed>=seconds:break
                time.sleep(min(2,seconds-elapsed))
        passed=elapsed>=seconds and minimum>=1.75*1024**3 and healthy
        value={'status':'BASELINE_RESOURCE_PASS' if passed else 'STOP_RESOURCE','continuous_seconds':round(elapsed,1),'samples':samples,'minimum_available_gib':round(minimum/1024**3,3),'all_services_healthy':healthy,'training_started':False,'services_modified':False}
        with result.open('x') as receipt:os.chmod(receipt.name,0o600);json.dump(value,receipt,indent=2);receipt.flush();os.fsync(receipt.fileno())
        print(json.dumps(value))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--seconds',type=int,default=900);args=parser.parse_args()
    if not 900<=args.seconds<=3600:parser.error('Full-stack baseline requires 900–3600 seconds')
    main(args.output,args.seconds)
