#!/usr/bin/env python3
"""SIGKILL/readback on the isolated smoke DB; never targets the live collector."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid
from ueba_research_artifacts import private_directory,commit

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
r=private_directory(a.output.resolve());child=r/'capture-smoke-v2';run=hashlib.sha256(str(child).encode()).hexdigest()[:12]
name='flare-prep-'+run+'-mysql'
operator=json.loads((r/'operator-state.private.json').read_text())
assert name not in (operator.get('active_handle') or {}).get('containers',[]),'NEVER_KILL_ACTIVE_CAPTURE_DB'
state=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]
assert state['Config']['Labels']['flare.preparation.run']==run and not state['State']['Running']

def query(sql):
    return subprocess.check_output(['docker','exec','--env','MYSQL_PWD=flare-preparation-only',name,
        'mysql','-u','flare','--batch','--raw','--skip-column-names','flare_fitness','-e',sql],text=True,stderr=subprocess.PIPE,timeout=15).strip()

def ready():
    until=time.monotonic()+90
    while time.monotonic()<until:
        try:
            if query('SELECT 1')=='1':return
        except subprocess.CalledProcessError:pass
        time.sleep(2)
    raise RuntimeError('SMOKE_DB_RECOVERY_DEADLINE')

started=time.monotonic()
try:
    subprocess.run(['docker','start',name],check=True,stdout=subprocess.DEVNULL,timeout=20);ready()
    assert query('SELECT @@innodb_flush_log_at_trx_commit')=='1'
    identifier=uuid.uuid4().hex;value=hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    query("CREATE TABLE IF NOT EXISTS lab_preparation_recovery_probe (id VARCHAR(32) PRIMARY KEY,value_sha256 CHAR(64) NOT NULL) ENGINE=InnoDB")
    query("INSERT INTO lab_preparation_recovery_probe VALUES ('"+identifier+"','"+value+"')")
    assert query("SELECT value_sha256 FROM lab_preparation_recovery_probe WHERE id='"+identifier+"'")==value
    subprocess.run(['docker','kill','--signal','KILL',name],check=True,stdout=subprocess.DEVNULL,timeout=20)
    stopped=json.loads(subprocess.check_output(['docker','inspect',name,'--format','{{json .State}}'],text=True))
    assert not stopped['Running'] and stopped['ExitCode']==137 and not stopped['OOMKilled']
    subprocess.run(['docker','start',name],check=True,stdout=subprocess.DEVNULL,timeout=20);ready()
    assert query("SELECT value_sha256 FROM lab_preparation_recovery_probe WHERE id='"+identifier+"'")==value
    commit(r,{'status':'ACTUAL_LAB_MYSQL_SIGKILL_COMMITTED_READBACK_PASS','container':name,
        'signal':'SIGKILL','committed_canary_sha256':value,'innodb_flush_log_at_trx_commit':1,
        'active_collector_untouched':True,'new_fits':0,'new_sensitive_attempts':0,
        'redis_recovery':'Ephemeral sessions may require reauthentication; no zero-loss Redis claim.',
        'not_hardware_powerloss_proof':True,'elapsed_seconds':time.monotonic()-started},phase='lab-crash-recovery-v1')
    print(json.dumps({'status':'ACTUAL_LAB_MYSQL_SIGKILL_COMMITTED_READBACK_PASS','new_fits':0,'active_collector_untouched':True}))
finally:
    subprocess.run(['docker','stop','--time','10',name],capture_output=True,timeout=20)
