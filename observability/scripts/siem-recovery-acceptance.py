#!/usr/bin/env python3
"""Controlled local failure/recovery checks after both observation gates complete.

Stops only known primary service containers; never recreates data services,
removes volumes, edits credentials, resets queues or restores a database.
"""
from datetime import datetime,timedelta,timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'observability/scripts'/filename);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

live=module('recovery_live','siem-live-acceptance.py');control=module('recovery_control','siem-cutover-local.py');ops=control.ops
FOLDER=ops.PRIVATE if hasattr(ops,'PRIVATE') else ROOT/'observability/runtime/private-backups'
FOLDER=FOLDER/'siem-upgrade-20261023-r1'

def docker(*args,timeout=40):
    result=subprocess.run(['docker',*args],capture_output=True,timeout=timeout)
    if result.returncode:raise RuntimeError('Recovery container operation failed')
    return result.stdout

def healthy(name,seconds=180):
    start=time.monotonic()
    while time.monotonic()-start<seconds:
        state=ops.inspect(name)['State']
        if state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy':return
        time.sleep(2)
    raise RuntimeError('Recovery health deadline: '+name)

def literal(value):return "CONVERT(X'"+str(value).encode().hex()+"' USING utf8mb4)"

def require_gates():
    results=[json.loads(p.read_text()) for p in FOLDER.glob('operational-gate-*.receipt.private.json')]
    assert any(d.get('status')=='SIEM_ONE_HOUR_HTTP_GATE_PASS' and d.get('continuous_seconds',0)>=3600 and d.get('evaluations',0)>=30 for d in results)
    assert json.loads((ROOT/'audit-results/siem-upgrade-20261023/live-primary-monitor-contract.json').read_text())['status']=='PRIMARY_STACK_CONTINUOUS_SAMPLING_PASS'

def main():
    require_gates();before=ops.fingerprint();stopped=set();c=live.client('l1');l2=live.client('l2');blocks=[]
    workflow=json.loads((ROOT/'audit-results/siem-upgrade-20261023/live-soc-workflow-contract.json').read_text())['incident_id']
    detail=c.request('GET','/api/siem/incidents/'+workflow);history=c.request('GET','/api/siem/incidents/'+workflow+'/history')
    try:
        # ELK interruption: the case remains readable while evidence explicitly reports unavailable.
        docker('stop','--timeout','20','flare-otp-local-elasticsearch-1');stopped.add('flare-otp-local-elasticsearch-1')
        query=urllib.parse.urlencode({'from':(datetime.now(timezone.utc)-timedelta(minutes=5)).replace(tzinfo=None).isoformat(),'to':datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
        unavailable=c.request('GET','/api/siem/evidence?'+query);assert unavailable['source_status']=='UNAVAILABLE'
        assert c.request('GET','/api/siem/incidents/'+workflow)==detail
        assert c.request('GET','/api/siem/incidents/'+workflow+'/history')==history
        traces=[]
        for _ in range(3):
            with urllib.request.urlopen('http://127.0.0.1:8088/api/health',timeout=10) as response:assert response.status==200;traces.append(response.headers['X-Request-ID'])
        docker('start','flare-otp-local-elasticsearch-1');stopped.remove('flare-otp-local-elasticsearch-1');healthy('flare-otp-local-elasticsearch-1')
        start=time.monotonic();observed=set()
        while time.monotonic()-start<120:
            for trace in traces:
                if trace in observed:continue
                data=live.es('POST','/logs-nginx.access-lab/_search',{'size':10,'query':{'term':{'trace.id':trace}}})['hits']['hits']
                if data:assert len(data)==1;observed.add(trace)
            if len(observed)==len(traces):break
            time.sleep(2)
        assert len(observed)==3,'Events lost or not replayed after Elasticsearch recovery'
        live.publish('live-elastic-outage-recovery-contract.json',{'status':'ELASTIC_OUTAGE_NOTES_AND_QUEUE_REPLAY_PASS','case_notes_history_readable_during_outage':True,'evidence_unavailable_explicit':True,'requests_during_outage':3,'recovered_unique_traces':3,'queues_or_registry_reset':False,'database_restored':False})
        # Redis interruption: prior authenticated requests fail closed and data survives restart.
        docker('stop','--timeout','15','flare-otp-local-redis-1');stopped.add('flare-otp-local-redis-1')
        try:c.request('GET','/api/siem/status');raise AssertionError('Authenticated API accepted while Redis unavailable')
        except urllib.error.HTTPError as error:assert error.code in (401,403,500,503)
        docker('start','flare-otp-local-redis-1');stopped.remove('flare-otp-local-redis-1');healthy('flare-otp-local-redis-1',60)
        c=live.client('l1');l2=live.client('l2')
        assert c.request('GET','/api/siem/incidents/'+workflow)==detail
        assert c.request('GET','/api/siem/incidents/'+workflow+'/history')==history
        live.publish('live-redis-outage-recovery-contract.json',{'status':'REDIS_OUTAGE_FAIL_CLOSED_AND_RECOVERY_PASS','authenticated_api_failed_closed':True,'case_notes_history_preserved':True,'existing_redis_container_and_volume_retained':True,'credentials_changed':False})
        # Commit/publish/ACK boundary: create a controlled timed block, then stop backend
        # before its next pull ACK. SQL outbox is retained and applied after restart.
        pending_observed=False
        for address in ['9.9.9.9','149.112.112.112']:
            block=l2.request('POST','/api/siem/ip-blocks',{'ip_address':address,'duration_minutes':15,'reason':'SOC-PRACTICE durable policy outbox acceptance; no external traffic.'});blocks.append(block)
            docker('stop','--timeout','20','flare-otp-local-app-1');stopped.add('flare-otp-local-app-1')
            pending=ops.sql('SELECT COUNT(*) FROM siem_ip_blocks b JOIN siem_prevention_policies p ON p.version=b.published_policy_version WHERE b.id='+literal(block['id'])+' AND p.acknowledged_at IS NULL;').decode().strip()=='1'
            docker('start','flare-otp-local-app-1');stopped.remove('flare-otp-local-app-1');healthy('flare-otp-local-app-1')
            l2=live.client('l2');start=time.monotonic()
            while time.monotonic()-start<10:
                value=l2.request('GET','/api/siem/prevention/status')
                if value['gateway_state']=='APPLIED' and value['published_version']==value['applied_version']:break
                time.sleep(.5)
            else:raise RuntimeError('Outbox did not ACK after backend recovery')
            if pending:pending_observed=True;break
        assert pending_observed,'Did not capture a pre-ACK outbox boundary'
        for block in blocks:
            l2.request('POST','/api/siem/prevention/blocks/'+block['id']+'/revoke',{'request_id':str(uuid.uuid4()),'expected_version':block['version'],'reason':'SOC-PRACTICE outbox recovered and ACK confirmed; release controlled block.','outcome':'RISK_ACCEPTED'})
        start=time.monotonic()
        while time.monotonic()-start<10:
            if l2.request('GET','/api/siem/prevention/status')['gateway_state']=='APPLIED':break
            time.sleep(.5)
        else:raise RuntimeError('Revoke did not ACK after recovery')
        assert ops.fingerprint()==before,'Protected state changed during recovery tests'
        live.publish('live-policy-outbox-recovery-contract.json',{'status':'COMMIT_PUBLISH_ACK_OUTBOX_RESTART_PASS','pending_outbox_observed_before_backend_restart':True,'no_pending_state_claimed_applied':True,'ack_recovered_after_restart':True,'controlled_blocks_released':True,'protected_state_unchanged':True})
    finally:
        for name in stopped:
            try:docker('start',name)
            except Exception:pass
        for connection in (c,l2):
            try:connection.request('POST','/api/auth/logout',{})
            except Exception:pass

if __name__=='__main__':main()
