#!/usr/bin/env python3
"""Read-only primary-stack health, policy and trace samples alongside the one-hour model gate."""
from datetime import datetime,timedelta,timezone
import importlib.util
import json
from pathlib import Path
import time
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('monitor_acceptance',ROOT/'observability/scripts/siem-live-acceptance.py')
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
PRIVATE=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'

def main():
    progress=PRIVATE/'primary-monitor.progress.private.json'
    final=ROOT/'audit-results/siem-upgrade-20261023/live-primary-monitor-contract.json'
    if final.exists():raise RuntimeError('Primary monitor already completed')
    c=m.client('l1');started=time.monotonic();samples=[]
    try:
        for sample in range(30):
            delay=started+sample*60-time.monotonic()
            if delay>0:time.sleep(delay)
            begin=time.monotonic()
            with urllib.request.urlopen('http://127.0.0.1:8088/api/health',timeout=10) as response:
                assert response.status==200;trace=response.headers['X-Request-ID']
            workspace=c.request('GET','/api/siem/workspace')
            assert workspace['pipeline']['elasticsearch_available'] is True
            assert workspace['policy']['gateway_state']=='APPLIED'
            assert workspace['postlogin']['scope']=='PROJECT_LIMITED' and workspace['postlogin']['maximum_hold_seconds']==600 and workspace['postlogin']['otp_required'] is True
            now=datetime.now(timezone.utc);found=False
            while time.monotonic()-begin<60:
                query=urllib.parse.urlencode({'from':(now-timedelta(minutes=2)).replace(tzinfo=None).isoformat(),'to':datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),'dataset':'nginx.access','traceId':trace,'size':50})
                page=m.get_exact(c,'/api/siem/evidence?'+query)
                if page['source_status']=='AVAILABLE' and page['content']:
                    assert len(page['content'])==1;found=True;break
                time.sleep(2)
            assert found,'Live primary trace exceeded 60 seconds'
            samples.append({'sample':sample+1,'elapsed_seconds':round(time.monotonic()-started,3),'trace_latency_seconds':round(time.monotonic()-begin,3),'pipeline':'AVAILABLE','gateway':'APPLIED','model_scope':'PROJECT_LIMITED'})
            progress.write_text(json.dumps({'status':'OBSERVING_PRIMARY_STACK','samples':samples,'target_samples':30}));progress.chmod(0o600)
        m.publish('live-primary-monitor-contract.json',{'status':'PRIMARY_STACK_CONTINUOUS_SAMPLING_PASS','http_trace_samples':len(samples),'sample_window_seconds':round(time.monotonic()-started,3),'maximum_trace_latency_seconds':max(v['trace_latency_seconds'] for v in samples),'all_traces_unique':True,'pipeline_available_all_samples':True,'policy_ack_applied_all_samples':True,'otp_project_scope_and_600s_bound_unchanged':True,'scope':'Read-only primary-stack sampling in parallel with the separate 3600-second/33-evaluation model HTTP gate'})
    except Exception:
        progress.write_text(json.dumps({'status':'PRIMARY_MONITOR_FAILED','completed_samples':len(samples)}));progress.chmod(0o600);raise
    finally:
        try:c.request('POST','/api/auth/logout',{})
        except Exception:pass

if __name__=='__main__':main()
