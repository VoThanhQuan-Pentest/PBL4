#!/usr/bin/env python3
"""Bounded local SIEM acceptance. Fixtures are explicit SOC-PRACTICE data, never model input."""
import argparse
from datetime import datetime,timedelta,timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'audit-results/siem-upgrade-20261023'
ES='flare-otp-local-elasticsearch-1'

def es(method,path,body=None):
    if not path.startswith(('/logs-','/.ds-logs-','/_index_template/','/_cluster/','/_search','/_pit')):
        raise ValueError('Unsupported local acceptance endpoint')
    program=('exec curl --fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt '
             '--user "elastic:$(cat /run/flare-secrets/elasticsearch.password)" -X "$1" '
             '--header "Content-Type: application/json" --data-binary @- "https://localhost:9200$2"')
    payload=b'' if body is None else body.encode() if isinstance(body,str) else json.dumps(body,ensure_ascii=False).encode()
    result=subprocess.run(['docker','exec','-i',ES,'sh','-ceu',program,'acceptance',method,path],input=payload,capture_output=True,timeout=20)
    if result.returncode:raise RuntimeError('Local ES acceptance request failed: '+str(result.returncode))
    return json.loads(result.stdout,parse_float=Decimal)

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def client(role='l1'):
    demo=module('acceptance_demo','observability/scripts/local-soc-demo.py');demo.ORIGIN='http://127.0.0.1:8089'
    c=demo.client();c.login(demo.ACCOUNTS[role]);return c

def get_exact(c,path):
    request=urllib.request.Request(c.origin+path,headers={'Accept':'application/json'})
    with c.opener.open(request,timeout=20) as response:
        body=response.read(16*1024*1024+1)
    if len(body)>16*1024*1024:raise RuntimeError('Raw evidence exceeds acceptance response budget')
    return json.loads(body,parse_float=Decimal)

def publish(name,value):
    OUT.mkdir(exist_ok=True,parents=True);path=OUT/name
    if path.exists():raise RuntimeError('Acceptance receipt exists; reconcile instead of overwriting '+name)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n');print(json.dumps(value,ensure_ascii=False),flush=True)

def mappings():
    names={'nginx-access.json':'flare-nginx-access','flare-security.json':'flare-security-events','flare-prevention.json':'flare-prevention-events'}
    for filename,name in names.items():
        body=json.loads((ROOT/'observability/elasticsearch/templates'/filename).read_text());es('PUT','/_index_template/'+name,body)
    es('PUT','/logs-flare.security-lab/_mapping',{'properties':{'user':{'properties':{'name':{'type':'keyword'}}},'observer':{'properties':{'type':{'type':'keyword'}}}}})
    es('PUT','/logs-flare.prevention-lab/_mapping',{'properties':{'destination':{'properties':{'ip':{'type':'ip'},'port':{'type':'integer'}}},'observer':{'properties':{'type':{'type':'keyword'}}},'flare':{'properties':{'prevention':{'properties':{'provenance':{'type':'keyword'}}}}}}})
    # Existing dynamic server fields can have historical text/long mappings. A rollover
    # applies the new ECS types only to new documents, without reindexing or rewriting old hits.
    rollover=es('POST','/logs-nginx.access-lab/_rollover',{})
    health=es('GET','/_cluster/health')
    assert health['status']!='red' and not health.get('unassigned_primary_shards',0)
    publish('live-mapping-contract.json',{'status':'ADDITIVE_TEMPLATES_AND_MAPPING_PASS','new_access_write_index':rollover.get('new_index'),'historical_documents_modified':False,'elasticsearch_status':health['status']})

def trace():
    begin=time.monotonic()
    with urllib.request.urlopen('http://127.0.0.1:8088/api/health',timeout=10) as response:
        assert response.status==200;trace=response.headers['X-Request-ID']
    from_time=(datetime.now(timezone.utc)-timedelta(minutes=2)).replace(tzinfo=None).isoformat()
    c=client()
    try:
        while time.monotonic()-begin<60:
            q=urllib.parse.urlencode({'from':from_time,'to':datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),'traceId':trace,'dataset':'nginx.access','size':100})
            page=get_exact(c,'/api/siem/evidence?'+q)
            if page['source_status']=='AVAILABLE' and page['content']:
                assert len(page['content'])==1
                hit=page['content'][0]['elk_hit'];source=hit['_source']
                assert source['server']['ip'] and isinstance(source['server']['port'],int)
                assert source['observer']['type']=='nginx'
                direct=es('GET','/'+hit['_index']+'/_doc/'+hit['_id'])
                assert direct['_source']==source
                publish('live-trace-contract.json',{'status':'LIVE_MAIN_APPLICATION_TRACE_PASS','latency_seconds':round(time.monotonic()-begin,3),'matching_events':1,'native_source_equal':True,'observed_server_ip_port':True,'origin':'gateway_nginx_main_otp_application'})
                return
            time.sleep(2)
        raise RuntimeError('Trace did not reach ELK/API within 60 seconds')
    finally:c.request('POST','/api/auth/logout',{})

def append_fixture(container,user,path,payload):
    command='umask 027; cat >> "$1"'
    subprocess.run(['docker','exec','-i','--user',user,container,'sh','-ceu',command,'fixture',path],input=(payload+'\n').encode(),check=True,capture_output=True,timeout=10)

def precision_geo():
    ids={name:uuid.uuid4().hex for name in ('precision','public','private','test_net')}
    now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    item={'@timestamp':now,'event':{'id':ids['precision'],'dataset':'flare.security','type':'PRACTICE_ACCEPTANCE','action':'SOC_PRACTICE_RAW_PARITY','outcome':'SUCCESS'},'trace':{'id':ids['precision']},'source':{'ip':'127.0.0.1'},'observer':{'type':'acceptance_fixture'},'flare':{'synthetic':True,'demo_label':'SOC-PRACTICE-RAW-PARITY'},'acceptance':{'unicode':'Tiếng Việt 👩‍💻','huge':123456789012345678901234567890,'decimal':'__DECIMAL__','nested':{'array':[None,True,1,'x',{'dotted.key':'kept'}]},'empty':[]}}
    raw=json.dumps(item,ensure_ascii=False).replace('"__DECIMAL__"','0.123456789012345678901234567890')
    # Decimal precision is tested at the ES/API contract boundary. Filebeat/Logstash
    # parse ordinary JSON numbers as IEEE doubles before storage; never claim those
    # rounded producer values were changed by the evidence API.
    es('POST','/logs-flare.security-lab/_doc',raw)
    for name,address in [('public','8.8.8.8'),('private','10.23.45.67'),('test_net','203.0.113.17')]:
        value={'@timestamp':now,'trace.id':ids[name],'source.ip':address,'http.request.method':'GET','http.response.status_code':200,'http.request.bytes':100,'http.response.body.bytes':100,'event.duration_seconds':0.001,'url.path':'/soc-practice/geoip-fixture','observer.type':'acceptance_fixture','flare.synthetic':True,'flare.demo_label':'SOC-PRACTICE-GEOIP-FIXTURE'}
        append_fixture('flare-otp-local-nginx-1','101:1000','/var/log/nginx/access.json.log',json.dumps(value))
    c=client();begin=time.monotonic();found={}
    try:
        while time.monotonic()-begin<60:
            for name,trace in ids.items():
                if name in found:continue
                q=urllib.parse.urlencode({'from':(datetime.now(timezone.utc)-timedelta(minutes=3)).replace(tzinfo=None).isoformat(),'to':datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),'traceId':trace,'size':100})
                page=get_exact(c,'/api/siem/evidence?'+q)
                if page['source_status']=='AVAILABLE' and len(page['content'])==1:found[name]=page['content'][0]['elk_hit']
            if len(found)==4:break
            time.sleep(2)
        assert len(found)==4,'Practice fixtures did not arrive within 60 seconds'
        for hit in found.values():
            direct=es('GET','/'+hit['_index']+'/_doc/'+hit['_id']);assert direct['_source']==hit['_source']
        precision=found['precision']['_source']['acceptance']
        assert precision['huge']==123456789012345678901234567890
        assert precision['decimal']==Decimal('0.123456789012345678901234567890')
        assert precision['unicode']==item['acceptance']['unicode'] and precision['nested']==item['acceptance']['nested'] and precision['empty']==[]
        assert 'location' in found['public']['_source']['source']['geo']
        for name,scope in [('private','private'),('test_net','test_net')]:
            source=found[name]['_source'];assert source['flare']['source_ip_scope']==scope
            assert 'location' not in source.get('source',{}).get('geo',{})
        publish('live-precision-geo-contract.json',{'status':'LIVE_NATIVE_PRECISION_AND_GEOIP_PASS','fixture_scope':'SOC-PRACTICE: Elasticsearch-native exact-number fixture plus Filebeat GeoIP fixtures; never model input or recurrence strikes','deep_source_equality':True,'large_integer_exact':True,'decimal_exact':True,'unicode_null_nested_arrays_preserved':True,'public_city_location_enriched':True,'private_test_net_have_no_fake_coordinates':True,'model_scores_requested':0})
        private=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1/live-fixture-refs.private.json'
        private.write_text(json.dumps({name:{'index':h['_index'],'id':h['_id']} for name,h in found.items()}));os.chmod(private,0o600)
    finally:c.request('POST','/api/auth/logout',{})

def policy_restart():
    c=client('l2');l1=client('l1');folder=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'
    block=None;backend_stopped=False
    def ack(deadline=10):
        start=time.monotonic()
        while time.monotonic()-start<deadline:
            status=c.request('GET','/api/siem/prevention/status')
            if status['gateway_state']=='APPLIED' and status['published_version']==status['applied_version']:
                return round(time.monotonic()-start,3)
            time.sleep(.5)
        raise RuntimeError('Healthy gateway did not ACK within 10 seconds')
    def healthy(name,seconds=180):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            state=json.loads(subprocess.check_output(['docker','inspect',name]))[0]['State']
            if state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy':return
            time.sleep(2)
        raise RuntimeError('Container health deadline: '+name)
    try:
        start=time.monotonic()
        block=c.request('POST','/api/siem/ip-blocks',{'ip_address':'8.8.8.8','duration_minutes':15,'reason':'SOC-PRACTICE policy/cache acceptance only; no external traffic.'})
        apply_ack=ack();assert time.monotonic()-start<=10
        try:
            l1.request('POST','/api/siem/prevention/blocks/'+block['id']+'/revoke',{'request_id':str(uuid.uuid4()),'expected_version':block['version'],'reason':'SOC-PRACTICE verify L1 cannot release a block.','outcome':'RISK_ACCEPTED'})
            raise AssertionError('L1 response action was accepted')
        except urllib.error.HTTPError as error:assert error.code==403
        before=folder/'gateway-policy-before.private.json';after=folder/'gateway-policy-after.private.json'
        subprocess.run(['docker','cp','flare-otp-local-gateway-1:/var/log/flare/gateway-policy.json',str(before)],capture_output=True,check=True,timeout=15);before.chmod(0o600)
        policy=json.loads(before.read_text());payload=json.loads(policy['policy_json'])
        assert any(value['id']==block['id'] for value in payload['blocks'])
        subprocess.run(['docker','stop','--timeout','20','flare-otp-local-app-1'],capture_output=True,check=True,timeout=40);backend_stopped=True
        subprocess.run(['docker','restart','--timeout','15','flare-otp-local-gateway-1'],capture_output=True,check=True,timeout=30)
        healthy('flare-otp-local-gateway-1',45)
        with urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=5) as response:
            health=json.load(response);assert health['policy_version']==policy['version'] and health['durable_policy'] is True
        subprocess.run(['docker','cp','flare-otp-local-gateway-1:/var/log/flare/gateway-policy.json',str(after)],capture_output=True,check=True,timeout=15);after.chmod(0o600)
        assert json.loads(before.read_text())==json.loads(after.read_text())
        subprocess.run(['docker','start','flare-otp-local-app-1'],capture_output=True,check=True,timeout=20);backend_stopped=False
        healthy('flare-otp-local-app-1')
        c=client('l2')
        release_start=time.monotonic()
        revoked=c.request('POST','/api/siem/prevention/blocks/'+block['id']+'/revoke',{'request_id':str(uuid.uuid4()),'expected_version':block['version'],'reason':'SOC-PRACTICE cache/restart verified; release controlled temporary block.','outcome':'RISK_ACCEPTED'})
        assert revoked['revoked_at'];release_ack=ack();assert time.monotonic()-release_start<=10
        publish('live-policy-restart-contract.json',{'status':'LIVE_POLICY_ACK_CACHE_RESTART_AND_REVOKE_PASS','create_ack_wait_seconds':apply_ack,'revoke_ack_wait_seconds':release_ack,'policy_preserved_with_backend_unavailable':True,'gateway_restarted':True,'l1_direct_response_api_rejected':True,'test_target':'Controlled manual temporary block; no external traffic','until_revoked_behavior':'Covered by controlled-clock backend and gateway restart tests; private/local IPs never qualify for escalation'})
    finally:
        if backend_stopped:subprocess.run(['docker','start','flare-otp-local-app-1'],capture_output=True,timeout=20)
        for connection in (c,l1):
            try:connection.request('POST','/api/auth/logout',{})
            except Exception:pass

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('mappings','trace','precision-geo','policy-restart'))
    args=parser.parse_args();{'mappings':mappings,'trace':trace,'precision-geo':precision_geo,'policy-restart':policy_restart}[args.phase]()
