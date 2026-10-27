"""Loopback HTTP, fault and soak acceptance; no application stack or extra fits."""
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from collections import deque
import gzip
import json
import math
import os
from pathlib import Path
import resource
import socket
import threading
import time
import urllib.error
import urllib.request

import numpy as np
import uvicorn
from .auth_extensions_core import read_json,write_new,sha
from .auth_extensions_http import ModelRegistry,create_app,Circuit,IntegrityError


def sample_packets(folder):
    packets=[]
    for cohort in ('ready','cold'):
        found=[]
        with gzip.open(folder/(cohort+'.jsonl.gz'),'rt') as source:
            for line in source:
                if len(line)>65536:raise ValueError('oversized sample')
                row=json.loads(line);packet=row.get('snapshot')
                if row['status']=='OBSERVED' and packet and packet['baseline_established']==(cohort=='ready'):
                    found.append(packet)
                    if len(found)==32:break
        if len(found)!=32:raise ValueError('insufficient covered samples')
        packets.append(found)
    return [p for pair in zip(*packets) for p in pair]


@contextmanager
def server(registry):
    app=create_app(registry);sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(128)
    port=sock.getsockname()[1]
    service=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,loop='asyncio',
                                        log_level='error',access_log=False,lifespan='on'))
    thread=threading.Thread(target=lambda:service.run(sockets=[sock]),daemon=True);thread.start()
    deadline=time.monotonic()+10
    while not service.started:
        if not thread.is_alive() or time.monotonic()>deadline:raise RuntimeError('HTTP prototype failed startup')
        time.sleep(.01)
    try:yield f'http://127.0.0.1:{port}',app.state.service
    finally:
        service.should_exit=True;thread.join(timeout=10);sock.close()
        if thread.is_alive():raise RuntimeError('HTTP prototype did not stop')


def request(url,packets,*,raw=None):
    body=json.dumps({'snapshots':packets},separators=(',',':')).encode() if raw is None else raw
    req=urllib.request.Request(url+'/lab/assess',data=body,headers={'Content-Type':'application/json'},method='POST')
    started=time.perf_counter()
    try:
        with urllib.request.urlopen(req,timeout=3) as response:
            encoded=response.read(1024**2+1)
            if len(encoded)>1024**2:raise ValueError('response exceeded bound')
            return response.status,json.loads(encoded),(time.perf_counter()-started)*1000
    except urllib.error.HTTPError as error:return error.code,{},(time.perf_counter()-started)*1000


def expected_for(registry,packets):
    result={}
    for start in range(0,len(packets),32):
        for row in registry.assess_batch(packets[start:start+32]):result[row['snapshot_id']]=row
    return result


def check_response(status,body,packets,expected):
    if status!=200 or body.get('scope')!='OFFLINE_RESEARCH_ONLY':raise ValueError('HTTP assessment failed')
    results=body['assessments']
    if [x['snapshot_id'] for x in results]!=[p['snapshot_id'] for p in packets]:raise ValueError('HTTP IDs reordered/lost')
    if any(body['candidate_side_effects'].values()):raise ValueError('unexpected side effect')
    for result in results:
        original=expected[result['snapshot_id']]
        if result['recommendation']!=original['recommendation'] or result['context']!=original['context']:
            raise ValueError('HTTP recommendation differs')
        if result['raw_score'] is not None and not math.isclose(result['raw_score'],original['raw_score'],rel_tol=1e-12,abs_tol=1e-12):
            raise ValueError('HTTP score differs')


def packet_batch(pool,size,offset):return [pool[(offset+i)%len(pool)] for i in range(size)]
def rss():return int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('VmRSS:')))*1024


def fault_tests(registry,packets):
    outcomes={};expected=expected_for(registry,packets)
    with server(registry) as (url,service):
        status,body,_=request(url,packets[:8]);check_response(status,body,packets[:8],expected);outcomes['mapping']='PASS'
        for name,raw,code in [('duplicate',None,400),('envelope',b'{}',400),('oversized',b'x'*(512*1024+1),413)]:
            status,_,_=request(url,[packets[0],packets[0]],raw=raw)
            if status!=code:raise ValueError('fault response differs: '+name)
            outcomes[name]='PASS'
        broken=deepcopy(packets[0]);broken['coverage']['otp_history']=False
        status,body,_=request(url,[broken,packets[1]])
        if status!=200 or body['assessments'][0]['recommendation']!='UNDETERMINED':raise ValueError('invalid item not isolated')
        if body['assessments'][1]['recommendation']!=expected[packets[1]['snapshot_id']]['recommendation']:raise ValueError('valid sibling lost')
        outcomes['missing_coverage']='PASS'
        original=service.registry
        class Fault:
            mode='reverse'
            def assess_batch(self,items):
                if self.mode=='error':raise RuntimeError('injected inference failure')
                if self.mode=='integrity':raise IntegrityError('injected checksum mismatch')
                if self.mode=='timeout':time.sleep(2.2)
                result=original.assess_batch(items)
                if self.mode=='identity':result[0]['snapshot_id']='unexpected-snapshot'
                return list(reversed(result)) if self.mode=='reverse' else result
        fault=Fault();service.registry=fault
        status,body,_=request(url,packets[:8]);check_response(status,body,packets[:8],expected);outcomes['response_reordering']='PASS'
        for mode in ('identity','error','integrity','timeout'):
            fault.mode=mode;service.circuit=Circuit()
            status,body,_=request(url,packets[:1])
            if status!=200 or body['assessments'][0]['recommendation']!='UNDETERMINED':raise ValueError('fault not contained: '+mode)
            outcomes[mode]='PASS'
            if mode=='timeout':time.sleep(.3)
        fault.mode='error';service.circuit=Circuit()
        for _ in range(5):request(url,packets[:1])
        if service.circuit.state()!='OPEN':raise ValueError('circuit did not open')
        fault.mode='reverse';now=time.monotonic();service.circuit.clock=lambda:now+31
        request(url,packets[:1])
        if service.circuit.state()!='CLOSED':raise ValueError('half-open did not recover')
        outcomes['circuit']='PASS';service.registry=original
        # Capacity/cancellation tests target the queue only, never model state.
        old_capacity=service.capacity;service.capacity=1
        if request(url,packets[:2])[0]!=503:raise ValueError('overload not bounded')
        service.capacity=old_capacity;outcomes['overload']='PASS'
    return {'status':'HTTP_FAULT_PASS','scenarios':outcomes,'new_fits':0}


def benchmark(registry,pool):
    expected=expected_for(registry,pool);results=[]
    with server(registry) as (url,service),ThreadPoolExecutor(max_workers=4) as executor:
        for size in (1,8,32):
            for concurrency in (1,2,4):
                timings=[]
                def call(i):
                    packets=packet_batch(pool,size,i*size)
                    status,body,elapsed=request(url,packets);check_response(status,body,packets,expected)
                    return elapsed
                for phase,count in (('warmup',100),('measured',1000)):
                    for start in range(0,count,concurrency):
                        values=list(executor.map(call,range(start,min(start+concurrency,count))))
                        if phase=='measured':timings.extend(values)
                entry={'batch':size,'concurrency':concurrency,'warmup':100,'measured':1000,
                       'p95_ms':float(np.percentile(timings,95)),'maximum_ms':max(timings)}
                results.append(entry);print(json.dumps({'phase':'HTTP_BENCHMARK',**entry}),flush=True)
        numeric={}
        for size in (1,8,32):
            packets=pool[:size]
            for _ in range(100):registry.assess_batch(packets)
            times=[]
            for _ in range(1000):
                at=time.perf_counter();registry.assess_batch(packets);times.append((time.perf_counter()-at)*1000)
            numeric[str(size)]={'p95_ms':float(np.percentile(times,95)),'includes':'integrity, projection, inference, diagnostics and monitor'}
    peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
    passed=(peak<=448*1024**2 and numeric['32']['p95_ms']<=100
            and next(x['p95_ms'] for x in results if x['batch']==32 and x['concurrency']==4)<=250)
    return {'status':'HTTP_LAB_PASS' if passed else 'HTTP_NO_ADMISSION','results':results,
            'model_adapter':numeric,'maximum_rss_bytes':peak,'new_fits':0}


def soak(registry,pool,seconds=3600):
    if seconds!=3600:raise ValueError('qualification requires exactly one hour')
    expected=expected_for(registry,pool);samples=[];latency={str(n):deque(maxlen=4096) for n in (1,8,32)}
    start=time.monotonic();next_sample=start;rounds=0
    with server(registry) as (url,service),ThreadPoolExecutor(max_workers=4) as executor:
        while time.monotonic()-start<seconds:
            size=(1,8,32)[rounds%3]
            def call(offset):
                packets=packet_batch(pool,size,offset)
                status,body,elapsed=request(url,packets);check_response(status,body,packets,expected);return elapsed
            values=list(executor.map(call,[rounds*4+i for i in range(4)]));latency[str(size)].extend(values);rounds+=1
            if time.monotonic()>=next_sample:
                sample={'seconds':round(time.monotonic()-start,2),'rss_bytes':rss(),'pending':service.pending}
                samples.append(sample);next_sample+=5
                if sample['rss_bytes']>448*1024**2:raise RuntimeError('SOAK_MEMORY_LIMIT')
                if len(samples)%12==0:print(json.dumps({'phase':'SOAK','sample':sample,'rounds':rounds}),flush=True)
            time.sleep(.2)
    first=[x['rss_bytes'] for x in samples if 1800<=x['seconds']<2100]
    last=[x['rss_bytes'] for x in samples if 3300<=x['seconds']<=3605]
    if not first or not last:raise RuntimeError('incomplete soak windows')
    growth=float(np.median(last)/np.median(first)-1)
    peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
    return {'status':'SOAK_LAB_PASS' if growth<=.05 and peak<=448*1024**2 else 'SOAK_NO_ADMISSION',
            'continuous_seconds':round(time.monotonic()-start,2),'sample_count':len(samples),
            'samples':samples,'rss_growth_fraction':growth,'maximum_rss_bytes':peak,'http_requests':rounds*4,
            'rolling_last_4096_p95_ms':{k:float(np.percentile(v,95)) for k,v in latency.items()},'new_fits':0}


def main():
    if os.environ.get('AUTH_RESEARCH_SUPERVISED')!='1':raise SystemExit('bounded supervisor required')
    p=argparse.ArgumentParser();p.add_argument('stage',choices=('http-test','benchmark','soak'))
    for name in ('bundle','baseline','samples','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();registry=ModelRegistry(a.bundle,a.baseline);pool=sample_packets(a.samples)
    path=a.output/(a.stage+'-started.json');write_new(path,{'status':'RESERVED','bundle_sha256':sha(a.bundle),'at':time.time()})
    result=fault_tests(registry,pool) if a.stage=='http-test' else benchmark(registry,pool) if a.stage=='benchmark' else soak(registry,pool)
    result.update(scope='OFFLINE_RESEARCH_ONLY',bundle_sha256=sha(a.bundle),automatic_enforcement=False,strict_production_qualified=False)
    write_new(a.output/(a.stage+'-receipt.json'),result);print(json.dumps({k:v for k,v in result.items() if k!='samples'}),flush=True)


if __name__=='__main__':main()
