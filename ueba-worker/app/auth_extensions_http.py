"""Isolated HTTP laboratory. Never imported or registered by production main.py."""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
import math
from pathlib import Path
import re
import time

import numpy as np
from fastapi import FastAPI,HTTPException,Request
from scipy.special import logsumexp

from .auth_extensions_core import read_json,sha,project,logits,validate_state
from .auth_extensions_diagnostics import diagnostics,BoundedMonitor,StreamingDrift
from .postlogin_serving import ProjectPostloginModel

CONTEXTS=('ROUTINE_CONTEXT','BEHAVIOR_REVIEW_CONTEXT','SERVICE_DEGRADATION_CONTEXT')
BASELINE_SHA='7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784'


def und(packet,reason):
    return {'snapshot_id':packet.get('snapshot_id'),'recommendation':'UNDETERMINED','context':None,
            'raw_score':None,'diagnostics':{'confidence':None,'confidence_status':'UNAVAILABLE',
            'confidence_method':'NONE','confidence_scope':'LAB_CONTEXT_ONLY','reason_codes':[reason],
            'evidence_summary':[]}}


class IntegrityError(ValueError):pass


class ModelRegistry:
    def __init__(self,bundle,baseline_dir):
        self.path=Path(bundle);self.root=self.path.parent;self.expected=sha(self.path)
        self.manifest=read_json(self.path,65536)
        if self.manifest.get('format')!='AUTH_EXTENSIONS_BUNDLE_V1' or self.manifest.get('scope')!='OFFLINE_RESEARCH_ONLY':
            raise ValueError('offline bundle required')
        self.baseline=ProjectPostloginModel(baseline_dir,BASELINE_SHA);self.models={};self.files={};self.drift={}
        for cohort,item in self.manifest['models'].items():
            if cohort not in ('READY','COLD'):raise ValueError('unknown model role')
            name=item['state_file']
            if type(name) is not str or Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('relative bundle artifact required')
            path=self.root/name
            if any(p.is_symlink() for p in (path,*path.parents)) or sha(path)!=item['state_sha256']:
                raise IntegrityError('model state checksum differs')
            state=validate_state(read_json(path));width=81 if cohort=='READY' else 42
            if state['features']!=width:raise ValueError('model role/width differs')
            threshold=item['threshold']
            if type(threshold) not in (int,float) or not math.isfinite(threshold):raise ValueError('finite threshold required')
            calibrator=item.get('calibrator')
            if calibrator is not None and (calibrator.get('format')!='AUTH_CONTEXT_TEMPERATURE_V1'
                    or calibrator.get('class_order')!=[0,1,2] or type(calibrator.get('temperature')) not in (int,float)
                    or not .25<=calibrator['temperature']<=4):raise ValueError('invalid calibrator')
            self.models[cohort]=(state,item);self.files[path]=item['state_sha256']
            if item.get('drift_file'):
                drift_path=self.root/item['drift_file']
                if drift_path.is_symlink() or drift_path.parent!=self.root or sha(drift_path)!=item.get('drift_sha256'):
                    raise IntegrityError('drift reference differs')
                drift=read_json(drift_path,2*1024**2)
                if drift.get('format')!='AUTH_CONTEXT_DRIFT_OPERATIONS_V1' or set(drift.get('operations',{}))!={'PASSWORD_CHANGE','EMAIL_CHANGE'}:
                    raise ValueError('operation drift reference required')
                self.drift[cohort]={op:StreamingDrift(ref) for op,ref in drift['operations'].items()}
                self.files[drift_path]=item['drift_sha256']
        if 'READY' not in self.models:raise ValueError('READY fallback required')
        self.monitor=BoundedMonitor()

    def verify(self):
        try:
            if sha(self.path)!=self.expected or any(sha(p)!=expected for p,expected in self.files.items()):
                raise IntegrityError('research bundle changed')
            self.baseline.verify_identity()
        except (OSError,ValueError,RuntimeError) as error:raise IntegrityError('model integrity unavailable') from error

    def assess_batch(self,packets):
        self.verify();results=[None]*len(packets);groups={'READY':[],'COLD':[]}
        for i,packet in enumerate(packets):
            try:
                cohort='READY' if packet.get('baseline_established') is True else 'COLD'
                row=project(packet,cohort)
                if cohort not in self.models:results[i]=und(packet,'MODEL_NOT_ADMITTED');continue
                groups[cohort].append((i,packet,row))
            except (ValueError,TypeError,KeyError):results[i]=und(packet,'INVALID_OBSERVATION')
        for cohort,items in groups.items():
            if not items:continue
            state,metadata=self.models[cohort];values=np.vstack([x[2] for x in items])
            raw_logits=logits(state,values);raw=logsumexp(raw_logits[:,1:],axis=1)-raw_logits[:,0]
            novelty=np.full(len(items),np.nan)
            if cohort=='READY':
                novelty=self.baseline.model._normal.anomaly_scores(values[:,:37])
                raw=np.maximum(raw,np.log(novelty+1e-12))
            if not np.isfinite(raw).all() or (np.abs(raw)>1e6).any():raise ValueError('invalid raw score')
            contexts=raw_logits.argmax(axis=1)
            for j,(position,packet,row) in enumerate(items):
                context=int(contexts[j]);recommendation='OPS' if context==2 else 'REVIEW' if context==1 and raw[j]>=metadata['threshold'] else 'ROUTINE'
                info=diagnostics(packet,raw_logits[j],metadata.get('calibrator'),metadata.get('calibration_pass',False))
                info.update(cohort=cohort,model_state_sha256=metadata['state_sha256'],
                            normal_support_novelty=float(novelty[j]) if cohort=='READY' else None)
                if cohort=='COLD':info['reason_codes'].append('NO_QUALIFIED_COLD_SUPPORT')
                results[position]={'snapshot_id':packet['snapshot_id'],'recommendation':recommendation,
                                   'context':CONTEXTS[context],'raw_score':float(raw[j]),'diagnostics':info}
        for packet,result in zip(packets,results):
            cohort='READY' if packet.get('baseline_established') is True else 'COLD'
            values=packet.get('features')
            if (type(values) is list and len(values)==81 and type(values[37]) in (int,float)
                    and type(values[38]) in (int,float) and values[37] in (0,1) and values[38]==1-values[37]):
                operation='PASSWORD_CHANGE' if values[37]==1 else 'EMAIL_CHANGE'
                self.monitor.observe(cohort,operation,result['recommendation'])
                if cohort in self.drift:
                    self.drift[cohort][operation].observe(project(packet,cohort) if result['raw_score'] is not None else None)
        return results

    def metrics(self):
        return {'counts':self.monitor.snapshot(),'drift':{role:{op:v.snapshot() for op,v in refs.items()} for role,refs in self.drift.items()}}


class Circuit:
    def __init__(self,clock=time.monotonic):self.clock=clock;self.failures=0;self.opened=None;self.permanent=False
    def state(self):
        if self.permanent:return 'OPEN'
        if self.opened is None:return 'CLOSED'
        return 'HALF_OPEN' if self.clock()-self.opened>=30 else 'OPEN'
    def success(self):self.failures=0;self.opened=None
    def failure(self,permanent=False):
        self.failures+=1;self.permanent|=permanent
        if permanent or self.failures>=5 or self.opened is not None:self.opened=self.clock()


class BatchService:
    def __init__(self,registry,*,wait=.05,deadline=2.,capacity=256):
        self.registry=registry;self.wait=wait;self.deadline=deadline;self.capacity=capacity
        self.queue=deque();self.pending=0;self.task=None;self.circuit=Circuit();self.closed=False

    async def start(self):self.task=asyncio.create_task(self._worker())
    async def close(self):
        self.closed=True
        if self.task:self.task.cancel()
        if self.task:
            try:await self.task
            except asyncio.CancelledError:pass
        while self.queue:
            item=self.queue.popleft();self._release(item)
            if not item['future'].done():item['future'].set_result(und(item['packet'],'REQUEST_CANCELLED'))

    def _release(self,item):
        if not item['released']:self.pending-=1;item['released']=True

    def _cancel(self,items):
        for item in items:
            item['future'].cancel()
            if not item['inflight']:
                try:self.queue.remove(item)
                except ValueError:pass
                self._release(item)

    async def submit(self,packets):
        if (type(packets) is not list or not 1<=len(packets)<=32
                or any(type(p) is not dict or type(p.get('snapshot_id')) is not str
                       or not re.fullmatch('[a-z0-9_-]{8,128}',p['snapshot_id']) for p in packets)
                or len({p['snapshot_id'] for p in packets})!=len(packets)):
            raise HTTPException(400,'invalid snapshot envelope')
        if self.closed or self.pending+len(packets)>self.capacity:raise HTTPException(503,'OVERLOADED')
        loop=asyncio.get_running_loop();items=[]
        for packet in packets:
            item={'packet':packet,'future':loop.create_future(),'released':False,'inflight':False}
            self.queue.append(item);items.append(item);self.pending+=1
        try:
            return await asyncio.wait_for(asyncio.gather(*(i['future'] for i in items)),self.deadline)
        except asyncio.TimeoutError:
            self._cancel(items);self.circuit.failure()
            return [und(p,'WORKER_TIMEOUT') for p in packets]
        except asyncio.CancelledError:
            self._cancel(items);raise

    async def _worker(self):
        while True:
            await asyncio.sleep(0 if len(self.queue)>=32 else self.wait)
            if not self.queue:continue
            mode=self.circuit.state();limit=1 if mode=='HALF_OPEN' else 32;items=[]
            while self.queue and len(items)<limit:
                item=self.queue.popleft()
                if item['future'].done():self._release(item);continue
                item['inflight']=True;items.append(item)
            if not items:continue
            packets=[i['packet'] for i in items]
            try:
                if mode=='OPEN':results=[und(p,'CIRCUIT_OPEN') for p in packets]
                else:
                    results=await asyncio.to_thread(self.registry.assess_batch,packets)
                    ids=[r.get('snapshot_id') for r in results]
                    if len(ids)!=len(packets) or set(ids)!=set(p['snapshot_id'] for p in packets):
                        raise ValueError('inference result identity mismatch')
                    by_id={r['snapshot_id']:r for r in results};results=[by_id[p['snapshot_id']] for p in packets]
                    if (any(not item['future'].done() for item in items)
                            and any(r.get('raw_score') is not None for r in results)):self.circuit.success()
            except Exception as error:
                self.circuit.failure(isinstance(error,IntegrityError))
                results=[und(p,'MODEL_INTEGRITY_FAILURE' if isinstance(error,IntegrityError) else 'WORKER_UNAVAILABLE') for p in packets]
            finally:
                for item in items:self._release(item)
            for item,result in zip(items,results):
                if not item['future'].done():item['future'].set_result(result)


def create_app(registry):
    service=BatchService(registry)
    @asynccontextmanager
    async def lifespan(_app):
        await service.start()
        try:yield
        finally:await service.close()
    app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    app.state.service=service
    @app.get('/health')
    def health():return {'scope':'OFFLINE_RESEARCH_ONLY','pending':service.pending,'circuit':service.circuit.state()}
    @app.get('/lab/metrics')
    def metrics():return registry.metrics() if hasattr(registry,'metrics') else {'scope':'TEST_FIXTURE'}
    @app.post('/lab/assess')
    async def assess(request:Request):
        length=request.headers.get('content-length')
        if length is not None:
            if not length.isdigit() or len(length)>12:raise HTTPException(400,'invalid content length')
            if int(length)>512*1024:raise HTTPException(413,'payload too large')
        chunks=[];size=0
        async for chunk in request.stream():
            size+=len(chunk)
            if size>512*1024:raise HTTPException(413,'payload too large')
            chunks.append(chunk)
        body=b''.join(chunks)
        import json
        try:payload=json.loads(body)
        except (ValueError,UnicodeError):raise HTTPException(400,'invalid JSON') from None
        if type(payload) is not dict or set(payload)!={'snapshots'}:raise HTTPException(400,'invalid envelope')
        task=asyncio.create_task(service.submit(payload['snapshots']))
        try:
            while not task.done():
                if await request.is_disconnected():task.cancel();raise HTTPException(499,'request cancelled')
                await asyncio.sleep(.005)
            values=await task
        finally:
            if not task.done():task.cancel()
        return {'scope':'OFFLINE_RESEARCH_ONLY','assessments':values,
                'candidate_side_effects':{'holds':0,'incidents':0,'ip_blocks':0,'session_revocations':0,'policy_publications':0}}
    return app
