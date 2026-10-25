"""Optional, separately pinned SHADOW loader. The accepted baseline remains resident and authoritative."""
from datetime import datetime,timezone,timedelta
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import numpy as np
from .auth_shadow_contract import FEATURE_NAMES,validate
from .auth_shadow_model import MAX_BYTES,validate_state,score_components
from .postlogin_contract import LABELS
from .postlogin_serving import configured_model,load_bytes

class AuthShadowModel:
    def __init__(self, directory, expected):
        self.directory=Path(directory).absolute()
        if not re.fullmatch('[a-f0-9]{64}',expected or '') or any(p.is_symlink() for p in [self.directory,*self.directory.parents]):raise ValueError('pinned private shadow directory required')
        manifest_bytes=load_bytes(self.directory,'manifest.json',32768)
        if hashlib.sha256(manifest_bytes).hexdigest()!=expected:raise ValueError('shadow manifest differs')
        self.manifest=json.loads(manifest_bytes);self.sha=expected
        required={'format','scope','mode','feature_schema_version','feature_names','state_sha256','baseline_manifest_sha256','threshold','admission_sha256'}
        if set(self.manifest)!=required or self.manifest['format']!='AUTH_SHADOW_MANIFEST_V1' or self.manifest['scope']!='PILOT_ONLY' or self.manifest['mode']!='SHADOW' or self.manifest['feature_schema_version']!=7 or self.manifest['feature_names']!=list(FEATURE_NAMES):raise ValueError('unqualified shadow-only manifest required')
        self.baseline=configured_model()
        if self.manifest['baseline_manifest_sha256']!=self.baseline.manifest_sha256:raise ValueError('baseline pin mismatch')
        state_bytes=load_bytes(self.directory,'model-state.json',MAX_BYTES)
        admission_bytes=load_bytes(self.directory,'admission.json',32768)
        if hashlib.sha256(state_bytes).hexdigest()!=self.manifest['state_sha256'] or hashlib.sha256(admission_bytes).hexdigest()!=self.manifest['admission_sha256']:raise ValueError('shadow component identity differs')
        admission=json.loads(admission_bytes)
        if type(admission) is not dict:raise ValueError('typed admission receipt required')
        if admission.get('status')!='SHADOW_READY' or admission.get('strict_production_qualified') is not False or admission.get('automatic_enforcement') is not False or admission.get('baseline_manifest_sha256')!=self.baseline.manifest_sha256 or not re.fullmatch('[a-f0-9]{64}',admission.get('offline_receipt_sha256','')) or not re.fullmatch('[a-f0-9]{64}',admission.get('resource_receipt_sha256','')):raise ValueError('offline AND full-stack resource admission required')
        offline_bytes=load_bytes(self.directory,'offline-receipt.json',65536)
        resource_bytes=load_bytes(self.directory,'resource-receipt.json',65536)
        if hashlib.sha256(offline_bytes).hexdigest()!=admission['offline_receipt_sha256'] or hashlib.sha256(resource_bytes).hexdigest()!=admission['resource_receipt_sha256']:
            raise ValueError('admission receipt bytes differ')
        offline=json.loads(offline_bytes);resource=json.loads(resource_bytes)
        if type(offline) is not dict or offline.get('status')!='OFFLINE_PILOT_PASS' or offline.get('selected_state_sha256')!=self.manifest['state_sha256'] or offline.get('threshold')!=self.manifest['threshold']:
            raise ValueError('offline qualification does not bind this exact candidate')
        if type(resource) is not dict or resource.get('status')!='SHADOW_RESOURCE_PASS' or resource.get('state_sha256')!=self.manifest['state_sha256'] or resource.get('continuous_seconds',0)<3600 or resource.get('worker_memory_peak_bytes',2**63)>448*1024**2 or resource.get('incremental_rss_bytes',2**63)>128*1024**2 or resource.get('minimum_host_available_bytes',0)<1.5*1024**3 or resource.get('no_oom') is not True:
            raise ValueError('full-stack memory acceptance has not passed')
        threshold=self.manifest['threshold']
        if type(threshold) not in (int,float) or not math.isfinite(threshold):raise ValueError('finite calibration-only threshold required')
        self.state=validate_state(json.loads(state_bytes))
    def score(self,snapshots):
        if type(snapshots) is not list or not 1<=len(snapshots)<=32:raise ValueError('bounded shadow batch required')
        rows=[validate(v,require_ready=False) for v in snapshots]
        if len({v['snapshot_id'] for v in snapshots})!=len(snapshots):raise ValueError('duplicate snapshots refused')
        if any(datetime.fromisoformat(v['as_of'].replace('Z','+00:00'))>datetime.now(timezone.utc)+timedelta(seconds=1) for v in snapshots):raise ValueError('future shadow observations refused')
        # Re-read the small pinned manifest; changing a release cannot silently change a resident model.
        if hashlib.sha256(load_bytes(self.directory,'manifest.json',32768)).hexdigest()!=self.sha:raise ValueError('installed shadow release changed')
        self.baseline.verify_identity();assessments=[]
        ready=[i for i,snapshot in enumerate(snapshots) if snapshot['baseline_established']]
        components=score_components(self.state,[rows[i] for i in ready],self.baseline) if ready else None
        by_position={position:offset for offset,position in enumerate(ready)}
        for position,snapshot in enumerate(snapshots):
            if position not in by_position:
                assessments.append({'snapshot_id':snapshot['snapshot_id'],'recommendation':'UNDETERMINED','reason':'COLD','raw_score':None,'context':None});continue
            offset=by_position[position];context=LABELS[int(components['context_index'][offset])];raw=float(components['raw_score'][offset])
            recommendation='OPS' if context=='SERVICE_DEGRADATION_CONTEXT' else 'REVIEW' if context=='BEHAVIOR_REVIEW_CONTEXT' and raw>=self.manifest['threshold'] else 'ROUTINE'
            assessments.append({'snapshot_id':snapshot['snapshot_id'],'recommendation':recommendation,'raw_score':raw,'context':context})
        return {'scope':'PILOT_ONLY','mode':'SHADOW','feature_schema_version':7,'manifest_sha256':self.sha,'assessments':assessments,
            'candidate_side_effects':{'holds':0,'incidents':0,'ip_blocks':0,'session_revocations':0,'policy_publications':0}}

@lru_cache(maxsize=1)
def configured_shadow():
    directory=os.environ.get('UEBA_AUTH_SHADOW_MODEL_DIR');expected=os.environ.get('UEBA_AUTH_SHADOW_MANIFEST_SHA256')
    if not directory or not expected:raise RuntimeError('shadow disabled')
    return AuthShadowModel(directory,expected)

def health():
    if not os.environ.get('UEBA_AUTH_SHADOW_MODEL_DIR'):return {'enabled':False,'scope':'PILOT_ONLY','mode':'OFF'}
    try:model=configured_shadow();return {'enabled':True,'scope':'PILOT_ONLY','mode':'SHADOW','manifest_sha256':model.sha}
    except (ValueError,RuntimeError,OSError):return {'enabled':False,'scope':'PILOT_ONLY','mode':'UNAVAILABLE'}
