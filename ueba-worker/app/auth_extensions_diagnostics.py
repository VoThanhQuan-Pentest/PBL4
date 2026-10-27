"""Context-only confidence, bounded observations and drift counters for the lab."""
import math
import numpy as np
from scipy.optimize import minimize_scalar
from scipy.special import logsumexp

from .auth_shadow_contract import FEATURE_NAMES


def probabilities(raw_logits, temperature=1.0):
    values=np.asarray(raw_logits,dtype=np.float64)
    if values.ndim!=2 or values.shape[1]!=3 or not np.isfinite(values).all() or not .25<=temperature<=4:
        raise ValueError('finite three-context logits and bounded temperature required')
    scaled=values/temperature
    return np.exp(scaled-logsumexp(scaled,axis=1,keepdims=True))


def calibration_metrics(raw_logits, labels, temperature=1.0):
    labels=np.asarray(labels)
    if labels.shape!=(len(raw_logits),) or labels.dtype.kind not in 'iu' or not np.isin(labels,[0,1,2]).all():
        raise ValueError('explicit context labels required')
    proba=probabilities(raw_logits,temperature)
    scaled=np.asarray(raw_logits)/temperature
    loss=float(np.mean(logsumexp(scaled,axis=1)-scaled[np.arange(len(labels)),labels]))
    brier=float(np.mean(np.sum((proba-np.eye(3)[labels])**2,axis=1)))
    confidence=proba.max(axis=1);correct=proba.argmax(axis=1)==labels
    bins=np.minimum((confidence*15).astype(int),14);curve=[];ece=0.
    for i in range(15):
        selected=bins==i;n=int(selected.sum())
        accuracy=float(correct[selected].mean()) if n else None
        mean=float(confidence[selected].mean()) if n else None
        if n:ece+=n/len(labels)*abs(accuracy-mean)
        curve.append({'bin':i,'count':n,'accuracy':accuracy,'confidence':mean})
    return {'log_loss':loss,'brier':brier,'ece_15':float(ece),'reliability':curve}


def fit_temperature(raw_logits, labels):
    values=np.asarray(raw_logits,dtype=np.float64);labels=np.asarray(labels)
    calibration_metrics(values,labels)
    def loss(log_t):
        scaled=values/np.exp(log_t)
        return float(np.mean(logsumexp(scaled,axis=1)-scaled[np.arange(len(labels)),labels]))
    result=minimize_scalar(loss,bounds=(math.log(.25),math.log(4)),method='bounded',options={'xatol':1e-7})
    if not result.success or not math.isfinite(result.fun):raise ValueError('temperature optimizer failed')
    candidates=[.25,1.,4.,float(np.exp(result.x))]
    temperature=min(candidates,key=lambda t:loss(math.log(t)))
    return {'format':'AUTH_CONTEXT_TEMPERATURE_V1','temperature':temperature,'class_order':[0,1,2],
            'scope':'LAB_CONTEXT_ONLY','calibration_rows':len(labels)}


def calibration_pass(raw_logits, labels, calibrator):
    before=calibration_metrics(raw_logits,labels)
    after=calibration_metrics(raw_logits,labels,calibrator['temperature'])
    passed=all(after[k]<=before[k]+1e-6 for k in ('log_loss','brier'))
    return {'status':'CALIBRATION_PASS' if passed else 'CALIBRATION_NO_ADMISSION',
            'uncalibrated':before,'calibrated':after}


def diagnostics(packet, raw_logits, calibrator=None, calibrated=False):
    # Confidence never changes the core recommendation.
    temperature=calibrator['temperature'] if calibrated and calibrator else 1.
    p=probabilities(np.asarray(raw_logits).reshape(1,3),temperature)[0]
    confidence=float(p.max());reason=['LOW_CONFIDENCE' if confidence<.8 else 'CONTEXT_SUPPORTED']
    observed=dict(zip(FEATURE_NAMES,packet['features']))
    names=('prior_otp_failures_session_operation_15m','source_changed_since_session_login',
           'ua_family_changed_since_session_login','account_session_switches_15m',
           'prior_failed_logins_same_source_target_10m')
    evidence=[{'feature':name,'observed':float(observed[name]),'kind':'OBSERVATION_NOT_ATTRIBUTION'}
              for name in names if observed.get(name,0)>0][:3]
    return {'confidence':confidence,'context_probabilities':p.tolist(),
            'confidence_status':'LOW_CONFIDENCE' if confidence<.8 else 'AVAILABLE',
            'confidence_method':'TEMPERATURE_SCALING' if calibrated else 'UNCALIBRATED_SOFTMAX',
            'confidence_scope':'LAB_CONTEXT_ONLY','reason_codes':reason,'evidence_summary':evidence}


class DriftReference:
    def __init__(self,state):
        if (type(state) is not dict or state.get('format')!='AUTH_CONTEXT_DRIFT_V1'
                or type(state.get('features')) is not list or not 1<=len(state['features'])<=81
                or len(state.get('edges',[]))!=len(state['features'])
                or len(state.get('probabilities',[]))!=len(state['features'])):
            raise ValueError('bounded drift reference required')
        self.state=state;self.previous=set();self.previous_strong=set()
        for edges,p in zip(state['edges'],state['probabilities']):
            if (len(edges)>12 or any(not math.isfinite(x) for x in edges)
                    or any(a>=b for a,b in zip(edges,edges[1:]))
                    or len(p)!=len(edges)+1 or any(not math.isfinite(x) or x<0 for x in p)
                    or abs(sum(p)-1)>1e-8):raise ValueError('invalid histogram reference')

    @classmethod
    def fit(cls,values,feature_names):
        values=np.asarray(values,dtype=np.float64)
        if values.ndim!=2 or values.shape[1]!=len(feature_names) or len(values)<1000 or not np.isfinite(values).all():
            raise ValueError('sufficient finite drift reference required')
        edges=[];prob=[]
        for column in values.T:
            unique=np.unique(column)
            if len(unique)<=2 and np.isin(unique,[0,1]).all():cut=np.array([-1e-9,.5,1+1e-9])
            else:
                epsilon=max(1e-9,float(np.max(np.abs(column)))*1e-9)
                cut=np.unique(np.r_[column.min()-epsilon,np.quantile(column,np.arange(.1,1,.1)),column.max()+epsilon])
            counts=np.bincount(np.searchsorted(cut,column,side='right'),minlength=len(cut)+1)
            edges.append(cut.tolist());prob.append((counts/len(column)).tolist())
        return cls({'format':'AUTH_CONTEXT_DRIFT_V1','features':list(feature_names),
                    'edges':edges,'probabilities':prob,'reference_coverage':1.,'rows':len(values)})

    def window(self,values,attempted=None):
        values=np.asarray(values,dtype=np.float64)
        if values.ndim!=2 or values.shape[1]!=len(self.state['features']) or not np.isfinite(values).all():
            raise ValueError('valid drift window required')
        attempted=len(values) if attempted is None else attempted
        if type(attempted) is not int or attempted<len(values):raise ValueError('invalid coverage count')
        counts=[np.bincount(np.searchsorted(edges,column,side='right'),minlength=len(p))
                for column,edges,p in zip(values.T,self.state['edges'],self.state['probabilities'])]
        return self.assess_counts(counts,len(values),attempted)

    def assess_counts(self,counts,valid,attempted):
        if (type(valid) is not int or type(attempted) is not int or not 0<=valid<=attempted<=1000000
                or len(counts)!=len(self.state['features'])
                or any(len(c)!=len(p) or np.any(np.asarray(c)<0) or np.sum(c)!=valid
                       for c,p in zip(counts,self.state['probabilities']))):raise ValueError('invalid bounded window counts')
        coverage=valid/attempted if attempted else 0.
        if valid<1000:
            self.previous=set();self.previous_strong=set()
            return {'status':'INSUFFICIENT_DATA','coverage':coverage,'valid':valid,
                    'coverage_drop':coverage<=self.state['reference_coverage']-.05}
        distances=[]
        for c,p in zip(counts,self.state['probabilities']):
            current=np.asarray(c)/valid
            distances.append(float(np.abs(current-np.asarray(p)).sum()/2))
        moderate={i for i,d in enumerate(distances) if d>=.15}
        strong={i for i,d in enumerate(distances) if d>=.30}
        signals=strong|moderate if strong or len(moderate)>=3 else set()
        persistent=signals&self.previous
        alarm=bool(strong&self.previous_strong) or len(persistent)>=3
        self.previous=signals;self.previous_strong=strong
        return {'status':'DRIFT' if alarm else 'STABLE','coverage':coverage,'valid':valid,
                'coverage_drop':coverage<=self.state['reference_coverage']-.05,
                'total_variation':distances,
                'shifted_features':[self.state['features'][i] for i in sorted(persistent)] if alarm else []}


class StreamingDrift:
    def __init__(self,state):
        self.reference=DriftReference(state);self.last={'status':'INSUFFICIENT_DATA'};self.windows=0
        self._reset()
    def _reset(self):
        self.valid=0;self.attempted=0
        self.counts=[np.zeros(len(p),dtype=np.int64) for p in self.reference.state['probabilities']]
    def observe(self,row=None):
        if row is not None:
            row=np.asarray(row)
            if row.shape!=(len(self.counts),) or not np.isfinite(row).all():raise ValueError('valid observation required')
        self.attempted+=1
        if row is not None:
            for i,(x,edges) in enumerate(zip(row,self.reference.state['edges'])):
                self.counts[i][np.searchsorted(edges,x,side='right')]+=1
            self.valid+=1
        if self.attempted==1000:
            self.last=self.reference.assess_counts(self.counts,self.valid,self.attempted)
            self.windows+=1;self._reset()
    def snapshot(self):return {'windows':self.windows,'pending':self.attempted,'last':self.last}


class BoundedMonitor:
    """Fixed-label aggregate counters; never retains snapshots or identifiers."""
    def __init__(self):self.counts=np.zeros((2,2,4),dtype=np.int64)
    def observe(self,cohort,operation,recommendation):
        cohorts=('READY','COLD');ops=('PASSWORD_CHANGE','EMAIL_CHANGE');results=('ROUTINE','REVIEW','OPS','UNDETERMINED')
        if cohort not in cohorts or operation not in ops or recommendation not in results:raise ValueError('unknown metric label')
        self.counts[cohorts.index(cohort),ops.index(operation),results.index(recommendation)]+=1
    def snapshot(self):return {'format':'AUTH_CONTEXT_COUNTERS_V1','counts':self.counts.tolist()}
