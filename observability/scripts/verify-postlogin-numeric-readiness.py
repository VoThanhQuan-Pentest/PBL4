#!/usr/bin/env python3
"""No-fit conversion of an already learned, hash-verified pilot model; no admission."""
import argparse
import copy
import io
import json
from pathlib import Path
import zipfile
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.normal_support import NormalSupportScorer
from app.hybrid_incident import HybridResearchConfig
from app.postlogin_model import PostLoginContextScorer
from app.postlogin_semantic import to_state,from_state,state_sha256
from app.postlogin_contract import validate_snapshot
from postlogin_pilot_artifacts import read_bundle
from ueba_research_artifacts import digest,commit

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--parent',type=Path,required=True);p.add_argument('--phase',choices=('schema6-numeric-readiness-v1','schema6-numeric-readiness-v2'),default='schema6-numeric-readiness-v2');a=p.parse_args()
parent=a.parent;ledger=digest(parent/'risk-fit-ledger.private.json')
prechange=json.loads((a.root/'prechange-snapshot-v1.receipt.private.json').read_text())['files_sha256']
for name in ('postlogin_risk_projection_model.py','postlogin_risk_ratio_model.py','postlogin_risk_model.py'):
    assert digest(Path(__file__).with_name(name))==prechange[name]
unit='projection-fit-fold3-candidate';directory=parent/'factorial-v1'
with zipfile.ZipFile(directory/(unit+'.bundle.zip')) as z:binding=json.loads(z.read('manifest.json'))['binding']
retained=read_bundle(directory,unit,binding)
# Only the explicitly hash-bound local model written by our own prior worker is
# decoded. The new external-facing codec below accepts primitive numbers only.
model=joblib.load(io.BytesIO(retained['model.joblib']))['model']

def forbidden(*args,**kwargs):raise AssertionError('PREPARATION_ATTEMPTED_A_FIT')
HistGradientBoostingClassifier.fit=forbidden;NormalSupportScorer.fit=forbidden
new=PostLoginContextScorer(HybridResearchConfig(100,15,0,42))
new._normal=model.normal;new._classifier=model.classifier;new.normal_fit_count=2000;new.labeled_fit_count=4240
state=to_state(new);restored=from_state(state)
rows=[]
smoke=a.root/'capture-smoke-v2'
for f in sorted(smoke.glob('p1-*-precommit.receipt.private.json')):
    value=json.loads(f.read_text());snapshot=value['snapshot'];rows.append(validate_snapshot(snapshot))
assert len(rows)==6
x=np.asarray(rows,dtype=np.float64)
assert np.array_equal(model.anomaly_scores(x),new.anomaly_scores(x))
assert np.array_equal(new.anomaly_scores(x),restored.anomaly_scores(x))
assert state_sha256(state)==state_sha256(restored)
for mutate in ('width','node','outcome'):
    bad=copy.deepcopy(state)
    if mutate=='width':bad['classifier_state']['n_features']=65
    elif mutate=='node':bad['classifier_state']['predictors'][0][0]['feature_idx'][0]=11
    else:bad['current_outcome']=True
    try:from_state(bad)
    except ValueError:pass
    else:raise AssertionError('Malformed numeric state accepted: '+mutate)
assert digest(parent/'risk-fit-ledger.private.json')==ledger
report={'status':'SCHEMA6_NUMERIC_CODEC_ZERO_FIT_PARITY_PASS','new_fits':0,'actual_capture_probes':6,
        'parent_bundle_sha256':digest(directory/(unit+'.bundle.zip')),'parent_fit_ledger_unchanged':True,
        'new_numeric_state_sha256':state_sha256(state),'score_parity_exact':True,'malformed_numeric_states_refused':3,
        'no_pickle_for_new_state':True,'strict_admission':False,'holdout_scored':False,'auto_containment':False}
commit(a.root,report,phase=a.phase);print(json.dumps(report))
