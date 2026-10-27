"""Bounded offline model primitives. No runtime admission or pickle loading."""
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import time

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from .auth_shadow_contract import FEATURE_NAMES, RECIPES, SEEDS, validate
from .auth_shadow_model import export_classifier as export_ready, logits as ready_logits, validate_state as validate_ready
from .normal_support import _signed_log
from .postlogin_contract import POSTLOGIN_NAMES, ROLLING_NAMES
from .auth_shadow_contract import NEW_NAMES

COLD_NAMES = POSTLOGIN_NAMES + ROLLING_NAMES[:6] + NEW_NAMES
COLD_FORMAT = 'AUTH_COLD_CONTEXT_V1'
ROOT = Path('/home/quan/.codex/research/model-capability-assessment')
REFERENCE_SHA = '35b3500d0d924a244224071c74aa9127e482be61863b665070b8532fe058971f'
COHORTS = ('READY', 'COLD')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024**2), b''): result.update(block)
    return result.hexdigest()


def safe_path(path, *, root=ROOT, existing=True):
    path = Path(path).absolute()
    if '..' in path.parts or path == root or root not in path.parents:
        raise ValueError('path must be below the private research root')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlinks are forbidden')
    if existing and not path.exists(): raise ValueError('research path missing')
    return path


def read_json(path, maximum=16*1024**2):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('bounded regular JSON required')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def write_new(path, value):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(canonical(value)); output.flush(); os.fsync(output.fileno())


@contextmanager
def lock(folder):
    with (Path(folder)/'operation.lock').open('a') as file:
        fcntl.flock(file, fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


class Ledger:
    def __init__(self, folder):
        self.folder = Path(folder); self.folder.mkdir(mode=0o700, exist_ok=True)

    def reserve(self, kind, cohort, identity, binding):
        if kind not in ('classifier','calibrator') or cohort not in COHORTS:
            raise ValueError('unknown fit role')
        allowed = {f'{r["name"]}-{s}' for r in RECIPES for s in SEEDS}
        if kind == 'classifier' and identity not in allowed: raise ValueError('unregistered trial')
        if kind == 'calibrator' and identity not in ('reference','selected'): raise ValueError('unregistered calibrator')
        if kind == 'calibrator' and cohort=='COLD' and identity!='selected':raise ValueError('COLD has no reference calibrator')
        with lock(self.folder):
            entries = list(self.folder.glob(kind+'-*.json'))
            if len(entries) >= (8 if kind == 'classifier' else 3): raise ValueError('fit budget exhausted')
            if kind == 'classifier' and len(list(self.folder.glob(f'classifier-{cohort}-*.json'))) >= 4:
                raise ValueError('cohort fit budget exhausted')
            path = self.folder/f'{kind}-{cohort}-{identity}.json'
            write_new(path, {'status':'RESERVED','kind':kind,'cohort':cohort,'identity':identity,
                             'binding':binding,'reserved_at':time.time()})
        return path


def project(packet, cohort):
    if cohort not in COHORTS: raise ValueError('unknown cohort')
    row = np.asarray(validate(packet, require_ready=False), dtype=np.float64)
    if datetime.fromisoformat(packet['as_of'].replace('Z','+00:00'))>datetime.now(timezone.utc)+timedelta(seconds=1):
        raise ValueError('future observation')
    observed = 'READY' if packet['baseline_established'] else 'COLD'
    if observed != cohort: raise ValueError('cohort mismatch')
    return row if cohort == 'READY' else np.r_[row[37:63],row[65:81]]


def fit_classifier(rows, labels, cohort, recipe, seed):
    width = 81 if cohort == 'READY' else 42 if cohort == 'COLD' else 0
    values = np.asarray(rows,dtype=np.float64); labels=np.asarray(labels)
    if (recipe not in RECIPES or seed not in SEEDS or values.ndim != 2
            or values.shape[1] != width or not 60 <= len(values) <= 40000
            or not np.isfinite(values).all() or labels.shape != (len(values),)
            or labels.dtype.kind not in 'iu' or set(labels.tolist()) != {0,1,2}):
        raise ValueError('registered bounded classifier input required')
    return HistGradientBoostingClassifier(max_iter=recipe['max_iter'],max_leaf_nodes=recipe['max_leaf_nodes'],
        learning_rate=.1,l2_regularization=1,min_samples_leaf=20,max_bins=255,early_stopping=False,
        categorical_features=None,class_weight=None,random_state=seed).fit(_signed_log(values),labels)


def export_classifier(model, cohort, recipe, seed):
    if cohort == 'READY': return export_ready(model,recipe,seed)
    if cohort != 'COLD' or model.n_features_in_ != 42 or model.classes_.tolist() != [0,1,2]:
        raise ValueError('fitted COLD classifier required')
    trees=[]
    for group in model._predictors:
        triple=[]
        for predictor in group:
            nodes=[]
            for row in predictor.nodes:
                if row['is_categorical']: raise ValueError('categorical tree forbidden')
                nodes.append({'value':float(row['value']),'feature':int(row['feature_idx']),
                    'threshold':float(row['num_threshold']),'left':int(row['left']),
                    'right':int(row['right']),'leaf':bool(row['is_leaf'])})
            triple.append(nodes)
        trees.append(triple)
    state={'format':COLD_FORMAT,'features':42,'feature_names':list(COLD_NAMES),'recipe':recipe,
           'seed':seed,'intercept':model._baseline_prediction.ravel().tolist(),'trees':trees}
    return validate_state(state)


def validate_state(state):
    if type(state) is not dict: raise ValueError('numeric mapping required')
    if state.get('format') != COLD_FORMAT: return validate_ready(state)
    if (set(state) != {'format','features','feature_names','recipe','seed','intercept','trees'}
            or state['features'] != 42 or state['feature_names'] != list(COLD_NAMES)
            or state['recipe'] not in RECIPES or state['seed'] not in SEEDS):
        raise ValueError('registered COLD numeric state required')
    if type(state['intercept']) is not list or len(state['intercept']) != 3 or any(type(x) not in (int,float) or not math.isfinite(x) for x in state['intercept']):
        raise ValueError('finite intercept required')
    if type(state['trees']) is not list or len(state['trees']) != state['recipe']['max_iter']:
        raise ValueError('registered tree count required')
    for group in state['trees']:
        if type(group) is not list or len(group)!=3: raise ValueError('three class trees required')
        for tree in group:
            if type(tree) is not list or not 1<=len(tree)<=2*state['recipe']['max_leaf_nodes']-1:
                raise ValueError('bounded tree required')
            visited=set();pending=[0]
            while pending:
                i=pending.pop()
                if i in visited or not 0<=i<len(tree): raise ValueError('invalid tree graph')
                visited.add(i);node=tree[i]
                if type(node) is not dict or set(node)!={'value','feature','threshold','left','right','leaf'} or type(node['leaf']) is not bool:
                    raise ValueError('invalid numeric node')
                if any(type(node[k]) not in (int,float) or not math.isfinite(node[k]) for k in ('value','threshold')):
                    raise ValueError('finite node required')
                if type(node['feature']) is not int or not 0<=node['feature']<42: raise ValueError('feature outside COLD width')
                if not node['leaf']:
                    children=[node['left'],node['right']]
                    if any(type(j) is not int or not i<j<len(tree) for j in children): raise ValueError('forward children required')
                    pending.extend(children)
            if len(visited)!=len(tree): raise ValueError('unreachable tree nodes')
    return state


def logits(state, rows):
    if state.get('format') != COLD_FORMAT: return ready_logits(state,rows)
    values=np.asarray(rows,dtype=np.float64)
    if values.ndim!=2 or values.shape[1]!=42 or not 1<=len(values)<=32 or not np.isfinite(values).all():
        raise ValueError('bounded finite COLD matrix required')
    values=_signed_log(values);result=np.tile(state['intercept'],(len(values),1)).astype(np.float64)
    for group in state['trees']:
        for column,tree in enumerate(group):
            pending=[(0,np.arange(len(values)))]
            while pending:
                i,selection=pending.pop();node=tree[i]
                if node['leaf']: result[selection,column]+=node['value'];continue
                left=values[selection,node['feature']]<=node['threshold']
                if left.any():pending.append((node['left'],selection[left]))
                if (~left).any():pending.append((node['right'],selection[~left]))
    if not np.isfinite(result).all():raise ValueError('invalid logits')
    return result
