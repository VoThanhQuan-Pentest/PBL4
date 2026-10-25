"""Bounded numeric tree codec for a PILOT_ONLY auth-context classifier; never unpickles files."""
import math
import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier
from .auth_shadow_contract import RECIPES, SEEDS
from .normal_support import _signed_log

FORMAT='AUTH_SHADOW_NUMERIC_TREES_V1'
MAX_BYTES=16*1024**2

def fit_classifier(rows, labels, recipe, seed):
    if recipe not in RECIPES or seed not in SEEDS:raise ValueError('only preregistered recipe/seed allowed')
    rows=np.asarray(rows,dtype=np.float64);labels=np.asarray(labels)
    if rows.ndim!=2 or rows.shape[1]!=81 or not 1<=len(rows)<=40_000 or not np.isfinite(rows).all():raise ValueError('bounded81 train matrix required')
    if labels.shape!=(len(rows),) or set(labels.tolist())!={0,1,2}:raise ValueError('three independently labeled contexts required')
    return HistGradientBoostingClassifier(max_iter=recipe['max_iter'],max_leaf_nodes=recipe['max_leaf_nodes'],
        learning_rate=.1,l2_regularization=1,min_samples_leaf=20,max_bins=255,early_stopping=False,
        categorical_features=None,class_weight=None,random_state=seed).fit(_signed_log(rows),labels)

def export_classifier(model, recipe, seed):
    if model.n_features_in_!=81 or model.classes_.tolist()!=[0,1,2] or len(model._predictors)!=recipe['max_iter']:
        raise ValueError('unexpected fitted classifier')
    trees=[]
    for iteration in model._predictors:
        triple=[]
        for predictor in iteration:
            nodes=[]
            for row in predictor.nodes:
                if bool(row['is_categorical']):raise ValueError('categorical predictors outside contract')
                nodes.append({'value':float(row['value']),'feature':int(row['feature_idx']),
                    'threshold':float(row['num_threshold']),'left':int(row['left']),'right':int(row['right']),
                    'leaf':bool(row['is_leaf'])})
            triple.append(nodes)
        trees.append(triple)
    state={'format':FORMAT,'recipe':recipe,'seed':seed,'features':81,
        'intercept':model._baseline_prediction.ravel().tolist(),'trees':trees}
    validate_state(state)
    return state

def validate_state(state):
    if type(state) is not dict or set(state)!={'format','recipe','seed','features','intercept','trees'} or state['format']!=FORMAT or state['features']!=81:
        raise ValueError('numeric-only auth state required')
    if state['recipe'] not in RECIPES or state['seed'] not in SEEDS:raise ValueError('unregistered recipe')
    if type(state['intercept']) is not list or len(state['intercept'])!=3 or any(type(v) not in (int,float) or not math.isfinite(v) for v in state['intercept']):raise ValueError('finite three-class intercept required')
    if type(state['trees']) is not list or len(state['trees'])!=state['recipe']['max_iter']:raise ValueError('invalid iteration count')
    for triple in state['trees']:
        if type(triple) is not list or len(triple)!=3:raise ValueError('three numeric trees per iteration required')
        for tree in triple:
            if type(tree) is not list or not 1<=len(tree)<=2*state['recipe']['max_leaf_nodes']-1:raise ValueError('bounded trees required')
            for i,node in enumerate(tree):
                if type(node) is not dict or set(node)!={'value','feature','threshold','left','right','leaf'} or type(node['leaf']) is not bool:raise ValueError('invalid node')
                if any(type(node[k]) not in (int,float) or not math.isfinite(node[k]) for k in ('value','threshold')):raise ValueError('finite tree values required')
                if type(node['feature']) is not int or not 0<=node['feature']<81:raise ValueError('feature index outside81')
                if not node['leaf'] and any(type(node[k]) is not int or not i<node[k]<len(tree) for k in ('left','right')):raise ValueError('cyclic or invalid child')
    return state

def logits(state, rows):
    rows=np.asarray(rows,dtype=np.float64)
    if rows.ndim!=2 or rows.shape[1]!=81 or not 1<=len(rows)<=32 or not np.isfinite(rows).all():raise ValueError('one to32 finite81 observations required')
    transformed=_signed_log(rows);result=np.tile(state['intercept'],(len(rows),1)).astype(np.float64)
    for triple in state['trees']:
        for column,tree in enumerate(triple):
            pending=[(0,np.arange(len(rows)))]
            while pending:
                index,selection=pending.pop();node=tree[index]
                if node['leaf']:result[selection,column]+=node['value'];continue
                left=transformed[selection,node['feature']]<=node['threshold']
                if left.any():pending.append((node['left'],selection[left]))
                if (~left).any():pending.append((node['right'],selection[~left]))
    if not np.isfinite(result).all():raise ValueError('nonfinite classifier output')
    return result

def score_components(state, rows, baseline):
    values=logits(state,rows);margin=logsumexp(values[:,1:],axis=1)-values[:,0]
    # The already accepted normal component is read-only, never re-fitted or replaced.
    normal=baseline.model._normal.anomaly_scores(np.asarray(rows,dtype=np.float64)[:,:37])
    return {'raw_score':np.maximum(margin,np.log(normal+1e-12)),
        'context_index':np.argmax(values,axis=1),'logits':values}
