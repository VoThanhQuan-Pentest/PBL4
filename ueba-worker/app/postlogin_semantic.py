"""Numeric-only codec for the schema6/11-view context scorer; never unpickles input."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import numpy as np
import scipy
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.ensemble._hist_gradient_boosting.binning import _BinMapper
from sklearn.ensemble._hist_gradient_boosting.common import PREDICTOR_RECORD_DTYPE
from sklearn.ensemble._hist_gradient_boosting.predictor import TreePredictor
from .normal_support import NormalSupportScorer,MAX_REFERENCE_ROWS
from .hybrid_incident import HybridResearchConfig,MAX_LABELED_ROWS
from .postlogin_model import PostLoginContextScorer
from .hybrid_semantic import _mapping,_same,_integer,_floats,_classifier,_nodes as legacy_nodes,NODE_FIELDS,_TOP,_CLASSIFIER,_CLASSIFIER_ATTRIBUTES,MAX_NUMERIC_BYTES
FORMAT="POSTLOGIN_CONTEXT_NUMERIC_STATE_V2"

def verifier_sha256():
    h=hashlib.sha256(FORMAT.encode())
    for name in ("postlogin_semantic.py","postlogin_model.py","postlogin_contract.py","hybrid_semantic.py","hybrid_incident.py","normal_support.py","contract.py"):
        h.update(name.encode());h.update(Path(__file__).with_name(name).read_bytes())
    for v in (np.__version__,scipy.__version__,sklearn.__version__):h.update(v.encode());h.update(b"\0")
    return h.hexdigest()

def _config(parameters):
    if type(parameters) is not dict or type(parameters.get("config")) is not dict:raise ValueError("typed postlogin recipe required")
    _mapping(parameters["config"],HybridResearchConfig.__dataclass_fields__)
    config=HybridResearchConfig(**parameters["config"])
    if not _same(parameters,PostLoginContextScorer(config).parameters()):raise ValueError("postlogin parameters differ from fixed recipe")
    return config

def _nodes(fields,config,count):
    nodes=legacy_nodes(fields,config,count)
    if np.any(nodes["feature_idx"]>=11):raise ValueError("tree references outside the11-view classifier")
    return nodes

def from_state(state):
    """Restore a known research scorer without calling either component's fit()."""
    _mapping(state, _TOP)
    if (not _same(state["state_format"], FORMAT) or not _same(state["state_version"], 2)
            or not _same(state["verifier_sha256"], verifier_sha256())):
        raise ValueError("hybrid numeric format/implementation mismatch")
    config = _config(state["parameters"])
    normal_count = _integer(state["normal_fit_count"], 256, MAX_REFERENCE_ROWS)
    labeled_count = _integer(state["labeled_fit_count"], 60, MAX_LABELED_ROWS)
    normal_state = state["normal_state"]
    if (type(normal_state) is not dict or type(normal_state.get("fit_rows")) is not list
            or len(normal_state["fit_rows"]) != normal_count):
        raise ValueError("bounded hybrid normal FIT state required")
    for row in normal_state["fit_rows"]:
        _floats(row, 37, count=37)
    normal = NormalSupportScorer.from_state(normal_state)
    if (normal.fit_count != normal_count or not _same(normal.parameters(),
            NormalSupportScorer(8, 256, "euclidean", config.random_state).parameters())):
        raise ValueError("hybrid normal component recipe/count mismatch")
    learned = state["classifier_state"]
    _mapping(learned, _CLASSIFIER)
    if not _same(learned["classes"], [0, 1, 2]) or not _same(learned["n_features"], 11):
        raise ValueError("hybrid learned class/feature order mismatch")
    baseline = learned["baseline"]
    if type(baseline) is not list or len(baseline) != 1:
        raise ValueError("hybrid baseline shape mismatch")
    baseline = _floats(baseline[0], 3, count=3).reshape(1, 3)
    thresholds = learned["bin_thresholds"]
    if type(thresholds) is not list or len(thresholds) != 11:
        raise ValueError("hybrid bin feature count mismatch")
    thresholds = [_floats(v, 254) for v in thresholds]
    if any(np.any(v[1:] <= v[:-1]) for v in thresholds):
        raise ValueError("strictly ordered hybrid bin thresholds required")
    predictors = learned["predictors"]
    if type(predictors) is not list or len(predictors) != config.max_iter or len(predictors) > 400:
        raise ValueError("hybrid iteration count mismatch")
    restored, byte_count = [], normal_count * 37 * 8 + 24 + sum(v.nbytes for v in thresholds)
    for group in predictors:
        if type(group) is not list or len(group) != 3:
            raise ValueError("three hybrid class trees per iteration required")
        trees = []
        for fields in group:
            nodes = _nodes(fields, config, labeled_count)
            byte_count += nodes.nbytes
            if byte_count > MAX_NUMERIC_BYTES:
                raise ValueError("hybrid aggregate numeric-byte budget exceeded")
            trees.append(TreePredictor(nodes, np.zeros((0, 8), dtype="<u4"), np.zeros((0, 8), dtype="<u4")))
        restored.append(trees)
    classifier = _classifier(config)
    classifier.n_features_in_ = 11
    classifier.classes_ = np.asarray([0, 1, 2], dtype="<i8")
    classifier._preprocessor = None
    classifier.n_trees_per_iteration_ = 3
    classifier._baseline_prediction = baseline
    classifier._predictors = restored
    classifier._bin_mapper = _BinMapper(n_bins=256)
    classifier._bin_mapper.is_categorical_ = np.zeros(11, dtype="u1")
    classifier._bin_mapper.bin_thresholds_ = thresholds
    model = PostLoginContextScorer(config)
    model._normal, model._classifier = normal, classifier
    model.normal_fit_count, model.labeled_fit_count = normal_count, labeled_count
    return model


def to_state(model):
    """Export only explicit numeric predictive fields, with no sklearn objects."""
    if (type(model) is not PostLoginContextScorer or type(model._normal) is not NormalSupportScorer
            or type(model._classifier) is not HistGradientBoostingClassifier
            or set(vars(model)) != {"_config", "_normal", "_classifier", "normal_fit_count", "labeled_fit_count"}):
        raise ValueError("exact fitted hybrid research classes required")
    config, clf = _config(model.parameters()), model._classifier
    if (set(vars(clf)) - _CLASSIFIER_ATTRIBUTES or not _same(clf.get_params(), _classifier(config).get_params())
            or clf._preprocessor is not None or getattr(clf, "is_categorical_", None) is not None
            or getattr(clf, "_is_categorical_remapped", None) is not None
            or type(clf.n_features_in_) is not int or clf.n_features_in_ != 11
            or type(clf.n_trees_per_iteration_) is not int or clf.n_trees_per_iteration_ != 3
            or type(clf._bin_mapper) is not _BinMapper
            or clf._bin_mapper.is_categorical is not None or clf._bin_mapper.known_categories is not None
            or type(clf._bin_mapper.is_categorical_) is not np.ndarray
            or clf._bin_mapper.is_categorical_.dtype != np.dtype("uint8")
            or clf._bin_mapper.is_categorical_.shape != (11,)
            or np.any(clf._bin_mapper.is_categorical_ != 0)):
        raise ValueError("unsupported hybrid classifier/preprocessor state")
    if (type(clf.classes_) is not np.ndarray or clf.classes_.dtype != np.dtype("int64")
            or clf.classes_.shape != (3,) or not np.array_equal(clf.classes_, [0, 1, 2])
            or type(clf._baseline_prediction) is not np.ndarray
            or clf._baseline_prediction.dtype != np.dtype("float64") or clf._baseline_prediction.shape != (1, 3)):
        raise ValueError("hybrid classifier class/baseline dtype mismatch")
    groups = []
    if type(clf._predictors) is not list or len(clf._predictors) != config.max_iter:
        raise ValueError("hybrid predictor iteration mismatch")
    for group in clf._predictors:
        if type(group) is not list or len(group) != 3:
            raise ValueError("hybrid predictor class count mismatch")
        fields_group = []
        for tree in group:
            if (type(tree) is not TreePredictor or set(vars(tree)) != {
                    "nodes", "binned_left_cat_bitsets", "raw_left_cat_bitsets"}
                    or type(tree.nodes) is not np.ndarray or tree.nodes.dtype != PREDICTOR_RECORD_DTYPE
                    or tree.nodes.ndim != 1 or not 1 <= len(tree.nodes) <= 2 * config.max_leaf_nodes - 1):
                raise ValueError("known bounded hybrid tree predictor required")
            for bits in (tree.binned_left_cat_bitsets, tree.raw_left_cat_bitsets):
                if type(bits) is not np.ndarray or bits.dtype != np.dtype("uint32") or bits.shape != (0, 8):
                    raise ValueError("hybrid categorical bitsets forbidden")
            fields_group.append({name: tree.nodes[name].tolist() for name, _ in NODE_FIELDS})
        groups.append(fields_group)
    bins = clf._bin_mapper.bin_thresholds_
    if (type(bins) is not list or len(bins) != 11 or any(type(v) is not np.ndarray
            or v.dtype != np.dtype("float64") or v.ndim != 1 or len(v) > 254 for v in bins)):
        raise ValueError("bounded numeric hybrid bin mapper required")
    state = {"state_format": FORMAT, "state_version": 2, "verifier_sha256": verifier_sha256(),
             "parameters": model.parameters(), "normal_fit_count": model.normal_fit_count,
             "labeled_fit_count": model.labeled_fit_count, "normal_state": model._normal.to_state(),
             "classifier_state": {"classes": clf.classes_.tolist(), "n_features": 11,
                 "baseline": clf._baseline_prediction.tolist(), "bin_thresholds": [v.tolist() for v in bins],
                 "predictors": groups}}
    from_state(state)
    return state


def state_sha256(value):
    state=to_state(value) if type(value) is PostLoginContextScorer else value
    from_state(state)
    return hashlib.sha256(json.dumps(state,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
