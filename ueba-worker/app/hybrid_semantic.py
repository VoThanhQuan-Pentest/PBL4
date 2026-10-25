"""Bounded numeric-only HYBRID research state; not ModelStore admission.

Only known local classes are constructed. No pickle, supplied class name, fit,
categorical encoder, or serving registration is involved. This format defines
predictive numeric identity, not the classifier's unused training RNG state.
"""

from dataclasses import asdict
import hashlib
from pathlib import Path
import struct

import numpy as np
import scipy
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.ensemble._hist_gradient_boosting.binning import _BinMapper
from sklearn.ensemble._hist_gradient_boosting.common import PREDICTOR_RECORD_DTYPE
from sklearn.ensemble._hist_gradient_boosting.predictor import TreePredictor

from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig, MAX_LABELED_ROWS
from app.normal_support import NormalSupportScorer, MAX_REFERENCE_ROWS

FORMAT = "HYBRID_RESEARCH_NUMERIC_STATE_V1"
MAX_NUMERIC_BYTES = 64 * 1024 * 1024
NODE_FIELDS = (
    ("value", "<f8"), ("count", "<u4"), ("feature_idx", "<i8"),
    ("num_threshold", "<f8"), ("missing_go_to_left", "u1"),
    ("left", "<u4"), ("right", "<u4"), ("gain", "<f8"),
    ("depth", "<u4"), ("is_leaf", "u1"), ("bin_threshold", "u1"),
    ("is_categorical", "u1"), ("bitset_idx", "<u4"),
)
_TOP = {"state_format", "state_version", "verifier_sha256", "parameters",
        "normal_fit_count", "labeled_fit_count", "normal_state", "classifier_state"}
_CLASSIFIER = {"classes", "n_features", "baseline", "bin_thresholds", "predictors"}
_CLASSIFIER_ATTRIBUTES = set(HistGradientBoostingClassifier().get_params()) | {
    "is_categorical_", "_preprocessor", "_is_categorical_remapped", "n_features_in_",
    "_label_encoder", "classes_", "n_trees_per_iteration_", "_random_seed",
    "_feature_subsample_rng", "_n_features", "_loss", "do_early_stopping_",
    "_use_validation_data", "_bin_mapper", "_baseline_prediction", "_predictors",
    "_scorer", "train_score_", "validation_score_",
}


def verifier_sha256():
    """Bind this new format only; existing IF/support verifier formats are untouched."""
    digest = hashlib.sha256(FORMAT.encode())
    for name in ("hybrid_semantic.py", "hybrid_incident.py", "normal_support.py", "contract.py"):
        digest.update(name.encode()); digest.update(Path(__file__).with_name(name).read_bytes())
    for version in (np.__version__, scipy.__version__, sklearn.__version__):
        digest.update(version.encode()); digest.update(b"\0")
    return digest.hexdigest()


def _mapping(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("invalid hybrid numeric state fields")


def _same(value, expected):
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(_same(value[k], v) for k, v in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(_same(a, b) for a, b in zip(value, expected))
    return value == expected


def _integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("bounded hybrid integer required")
    return value


def _floats(values, maximum, *, count=None):
    if type(values) is not list or len(values) > maximum or (count is not None and len(values) != count):
        raise ValueError("bounded hybrid numeric sequence required")
    if any(type(v) not in (int, float) for v in values):
        raise ValueError("plain hybrid numeric values required")
    try:
        result = np.asarray(values, dtype="<f8")
    except (OverflowError, ValueError, TypeError):
        raise ValueError("finite hybrid numeric values required") from None
    if not np.isfinite(result).all():
        raise ValueError("finite hybrid numeric values required")
    return result


def _classifier(config):
    return HistGradientBoostingClassifier(**asdict(config), learning_rate=0.1,
        min_samples_leaf=20, max_bins=255, early_stopping=False,
        categorical_features=None, class_weight=None)


def _config(parameters):
    if type(parameters) is not dict or type(parameters.get("config")) is not dict:
        raise ValueError("typed hybrid recipe required")
    _mapping(parameters["config"], HybridResearchConfig.__dataclass_fields__)
    config = HybridResearchConfig(**parameters["config"])
    if not _same(parameters, HybridIncidentScorer(config).parameters()):
        raise ValueError("hybrid parameters differ from fixed recipe")
    return config


def _nodes(fields, config, labeled_count):
    _mapping(fields, [name for name, _ in NODE_FIELDS])
    count = len(fields["value"]) if type(fields["value"]) is list else 0
    _integer(count, 1, 2 * config.max_leaf_nodes - 1)
    if PREDICTOR_RECORD_DTYPE != np.dtype(list(NODE_FIELDS)):
        raise ValueError("unsupported pinned sklearn node ABI")
    nodes = np.zeros(count, dtype=PREDICTOR_RECORD_DTYPE)
    for name, code in NODE_FIELDS:
        values = fields[name]
        dtype = np.dtype(code)
        if dtype.kind == "f":
            nodes[name] = _floats(values, count, count=count)
        else:
            if type(values) is not list or len(values) != count:
                raise ValueError("bounded hybrid node fields required")
            info = np.iinfo(dtype)
            for value in values:
                _integer(value, max(0, int(info.min)), int(info.max))
            nodes[name] = values
    if (np.any(nodes["is_categorical"] != 0) or np.any(nodes["bitset_idx"] != 0)
            or np.any(nodes["feature_idx"] >= 37) or np.any(nodes["bin_threshold"] > 254)
            or np.any(nodes["is_leaf"] > 1) or np.any(nodes["missing_go_to_left"] > 1)
            or np.any(nodes["count"] < 1) or np.any(nodes["count"] > labeled_count)
            or int(nodes["count"][0]) != labeled_count):
        raise ValueError("invalid numeric-only hybrid node values")
    seen, stack, leaves = set(), [(0, 0)], 0
    while stack:
        index, depth = stack.pop()
        if index in seen or not 0 <= index < count or depth >= config.max_leaf_nodes:
            raise ValueError("invalid hybrid tree graph")
        seen.add(index)
        node = nodes[index]
        if int(node["depth"]) != depth:
            raise ValueError("hybrid tree depth mismatch")
        left, right = int(node["left"]), int(node["right"])
        if node["is_leaf"]:
            leaves += 1
            if left or right or int(node["count"]) < 20:
                raise ValueError("hybrid leaf references/minimum sample count mismatch")
        else:
            if (not 0 <= left < count or not 0 <= right < count or left == right
                    or int(nodes["count"][left]) + int(nodes["count"][right]) != int(node["count"])):
                raise ValueError("hybrid child references/count conservation failed")
            stack.extend(((right, depth + 1), (left, depth + 1)))
    if len(seen) != count or leaves > config.max_leaf_nodes or count != 2 * leaves - 1:
        raise ValueError("unreachable or nonbinary hybrid tree nodes")
    nodes.setflags(write=False)
    return nodes


def from_state(state):
    """Restore a known research scorer without calling either component's fit()."""
    _mapping(state, _TOP)
    if (not _same(state["state_format"], FORMAT) or not _same(state["state_version"], 1)
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
    if not _same(learned["classes"], [0, 1, 2]) or not _same(learned["n_features"], 37):
        raise ValueError("hybrid learned class/feature order mismatch")
    baseline = learned["baseline"]
    if type(baseline) is not list or len(baseline) != 1:
        raise ValueError("hybrid baseline shape mismatch")
    baseline = _floats(baseline[0], 3, count=3).reshape(1, 3)
    thresholds = learned["bin_thresholds"]
    if type(thresholds) is not list or len(thresholds) != 37:
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
    classifier.n_features_in_ = 37
    classifier.classes_ = np.asarray([0, 1, 2], dtype="<i8")
    classifier._preprocessor = None
    classifier.n_trees_per_iteration_ = 3
    classifier._baseline_prediction = baseline
    classifier._predictors = restored
    classifier._bin_mapper = _BinMapper(n_bins=256)
    classifier._bin_mapper.is_categorical_ = np.zeros(37, dtype="u1")
    classifier._bin_mapper.bin_thresholds_ = thresholds
    model = HybridIncidentScorer(config)
    model._normal, model._classifier = normal, classifier
    model.normal_fit_count, model.labeled_fit_count = normal_count, labeled_count
    return model


def to_state(model):
    """Export only explicit numeric predictive fields, with no sklearn objects."""
    if (type(model) is not HybridIncidentScorer or type(model._normal) is not NormalSupportScorer
            or type(model._classifier) is not HistGradientBoostingClassifier
            or set(vars(model)) != {"_config", "_normal", "_classifier", "normal_fit_count", "labeled_fit_count"}):
        raise ValueError("exact fitted hybrid research classes required")
    config, clf = _config(model.parameters()), model._classifier
    if (set(vars(clf)) - _CLASSIFIER_ATTRIBUTES or not _same(clf.get_params(), _classifier(config).get_params())
            or clf._preprocessor is not None or getattr(clf, "is_categorical_", None) is not None
            or getattr(clf, "_is_categorical_remapped", None) is not None
            or type(clf.n_features_in_) is not int or clf.n_features_in_ != 37
            or type(clf.n_trees_per_iteration_) is not int or clf.n_trees_per_iteration_ != 3
            or type(clf._bin_mapper) is not _BinMapper
            or clf._bin_mapper.is_categorical is not None or clf._bin_mapper.known_categories is not None
            or type(clf._bin_mapper.is_categorical_) is not np.ndarray
            or clf._bin_mapper.is_categorical_.dtype != np.dtype("uint8")
            or clf._bin_mapper.is_categorical_.shape != (37,)
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
    if (type(bins) is not list or len(bins) != 37 or any(type(v) is not np.ndarray
            or v.dtype != np.dtype("float64") or v.ndim != 1 or len(v) > 254 for v in bins)):
        raise ValueError("bounded numeric hybrid bin mapper required")
    state = {"state_format": FORMAT, "state_version": 1, "verifier_sha256": verifier_sha256(),
             "parameters": model.parameters(), "normal_fit_count": model.normal_fit_count,
             "labeled_fit_count": model.labeled_fit_count, "normal_state": model._normal.to_state(),
             "classifier_state": {"classes": clf.classes_.tolist(), "n_features": 37,
                 "baseline": clf._baseline_prediction.tolist(), "bin_thresholds": [v.tolist() for v in bins],
                 "predictors": groups}}
    from_state(state)
    return state


def state_sha256(value):
    """Hash canonical numeric fields, never native struct padding or pickle bytes."""
    state = to_state(value) if type(value) is HybridIncidentScorer else value
    from_state(state)
    canonical = {**state, "normal_state": dict(state["normal_state"]),
                 "classifier_state": dict(state["classifier_state"])}
    normal = canonical["normal_state"]
    for key in ("fit_rows", "center", "scale", "reference_indices"):
        normal[key] = np.asarray(normal[key], dtype="<i8" if key == "reference_indices" else "<f8")
    learned = canonical["classifier_state"]
    learned["baseline"] = np.asarray(learned["baseline"], dtype="<f8")
    learned["bin_thresholds"] = [np.asarray(v, dtype="<f8") for v in learned["bin_thresholds"]]
    learned["predictors"] = [[{name: np.asarray(fields[name], dtype=code) for name, code in NODE_FIELDS}
                              for fields in group] for group in learned["predictors"]]
    digest = hashlib.sha256()
    def atom(tag, raw=b""):
        digest.update(tag); digest.update(struct.pack(">Q", len(raw))); digest.update(raw)
    def visit(item):
        if type(item) is dict:
            atom(b"dict", str(len(item)).encode())
            for key in sorted(item): visit(key); visit(item[key])
        elif type(item) is list:
            atom(b"list", str(len(item)).encode())
            for child in item: visit(child)
        elif type(item) is np.ndarray:
            atom(b"array", item.dtype.str.encode()); visit(list(item.shape))
            atom(b"numeric", np.ascontiguousarray(item).tobytes())
        elif type(item) is float: atom(b"float", struct.pack("<d", item))
        elif type(item) is bool: atom(b"bool", bytes([item]))
        elif type(item) is int: atom(b"int", str(item).encode())
        elif type(item) is str: atom(b"str", item.encode())
        elif item is None: atom(b"none")
        else: raise ValueError("unknown hybrid canonical state type")
    visit(canonical)
    return digest.hexdigest()
