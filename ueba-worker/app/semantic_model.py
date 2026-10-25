"""Exact numeric-model identity, independent of non-semantic ndarray padding.

Binary SHA-256 remains authoritative for file integrity, evaluation, shadow and
activation. This additional digest only compares independently refitted model
state: all parameters, caches, trees, named node fields and calibration values.
It ignores struct padding, not any numeric field, and never loads pickle bytes.
"""
import hashlib
from pathlib import Path
import struct

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.tree import ExtraTreeRegressor, _tree
from app.contract import IF_MODEL_KIND, SUPPORT_MODEL_KIND

FORMAT = "SKLEARN_NUMERIC_STATE_V2"
SUPPORT_FORMAT = "NORMAL_SUPPORT_NUMERIC_STATE_V1"
MODEL_TYPES = (IsolationForest, ExtraTreeRegressor, _tree.Tree)
MAX_VISITS = 200000
MAX_TOTAL_ARRAY_BYTES = 256 * 1024 * 1024


def verifier_sha256(model_kind=IF_MODEL_KIND):
    if model_kind not in (IF_MODEL_KIND, SUPPORT_MODEL_KIND): raise ValueError("unknown model state kind")
    digest = hashlib.sha256(Path(__file__).read_bytes())
    if model_kind == SUPPORT_MODEL_KIND:
        digest.update(Path(__file__).with_name("normal_support.py").read_bytes())
    return digest.hexdigest()


def state_format(payload_or_kind):
    if isinstance(payload_or_kind, str):
        kind = payload_or_kind
    elif isinstance(payload_or_kind, dict):
        if type(payload_or_kind.get("model")) is IsolationForest: kind = IF_MODEL_KIND
        else:
            from app.normal_support import NormalSupportScorer
            if type(payload_or_kind.get("model")) is not NormalSupportScorer:
                raise ValueError("known numeric model payload required")
            kind = SUPPORT_MODEL_KIND
    else: raise ValueError("known numeric model payload required")
    if kind == IF_MODEL_KIND: return FORMAT
    if kind == SUPPORT_MODEL_KIND: return SUPPORT_FORMAT
    raise ValueError("unknown numeric model state format")


def state_sha256(payload):
    if (not isinstance(payload, dict) or set(payload) not in ({"model", "calibration_scores"},
                                    {"model", "calibration_scores", "calibration_by_cohort"})):
        raise ValueError("known worker-created numeric model payload required")
    identity_format = state_format(payload)
    if identity_format == SUPPORT_FORMAT:
        from app.normal_support import NormalSupportScorer
        state = payload["model"].to_state()
        NormalSupportScorer.from_state(state)
        # Validate JSON state first, then hash arrays without visiting millions
        # of Python scalar objects. Numeric byte/traversal limits still apply.
        state = {**state, **{key: np.asarray(state[key], dtype="<i8" if key == "reference_indices" else "<f8")
                            for key in ("fit_rows", "reference_indices", "center", "scale")}}
        payload = {**payload, "model": state}
    digest = hashlib.sha256()
    ancestors = set()
    budget = {"visits": 0, "array_bytes": 0}
    def atom(tag, raw=b""):
        digest.update(tag); digest.update(struct.pack(">Q", len(raw))); digest.update(raw)
    def visit(value, depth=0):
        budget["visits"] += 1
        if budget["visits"] > MAX_VISITS: raise ValueError("aggregate model-state traversal budget exceeded")
        if depth > 32: raise ValueError("bounded model state depth required")
        if value is None: atom(b"none"); return
        if type(value) is bool: atom(b"bool", bytes([value])); return
        if type(value) is int: atom(b"int", str(value).encode("ascii")); return
        if type(value) is float: atom(b"float64", struct.pack("<d", value)); return
        if type(value) is str:
            if len(value) > 4096: raise ValueError("model state string exceeds bound")
            atom(b"str", value.encode("utf-8")); return
        ident = id(value)
        if ident in ancestors: raise ValueError("cyclic model state refused")
        ancestors.add(ident)
        try:
            if isinstance(value, np.generic):
                atom(b"numpy_scalar"); visit(np.asarray(value), depth + 1)
            elif isinstance(value, np.ndarray):
                atom(b"ndarray"); visit(tuple(value.shape), depth + 1)
                dtype = value.dtype
                if dtype.names is not None:
                    # Named fields and their ABI layout are retained; unrelated
                    # padding bytes are never mistaken for learned parameters.
                    atom(b"structured"); visit(dtype.itemsize, depth + 1)
                    visit(tuple(dtype.names), depth + 1)
                    for name in dtype.names:
                        field_type, offset = dtype.fields[name][:2]
                        visit(name, depth + 1); visit(offset, depth + 1)
                        visit(field_type.str, depth + 1); visit(value[name], depth + 1)
                else:
                    if dtype.kind not in "bifu" or dtype.itemsize > 8:
                        raise ValueError("only bounded numeric state arrays are supported")
                    if value.nbytes > 64 * 1024 * 1024: raise ValueError("numeric state array exceeds bound")
                    budget["array_bytes"] += value.nbytes
                    if budget["array_bytes"] > MAX_TOTAL_ARRAY_BYTES:
                        raise ValueError("aggregate model-state numeric-byte budget exceeded")
                    little = dtype.newbyteorder("<")
                    atom(b"numeric_dtype", little.str.encode("ascii"))
                    atom(b"numeric_data", np.ascontiguousarray(value, dtype=little).tobytes())
            elif type(value) is dict:
                if len(value) > 10000: raise ValueError("model state mapping exceeds bound")
                if any(type(key) is not str for key in value): raise ValueError("model state keys must be strings")
                atom(b"dict"); visit(len(value), depth + 1)
                for key in sorted(value): visit(key, depth + 1); visit(value[key], depth + 1)
            elif type(value) in (tuple, list):
                if len(value) > 10000: raise ValueError("model state sequence exceeds bound")
                atom(b"tuple" if type(value) is tuple else b"list"); visit(len(value), depth + 1)
                for item in value: visit(item, depth + 1)
            elif type(value) in MODEL_TYPES:
                atom(b"model_type", (type(value).__module__ + "." + type(value).__qualname__).encode("ascii"))
                if type(value) is _tree.Tree:
                    # __getstate__ omits Cython constructor state; it is part of
                    # exact identity too, even when score_samples happens to agree.
                    visit((value.n_features, value.n_classes, value.n_outputs), depth + 1)
                visit(value.__getstate__(), depth + 1)
            else:
                raise ValueError("unsupported model state type; never silently omit it")
        finally: ancestors.remove(ident)
    atom(b"identity_format", identity_format.encode("ascii")); visit(payload)
    return digest.hexdigest()
