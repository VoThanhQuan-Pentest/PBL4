"""Additive calibrated-state identity; legacy IF/support algorithms stay exact.

Hybrid predictive state uses the independently validated numeric-only codec.
Its outer identity additionally binds every actual calibration array. It is not
a binary-file signature, dataset proof, evaluation result or admission gate.
"""
import hashlib
from pathlib import Path
import struct

import numpy as np
from app.contract import HYBRID_MODEL_KIND, IF_MODEL_KIND
from app import semantic_model as legacy

HYBRID_FORMAT = "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1"
MAX_CALIBRATION_ROWS = 2_000_000
MAX_TOTAL_NUMERIC_BYTES = legacy.MAX_TOTAL_ARRAY_BYTES


def _hybrid_model(value):
    from app.hybrid_incident import HybridIncidentScorer
    from app.hybrid_semantic import FORMAT
    return (type(value) is HybridIncidentScorer
            or type(value) is dict and value.get("state_format") == FORMAT)


def state_format(payload_or_kind):
    if isinstance(payload_or_kind, str):
        hybrid = payload_or_kind == HYBRID_MODEL_KIND
    else:
        hybrid = type(payload_or_kind) is dict and _hybrid_model(payload_or_kind.get("model"))
    return HYBRID_FORMAT if hybrid else legacy.state_format(payload_or_kind)


def verifier_sha256(model_kind=IF_MODEL_KIND):
    if model_kind != HYBRID_MODEL_KIND:
        return legacy.verifier_sha256(model_kind)
    from app.hybrid_semantic import verifier_sha256 as model_verifier
    digest = hashlib.sha256(HYBRID_FORMAT.encode())
    digest.update(Path(__file__).read_bytes())
    digest.update(bytes.fromhex(model_verifier()))
    return digest.hexdigest()


def _calibration(values):
    if type(values) is np.ndarray:
        if (values.ndim != 1 or not 100 <= len(values) <= MAX_CALIBRATION_ROWS
                or values.dtype.kind not in "ifu" or values.dtype.itemsize > 8):
            raise ValueError("primitive hybrid calibration array required")
    elif type(values) in (list, tuple):
        if (not 100 <= len(values) <= MAX_CALIBRATION_ROWS
                or any(type(value) not in (int, float) for value in values)):
            raise ValueError("primitive hybrid calibration values required")
    else:
        raise ValueError("bounded hybrid calibration sequence required")
    try:
        result = np.asarray(values, dtype="<f8")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("finite hybrid calibration required") from None
    if (result.ndim != 1 or not 100 <= len(result) <= MAX_CALIBRATION_ROWS
            or not np.isfinite(result).all() or np.any(result[1:] < result[:-1])):
        raise ValueError("bounded sorted finite hybrid calibration required")
    return result


def state_sha256(payload):
    if type(payload) is not dict or not _hybrid_model(payload.get("model")):
        return legacy.state_sha256(payload)
    if set(payload) not in ({"model", "calibration_scores"},
                           {"model", "calibration_scores", "calibration_by_cohort"}):
        raise ValueError("known calibrated hybrid payload fields required")
    from app.hybrid_semantic import MAX_NUMERIC_BYTES, state_sha256 as model_sha
    predictive_sha = model_sha(payload["model"])
    scores = _calibration(payload["calibration_scores"])
    buckets = payload.get("calibration_by_cohort")
    arrays = {"calibration_scores": scores}
    if "calibration_by_cohort" in payload:
        if type(buckets) is not dict or set(buckets) != {"READY", "COLD"}:
            raise ValueError("exact hybrid calibration cohort buckets required")
        arrays.update({"calibration_by_cohort/" + name: _calibration(values) for name, values in buckets.items()})
        if not np.array_equal(scores, arrays["calibration_by_cohort/READY"]):
            raise ValueError("hybrid primary calibration must equal READY bucket")
    if MAX_NUMERIC_BYTES + sum(array.nbytes for array in arrays.values()) > MAX_TOTAL_NUMERIC_BYTES:
        raise ValueError("aggregate hybrid model/calibration numeric-byte budget exceeded")
    digest = hashlib.sha256()
    def atom(tag, body):
        digest.update(tag); digest.update(struct.pack(">Q", len(body))); digest.update(body)
    atom(b"format", HYBRID_FORMAT.encode())
    atom(b"model", bytes.fromhex(predictive_sha))
    for name, array in sorted(arrays.items()):
        atom(b"name", name.encode())
        atom(b"dtype", b"<f8")
        atom(b"rows", struct.pack(">Q", len(array)))
        atom(b"values", np.ascontiguousarray(array, dtype="<f8").tobytes())
    return digest.hexdigest()
