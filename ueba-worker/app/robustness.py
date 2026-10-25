"""100,000 distinct bounded numeric cases; actual scoring, not accuracy evidence.

Runs only against a new private PILOT_ONLY fixture. No network, primary model,
incident, IP provider or response-action integration is used.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import tempfile
import time

import numpy as np

from app.contract import TrainingConfig, feature_array
from app.model import ModelStore
from app.policy import ScorePolicy

VALID = ("COLD_INTEGER", "READY_PERSONAL", "COUNT_LIMIT", "DEVIATION_LIMIT")
INVALID = ("NEGATIVE_COUNT", "FRACTIONAL_COUNT", "HTTP_COUNT_OVERFLOW", "ROUTE_COUNT_OVERFLOW", "NONBINARY_FLAG",
           "NAN", "POSITIVE_INFINITY", "NEGATIVE_INFINITY", "MAGNITUDE_OVERFLOW", "HIGH_DEVIATION", "LOW_DEVIATION",
           "WRONG_ERROR_RATE", "WRONG_FAILURE_RATE", "SHORT_VECTOR", "LONG_VECTOR", "NONNUMERIC")


def vector(index, *, cold=False):
    request = index + 10
    errors, failures, success = index % 4, index % 5, 1 + index % 7
    return [request, errors, 0, failures, success, 0, 1 + index % 9, 1,
            0 if cold else index % 2, 0, 0,
            0 if cold else (index % 2001 - 1000) / 500, 0,
            errors / request, failures / (failures + success)]


def case(kind, index):
    row = vector(index, cold=kind == "COLD_INTEGER")
    if kind == "COUNT_LIMIT": row[0] = 1000000; row[1] = index + 1; row[13] = row[1] / row[0]
    elif kind == "DEVIATION_LIMIT": row[11:13] = [-20, 20]
    elif kind == "NEGATIVE_COUNT": row[index % 8] = -index - 1
    elif kind == "FRACTIONAL_COUNT": row[index % 8] += 0.5
    elif kind == "HTTP_COUNT_OVERFLOW": row[1] = row[0] + 1; row[13] = row[1] / row[0]
    elif kind == "ROUTE_COUNT_OVERFLOW": row[6] = row[0] + 1
    elif kind == "NONBINARY_FLAG": row[8 + index % 3] = index + 2
    elif kind == "NAN": row[index % 15] = math.nan
    elif kind == "POSITIVE_INFINITY": row[index % 15] = math.inf
    elif kind == "NEGATIVE_INFINITY": row[index % 15] = -math.inf
    elif kind == "MAGNITUDE_OVERFLOW": row[0] = 1000001 + index; row[13] = row[1] / row[0]
    elif kind == "HIGH_DEVIATION": row[11] = 20.01 + index / 100
    elif kind == "LOW_DEVIATION": row[12] = -20.01 - index / 100
    elif kind == "WRONG_ERROR_RATE": row[13] += 0.01
    elif kind == "WRONG_FAILURE_RATE": row[14] += 0.01
    elif kind == "SHORT_VECTOR": row.pop()
    elif kind == "LONG_VECTOR": row.append(index)
    elif kind == "NONNUMERIC": row[index % 15] = "owned-invalid-" + str(index)
    elif kind not in VALID: raise ValueError("unknown robustness case kind")
    return row


def run(output, *, per_kind=5000):
    if per_kind != 5000: raise ValueError("full robustness run requires 20 x 5000 distinct cases")
    if output.is_symlink() or output.exists(): raise ValueError("new owned robustness result path required")
    start = time.monotonic(); seen = set(); stream = hashlib.sha256(); completed = {}
    with tempfile.TemporaryDirectory(prefix="owned-ueba-robustness-") as directory:
        store = ModelStore(Path(directory) / "models"); policy = ScorePolicy.strict()
        fit = [vector(index) for index in range(600)]
        source = store.train("owned_robustness_source", fit, fit[:120], schema_version=2,
                             config=TrainingConfig(200, 128, 1.0, 42), policy=policy)
        _, payload = store.load_candidate(source["model_version"])
        buckets = {"READY": np.sort(-payload["model"].score_samples(feature_array(fit[:300], 300, 2))),
                   "COLD": np.sort(-payload["model"].score_samples(feature_array([vector(index, cold=True) for index in range(300)], 300, 2)))}
        calibrated = store.recalibrated_candidate(source["model_version"], "owned_robustness_candidate", buckets, policy,
                expected_source_sha256=source["sha256"], dataset_sha256=hashlib.sha256(repr(fit).encode()).hexdigest(),
                split_sha256={name: hashlib.sha256(values.tobytes()).hexdigest() for name, values in buckets.items()}, calibration_scope="PILOT_ONLY")
        scored = 0
        for kind in VALID + INVALID:
            pending = []
            for index in range(per_kind):
                row = case(kind, index); encoded = (kind + "/" + repr(row)).encode(); sha = hashlib.sha256(encoded).hexdigest()
                if sha in seen: raise AssertionError("duplicate input case would inflate the count")
                seen.add(sha); stream.update(encoded + b"\n")
                if kind in VALID:
                    feature_array([row], 1, 2); pending.append(row)
                    if len(pending) == 256 or index == per_kind - 1:
                        cohort = "COLD" if kind == "COLD_INTEGER" else "READY"
                        result = store.score_candidate(calibrated["model_version"], pending, 2, [cohort] * len(pending))
                        if not result["available"] or len(result["results"]) != len(pending): raise AssertionError("scoring correspondence changed")
                        for score in result["results"]:
                            percentile = score["normal_percentile"]
                            if (not math.isfinite(score["raw_anomaly_score"]) or not 0 <= percentile <= 100
                                    or score["scoring_cohort"] != cohort or score["level"] != policy.level(percentile, cohort)):
                                raise AssertionError("nonfinite or policy/cohort-inconsistent actual score")
                        scored += len(pending); pending = []
                else:
                    try: feature_array([row], 1, 2)
                    except (ValueError, TypeError): pass
                    else: raise AssertionError("malformed case accepted: " + kind + "/" + str(index))
            completed[kind] = per_kind
        if store.active_version is not None or (store.directory / "active.json").exists(): raise AssertionError("robustness must not alter a primary")
        evidence = {"status": "COMPLETED", "total_distinct_cases": len(seen), "case_groups": completed,
                    "actual_scored_valid_cases": scored, "rejected_invalid_cases": len(INVALID) * per_kind,
                    "input_case_stream_sha256": stream.hexdigest(), "fixture_model_sha256": calibrated["sha256"],
                    "fixture_calibration_scope": calibrated["calibration_scope"], "elapsed_seconds": time.monotonic() - start,
                    "quality_gate": "NOT_APPLICABLE", "evaluation_scope": "ROBUSTNESS_ONLY", "data_provenance": "DEMO_ONLY",
                    "primary_changed": False, "outbound_requests": 0, "completed_at_utc": datetime.now(timezone.utc).isoformat()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as result: json.dump(evidence, result, sort_keys=True, allow_nan=False)
    output.chmod(0o600); return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, required=True)
    result = run(parser.parse_args().output)
    print(json.dumps({key: result[key] for key in ("status", "total_distinct_cases", "actual_scored_valid_cases", "rejected_invalid_cases", "quality_gate")}))


if __name__ == "__main__": main()
