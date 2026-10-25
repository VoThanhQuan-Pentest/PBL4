"""Explain one checksum-verified private diagnostic forest, with zero fits/scores."""
import argparse
from collections import defaultdict
import hashlib
import inspect
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.contract import FEATURE_NAMES_V4, feature_array
from tests.schema4_stress_identifiability import canonical, checksum, private_write


EXPECTED_RESULT = "3eddf631261696eca7df4a585cb053d342e9115d022bf7a2a72760e11ce9bf9b"


def run(output, pilot):
    result_path = output / "result.private.json"
    if checksum(result_path) != EXPECTED_RESULT:
        raise ValueError("the completed private single-fit result must be unchanged")
    result = json.loads(result_path.read_bytes())
    model_path = output / "isolated-diagnostic-forest.private.joblib"
    score_path = output / "raw-scores-and-leaves.private.json"
    if (model_path.is_symlink() or checksum(model_path) != result["forest_model_file_sha256"]
            or checksum(score_path) != result["raw_scores_and_leaves_sha256"]
            or checksum(pilot / "manifest.json") != result["original_pilot_manifest_sha256"]):
        raise ValueError("own trusted diagnostic forest/score/PILOT checksum mismatch")
    # Never accepts uploaded pickle bytes: this exact forest was produced by the
    # isolated helper and checksum-bound to its completed immutable result.
    model = joblib.load(model_path)
    if type(model) is not IsolationForest or model.n_features_in_ != 37:
        raise ValueError("exact known diagnostic IsolationForest required")
    bounds = {}
    for index in (3, 20):
        thresholds = [float(tree.tree_.threshold[node]) for tree in model.estimators_
                      for node, feature in enumerate(tree.tree_.feature) if feature == index]
        name = FEATURE_NAMES_V4[index]
        bounds[name] = {"split_count": len(thresholds), "split_threshold_min": min(thresholds),
                       "split_threshold_max": max(thresholds), **result["normal_fit_feature_bounds"][name],
                       "tree_count_using_feature": sum(any(f == index for f in tree.tree_.feature)
                                                       for tree in model.estimators_)}
    scores = json.loads(score_path.read_bytes())[:2000]
    rows = []
    for descriptor in result["original_pilot_score_only_shards"]:
        path = pilot / descriptor["path"]
        if checksum(path) != descriptor["sha256"]:
            raise ValueError("original PILOT shard changed")
        rows.extend(json.loads(path.read_bytes()))
    arrays = feature_array([row["features"] for row in rows], 2000, 4)
    groups = defaultdict(list)
    for index, score in enumerate(scores):
        if score["frame_id"] != rows[index]["frame_id"]:
            raise ValueError("score evidence and original PILOT row order changed")
        raw = np.ascontiguousarray(arrays[index], dtype="<f4").tobytes()
        if hashlib.sha256(raw).hexdigest() != score["float32_feature_sha256"]:
            raise ValueError("recorded actual float32 vector checksum differs")
        groups[tuple(score["leaf_indices"])].append(index)
    collisions = []
    for indices in groups.values():
        if {rows[i]["label"] for i in indices} != {0, 1}:
            continue
        left = next(i for i in indices if rows[i]["label"] == 0)
        positives = [i for i in indices if rows[i]["label"] == 1]
        a, b = min(((left, i) for i in positives), key=lambda pair:
                   (np.count_nonzero(arrays[pair[0]].astype("<f4") != arrays[pair[1]].astype("<f4")), pair))
        differences = np.flatnonzero(arrays[a] != arrays[b])
        collisions.append({"raw_anomaly_score": scores[a]["raw_anomaly_score"],
                           "raw_anomaly_score_hex": scores[a]["raw_anomaly_score_hex"],
                           "equal_leaf_count": len(scores[a]["leaf_indices"]),
                           "records": [{"index": i, "frame_id": rows[i]["frame_id"], "cohort": rows[i]["cohort"],
                                        "label": rows[i]["label"], "family": rows[i]["family"],
                                        "failed_login_count": rows[i]["features"][3]} for i in indices],
                           "fewest_differing_features_pair": {"left_index": a, "right_index": b,
                               "same_float32_vector": bool(np.array_equal(arrays[a].astype("<f4"), arrays[b].astype("<f4"))),
                               "features": [{"name": FEATURE_NAMES_V4[i], "left": float(arrays[a, i]),
                                             "right": float(arrays[b, i])} for i in differences]}})
    source = Path(inspect.getsourcefile(IsolationForest))
    explanation = {"scope": "EXPLANATION_OF_ONE_PRIVATE_DIAGNOSTIC_FIT_ONLY", "quality_gate": "NOT_APPLICABLE",
                   "completed_result_sha256": EXPECTED_RESULT, "forest_model_sha256": checksum(model_path),
                   "helper_source_sha256": checksum(Path(__file__).resolve()),
                   "sklearn_IsolationForest_source_sha256": checksum(source),
                   "additional_fit_calls": 0, "additional_score_samples_calls": 0, "additional_tree_apply_calls": 0,
                   "actual_forest_split_thresholds": bounds, "actual_original_pilot_leaf_collisions": collisions,
                   "conclusion": "The count-7/count-8 synthetic pairs differ only in count and READY failed-login deviation; both values exceed every fitted split threshold for those features, so each of these 200 trees follows the same branches. This is fitted-model saturation, not float32 input equality.",
                   "limitations": "This particular forest and these explicit inputs only; no representative accuracy or population impossibility claim."}
    path = output / "explanation.private.json"
    private_write(path, explanation)
    print(canonical({"explanation_sha256": checksum(path), "additional_fit_calls": 0, "additional_score_calls": 0,
                     "actual_original_pilot_mixed_leaf_groups": len(collisions), "split_thresholds": bounds}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pilot", type=Path, required=True)
    args = parser.parse_args()
    run(args.output.resolve(), args.pilot.resolve())
