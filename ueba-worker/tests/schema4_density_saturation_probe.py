"""One isolated FIT-only forest and actual Java score-saturation diagnostics.

Never imports ModelStore or admits a catalogue candidate. Existing PILOT rows
are score-only; a separately named population of normal READY worlds is fitted.
This helper is not a quality campaign, calibration job, or prevalence estimate.
"""

import argparse
from collections import Counter, defaultdict
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import subprocess

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from app.contract import FEATURE_NAMES_V4, TrainingConfig, feature_array
from app import schema4_episodes as generator
from tests.schema4_stress_identifiability import (
    EXPECTED_GENERATOR, EXPECTED_WORKSPACE, canonical, checksum,
    duplicate_free, private_write, producer_identity, transported,
)


IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
PILOT_SHA = "ecf04c04b0f5156ae7cdc5f28b0428e1eb9381c4b536bf39035bd92b89233d59"
FIT_DATASET = "schema4-density-probe-fit"
PAIR_DATASET = "schema4-density-probe-pairs"
STAGE = "ISOLATED_MODEL_REPRESENTATIONAL_DIAGNOSTIC_ONLY"


def value_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def array_sha(array, dtype):
    return hashlib.sha256(np.ascontiguousarray(array, dtype=dtype).tobytes()).hexdigest()


def leaf_groups(leaves, rows):
    groups = defaultdict(list)
    for index, leaf in enumerate(leaves):
        groups[np.ascontiguousarray(leaf, dtype="<i8").tobytes()].append(index)
    return [indices for indices in groups.values()
            if {rows[index]["label"] for index in indices} == {0, 1}]


def comparison(left, right, scores, leaves, arrays, normal_bounds):
    a, b = arrays[left], arrays[right]
    differences = np.flatnonzero(a != b)
    quantized_differences = np.flatnonzero(a.astype("<f4") != b.astype("<f4"))
    return {"left_index": left, "right_index": right,
            "same_float64_vector": bool(np.array_equal(a, b)),
            "same_float32_vector": bool(np.array_equal(a.astype("<f4"), b.astype("<f4"))),
            "differing_float64_feature_names": [FEATURE_NAMES_V4[i] for i in differences],
            "differing_float32_feature_names": [FEATURE_NAMES_V4[i] for i in quantized_differences],
            "raw_anomaly_scores": [float(scores[left]), float(scores[right])],
            "raw_anomaly_score_hex": [float(scores[left]).hex(), float(scores[right]).hex()],
            "exact_raw_score_collision": bool(scores[left] == scores[right]),
            "same_leaf_in_tree_count": int(np.sum(leaves[left] == leaves[right])),
            "total_tree_count": leaves.shape[1],
            "left_leaf_sha256": array_sha(leaves[left], "<i8"),
            "right_leaf_sha256": array_sha(leaves[right], "<i8"),
            "left_features": a.tolist(), "right_features": b.tolist(),
            "differing_features_and_fit_bounds": [
                {"name": FEATURE_NAMES_V4[i], "left": float(a[i]), "right": float(b[i]),
                 "fit_min": float(normal_bounds[0][i]), "fit_max": float(normal_bounds[1][i])}
                for i in differences]}


class Exporter:
    def __init__(self, classpath):
        self.classpath = classpath
        self.process_calls = 0
        self.frames = 0
        self.raw_hash = hashlib.sha256()
        self.stdout_hash = hashlib.sha256()

    def batch(self, worlds):
        frames = [transported(episode) for context, evaluation in worlds for episode in (*context, evaluation)]
        wanted = {evaluation["frame"]["frame_id"]: evaluation for _, evaluation in worlds}
        if len(wanted) != len(worlds):
            raise ValueError("unique evaluation frames required")
        raw = "".join(canonical(frame) + "\n" for frame in frames)
        if len(frames) > 4000 or len(raw.encode()) > 64 * 1024 * 1024:
            raise ValueError("bounded Java batch required")
        self.raw_hash.update(raw.encode())
        command = ["java", "-Xmx256m", "-cp", self.classpath,
                   "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"]
        self.process_calls += 1
        result = subprocess.run(command, input=raw, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError("actual immutable Java exporter failed")
        self.stdout_hash.update(result.stdout.encode())
        rows = [json.loads(line, object_pairs_hook=duplicate_free) for line in result.stdout.splitlines()]
        if len(rows) != len(frames) or any(row["frame_id"] != frame["frame_id"] for row, frame in zip(rows, frames)):
            raise ValueError("actual Java must conserve every raw context/evaluation frame")
        self.frames += len(rows)
        selected = []
        for row in rows:
            evaluation = wanted.get(row["frame_id"])
            if evaluation is None:
                continue
            plan = evaluation["scenario"]
            if (row["feature_schema_version"] != 4 or row["telemetry_contract_version"] != 3
                    or row["feature_names"] != list(FEATURE_NAMES_V4) or row["data_provenance"] != "DEMO_ONLY"
                    or row["label"] != plan["label"] or row["family"] != plan["family"]
                    or row["baseline_established"] != (row["cohort"] != "COLD")):
                raise ValueError("actual Java feature/label/readiness contract changed")
            feature_array([row["features"]], 1, 4)
            row["cohort"] = {"DEVELOPMENT": "READY", "UNSEEN": "UNSEEN_READY", "COLD": "COLD"}[evaluation["frame"]["cohort"]]
            selected.append(row)
        if len(selected) != len(worlds):
            raise ValueError("missing actual evaluated world")
        return selected

    def identity(self):
        return {"java_process_calls": self.process_calls, "actual_raw_frames": self.frames,
                "raw_stream_sha256": self.raw_hash.hexdigest(), "actual_java_stdout_sha256": self.stdout_hash.hexdigest()}


def fit_worlds(exporter, output):
    start = generator.PROTOCOL_ANCHOR + timedelta(days=6)
    rows, plans, batch = [], [], []
    for ordinal in range(700):
        at = start + timedelta(hours=ordinal % 12)
        context = generator.context_frames(FIT_DATASET, ordinal, at, cohort="READY")
        evaluation = generator.make_frame(FIT_DATASET, ordinal, 0, at, planned_cause="normal", cohort="READY")
        if (len(context) != 48 or evaluation["scenario"]["label"] != 0
                or evaluation["scenario"]["planned_cause"] != "normal"):
            raise ValueError("FIT-only normal 48-context protocol required")
        batch.append((context, evaluation))
        plans.append(evaluation["scenario"])
        if len(batch) == 64 or ordinal == 699:
            rows.extend(exporter.batch(batch))
            batch.clear()
            print(canonical({"stage": STAGE, "FIT_only_actual_normal_rows": len(rows), "fit_calls": 0}), flush=True)
    if (len({row["account_id"] for row in rows}) != 700
            or any(row["label"] != 0 or row["cohort"] != "READY" or not row["baseline_established"] for row in rows)):
        raise ValueError("FIT must have 700 distinct actually READY normal actors only")
    private_write(output / "fit-only-normal-rows.private.json", rows)
    private_write(output / "fit-only-plans.private.json", plans)
    return rows, {"dataset_id": FIT_DATASET, "scope": "FIT_ONLY_SYNTHETIC_DIAGNOSTIC_POPULATION",
                  "records": len(rows), "normal": 700, "positive": 0, "actual_cohort": "READY",
                  "context_frames_per_actor": 48, "distinct_actors": 700,
                  "target_date": "2026-04-07", "strict_14_day_temporal_fit_claimed": False,
                  "plans_sha256": value_sha(plans), "rows_sha256": checksum(output / "fit-only-normal-rows.private.json"),
                  **exporter.identity()}


def pilot_rows(pilot):
    manifest_path = pilot / "manifest.json"
    if checksum(manifest_path) != PILOT_SHA:
        raise ValueError("frozen original schema4 PILOT required")
    manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=duplicate_free)
    if manifest["stage"] != "PILOT" or manifest["feature_schema_version"] != 4:
        raise ValueError("PILOT scope required")
    rows = []
    identities = []
    for descriptor in manifest["splits"]["fold1-validation"]["shards"]:
        path = pilot / descriptor["path"]
        if path.is_symlink() or checksum(path) != descriptor["sha256"]:
            raise ValueError("frozen PILOT shard changed")
        shard = json.loads(path.read_bytes(), object_pairs_hook=duplicate_free)
        rows.extend(shard)
        identities.append({"path": descriptor["path"], "sha256": descriptor["sha256"], "records": len(shard)})
    if len(rows) != 2000 or sum(row["label"] for row in rows) != 1000:
        raise ValueError("exact original balanced 2000-row PILOT required")
    return rows, identities


def synthetic_pairs(classpath, output):
    start = generator.PROTOCOL_ANCHOR + timedelta(days=14, hours=12)
    profile = generator.account_profile(PAIR_DATASET, 0)
    # Purpose-selected only by planned counts, before any model exists/scores.
    # Never edits observed/labeled vectors, counts, rates, contexts or raw events.
    seed = None
    for candidate in range(4096):
        a = generator.build_scenario(candidate, profile, "benign_login_only_retries", start)
        b = generator.build_scenario(candidate, profile, "auth_failure_burst", start)
        if (a["scenario"]["plan"]["failed_logins"], b["scenario"]["plan"]["failed_logins"]) == (7, 8):
            seed = candidate
            break
    if seed is None:
        raise ValueError("no bounded source-generated neighboring planned counts")
    exporter = Exporter(classpath)
    rows, pairs = [], []
    for ordinal, cohort in enumerate(("READY", "UNSEEN_READY", "COLD")):
        profile = generator.account_profile(PAIR_DATASET, ordinal)
        context = generator.context_frames(PAIR_DATASET, ordinal, start, cohort=cohort)
        account = context[-1]["frame"]["account_id"]
        # Fixed profile/seed and past context on both sides of each synthetic pair.
        sides = [generator.build_scenario(seed, profile, cause, start, cohort,
                  account_id=account, frame_id=f"density-probe-frame-{ordinal}-{side}")
                 for side, cause in enumerate(("benign_login_only_retries", "auth_failure_burst"))]
        # Separate Java histories: sharing an account between sides in one
        # process would replay/duplicate its baseline context.
        actual = [exporter.batch([(context, evaluation)])[0] for evaluation in sides]
        if [row["features"][3] for row in actual] != [7, 8]:
            raise ValueError("source-generated neighboring count pair changed")
        path = output / f"synthetic-pair-{ordinal}.private.json"
        private_write(path, {"context": context, "evaluations": sides, "actual_java_rows": actual})
        pairs.append({"cohort": cohort, "selected_fixed_seed": seed, "planned_seed_candidates_checked": seed + 1,
                      "selection_basis": "FIRST_SEED_WITH_PLANNED_FAILED_COUNTS_7_AND_8_BEFORE_FITTING_OR_SCORING",
                      "same_profile": True, "same_execution_seed": True, "same_context": True,
                      "actual_failed_login_counts": [row["features"][3] for row in actual],
                      "evidence_path": path.name, "evidence_sha256": checksum(path)})
        rows.extend(actual)
    return rows, pairs, exporter.identity()


def run(root, pilot, workspace, output):
    output.mkdir(mode=0o700)
    source_paths = [Path(__file__).resolve(), Path(generator.__file__).resolve(),
                    root / "ueba-worker/app/contract.py", root / "ueba-worker/app/model.py",
                    root / "ueba-worker/tests/schema4_stress_identifiability.py"]
    sources = {str(path.relative_to(root)): checksum(path) for path in source_paths}
    if checksum(Path(generator.__file__)) != EXPECTED_GENERATOR:
        raise ValueError("frozen generator source required")
    classpath, producers = producer_identity(workspace)
    pilot, shard_identity = pilot_rows(pilot)
    synthetic, pairs, synthetic_java = synthetic_pairs(classpath, output)
    exporter = Exporter(classpath)
    normal, fit_identity = fit_worlds(exporter, output)
    if {row["account_id"] for row in normal} & {row["account_id"] for row in (*pilot, *synthetic)}:
        raise ValueError("FIT and score-only actors must be disjoint")
    training = feature_array([row["features"] for row in normal], 700, 4)
    rows = [*pilot, *synthetic]
    arrays = feature_array([row["features"] for row in rows], 2006, 4)
    recipe = TrainingConfig(200, 256, 1.0, 42)
    forest = IsolationForest(**recipe.parameters())
    forest.fit(training)  # The sole fit call. No validation, positives, or holdout.
    model_path = output / "isolated-diagnostic-forest.private.joblib"
    joblib.dump(forest, model_path)
    model_path.chmod(0o600)
    scores = -forest.score_samples(arrays)
    quantized = arrays.astype("<f4")
    quantized_scores = -forest.score_samples(quantized)
    leaves = np.column_stack([tree.apply(quantized[:, features])
                              for tree, features in zip(forest.estimators_, forest.estimators_features_)])
    bounds = training.min(axis=0), training.max(axis=0)
    all_mixed_leaves = leaf_groups(leaves[:2000], pilot)
    raw_groups = defaultdict(list)
    for index, score in enumerate(scores[:2000]):
        raw_groups[float(score).hex()].append(index)
    mixed_scores = [indices for indices in raw_groups.values()
                    if {pilot[index]["label"] for index in indices} == {0, 1}]
    observed = []
    for cohort in ("READY", "UNSEEN_READY", "COLD"):
        left = [i for i, row in enumerate(pilot) if row["label"] == 0 and row["cohort"] == cohort
                and row["features"][0] == 0 and row["features"][3] > 0]
        right = [i for i, row in enumerate(pilot) if row["family"] == "auth_failure_burst" and row["cohort"] == cohort]
        if left and right:
            a, b = min(((a, b) for a in left for b in right), key=lambda pair:
                       (abs(arrays[pair[0], 3] - arrays[pair[1], 3]),
                        np.count_nonzero(quantized[pair[0]] != quantized[pair[1]]),
                        float(np.sum(np.abs(arrays[pair[0]] - arrays[pair[1]]))), pair))
            observed.append({"cohort": cohort, "normal_login_only_rows": len(left), "auth_anomaly_rows": len(right),
                             "nearest_pair_rule": "MIN_FAILED_COUNT_GAP_THEN_FLOAT32_DIFFERING_FEATURE_COUNT_THEN_L1_THEN_ROW_INDEX",
                             "left_frame_id": pilot[a]["frame_id"], "right_frame_id": pilot[b]["frame_id"],
                             **comparison(a, b, scores, leaves, arrays, bounds)})
    for index, pair in enumerate(pairs):
        pair.update(comparison(2000 + index * 2, 2001 + index * 2, scores, leaves, arrays, bounds))
    score_artifact = [{"frame_id": row["frame_id"], "label": row["label"], "family": row["family"], "cohort": row["cohort"],
                       "raw_anomaly_score": float(scores[i]), "raw_anomaly_score_hex": float(scores[i]).hex(),
                       "float32_feature_sha256": array_sha(quantized[i], "<f4"), "leaf_indices": leaves[i].tolist()}
                      for i, row in enumerate(rows)]
    private_write(output / "raw-scores-and-leaves.private.json", score_artifact)
    if any(checksum(root / name) != digest for name, digest in sources.items()):
        raise ValueError("diagnostic source changed during run")
    _, after = producer_identity(workspace)
    if after != producers:
        raise ValueError("immutable Java producer changed during run")
    result = {"stage": STAGE, "status": "COMPLETED", "quality_gate": "NOT_APPLICABLE",
              "pinned_image": IMAGE, "versions": {"sklearn": sklearn.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
              "helper_and_relevant_source_sha256": sources, "generator_source_sha256": EXPECTED_GENERATOR,
              "workspace_snapshot_sha256": EXPECTED_WORKSPACE, "immutable_java": producers,
              "original_pilot_manifest_sha256": PILOT_SHA, "original_pilot_score_only_shards": shard_identity,
              "fit_only_population": fit_identity, "fit_parameters": recipe.parameters(), "fit_calls": 1,
              "original_pilot_rows_fitted": 0, "validation_rows_fitted": 0, "positive_rows_fitted": 0,
              "holdout_records_read": 0, "calibration_records_read": 0, "aws_calls": 0,
              "candidate_registration_calls": 0, "activation_calls": 0, "threshold_selection_calls": 0,
              "forest_model_file_sha256": checksum(model_path), "fit_float64_matrix_sha256": array_sha(training, "<f8"),
              "fit_internal_float32_matrix_sha256": array_sha(training, "<f4"), "fit_shape": list(training.shape),
              "score_shape": list(arrays.shape), "score_samples_calls": 2, "tree_apply_calls": len(forest.estimators_),
              "float64_and_float32_scores_exactly_equal": bool(np.array_equal(scores, quantized_scores)),
              "original_pilot_mixed_exact_raw_score_groups": len(mixed_scores),
              "original_pilot_mixed_exact_leaf_groups": len(all_mixed_leaves),
              "original_pilot_mixed_leaf_group_records": sum(map(len, all_mixed_leaves)),
              "mixed_leaf_group_label_counts": [dict(Counter(str(pilot[i]["label"]) for i in group)) for group in all_mixed_leaves],
              "nearest_observed_target_associated_auth_pairs": observed,
              "synthetic_neighbor_pairs": pairs, "synthetic_pair_java": synthetic_java,
              "raw_scores_and_leaves_sha256": checksum(output / "raw-scores-and-leaves.private.json"),
              "normal_fit_feature_bounds": {name: {"min": float(bounds[0][i]), "max": float(bounds[1][i])}
                                             for i, name in enumerate(FEATURE_NAMES_V4)},
              "representative_accuracy_claimed": False, "population_impossibility_claimed": False,
              "captured_or_existing_labeled_data_transformed": False,
              "limitations": ["One diagnostic fit, not 360 approved campaign fits or strict candidate admission.",
                              "700 separately generated normal READY worlds, not original captures or representative real training traffic.",
                              "Existing balanced 2000-row PILOT is score-only; no validation/positive/holdout fits.",
                              "Purpose-selected count-7/count-8 neighbors are synthetic and not a prevalence sample.",
                              "Exact score/leaf collisions describe this fitted forest and these inputs, not population impossibility or accuracy.",
                              "No percentiles, calibration, thresholds, model promotion or production-model changes."]}
    private_write(output / "result.private.json", result)
    private_write(output / "receipt.json", {"stage": STAGE, "status": "COMPLETED", "fit_calls": 1,
                  "quality_gate": "NOT_APPLICABLE", "result_sha256": checksum(output / "result.private.json")})
    print(canonical({"result": str(output / "result.private.json"), "result_sha256": checksum(output / "result.private.json"),
                     "fit_calls": 1, "mixed_raw_score_groups": len(mixed_scores), "mixed_leaf_groups": len(all_mixed_leaves),
                     "synthetic_pair_exact_collisions": [pair["exact_raw_score_collision"] for pair in pairs]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "pilot", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    run(args.root.resolve(), args.pilot.resolve(), args.workspace.resolve(), args.output.resolve())
