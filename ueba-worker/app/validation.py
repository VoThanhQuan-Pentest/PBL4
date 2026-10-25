"""Validation-only grid sweeps of cached actual forest scores and Java rule decisions.

No numeric holdout row is read here. Labels are confined to metric aggregation.
SIEM decisions combine independent ML with Java's frozen-policy rule-only
decision; no Python copy of the risk weights or signal thresholds exists.
"""

from collections import defaultdict
from dataclasses import asdict
import fcntl
import hashlib
from itertools import product
import os
from pathlib import Path

import numpy as np

from app.calibration import connect, identity, private_directory, prove_unique_split, score_cache
from app.catalog import ShardedDataset
from app.contract import (CAMPAIGN_SEEDS, HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, campaign_runs,
                          model_recipe_binding, parse_training_config, recipe_binding)
from app.model import ModelStore
from app.policy import DETECTION_GRID, PERCENTILE_SCALE, PROBABILITY_SCALE, ScorePolicy, canonical
from app.risk_replay import JavaRiskReplay
from app.strict_metrics import Confusion, FAMILIES

COHORT_NAMES = ("READY", "UNSEEN_READY", "COLD")
RULE_THRESHOLDS = (45, 60, 70)


def config_document(config):
    """Hybrid's typed config has no scorer-level parameters() contract."""
    return asdict(config) if recipe_binding(config)["model_kind"] == HYBRID_MODEL_KIND else config.parameters()


def class_binding(workspace):
    from app.risk_replay import CLASS_FILES
    directory = workspace / "backend/target/classes/com/flarefitness/backend"
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in CLASS_FILES}


def java_rules(dataset, name, directory, workspace, *, progress=None):
    """Cache three production rule-only decisions once per split/code binding."""
    if name == "holdout": raise ValueError("validation rule cache must not open holdout")
    split = dataset.split(name); classes = class_binding(workspace)
    policies = [ScorePolicy.strict(rule_threshold=threshold, schema=dataset.manifest["feature_schema_version"])
                for threshold in RULE_THRESHOLDS]
    binding = {"dataset_sha256": dataset.sha256, "split_sha256": split["sha256"], "classes": classes,
               "policy_sha256": [policy.sha256 for policy in policies], "records": split["records"]}
    leaf = private_directory(directory / ("rules-" + hashlib.sha256(canonical(binding).encode()).hexdigest()[:24]))
    prove_unique_split(dataset, name, directory)
    with (leaf / "writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = connect(leaf / "rules.sqlite")
        replays = []
        try:
            identity(db, binding)
            db.execute("CREATE TABLE IF NOT EXISTS shards(id TEXT PRIMARY KEY,input_sha256 TEXT NOT NULL,offset INTEGER NOT NULL,records INTEGER NOT NULL,decision_sha256 TEXT NOT NULL)")
            path = leaf / "rules.u8"
            if path.is_symlink(): raise ValueError("decision cache cannot be a symlink")
            if not path.exists():
                if db.execute("SELECT count(*) FROM shards").fetchone()[0]: raise ValueError("committed decision bytes were lost")
                with path.open("xb") as stream: stream.truncate(split["records"] * 3)
                path.chmod(0o600)
            if path.stat().st_size != split["records"] * 3: raise ValueError("decision cache size changed")
            values = np.memmap(path, dtype="u1", mode="r+", shape=(split["records"], 3))
            offset, computed, reused = 0, 0, 0
            try:
                for descriptor, rows in dataset.iter_shards(name):
                    end = offset + len(rows)
                    previous = db.execute("SELECT input_sha256,offset,records,decision_sha256 FROM shards WHERE id=?", (descriptor["id"],)).fetchone()
                    if previous is not None:
                        digest = hashlib.sha256(values[offset:end].tobytes()).hexdigest()
                        if previous != (descriptor["sha256"], offset, len(rows), digest): raise ValueError("cached production decisions changed")
                        reused += 1
                    else:
                        if not replays:
                            replays = [JavaRiskReplay(workspace, policy, expected_classes=classes) for policy in policies]
                        scores = [{"raw_anomaly_score": 0.0, "normal_percentile": 0.0, "level": "NORMAL_RANGE"} for _ in rows]
                        for column, replay in enumerate(replays):
                            actual = replay.score(rows, scores)
                            if any(row["predictions"]["MODEL_ONLY"] for row in actual):
                                raise ValueError("rule-only cache unexpectedly contained model detections")
                            values[offset:end, column] = [row["predictions"]["SIEM_FINAL"] for row in actual]
                        values.flush()
                        with path.open("rb") as stream:
                            os.fsync(stream.fileno())
                        digest = hashlib.sha256(values[offset:end].tobytes()).hexdigest()
                        with db: db.execute("INSERT INTO shards VALUES(?,?,?,?,?)", (descriptor["id"], descriptor["sha256"], offset, len(rows), digest))
                        computed += 1
                    offset = end
                    if progress: progress({"split": name, "rule_records": offset, "computed_shards": computed, "reused_shards": reused})
                if offset != split["records"] or db.execute("SELECT sum(records) FROM shards").fetchone()[0] != offset:
                    raise ValueError("incomplete production decision population")
                if not np.isin(values, (0, 1)).all(): raise ValueError("production decisions must be booleans")
                output = np.array(values, dtype=bool)
                receipt = {**binding, "decision_sha256": hashlib.sha256(values.tobytes()).hexdigest(),
                           "computed_shards": computed, "reused_shards": reused}
            finally: values._mmap.close()
            return output, receipt
        finally:
            for replay in replays: replay.close()
            db.close()


def midrank(calibration, raw):
    if len(calibration) < 100 or not np.isfinite(calibration).all() or np.any(calibration[1:] < calibration[:-1]):
        raise ValueError("sorted calibration required")
    return (np.searchsorted(calibration, raw, side="left") + np.searchsorted(calibration, raw, side="right")) / (2 * len(calibration)) * 100


def confusion(predicted, labels):
    positives = labels == 1; negatives = labels == 0
    return Confusion(int(np.count_nonzero(predicted & positives)), int(np.count_nonzero(~predicted & positives)),
                     int(np.count_nonzero(predicted & negatives)), int(np.count_nonzero(~predicted & negatives)))


def merge(values):
    return Confusion(*(sum(getattr(value, key) for value in values) for key in ("tp", "fn", "fp", "tn")))


def point_qualified(scopes, policy=None):
    policy = policy or ScorePolicy.strict()
    quality = policy.document["quality"]
    if set(scopes) != {"MODEL_ONLY", "SIEM_FINAL"}: raise ValueError("both independent and final scopes required")
    for result in scopes.values():
        if set(result["families"]) != set(FAMILIES) or set(result["cohorts"]) != set(COHORT_NAMES):
            raise ValueError("all observed families/cohorts required")
        for record in (result, *result["families"].values(), *result["cohorts"].values()):
            counted = Confusion(*(record[key] for key in ("tp", "fn", "fp", "tn"))).metrics()
            if any(record.get(key) != value for key, value in counted.items()):
                raise ValueError("validation metric differs from actual confusion counters")
        if (sum(record["positive_samples"] for record in result["families"].values()) != result["positive_samples"]
                or sum(record["positive_samples"] for record in result["cohorts"].values()) != result["positive_samples"]
                or sum(record["normal_samples"] for record in result["cohorts"].values()) != result["normal_samples"]):
            raise ValueError("validation group populations differ from global counters")
        if (result["precision"] is None or result["precision"] < quality["precision_min_ppm"] / PROBABILITY_SCALE or result["recall"] is None
                or result["recall"] <= quality["recall_min_ppm"] / PROBABILITY_SCALE or result["false_positive_rate"] is None
                or result["false_positive_rate"] >= quality["fpr_max_ppm"] / PROBABILITY_SCALE):
            return False
        for group in (*result["families"].values(), *result["cohorts"].values()):
            if group["recall"] is None or group["recall"] <= quality["slice_recall_min_ppm"] / PROBABILITY_SCALE: return False
    return True


def sweep(percentiles, labels, family_codes, cohort_codes, rules, *, schema=2):
    """Aggregate cohort-local thresholds first; do not replay 192 full datasets."""
    count = len(labels)
    if (percentiles.shape != (count,) or family_codes.shape != (count,) or cohort_codes.shape != (count,)
            or rules.shape != (count, 3) or rules.dtype != np.dtype(bool) or not np.isfinite(percentiles).all()
            or not np.isin(labels, (0, 1)).all() or not np.isin(cohort_codes, (0, 1, 2)).all()
            or (percentiles < 0).any() or (percentiles > 100).any()
            or not np.isin(family_codes, range(6)).all() or not np.array_equal(labels == 0, family_codes == 0)):
        raise ValueError("complete corresponding validation arrays required")
    local = {}
    for cohort_index, cohort in enumerate(COHORT_NAMES):
        rows = cohort_codes == cohort_index
        truth, families = labels[rows], family_codes[rows]
        for detection in DETECTION_GRID:
            ml = percentiles[rows] >= detection / PERCENTILE_SCALE
            for rule_index, rule in enumerate(RULE_THRESHOLDS):
                for scope, prediction in (("MODEL_ONLY", ml), ("SIEM_FINAL", ml | rules[rows, rule_index])):
                    total = confusion(prediction, truth)
                    by_family = {family: confusion(prediction[families == index + 1], truth[families == index + 1])
                                 for index, family in enumerate(FAMILIES)}
                    local[(cohort, detection, rule, scope)] = (total, by_family)
    results = []
    for ready, cold, rule in product(DETECTION_GRID, DETECTION_GRID, RULE_THRESHOLDS):
        scopes = {}
        for scope in ("MODEL_ONLY", "SIEM_FINAL"):
            groups = {name: local[(name, cold if name == "COLD" else ready, rule, scope)] for name in COHORT_NAMES}
            total = merge([value[0] for value in groups.values()])
            families = {family: merge([value[1][family] for value in groups.values()]).metrics() for family in FAMILIES}
            scopes[scope] = {**total.metrics(), "families": families,
                             "cohorts": {name: value[0].metrics() for name, value in groups.items()}}
        policy = ScorePolicy.strict(ready, cold, rule, schema=schema)
        results.append({"policy": policy.wire(), "scopes": scopes, "point_qualified_for_selection": point_qualified(scopes),
                        "evaluation_scope": "VALIDATION", "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY"})
    return results


def validate_candidate(dataset, store, version, fold, directory, workspace, *, progress=None):
    if type(fold) is not int or fold not in (1, 2, 3): raise ValueError("approved temporal validation fold required")
    name = f"fold{fold}-validation"; split = dataset.split(name)
    if dataset.manifest["stage"] == "STRICT" and (split["normal"] != 1000000 or split["positive"] != 1000):
        raise ValueError("strict validation population required")
    metadata, payload = store.load_candidate(version)
    schema = dataset.manifest["feature_schema_version"]
    if (metadata.get("dataset_manifest_sha256") != dataset.sha256 or metadata.get("fold") != fold
            or metadata.get("feature_schema_version") != schema
            or ScorePolicy.from_wire(metadata["score_policy"]).document["feature_schema_version"] != schema):
        raise ValueError("candidate dataset/fold binding mismatch")
    binding = model_recipe_binding(metadata)
    if binding["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
        config = parse_training_config(binding["model_kind"], metadata["model_config"])
        if config_document(config) != metadata["model_config"] or recipe_binding(config) != binding:
            raise ValueError("validation model recipe/configuration mismatch")
    if binding["model_kind"] == HYBRID_MODEL_KIND and schema != 4:
        raise ValueError("hybrid validation requires schema 4")
    buckets = payload.get("calibration_by_cohort")
    if not isinstance(buckets, dict) or set(buckets) != {"READY", "COLD"}: raise ValueError("both actual calibrated cohorts required")
    raw, raw_receipt = score_cache(dataset, name, payload["model"], metadata["sha256"], directory, progress=progress, sort_output=False)
    rules, rule_receipt = java_rules(dataset, name, directory, workspace, progress=progress)
    labels = np.empty(split["records"], dtype="u1"); families = np.empty_like(labels); cohorts = np.empty_like(labels)
    offset = 0
    for _, rows in dataset.iter_shards(name):
        end = offset + len(rows)
        labels[offset:end] = [row["label"] for row in rows]
        families[offset:end] = [0 if row["family"] == "normal" else 1 + FAMILIES.index(row["family"]) for row in rows]
        cohorts[offset:end] = [COHORT_NAMES.index(row["cohort"]) for row in rows]
        offset = end
    if offset != len(labels): raise ValueError("validation labels/cohorts have incomplete correspondence")
    percentiles = np.empty_like(raw)
    for cohort_name, codes in (("READY", (0, 1)), ("COLD", (2,))):
        mask = np.isin(cohorts, codes); percentiles[mask] = midrank(buckets[cohort_name], raw[mask])
    result = sweep(percentiles, labels, families, cohorts, rules, schema=schema)
    return {"model_version": version, "model_sha256": metadata["sha256"], "dataset_manifest_sha256": dataset.sha256,
            "validation_split_sha256": split["sha256"], "calibration_sha256": metadata["calibration_sha256"],
            "fold": fold, "config": metadata["model_config"], "policies": result,
            "raw_score_receipt": raw_receipt, "production_rule_receipt": rule_receipt,
            **(binding if binding["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) else {}),
            "quality_gate": "NOT_APPLICABLE", "evaluation_scope": "VALIDATION", "data_provenance": "DEMO_ONLY"}


def rank_configurations(receipts, model_kind=IF_MODEL_KIND):
    """One common policy must survive every seed/fold; no lucky representative."""
    if len(receipts) != 360: raise ValueError("all 360 actual validation receipts are required")
    approved = campaign_runs(model_kind)
    fields = (("max_iter", "max_leaf_nodes", "l2_regularization") if model_kind == HYBRID_MODEL_KIND else
              ("neighbor_count", "reference_count", "metric") if model_kind == SUPPORT_MODEL_KIND else
              ("n_estimators", "max_samples", "max_features"))
    expected_configurations = {tuple(config_document(run["config"])[key] for key in fields) for run in approved}
    approved_policies = {ScorePolicy.strict(ready, cold, rule, schema=4).sha256
                         for ready, cold, rule in product(DETECTION_GRID, DETECTION_GRID, RULE_THRESHOLDS)} if model_kind == HYBRID_MODEL_KIND else None
    grouped = defaultdict(list)
    for receipt in receipts:
        config = receipt["config"]
        binding = model_recipe_binding(receipt)
        if binding["model_kind"] != model_kind: raise ValueError("validation receipt model kind differs from campaign")
        typed = parse_training_config(model_kind, config)
        if config != config_document(typed): raise ValueError("complete approved validation configuration required")
        if binding["recipe_sha256"] is not None and binding != recipe_binding(typed):
            raise ValueError("validation receipt recipe/configuration mismatch")
        if model_kind == HYBRID_MODEL_KIND:
            if type(receipt["fold"]) is not int or receipt["fold"] not in (1, 2, 3):
                raise ValueError("approved hybrid temporal validation fold required")
            if (len(receipt["policies"]) != 192
                    or {ScorePolicy.from_wire(case["policy"]).sha256 for case in receipt["policies"]} != approved_policies):
                raise ValueError("all approved schema 4 policy grid cases must be evaluated")
        grouped[tuple(config[key] for key in fields)].append(receipt)
    if set(grouped) != expected_configurations: raise ValueError("all 24 approved configurations are required")
    considered = []
    for configuration, runs in grouped.items():
        expected = {(fold, seed) for fold in (1, 2, 3) for seed in CAMPAIGN_SEEDS}
        if len(runs) != 15 or {(run["fold"], run["config"]["random_state"]) for run in runs} != expected:
            raise ValueError("each configuration needs all fifteen real seed/fold validation runs")
        maps = [{ScorePolicy.from_wire(case["policy"]).sha256: case for case in run["policies"]} for run in runs]
        common = set.intersection(*(set(value) for value in maps))
        if len(common) != 192: raise ValueError("all approved policy grid cases must be evaluated")
        policies = []
        for checksum in sorted(common):
            cases = [value[checksum] for value in maps]
            qualified = all(point_qualified(case["scopes"], ScorePolicy.from_wire(case["policy"])) for case in cases)
            recalls = [case["scopes"][scope]["recall"] or 0 for case in cases for scope in ("MODEL_ONLY", "SIEM_FINAL")]
            precisions = [case["scopes"][scope]["precision"] or 0 for case in cases for scope in ("MODEL_ONLY", "SIEM_FINAL")]
            fprs = [case["scopes"][scope]["false_positive_rate"] if case["scopes"][scope]["false_positive_rate"] is not None else 1.0
                    for case in cases for scope in ("MODEL_ONLY", "SIEM_FINAL")]
            spreads = [max(value) - min(value) for fold in (1, 2, 3) for scope in ("MODEL_ONLY", "SIEM_FINAL")
                       if (value := [case["scopes"][scope]["recall"] or 0 for case, run in zip(cases, runs) if run["fold"] == fold])]
            policies.append({"policy": cases[0]["policy"], "qualified": qualified, "worst_recall": min(recalls),
                             "worst_precision": min(precisions), "worst_fpr": max(fprs), "maximum_seed_recall_spread": max(spreads)})
        policies.sort(key=lambda value: (not value["qualified"], -value["worst_recall"], -value["worst_precision"], value["worst_fpr"],
                                       value["maximum_seed_recall_spread"], value["policy"]["policy_sha256"]))
        considered.append({"configuration": dict(zip(fields, configuration)),
                           "best_common_policy": policies[0], "qualified": policies[0]["qualified"]})
    if len(considered) != 24: raise ValueError("all 24 approved configurations are required")
    considered.sort(key=lambda value: (not value["qualified"], -value["best_common_policy"]["worst_recall"],
                                      -value["best_common_policy"]["worst_precision"], value["best_common_policy"]["worst_fpr"],
                                      value["best_common_policy"]["maximum_seed_recall_spread"],
                                      *(value["configuration"][key] for key in fields)))
    return {"status": "RANKED" if any(value["qualified"] for value in considered) else "NO_QUALIFIED_CONFIG",
            "configurations": considered, "quality_gate": "NOT_RUN", "holdout_scored": False,
            **({"model_kind": model_kind, "recipe_version": 1} if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) else {}),
            "criterion": "one common policy passes both scopes and all family/cohort point recalls in every seed/fold; worst-case quality before spread/complexity"}
