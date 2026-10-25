#!/usr/bin/env python3
"""Fixed fold-1/seed-42 normal-density PILOT diagnostic; never serving admission.

Run inside the pinned research image, with the repository read-only and a new
private output directory writable. A single fixed default must complete before
the optional complete 24-recipe grid. No selection, threshold tuning, strict
campaign, holdout access, serialization, registration or promotion occurs.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import inspect
import os
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))

import numpy as np
from sklearn.neighbors import LocalOutlierFactor

from app.catalog import ShardedDataset, parse_json, row_stats, utc
from app.contract import FEATURE_NAMES_V4
from app.normal_density import CONFIGURATIONS, NormalDensityScorer, RECIPE_VERSION
from app.policy import ScorePolicy, canonical
from app.risk_replay import CLASS_FILES, JavaRiskReplay
from app.strict_metrics import Confusion, FAMILIES
from app.validation import point_qualified

IMAGE_ID = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
PILOT = ROOT / "observability/runtime/ueba-experiments/schema4-pilot-20261003-a01"
PILOT_SHA = "3c127c1e57a4a436ecabef1c9fe9d40465fc9191313259560a85554b6d7b9f12"
WORKSPACE = ROOT / "observability/runtime/schema4-java-workspace-20261002-bleITZXE/frozen-exporter"
WORKSPACE_SHA = "64e5aee49d6f716a66e2f700e3888e9fe0e53e6123ad11e3a1713fd57f83f8d2"
SPLITS = ("fold1-fit", "fold1-calibration-ready", "fold1-calibration-cold", "fold1-validation")
DEFAULT = (8, 256, "euclidean")
RAW_REPRESENTATION = "LOG1P_NONNEGATIVE_LOF_NOVELTY_RATIO"
SCOPES = ("MODEL_ONLY", "SIEM_FINAL")
STAGE = "BOUNDED_NORMAL_DENSITY_PILOT_DIAGNOSTIC"
EXPECTED_SOURCES = (
    "observability/scripts/diagnose-ueba-normal-density.py",
    "ueba-worker/app/normal_density.py", "ueba-worker/app/normal_support.py",
    "ueba-worker/app/catalog.py", "ueba-worker/app/contract.py",
    "ueba-worker/app/policy.py", "ueba-worker/app/risk_replay.py",
    "ueba-worker/app/strict_metrics.py", "ueba-worker/app/validation.py", "ueba-worker/requirements.lock",
)


def checksum(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular non-symlink bound file required")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def value_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def array_sha(value):
    return hashlib.sha256(np.ascontiguousarray(value, dtype="<f8").tobytes()).hexdigest()


def write_private(path, value):
    # Exclusive creation preserves all previous diagnostics, including failures.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


class PilotOnlyDataset(ShardedDataset):
    """Refuse holdout or any other split before touching its numeric file."""
    def _read(self, relative, maximum):
        if relative != "manifest.json" and not re.fullmatch(
                r"shards/fold1-(?:fit|calibration-(?:ready|cold)|validation)-part[0-9]{2}-batch[0-9]{6}-[0-9]{3}\.json", relative):
            raise ValueError("only fixed fold-1 pilot numeric files may be read")
        return super()._read(relative, maximum)


def load_pilot():
    dataset = PilotOnlyDataset(PILOT, expected_sha256=PILOT_SHA)
    manifest = dataset.manifest
    if (manifest["stage"] != "PILOT" or manifest["feature_schema_version"] != 4
            or manifest["telemetry_contract_version"] != 3 or manifest["feature_names"] != list(FEATURE_NAMES_V4)
            or manifest["workspace_snapshot_sha256"] != WORKSPACE_SHA or set(manifest["splits"]) != set(SPLITS)):
        raise ValueError("exact frozen schema-4 pilot scope required")
    populations = {
        "fold1-fit": (2000, 0, {"READY": 2000}),
        "fold1-calibration-ready": (1000, 0, {"READY": 1000}),
        "fold1-calibration-cold": (1000, 0, {"COLD": 1000}),
        "fold1-validation": (20000, 1000, {"READY": 14700, "UNSEEN_READY": 4200, "COLD": 2100}),
    }
    rows, frames, episodes = {}, set(), set()
    for name in SPLITS:
        group = [row for _, shard in dataset.iter_shards(name) for row in shard]
        stats = row_stats(group)
        split = dataset.split(name)
        if any(split[key] != value for key, value in stats.items()):
            raise ValueError("full loaded split differs from frozen manifest")
        normal, positive, cohorts = populations[name]
        if (stats["normal"], stats["positive"], stats["cohorts"]) != (normal, positive, cohorts):
            raise ValueError("fixed complete pilot population required")
        for row in group:
            episode = (row["account_id"], utc(row["window_start"]).strftime("%Y-%m-%dT%H"))
            if row["frame_id"] in frames or episode in episodes:
                raise ValueError("cross-shard/split duplicate evaluated episode")
            frames.add(row["frame_id"])
            episodes.add(episode)
        rows[name] = group
    if any(row["label"] != 0 or row["family"] != "normal" or row["cohort"] != "READY"
           or row["baseline_established"] is not True for row in rows["fold1-fit"]):
        raise ValueError("genuine FIT requires normal READY only")
    if (max(utc(row["window_start"]) for row in rows["fold1-fit"])
            >= min(utc(row["window_start"]) for name in SPLITS[1:3] for row in rows[name])
            or max(utc(row["window_start"]) for name in SPLITS[1:3] for row in rows[name])
            >= min(utc(row["window_start"]) for row in rows["fold1-validation"])):
        raise ValueError("separate chronological FIT/calibration/validation required")
    if Counter(row["family"] for row in rows["fold1-validation"] if row["label"]) != Counter({name: 200 for name in FAMILIES}):
        raise ValueError("all five unchanged validation families required")
    return dataset, rows


def frozen_java():
    snapshot = WORKSPACE / "snapshot.json"
    if checksum(snapshot) != WORKSPACE_SHA:
        raise ValueError("frozen Java snapshot checksum mismatch")
    package = parse_json(snapshot.read_bytes())
    if set(package) != {"classes", "jars"} or not set(CLASS_FILES) <= set(package["classes"]):
        raise ValueError("complete actual Java replay classes required")
    classes = WORKSPACE / "backend/target/classes"
    expected = set()
    for name, expected_sha in package["classes"].items():
        if not re.fullmatch(r"(?:[A-Za-z0-9_$]+/)*[A-Za-z0-9_$]+\.class", name):
            raise ValueError("invalid frozen Java class path")
        relative = "com/flarefitness/backend/" + name
        expected.add(relative)
        if checksum(classes / relative) != expected_sha:
            raise ValueError("frozen Java class changed")
    if any(path.is_symlink() for path in classes.rglob("*")) or {
            str(path.relative_to(classes)) for path in classes.rglob("*.class")} != expected:
        raise ValueError("unbound or symlinked loadable Java class")
    jars = []
    for name, expected_sha in sorted(package["jars"].items()):
        if not re.fullmatch(r"[0-9]{4}-[A-Za-z0-9_.-]+\.jar", name) or checksum(WORKSPACE / "jars" / name) != expected_sha:
            raise ValueError("frozen Java jar changed")
        jars.append(str(WORKSPACE / "jars" / name))
    if {path.name for path in (WORKSPACE / "jars").iterdir()} != set(package["jars"]):
        raise ValueError("unbound frozen Java dependency")
    classpath = WORKSPACE / "backend/target/ueba-experiment.classpath"
    if classpath.is_symlink() or classpath.stat().st_size > 65536 or classpath.read_text().strip() != os.pathsep.join(jars):
        raise ValueError("actual replay classpath must contain only frozen jars")
    return {"snapshot_sha256": WORKSPACE_SHA, "classes": package["classes"], "jars": package["jars"],
            "classpath_sha256": checksum(classpath),
            "replay_classes": {name: package["classes"][name] for name in CLASS_FILES}}


def integrity(dataset):
    generation = PILOT / "generation.identity.json"
    if checksum(PILOT / "manifest.json") != PILOT_SHA or checksum(generation) != dataset.manifest["generation_identity_sha256"]:
        raise ValueError("frozen pilot manifest/generation identity changed")
    shards = {descriptor["path"]: descriptor["sha256"] for name in SPLITS
              for descriptor in dataset.split(name)["shards"]}
    if any(checksum(PILOT / path) != expected for path, expected in shards.items()):
        raise ValueError("frozen pilot numeric shard changed")
    lof_source = Path(inspect.getsourcefile(LocalOutlierFactor))
    return {"repository_sources": {name: checksum(ROOT / name) for name in EXPECTED_SOURCES},
            "dependencies": {name: importlib.metadata.version(name) for name in ("scikit-learn", "numpy", "scipy", "joblib")},
            "sklearn_lof_source_sha256": checksum(lof_source),
            "execution_image_id": IMAGE_ID, "image_identity_source": "PINNED_DOCKER_OPERATOR_INVOCATION",
            "dataset": {"manifest_sha256": PILOT_SHA, "generation_identity_sha256": checksum(generation),
                        "shards": shards, "split_sha256": {name: dataset.split(name)["sha256"] for name in SPLITS}},
            "java": frozen_java()}


def midrank(calibration, scores):
    normal = np.asarray(calibration, dtype=np.float64)
    query = np.asarray(scores, dtype=np.float64)
    if (normal.ndim != 1 or query.ndim != 1 or not len(normal) or not len(query)
            or not np.isfinite(normal).all() or not np.isfinite(query).all() or np.any(normal[1:] < normal[:-1])):
        raise ValueError("sorted finite independent normal calibration required")
    return (np.searchsorted(normal, query, side="left") + np.searchsorted(normal, query, side="right")) / (2 * len(normal)) * 100


def calibrate_scores(raw, rows, buckets, policy):
    raw = np.asarray(raw, dtype=np.float64)
    if raw.shape != (len(rows),) or set(buckets) != {"READY", "COLD"}:
        raise ValueError("complete corresponding cohort score buckets required")
    percentiles = np.empty(len(rows), dtype=np.float64)
    for cohort in ("READY", "COLD"):
        indices = [i for i, row in enumerate(rows) if ("COLD" if row["cohort"] == "COLD" else "READY") == cohort]
        if indices:
            percentiles[indices] = midrank(buckets[cohort], raw[indices])
    return [{"raw_anomaly_score": float(score), "normal_percentile": float(percentile),
             "level": policy.level(float(percentile), "COLD" if row["cohort"] == "COLD" else "READY")}
            for row, score, percentile in zip(rows, raw, percentiles)]


def decision_metrics(decisions):
    def summary(selected, scope):
        counters = [0, 0, 0, 0]
        for row in selected:
            truth, predicted = row["label"], row["predictions"][scope]
            if type(truth) is not int or truth not in (0, 1) or type(predicted) is not bool:
                raise ValueError("actual fixed labels and boolean Java predictions required")
            counters[0 if truth and predicted else 1 if truth else 2 if predicted else 3] += 1
        return Confusion(*counters).metrics()
    groups = {"families": defaultdict(list), "cohorts": defaultdict(list), "family_cohort": defaultdict(list)}
    for row in decisions:
        groups["families"][row["family"]].append(row)
        groups["cohorts"][row["cohort"]].append(row)
        groups["family_cohort"][row["family"] + ":" + row["cohort"]].append(row)
    return {scope: {"complete_validation": summary(decisions, scope),
                    **{name: {key: summary(group, scope) for key, group in sorted(values.items())}
                       for name, values in groups.items()},
                    "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY"}
            for scope in SCOPES}


def point_diagnostic(metrics, policy):
    # Reuse the existing counter-verified point test, never its selection path.
    scopes = {scope: {**metrics[scope]["complete_validation"],
                      "families": {name: metrics[scope]["families"][name] for name in FAMILIES},
                      "cohorts": metrics[scope]["cohorts"]} for scope in SCOPES}
    return {"both_scopes_point_qualified_diagnostic_only": point_qualified(scopes, policy),
            "strict_qualification": False, "selection_performed": False,
            "minimum_strict_population": {"normal": policy.document["quality"]["minimum_normal"],
                                          "positive": policy.document["quality"]["minimum_positive"],
                                          "family_positive": policy.document["quality"]["minimum_family_positive"]},
            "pilot_population_meets_strict_minimum": False,
            "confidence_gate": "NOT_EVALUATED_PILOT_ONLY", "quality_gate": "NOT_APPLICABLE"}


def verify_default(path, before, policy):
    if path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("complete fixed-default result required before grid")
    result = parse_json(path.read_bytes())
    if (result.get("status") != "COMPLETED" or result.get("mode") != "FIXED_DEFAULT"
            or result.get("stage") != STAGE or result.get("quality_gate") != "NOT_APPLICABLE"
            or result.get("integrity_before") != before or result.get("integrity_after") != before
            or result.get("policy_sha256") != policy.sha256 or result.get("actual_fit_calls") != 1
            or result.get("actual_validation_rows_replayed") != 21000
            or result.get("holdout_numeric_records_read") != 0 or result.get("strict_fit_calls") != 0
            or len(result.get("configurations", [])) != 1
            or result["configurations"][0].get("configuration") != list(DEFAULT)):
        raise ValueError("same-source complete fixed-default receipt required")
    receipt = path.parent / "predeclared.private.json"
    if checksum(receipt) != result["predeclared_receipt_sha256"]:
        raise ValueError("default predeclared receipt changed")
    for name, expected in result["private_artifacts"].items():
        if Path(name).name != name or checksum(path.parent / name) != expected:
            raise ValueError("completed default evidence changed")
    return {"result_sha256": checksum(path), "predeclared_receipt_sha256": checksum(receipt)}


def run(output, *, grid=False, default_result=None):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE_ID or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only execution required; do not install host sklearn")
    dataset, rows = load_pilot()
    policy = ScorePolicy.strict(schema=4)
    before = integrity(dataset)
    if RECIPE_VERSION != 2 or NormalDensityScorer().parameters().get("raw_score_representation") != RAW_REPRESENTATION:
        raise ValueError("frozen v2 log-density score representation required")
    previous = verify_default(default_result, before, policy) if grid else None
    if default_result is not None and not grid:
        raise ValueError("default receipt is only valid for a complete grid invocation")
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="normal-density-diagnostic-", dir=ROOT / "observability/runtime"))
    else:
        output = output.absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
            raise ValueError("new private output directory required")
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    configurations = tuple(CONFIGURATIONS) if grid else (DEFAULT,)
    if len(CONFIGURATIONS) != 24 or len(set(CONFIGURATIONS)) != 24 or DEFAULT not in CONFIGURATIONS:
        raise ValueError("exact predeclared distinct 24-recipe density grid required")
    declaration = {"stage": STAGE, "mode": "COMPLETE_PREDECLARED_GRID" if grid else "FIXED_DEFAULT",
                   "fold": 1, "seed": 42, "configurations": [list(value) for value in configurations],
                   "all_predeclared_configurations": [list(value) for value in CONFIGURATIONS],
                   "parameters": [NormalDensityScorer(*value, random_state=42).parameters() for value in configurations],
                   "integrity_before": before, "policy": policy.wire(), "fixed_default_before_grid": previous,
                   "density_score_representation": {"recipe_version": RECIPE_VERSION,
                       "representation": RAW_REPRESENTATION,
                       "revision_purpose": "COMPATIBILITY_WITH_UNCHANGED_FROZEN_JAVA_RAW_SCORE_BOUND",
                       "same_scorer_representation_for_calibration_and_query": True, "score_clipping": False,
                       "rank_equivalence": "MATHEMATICAL_MONOTONICITY_ONLY_FLOATING_POINT_TIES_USE_ACTUAL_MIDRANK"},
                   "fit_population": "EXACT_NORMAL_READY_FOLD1_FIT_ONLY", "quality_gate": "NOT_APPLICABLE",
                   "data_provenance": "DEMO_ONLY", "fit_calls_before_declaration": 0, "score_calls_before_declaration": 0,
                   "threshold_tuning": False, "feature_or_label_modification": False, "selection_or_promotion": False}
    receipt = output / "predeclared.private.json"
    write_private(receipt, declaration)  # Must commit source/recipe before any fit or score.
    write_private(output / "integrity-before.private.json", before)
    completed, artifacts, replayed, fit_calls = [], {}, 0, 0
    started = time.monotonic()
    fit_features = [row["features"] for row in rows["fold1-fit"]]
    for ordinal, configuration in enumerate(configurations):
        candidate_start = time.monotonic()
        scorer = NormalDensityScorer(*configuration, random_state=42)
        scorer.fit(fit_features)  # One new genuine normal-READY-only fit per recipe.
        fit_calls += 1
        if scorer.fit_count != 2000:
            raise ValueError("each genuine fit must conserve all normal READY FIT rows")
        buckets = {cohort: np.sort(scorer.anomaly_scores([row["features"] for row in rows["fold1-calibration-" + cohort.lower()]]))
                   for cohort in ("READY", "COLD")}
        calibration_path = output / f"candidate-{ordinal:02d}-calibration.private.json"
        write_private(calibration_path, {key: value.tolist() for key, value in buckets.items()})
        artifacts[calibration_path.name] = checksum(calibration_path)
        decisions, raw_scores, percentages = [], [], []
        score_path = output / f"candidate-{ordinal:02d}-scores-decisions.private.jsonl"
        descriptor = os.open(score_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        batch_calls = 0
        with os.fdopen(descriptor, "w", encoding="utf-8") as evidence, JavaRiskReplay(
                WORKSPACE, policy, expected_classes=before["java"]["replay_classes"]) as java:
            validation = rows["fold1-validation"]
            for offset in range(0, len(validation), 1000):
                batch = validation[offset:offset + 1000]
                raw = scorer.anomaly_scores([row["features"] for row in batch])
                scores = calibrate_scores(raw, batch, buckets, policy)
                actual = java.score(batch, scores)
                decisions.extend(actual)
                raw_scores.extend(float(value) for value in raw)
                percentages.extend(score["normal_percentile"] for score in scores)
                for original, score, decision in zip(batch, scores, actual):
                    evidence.write(canonical({"frame_id": original["frame_id"], **score, "predictions": decision["predictions"]}) + "\n")
                batch_calls += 1
                replayed += len(actual)
            evidence.flush()
            os.fsync(evidence.fileno())
        if len(decisions) != 21000 or sum(row["label"] for row in decisions) != 1000:
            raise ValueError("actual Java must conserve the full unchanged validation population")
        artifacts[score_path.name] = checksum(score_path)
        metrics = decision_metrics(decisions)
        record = {"ordinal": ordinal, "configuration": list(configuration), "parameters": scorer.parameters(),
                  "actual_fit_calls": 1, "actual_normal_ready_fit_rows": scorer.fit_count,
                  "calibration_rows": {cohort: len(bucket) for cohort, bucket in buckets.items()},
                  "calibration_scope": "PILOT_COHORT_INDEPENDENT_NORMAL_ONLY_MIDRANK",
                  "calibration_sha256": {cohort: array_sha(bucket) for cohort, bucket in buckets.items()},
                  "actual_java_replay_batches": batch_calls, "actual_validation_rows_replayed": len(decisions),
                  "raw_score_sha256": array_sha(raw_scores), "percentile_sha256": array_sha(percentages),
                  "decisions": metrics, "point_diagnostic": point_diagnostic(metrics, policy),
                  "finite_calibration_tail": {"normal_rows_per_bucket": 1000,
                      "detection_percentile_micro": policy.document["detection_percentile_micro"],
                      "detection_requires_score_strictly_above_observed_calibration_max": True,
                      "not_equivalent_to_million_row_strict_calibration": True},
                  "elapsed_seconds": time.monotonic() - candidate_start,
                  "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY"}
        candidate_path = output / f"candidate-{ordinal:02d}.private.json"
        write_private(candidate_path, record)
        artifacts[candidate_path.name] = checksum(candidate_path)
        completed.append(record)
        print(canonical({"stage": STAGE, "completed_configurations": len(completed), "planned_configurations": len(configurations),
                         "actual_fit_calls": fit_calls, "actual_validation_rows_replayed": replayed,
                         "configuration": list(configuration), "aggregate_decisions": {
                             scope: record["decisions"][scope]["complete_validation"] for scope in SCOPES},
                         "quality_gate": "NOT_APPLICABLE"}), flush=True)
    after = integrity(dataset)
    write_private(output / "integrity-after.private.json", after)
    if before != after:
        raise ValueError("bound source/dataset/Java/dependencies changed; retain unqualified evidence")
    if any(checksum(output / name) != expected for name, expected in artifacts.items()):
        raise ValueError("private evidence changed before terminal receipt")
    result = {"status": "COMPLETED", "stage": STAGE, "mode": declaration["mode"], "fold": 1, "seed": 42,
              "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY", "policy_sha256": policy.sha256,
              "policy": policy.wire(), "predeclared_receipt_sha256": checksum(receipt),
              "density_score_representation": declaration["density_score_representation"],
              "fixed_default_before_grid": previous, "integrity_before": before, "integrity_after": after,
              "integrity_unchanged": True, "configurations": completed, "private_artifacts": artifacts,
              "actual_fit_calls": fit_calls, "strict_fit_calls": 0, "actual_validation_rows_replayed": replayed,
              "holdout_numeric_records_read": 0, "labels_features_counters_cohorts_modified": False,
              "serving_contract_changed": False, "primary_or_aws_changed": False,
              "registered_serialized_selected_or_promoted": False,
              "limitations": ["SIMULATED_PILOT_NOT_REPRESENTATIVE_PREVALENCE_OR_DEPLOYMENT_EVIDENCE",
                              "NO_STRICT_QUALIFICATION_OR_CONFIDENCE_GATE", "READY_FIT_DOES_NOT_QUALIFY_COLD_SERVING",
                              "FINITE_1000_ROW_CALIBRATION_TAIL_IS_NOT_MILLION_ROW_STRICT_QUANTILE",
                              "SUBSAMPLED_FIT_REFERENCES_CAN_MISS_RARE_NORMAL_MODES",
                              "PILOT_FAILURE_DOES_NOT_PROVE_ALL_STRICT_POPULATIONS_IMPOSSIBLE",
                              "LOG_REPRESENTATION_IS_NOT_CLIPPING_BUT_FINITE_PRECISION_CAN_COALESCE_CLOSE_RATIOS",
                              "ALL_PREDECLARED_RECIPES_REPORTED_WITHOUT_WINNER_SELECTION"],
              "elapsed_seconds": time.monotonic() - started,
              "completed_at_utc": datetime.now(timezone.utc).isoformat()}
    write_private(output / "result.private.json", result)
    return output, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--grid", action="store_true", help="run all 24 predeclared recipes, with no selection")
    parser.add_argument("--default-result", type=Path, help="same-source completed fixed-default private result")
    args = parser.parse_args()
    output, result = run(args.output, grid=args.grid, default_result=args.default_result)
    print(canonical({"status": result["status"], "output": str(output), "result_sha256": checksum(output / "result.private.json"),
                     "actual_fit_calls": result["actual_fit_calls"], "quality_gate": "NOT_APPLICABLE"}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Normal-density diagnostic refused/failed: " + type(failure).__name__ + "; private evidence retained") from None
