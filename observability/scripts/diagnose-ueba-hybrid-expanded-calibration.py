#!/usr/bin/env python3
"""Default hybrid reproduction with larger replacement normal calibration.

No old files or thresholds are changed. This explicitly refits both components
from the same frozen training, checks exact original validation raw-score
reproduction, and replaces (never merges) the two small calibration buckets.
It is a descriptive PILOT, not zero-fit strict recalibration or serving proof.
"""

import argparse
from datetime import timedelta
import importlib.util
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
SPEC = importlib.util.spec_from_file_location("hybrid_expanded_base", ROOT / "observability/scripts/diagnose-ueba-hybrid.py")
hybrid = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hybrid
SPEC.loader.exec_module(hybrid)
fixed = hybrid.fixed

import numpy as np
from app.expanded_calibration import load_expanded_calibration
from app.hybrid_dataset import load_hybrid_fit, training_targets
from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig

DEFAULT_PATH = ROOT / "observability/runtime/hybrid-diagnostic-20261003-GEXijOUR/default/result.private.json"
DEFAULT_SHA = "925d00e73c8e89d4497d91b7fd1ec78ea70b25e0194138e70550e0e43d6af3f3"
TRAINING = ROOT / "observability/runtime/hybrid-training-20261003-TNVXAURk/data"
TRAINING_SHA = "b080e99633e6dfe364d83fd67656baf71989b900682f4b7296369f168d9ae5de"
STAGE = "PILOT_EXPANDED_NORMAL_CALIBRATION_DIAGNOSTIC_ONLY"
SOURCES = ("observability/scripts/diagnose-ueba-hybrid-expanded-calibration.py",
           "observability/scripts/diagnose-ueba-hybrid.py", "ueba-worker/app/expanded_calibration.py",
           "observability/scripts/prepare-ueba-expanded-calibration.py")


def source_binding(dataset, manifest, expanded_root, expanded_sha):
    original = hybrid.integrity(dataset, TRAINING, TRAINING_SHA, manifest)
    buckets, expanded = load_expanded_calibration(expanded_root, expanded_sha)
    generation_sources = expanded["source_identity_before"]["sources"]
    if any(fixed.checksum(ROOT / name) != sha for name, sha in generation_sources.items()):
        raise ValueError("expanded generation source changed")
    receipts = expanded["batch_receipt_sha256"]
    if any(Path(name).name != name or fixed.checksum(expanded_root / name) != sha for name, sha in receipts.items()):
        raise ValueError("expanded actual Java extraction receipt changed")
    return {"original_hybrid": original, "sources": {name: fixed.checksum(ROOT / name) for name in SOURCES},
            "expanded_manifest_sha256": expanded_sha, "expanded_sources": generation_sources,
            "expanded_shards": {entry["path"]: entry["sha256"] for split in expanded["splits"].values()
                                for entry in split["shards"]}, "expanded_batch_receipts": receipts}, buckets


def separation(training, old, buckets):
    hybrid.separation_checks(training, old)
    train_frames = {row["frame_id"] for row in training}
    train_hours = {hybrid.episode(row) for row in training}
    validation = old["fold1-validation"]
    val_frames = {row["frame_id"] for row in validation}
    val_hours = {hybrid.episode(row) for row in validation}
    forbidden_frames = train_frames | val_frames
    forbidden_hours = train_hours | val_hours
    ready_accounts = {row["account_id"] for row in old["fold1-fit"]}
    latest_training = max(fixed.utc(row["window_start"]) for row in training)
    earliest_validation = min(fixed.utc(row["window_start"]) for row in validation)
    for cohort, rows in buckets.items():
        if len(rows) != 60000 or any(row["label"] != 0 or row["family"] != "normal" or row["cohort"] != cohort for row in rows):
            raise ValueError("complete independent normal-only expanded buckets required")
        for row in rows:
            at = fixed.utc(row["window_start"])
            if (row["frame_id"] in forbidden_frames or hybrid.episode(row) in forbidden_hours
                    or at - latest_training <= timedelta(days=14)
                    or earliest_validation - at <= timedelta(days=14)
                    or cohort == "READY" and row["account_id"] not in ready_accounts):
                raise ValueError("expanded calibration leaked evaluated data or crossed history gap")
    return {"all_training_calibration_validation_gaps_exceed14days": True,
            "training_and_validation_evaluated_frames_hours_disjoint": True,
            "ready_accounts_in_original_fitted_population": True,
            "old_calibration_merged": False, "normal_rows_per_bucket": 60000}


def chunk_scores(scorer, rows):
    parts = [scorer.anomaly_scores([row["features"] for row in rows[offset:offset + 5000]])
             for offset in range(0, len(rows), 5000)]
    values = np.concatenate(parts)
    if values.shape != (len(rows),) or not np.isfinite(values).all():
        raise ValueError("complete finite expanded scores required")
    return values


def run(expanded_root, expanded_sha, output):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != fixed.IMAGE_ID or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only diagnostic required")
    if fixed.checksum(DEFAULT_PATH) != DEFAULT_SHA:
        raise ValueError("frozen original default evidence changed")
    previous = fixed.parse_json(DEFAULT_PATH.read_bytes())
    dataset, old = fixed.load_pilot()
    training, manifest = load_hybrid_fit(TRAINING, TRAINING_SHA)
    policy = fixed.ScorePolicy.strict(schema=4)
    before, buckets = source_binding(dataset, manifest, Path(expanded_root), expanded_sha)
    hybrid.verify_default(DEFAULT_PATH, before["original_hybrid"], policy)
    proof = separation(training, old, buckets)
    output = hybrid.protected_directory(output)
    declaration = {"stage": STAGE, "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE",
        "integrity_before": before, "original_default_sha256": DEFAULT_SHA, "policy": policy.wire(),
        "configuration": list(hybrid.DEFAULT), "parameters": HybridIncidentScorer().parameters(),
        "separation": proof, "composite_fit_trials_before_declaration": 0,
        "component_fit_calls_before_declaration": 0, "score_calls_before_declaration": 0,
        "reproduction_requires_two_genuine_component_fits": True, "zero_fit_strict_recalibration": False,
        "old_calibration_replaced_not_merged": True, "threshold_tuning": False,
        "validation_or_training_modified": False, "selection_or_promotion": False}
    fixed.write_private(output / "predeclared.private.json", declaration)
    started = time.monotonic()
    scorer = HybridIncidentScorer(HybridResearchConfig(*hybrid.DEFAULT, random_state=42))
    with hybrid.FitCounter() as count:
        scorer.fit([row["features"] for row in old["fold1-fit"]],
                   [row["features"] for row in training], training_targets(training))
    if count.counts != {"composite_fit_trials": 1, "normal_component_fit_calls": 1, "supervised_component_fit_calls": 1}:
        raise ValueError("actual component fit counts changed")
    calibration = {cohort: np.sort(chunk_scores(scorer, rows)) for cohort, rows in buckets.items()}
    fixed.write_private(output / "calibration.private.json", {key: value.tolist() for key, value in calibration.items()})
    decisions, raw_scores, percentages = [], [], []
    score_file = output / "scores-decisions.private.jsonl"
    descriptor = os.open(score_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as evidence, fixed.JavaRiskReplay(
            fixed.WORKSPACE, policy, expected_classes=before["original_hybrid"]["original_fixed_pilot"]["java"]["replay_classes"]) as java:
        validation = old["fold1-validation"]
        for offset in range(0, len(validation), 1000):
            rows = validation[offset:offset + 1000]
            raw = scorer.anomaly_scores([row["features"] for row in rows])
            scores = fixed.calibrate_scores(raw, rows, calibration, policy)
            actual = java.score(rows, scores)
            decisions.extend(actual); raw_scores.extend(float(value) for value in raw)
            percentages.extend(score["normal_percentile"] for score in scores)
            for original, score, decision in zip(rows, scores, actual):
                evidence.write(fixed.canonical({"frame_id": original["frame_id"], **score,
                                               "predictions": decision["predictions"]}) + "\n")
        evidence.flush(); os.fsync(evidence.fileno())
    if (len(decisions) != 21000 or fixed.array_sha(raw_scores) != previous["configurations"][0]["raw_score_sha256"]):
        raise ValueError("original default validation raw scores did not reproduce exactly")
    after, _ = source_binding(dataset, manifest, Path(expanded_root), expanded_sha)
    if before != after:
        raise ValueError("source or any frozen artifact changed")
    metrics = fixed.decision_metrics(decisions)
    result = {"status": "COMPLETED", "stage": STAGE, "data_provenance": "DEMO_ONLY",
        "quality_gate": "NOT_APPLICABLE", "integrity_before": before, "integrity_after": after,
        "integrity_unchanged": True, "separation": proof, "policy_sha256": policy.sha256,
        "original_default_result_sha256": DEFAULT_SHA, "actual_composite_fit_trials": 1,
        "actual_component_fit_calls": 2, "actual_fit_frames_observed": count.counts,
        "strict_fit_calls": 0, "holdout_numeric_records_read": 0,
        "actual_normal_calibration_rows": {key: len(rows) for key, rows in buckets.items()},
        "actual_validation_rows_replayed": len(decisions), "validation_raw_scores_exactly_reproduced": True,
        "raw_score_sha256": fixed.array_sha(raw_scores), "percentile_sha256": fixed.array_sha(percentages),
        "calibration_sha256": {key: fixed.array_sha(values) for key, values in calibration.items()},
        "decisions": metrics, "point_diagnostic": fixed.point_diagnostic(metrics, policy),
        "old_calibration_merged_or_files_changed": False, "model_registered_selected_promoted_or_aws_changed": False,
        "predeclared_sha256": fixed.checksum(output / "predeclared.private.json"),
        "private_artifacts": {path.name: fixed.checksum(path) for path in (score_file, output / "calibration.private.json")},
        "elapsed_seconds": time.monotonic() - started,
        "limitations": ["SAME_INSPECTED_VALIDATION_NOT_UNOPENED_HOLDOUT", "60000_NOT_MILLION_CALIBRATION_ROWS_PER_COHORT",
                        "NO_STRICT_CONFIDENCE_OR_360_FIT_SELECTION", "SIMULATED_NOT_PRODUCTION_PRECISION"]}
    fixed.write_private(output / "result.private.json", result)
    return output, result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expanded-calibration", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        location, result = run(args.expanded_calibration, args.manifest_sha256, args.output)
        print(fixed.canonical({"status": result["status"], "output": str(location),
            "decisions": {key: value["complete_validation"] for key, value in result["decisions"].items()},
            "point_diagnostic": result["point_diagnostic"], "quality_gate": "NOT_APPLICABLE"}), flush=True)
    except Exception as failure:
        raise SystemExit("Expanded hybrid diagnostic refused/failed: " + type(failure).__name__ + "; private evidence retained") from None
