"""Fresh strict HYBRID source protocol, not a selected or evaluated model.

This module defines immutable population/time/identity requirements only. It
never opens numeric data, fits a scorer, ranks recipes or reads the holdout.
The ordinary normal-only ShardedDataset contract remains unchanged.
"""
from dataclasses import asdict
import hashlib
import re

from app.contract import FEATURE_NAMES_V4, HYBRID_MODEL_KIND, campaign_runs, recipe_binding
from app.hybrid_dataset import CLASS_TARGETS, CLASS_TARGET_NAMES
from app.policy import canonical

FORMAT = "HYBRID_STRICT_SOURCE_PROTOCOL_V1"
FOLD_TIMES = ((1, 15, 33, 51), (2, 22, 40, 58), (3, 29, 47, 65))
STANDARD_ROWS = 19_163_000
SUPPLEMENT_ROWS = 31_500
NORMAL_ROWS = 50_000
LABELED_ROWS = 81_500
RESERVE_BYTES = 5_000_000_000


def source_protocol(dataset_id):
    if (not isinstance(dataset_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset_id)
            or "pilot" in dataset_id or dataset_id.startswith("schema4-")):
        raise ValueError("fresh strict hybrid dataset ID required, never a pilot alias")
    folds = []
    for fold, fit_day, calibration_day, validation_day in FOLD_TIMES:
        folds.append({"fold": fold, "fit_day": fit_day, "normal_fit": {"records": NORMAL_ROWS, "positive": 0, "cohort": "READY"},
            "labeled_training": {"records": LABELED_ROWS, "shared_exact_normal_fit_rows": NORMAL_ROWS,
                "new_supplement_rows": SUPPLEMENT_ROWS, "class_counts": {"0": 71500, "1": 8000, "2": 2000},
                "supplement_normal_cohorts": {"READY": 50, "UNSEEN_READY": 14300, "COLD": 7150},
                "positive_per_family": {"READY": 1400, "UNSEEN_READY": 400, "COLD": 200},
                "namespace": "hybrid-label-" + hashlib.sha256((dataset_id + ":" + str(fold)).encode()).hexdigest()[:16]},
            "calibration": {"start_day": calibration_day, "days": 3, "READY": 1000000, "COLD": 1000000, "positive": 0},
            "validation": {"start_day": validation_day, "days": 4, "normal": 1000000, "positive": 1000,
                "positive_per_family": 200, "cohort_ratio": [70, 20, 10]},
            "training_to_calibration_gap_days_min": calibration_day - fit_day - 1,
            "calibration_to_validation_gap_days_min": validation_day - calibration_day - 3})
    runs = campaign_runs(HYBRID_MODEL_KIND)
    if len(runs) != 360 or len({item["run_id"] for item in runs}) != 360:
        raise ValueError("exact predeclared genuine hybrid 360-run grid required")
    return {"format": FORMAT, "dataset_id": dataset_id, "stage": "STRICT_SOURCE", "quality_gate": "NOT_EVALUATED",
        "data_provenance": "DEMO_ONLY", "feature_schema_version": 4, "telemetry_contract_version": 3,
        "feature_names": list(FEATURE_NAMES_V4), "model_kind": HYBRID_MODEL_KIND,
        "folds": folds, "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES,
        "holdout": {"start_day": 85, "days": 14, "normal": 10000000, "positive": 10000,
                    "positive_per_family": 2000, "cohort_ratio": [70, 20, 10], "numeric_read_permitted_before_selection": False},
        "standard_numeric_rows": STANDARD_ROWS, "additional_labeled_rows": SUPPLEMENT_ROWS * 3,
        "shared_normal_rows_not_generated_or_counted_twice": True,
        "campaign": [{"run_id": run["run_id"], "fold": run["fold"], "config": asdict(run["config"]),
                      **recipe_binding(run["config"])} for run in runs],
        "required_composite_trials": 360, "required_component_fit_calls": 720,
        "required_top_recalibrations": 45, "additional_fits_in_recalibration": 0,
        "required_proofs": ["EXACT_NORMAL_SECTION_EQUALS_MATCHING_FOLD_FIT",
            "LABEL_TARGETS_OUTSIDE_ALL37_NUMERIC_FEATURES", "FRAME_AND_ACCOUNT_HOUR_ISOLATION",
            "UNSEEN_VALIDATION_ACCOUNTS_NOT_IN_ANY_TRAINING", "MATCHING_FOLD_HISTORY_GAPS_GT14DAYS",
            "SOURCE_GENERATOR_JAVA_PROTOCOL_AND_DEPENDENCIES_PREDECLARED_BEFORE_GENERATION",
            "FRESH_CAUSAL_WORLDS_NO_PILOT_COPY_RELABEL_OR_ROW_AMPLIFICATION",
            "COMPLETE360_SEED_FOLD_VALIDATIONS_AND_COMMON_POLICY_BEFORE_UNOPENED_HOLDOUT"],
        "fit_or_score_calls": 0, "holdout_numeric_records_read": 0,
        "selection_performed": False, "registration_or_activation_or_aws_changed": False}


def protocol_sha256(protocol):
    return hashlib.sha256(canonical(protocol).encode()).hexdigest()


def validate_manifest(manifest, protocol):
    if (not isinstance(manifest, dict) or manifest.get("format") != FORMAT
            or manifest.get("stage") != "STRICT_SOURCE" or manifest.get("quality_gate") != "NOT_EVALUATED"
            or manifest.get("dataset_id") != protocol["dataset_id"]
            or manifest.get("protocol_sha256") != protocol_sha256(protocol)
            or manifest.get("source_identity_before") != manifest.get("source_identity_after")
            or not isinstance(manifest.get("source_identity_before"), dict)
            or not manifest.get("source_identity_before")
            or type(manifest.get("fit_or_score_calls")) is not int
            or type(manifest.get("holdout_numeric_records_read")) is not int
            or manifest.get("fit_or_score_calls") != 0 or manifest.get("holdout_numeric_records_read") != 0):
        raise ValueError("fresh unqualified strict source identity required")
    sections = manifest.get("fold_training_sections")
    if not isinstance(sections, dict) or set(sections) != {"1", "2", "3"}:
        raise ValueError("all three independently bound training folds required")
    for fold in (1, 2, 3):
        section = sections[str(fold)]
        if (not isinstance(section, dict)
                or any(type(section.get(key)) is not int for key in ("normal_records", "labeled_records", "fold"))
                or section.get("normal_records") != NORMAL_ROWS or section.get("labeled_records") != LABELED_ROWS
                or section.get("class_counts") != {"0": 71500, "1": 8000, "2": 2000}
                or section.get("fold") != fold or section.get("normal_fit_sha256") != section.get("standard_fit_sha256")):
            raise ValueError("exact matching-fold normal and independent labeled source proof required")
        for name in ("normal_fit_sha256", "standard_fit_sha256", "labeled_split_sha256"):
            if not isinstance(section.get(name), str) or not re.fullmatch(r"[a-f0-9]{64}", section[name]):
                raise ValueError("actual checksum-bound complete training sections required")
    return manifest


def disk_plan(*, verified_compressed_artifact_upper_bytes=None):
    """Conservative full-retention budget; compression is never assumed from one pilot."""
    if verified_compressed_artifact_upper_bytes is not None and (
            type(verified_compressed_artifact_upper_bytes) is not int or verified_compressed_artifact_upper_bytes < 1):
        raise ValueError("positive independently verified compression upper bound required")
    # 600B/row exceeds measured454B/row; retain both source and numeric caches.
    components = {"numeric_json_upper": (STANDARD_ROWS + SUPPLEMENT_ROWS * 3) * 600,
        "shared37_float64_cache": STANDARD_ROWS * 37 * 8,
        "raw_calibration_and_validation_scores": 360 * (2000000 + 1001000) * 8,
        "sorted_calibration_values": 360 * 2000000 * 8,
        "journals_receipts_workspace_and_batch_scratch": 10 * 1024**3}
    # 360 source +360 calibrated +minimum45 top clones. Codec allows64MiB
    # model state plus24MB outer calibration (READY also stored separately).
    upper = verified_compressed_artifact_upper_bytes or (64 * 1024**2 + 24000000)
    components["765_retained_model_artifacts"] = 765 * upper
    return {"components_bytes": components, "planned_bytes": sum(components.values()),
            "required_free_bytes": sum(components.values()) + RESERVE_BYTES, "reserve_bytes": RESERVE_BYTES,
            "compression_upper_verified": verified_compressed_artifact_upper_bytes is not None,
            "generation_only_required_free_bytes": components["numeric_json_upper"] + 1024**3 + RESERVE_BYTES,
            "warning": "ONE_PILOT_COMPRESSION_RATIO_IS_NOT_A_STRICT_MILLION_CALIBRATION_UPPER_BOUND"}


def require_space(free_bytes, plan, *, generation_only=False):
    if type(free_bytes) is not int or free_bytes < 0:
        raise ValueError("actual nonnegative filesystem free bytes required")
    required = plan["generation_only_required_free_bytes"] if generation_only else plan["required_free_bytes"]
    if free_bytes < required:
        raise ValueError("insufficient disk for retained strict work plus5GB reserve")
    return required
