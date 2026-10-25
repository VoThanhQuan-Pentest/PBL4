#!/usr/bin/env python3
"""Read-only trusted BULK compression probe, never STRICT population evidence.

Only the SHA-pinned, own-worker-created 24-artifact grid is accepted. Synthetic
sorted calibration arrays exercise storage size; they are not genuine scores,
calibration, fitting, validation, qualification, admission, or a future maximum.
No original artifact, metadata, ModelStore, or calibration code is modified.
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.metadata
import json
import lzma
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_incident import CONFIGURATIONS, HybridIncidentScorer
from app.hybrid_semantic import FORMAT, state_sha256 as model_sha
from app.model_state_dispatch import state_sha256, verifier_sha256
from app.normal_support import NormalSupportScorer
from app.policy import canonical

IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
GRID = ROOT / "observability/runtime/hybrid-bulk-grid-20261004-hqYCI8wc/grid"
GRID_SHA = "9bb44c4aa7294f32bb7d5d55b74a616a73a97b87675a3adc313c0f0f39e564c5"
COHORT_ROWS = 1_000_000
SCORE_SOURCES = {"hybrid_incident.py", "hybrid_semantic.py", "model.py",
                 "normal_support.py", "contract.py", "model_state_dispatch.py"}
# Authorized STRICT adapter change is not imported/called by this storage probe.
# This exact exception never extends to model/scoring/load implementation files.
WORKFLOW_ONLY_DRIFT = {"ueba-worker/app/validation.py": {
    "historical_sha256": "ecc01e828e8c550c5dbdd557d4ed73ffda7520136f44123f94802dbd25bb0967",
    "current_sha256": "7697193587e7cf7d44a685297587c630d559a76fbe4687efdc135f470c002688"}}


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_path(path, *, directory=False):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink path refused")
    mode = path.stat().st_mode
    if (mode & 0o077 or (not stat.S_ISDIR(mode) if directory else not stat.S_ISREG(mode))):
        raise ValueError("private regular path required")
    return path


def read_json(path, expected_sha, maximum=2_000_000):
    path = private_path(path)
    if path.stat().st_size > maximum or checksum(path) != expected_sha:
        raise ValueError("trusted source hash/size mismatch")
    return json.loads(path.read_text(encoding="utf-8"))


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def verify_owned_grid():
    """Verify all metadata, binaries, source code, and dependencies before load."""
    private_path(GRID, directory=True)
    report = read_json(GRID / "result.private.json", GRID_SHA)
    if (report.get("status") != "COMPLETED" or report.get("stage") != "BULK_PILOT_DEMO_ONLY"
            or report.get("actual_composite_fit_trials") != 24
            or report.get("actual_component_fit_calls") != 48
            or report.get("additional_load_recalibration_fit_calls") != 0
            or report.get("integrity_unchanged") is not True
            or report.get("integrity_before") != report.get("integrity_after")
            or report["integrity_before"].get("execution_image_id") != IMAGE
            or len(report.get("configurations", [])) != 24):
        raise ValueError("completed own grid provenance required")
    fingerprint = report["integrity_before"]
    drift = {}
    # These are fixed, trusted names from the hash-bound report, not arbitrary paths.
    for relative, digest in fingerprint["sources"].items():
        source = (ROOT / relative).absolute()
        if (not source.is_relative_to(ROOT) or any(p.is_symlink() for p in (source, *source.parents))
                or not source.is_file()):
            raise ValueError("grid source implementation drift")
        actual = checksum(source)
        if actual != digest:
            receipt = {"historical_sha256": digest, "current_sha256": actual}
            if WORKFLOW_ONLY_DRIFT.get(relative) != receipt:
                raise ValueError("grid source implementation drift")
            drift[relative] = receipt
    if checksum(ROOT / "observability/scripts/diagnose-ueba-hybrid-bulk-grid.py") != fingerprint["grid_source_sha256"]:
        raise ValueError("grid workflow source drift")
    for package, version in fingerprint["dependencies"].items():
        if importlib.metadata.version(package) != version:
            raise ValueError("pinned dependency drift")
    verified = []
    for ordinal, (trial, recipe) in enumerate(zip(report["configurations"], CONFIGURATIONS)):
        folder = GRID / f"candidate-{ordinal:02d}"
        private_path(folder, directory=True)
        private_path(folder / "models", directory=True)
        relative = "models/grid_calibrated_42.json"
        metadata = read_json(folder / relative, trial["private_artifacts"][relative])
        expected_config = dict(zip(("max_iter", "max_leaf_nodes", "l2_regularization"), recipe), random_state=42)
        source = private_path(folder / "models/grid_calibrated_42.joblib")
        binary_sha = trial["private_artifacts"]["models/grid_calibrated_42.joblib"]
        if (trial.get("ordinal") != ordinal or trial.get("configuration") != expected_config
                or metadata != trial.get("calibrated_model_metadata")
                or metadata.get("model_config") != expected_config
                or metadata.get("model_kind") != "normal_plus_incident_research"
                or metadata.get("training_windows") != 50_000
                or metadata.get("labeled_training_windows") != 81_500
                or metadata.get("calibration_cohort_windows") != {"READY": 60_000, "COLD": 60_000}
                or metadata.get("sha256") != binary_sha or checksum(source) != binary_sha
                or metadata.get("model_state_verifier_sha256") != verifier_sha256("normal_plus_incident_research")):
            raise ValueError("owned recipe metadata/binary drift")
        implementation = metadata["scoring_implementation"]
        if set(implementation["sources"]) != SCORE_SOURCES:
            raise ValueError("known scoring source set required")
        for name, digest in implementation["sources"].items():
            if checksum(ROOT / "ueba-worker/app" / name) != digest:
                raise ValueError("scoring source drift")
        for package, version in implementation["dependencies"].items():
            if importlib.metadata.version(package) != version:
                raise ValueError("scoring dependency drift")
        verified.append((ordinal, source, metadata, trial["fitted_numeric_state_sha256"]))
    return report, verified, drift


def synthetic_arrays(ordinal, rows=COHORT_ROWS):
    if type(ordinal) is not int or not 0 <= ordinal < 24 or type(rows) is not int or not 100 <= rows <= COHORT_ROWS:
        raise ValueError("bounded storage-only array recipe required")
    arrays = {}
    for offset, cohort in enumerate(("READY", "COLD")):
        values = np.random.default_rng(20261004 + ordinal * 2 + offset).uniform(-64.0, 64.0, rows)
        values.sort(); arrays[cohort] = values.astype("<f8", copy=False)
    return arrays


def array_receipts(arrays):
    return {name: {"rows": len(values), "dtype": values.dtype.str, "bytes": values.nbytes,
                   "sha256": hashlib.sha256(values.tobytes()).hexdigest()}
            for name, values in arrays.items()}


def compressed_copy(payload, path, expected_state):
    """Restore only our freshly written private copy; no generic pickle ingress."""
    if path.exists() or path.is_symlink():
        raise ValueError("new private compressed copy required")
    started = time.monotonic()
    joblib.dump(payload, path, compress=("lzma", 3)); path.chmod(0o600)
    saved = time.monotonic() - started
    digest = checksum(path)
    private_path(path)
    if checksum(path) != digest:
        raise ValueError("own compressed artifact changed before load")
    started = time.monotonic()
    restored = joblib.load(path)
    loaded = time.monotonic() - started
    if state_sha256(restored) != expected_state:
        raise ValueError("compressed exact calibrated state changed")
    return {"bytes": path.stat().st_size, "sha256": digest, "save_seconds": saved,
            "load_seconds": loaded, "exact_state_sha256": expected_state, "exact_state_identical": True}


def exact_byte_archive(source, expected_sha, path):
    """Preserve original binary SHA via ordinary bytewise XZ, without pickle."""
    private_path(source); private_path(path.parent, directory=True)
    if checksum(source) != expected_sha or path.exists() or path.is_symlink():
        raise ValueError("trusted source and new exact-byte archive required")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    started = time.monotonic()
    with os.fdopen(fd, "wb") as target, source.open("rb") as original:
        with lzma.LZMAFile(target, "w", preset=3) as compressed:
            for block in iter(lambda: original.read(65536), b""):
                compressed.write(block)
        target.flush(); os.fsync(target.fileno())
    saved = time.monotonic() - started
    restored_sha = hashlib.sha256(); restored_bytes = 0; started = time.monotonic()
    with lzma.open(path, "rb") as restored:
        for block in iter(lambda: restored.read(65536), b""):
            restored_sha.update(block); restored_bytes += len(block)
    if restored_sha.hexdigest() != expected_sha or restored_bytes != source.stat().st_size or checksum(source) != expected_sha:
        raise ValueError("exact original binary archive restoration failed")
    return {"bytes": path.stat().st_size, "sha256": checksum(path), "save_seconds": saved,
            "restore_hash_seconds": time.monotonic() - started, "restored_original_sha256": expected_sha,
            "restored_original_bytes": restored_bytes, "byte_for_byte_identical": True, "pickle_loads": 0}


def journal_evidence():
    cache = GRID / "descriptive-rule-cache"
    paths = {
        "uniqueness_journal": cache / "integrity-abec3f8947209b80b5a2dabf/episodes.sqlite",
        "rule_journal": cache / "rules-69016ef1191b8385879d23c8/rules.sqlite",
        "rule_decisions": cache / "rules-69016ef1191b8385879d23c8/rules.u8",
    }
    result = {}
    for name, path in paths.items():
        private_path(path)
        result[name] = {"bytes": path.stat().st_size, "sha256": checksum(path),
                        "actual_rows": 21_000, "bytes_per_row": path.stat().st_size / 21_000}
    with sqlite3.connect(paths["uniqueness_journal"].as_uri() + "?mode=ro&immutable=1", uri=True) as db:
        if db.execute("SELECT count(*) FROM windows").fetchone()[0] != 21_000:
            raise ValueError("actual uniqueness journal population changed")
    with sqlite3.connect(paths["rule_journal"].as_uri() + "?mode=ro&immutable=1", uri=True) as db:
        if db.execute("SELECT sum(records) FROM shards").fetchone()[0] != 21_000:
            raise ValueError("actual rule journal population changed")
    return result


def run(output):
    if (os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE or not Path("/.dockerenv").exists()
            or any(os.environ.get(name) != "1" for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"))):
        raise ValueError("pinned Docker and single-thread context required")
    output = Path(output).absolute()
    private_path(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise ValueError("new private storage output required")
    report, sources, drift = verify_owned_grid()  # Every scoring source is verified before any joblib.load.
    output.mkdir(mode=0o700)
    before = {str(source): checksum(source) for _, source, _, _ in sources}
    journals = journal_evidence()
    declaration = {"scope": "STORAGE_ONLY", "quality_gate": "NOT_APPLICABLE", "source_grid_sha256": GRID_SHA,
        "image_id": IMAGE, "artifacts": 24, "algorithm": "lzma", "level": 3,
        "synthetic_cohort_rows": {"READY": COHORT_ROWS, "COLD": COHORT_ROWS},
        "synthetic_recipe": "PCG64_UNIFORM_NEGATIVE64_POSITIVE64_SORTED_FLOAT64_SEED20261004_PLUS2ORDINAL_PLUSCOHORT",
        "synthetic_arrays_are_genuine_calibration": False, "fit_calls": 0, "holdout_rows_read": 0}
    declaration.update(historical_workflow_only_source_drift=drift,
                       all_grid_workflow_sources_currently_identical=not bool(drift),
                       all_model_scoring_sources_currently_identical=True)
    write_new(output / "predeclared.private.json", declaration)
    results = []
    with ExitStack() as stack:
        for cls in (HybridIncidentScorer, NormalSupportScorer, HistGradientBoostingClassifier):
            stack.enter_context(patch.object(cls, "fit", side_effect=AssertionError("storage-only probe forbids fit")))
        for ordinal, source, metadata, predictive_sha in sources:
            if checksum(source) != metadata["sha256"]:
                raise ValueError("trusted source drift before load")
            payload = joblib.load(source)
            if (type(payload) is not dict or type(payload.get("model")) is not dict
                    or payload["model"].get("state_format") != FORMAT
                    or state_sha256(payload) != metadata["model_state_sha256"]
                    or model_sha(payload["model"]) != predictive_sha):
                raise ValueError("known plain numeric model state required")
            actual = compressed_copy(payload, output / f"candidate-{ordinal:02d}-actual.lzma.joblib",
                                     metadata["model_state_sha256"])
            archive = exact_byte_archive(source, metadata["sha256"], output / f"candidate-{ordinal:02d}-original.joblib.xz")
            arrays = synthetic_arrays(ordinal)
            synthetic = {"model": payload["model"], "calibration_scores": arrays["READY"],
                         "calibration_by_cohort": arrays}
            synthetic_identity = state_sha256(synthetic)
            expanded = compressed_copy(synthetic, output / f"candidate-{ordinal:02d}-storage-only-million.lzma.joblib",
                                       synthetic_identity)
            if model_sha(synthetic["model"]) != predictive_sha:
                raise ValueError("storage clone predictive model changed")
            row = {"ordinal": ordinal, "configuration": metadata["model_config"], "original_bytes": source.stat().st_size,
                   "original_sha256": metadata["sha256"], "predictive_numeric_state_sha256": predictive_sha,
                   "actual_calibrated_copy": actual, "exact_original_binary_archive": archive,
                   "storage_only_million_copy": expanded,
                   "synthetic_array_receipts": array_receipts(arrays), "fit_calls": 0, "quality_gate": "NOT_APPLICABLE"}
            write_new(output / f"candidate-{ordinal:02d}.private.json", row); results.append(row)
            print(canonical({"completed_storage_recipes": len(results), "actual_compressed_bytes": actual["bytes"],
                             "storage_only_million_compressed_bytes": expanded["bytes"], "quality_gate": "NOT_APPLICABLE"}), flush=True)
    if before != {str(source): checksum(source) for _, source, _, _ in sources}:
        raise ValueError("original binary changed during storage probe")
    # Recheck all metadata and source/dependency bindings, without loading any model.
    _, _, after_drift = verify_owned_grid()
    if drift != after_drift:
        raise ValueError("authorized workflow drift changed during storage probe")
    worst = max(results, key=lambda row: row["storage_only_million_copy"]["bytes"])
    retained = {"model_copies": worst["storage_only_million_copy"]["bytes"] * 765,
                "raw_score_caches": 360 * 3_000_000 * 8,
                "sorted_cohort_arrays_separate": 360 * 2_000_000 * 8,
                "plain_numeric_source_json_upper": 19_257_500 * 600,
                "shared_standard_numeric_features": 19_163_000 * 37 * 8,
                "journals_budget": 10 * 1024 ** 3,
                "reserve": 5_000_000_000}
    result = {**declaration, "status": "COMPLETED", "recipes": results, "journal_evidence": journals,
              "worst_empirical_million_compressed_bytes": worst["storage_only_million_copy"]["bytes"],
              "worst_empirical_configuration": worst["configuration"], "all_original_artifacts_unchanged": True,
              "original_or_model_metadata_modified": False, "activation_calls": 0,
              "empirical_worst_is_formal_future_seed_maximum": False,
              "unique_source_rows": {"standard": 19_163_000, "new_labeled_supplement": 94_500,
                                     "total": 19_257_500, "shared_normal_fit_rows_not_counted_twice": 150_000},
              "source_json_forecast_is_conservative_assumption_bytes_per_row": 600,
              "retaining_every_cache_forecast_bytes": retained,
              "retaining_every_cache_total_bytes": sum(retained.values()),
              "limitations": ["STORAGE_ONLY_SYNTHETIC_ARRAYS_NOT_CALIBRATION_OR_QUALITY_EVIDENCE",
                              "HISTORICAL_VALIDATION_WORKFLOW_DRIFT_RECORDED_NOT_IMPORTED_OR_REPRODUCED",
                              "ONE_OBSERVED_SEED_AND_24_RECIPES_NOT_A_FORMAL_FUTURE_MODEL_SIZE_BOUND",
                              "COMPRESSED_COPIES_NOT_MODELSTORE_ADMITTED_OR_ACTIVATED",
                              "ALL_CACHE_RETENTION_NOT_REQUIRED_FOR_HASH_BOUND_RESTORABLE_ARCHIVING"]}
    write_new(output / "result.private.json", result)
    print(canonical({"status": "COMPLETED", "output": str(output), "result_sha256": checksum(output / "result.private.json"),
                     "worst_empirical_million_compressed_bytes": worst["storage_only_million_copy"]["bytes"],
                     "retaining_every_cache_total_bytes": sum(retained.values()), "quality_gate": "NOT_APPLICABLE"}), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.output)
    except Exception as failure:
        raise SystemExit("Storage-only probe refused/failed: " + type(failure).__name__ + "; original artifacts unchanged") from None
