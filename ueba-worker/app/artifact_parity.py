"""Offline reproduction of one already fitted frozen strict candidate.

This operator-only diagnostic is not catalogue admission, model selection,
quality evaluation, a holdout run or activation. Its private output must be
separate from the read-only reference experiment and any serving model volume.
"""
import argparse
import hashlib
import os
from pathlib import Path
import time

from app.catalog import ShardedDataset, parse_json
from app.model import ModelStore
from app.operator_catalog import Recipe, train_recipe
from app.policy import ScorePolicy, canonical
from app.strict_campaign import approved_run, fingerprint, run_identity, timestamp, write
from app.semantic_model import FORMAT, state_sha256, verifier_sha256


def read_receipt(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("bounded immutable fit receipt required")
    return parse_json(path.read_bytes())


def verify_receipt(dataset, run, receipt):
    if dataset.manifest["stage"] != "STRICT" or run["fold"] != 3 or run["config"].random_state != 42:
        raise ValueError("full strict representative fold/seed required")
    expected = run_identity(dataset, run)
    if (receipt.get("status") != "FITTED_CALIBRATED" or receipt.get("quality_gate") != "NOT_RUN"
            or any(receipt.get(key) != value for key, value in expected.items())
            or receipt.get("training_windows") != 50000
            or receipt.get("calibration_cohort_windows") != {"READY": 1000000, "COLD": 1000000}
            or receipt.get("score_policy") != ScorePolicy.strict().wire()):
        raise ValueError("receipt does not prove full frozen fitting/calibration identity")


class ReproductionStore(ModelStore):
    def __init__(self, directory, source_state_sha):
        super().__init__(directory)
        self.source_state_sha, self.actual_fit_calls = source_state_sha, 0
        self.actual_source_sha = None

    def train(self, *args, **kwargs):
        result = super().train(*args, **kwargs)
        self.actual_fit_calls += 1
        self.actual_source_sha = result["sha256"]
        _, payload = self.load_candidate(result["model_version"])
        if state_sha256(payload) != self.source_state_sha:
            raise ValueError("actual initial forest numeric state differs from frozen fitting receipt")
        return result


def reproduce(directory, output, run_id):
    os.umask(0o077)
    if directory.is_symlink() or output.is_symlink(): raise ValueError("diagnostic paths cannot be symlinks")
    directory = directory.resolve(strict=True)
    destination = output.resolve()
    if directory == destination or directory in destination.parents or destination in directory.parents:
        raise ValueError("diagnostic output must be disjoint from frozen reference")
    if output.exists() and any(output.iterdir()): raise ValueError("fresh empty private output required; retain earlier failures")
    output.mkdir(mode=0o700, parents=True, exist_ok=True); output.chmod(0o700)
    dataset = ShardedDataset(directory)
    run = approved_run(run_id)
    receipt = read_receipt(directory / "strict-runs" / f"{run_id}.json")
    verify_receipt(dataset, run, receipt)
    reference = ModelStore(directory / "strict-models")
    source, source_payload = reference.load_candidate(receipt["source_model_version"])
    calibrated, calibrated_payload = reference.load_candidate(receipt["model_version"])
    if (source["sha256"] != receipt["source_model_sha256"] or calibrated["sha256"] != receipt["model_sha256"]
            or calibrated["calibration_sha256"] != receipt["calibration_sha256"]):
        raise ValueError("frozen reference artifact changed")
    policy = ScorePolicy.from_wire(receipt["score_policy"])
    source_state_sha = state_sha256(source_payload)
    calibrated_state_sha = state_sha256(calibrated_payload)
    store = ReproductionStore(output / "models", source_state_sha)
    # Trusted diagnostic construction only. No registry is written, and the
    # application's OperatorCatalog admission still requires SELECTED evidence.
    recipe = Recipe("diagnostic-artifact-parity", dataset, run["config"], policy, 3, "STRICT",
                    calibrated["sha256"], calibrated["calibration_sha256"], calibrated_state_sha, verifier_sha256())
    version = "parity_" + hashlib.sha256(canonical(receipt).encode()).hexdigest()[:24]
    start = time.monotonic()
    write(output / "progress.json", {"status": "RUNNING", "run_id": run_id, "quality_gate": "NOT_RUN", "started_at_utc": timestamp()})
    def progress(value):
        write(output / "progress.json", {"status": "RUNNING", "run_id": run_id, "calibration_progress": value,
                                          "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()})
    try:
        actual = train_recipe(store, recipe, version, output / "cache", progress=progress)
        if store.actual_fit_calls != 1 or (store.directory / "active.json").exists() or store.active_version is not None:
            raise ValueError("diagnostic fitting/primary invariant failed")
        result = {"status": "SUCCEEDED", "artifact_parity": "PASS", "quality_gate": "NOT_APPLICABLE",
                  "evaluation_scope": "FROZEN_FIT_REPRODUCTION_ONLY", "catalogue_admission_verified": False,
                  "data_provenance": "DEMO_ONLY", "run_id": run_id, "dataset_sha256": dataset.sha256,
                  "reference_source_sha256": source["sha256"], "actual_source_sha256": store.actual_source_sha,
                  "initial_numeric_state_sha256": source_state_sha,
                  "reference_model_sha256": calibrated["sha256"], "actual_model_sha256": actual["sha256"],
                  "model_state_sha256": calibrated_state_sha, "model_state_format": FORMAT,
                  "model_state_verifier_sha256": verifier_sha256(), "binary_file_integrity_enforced": True,
                  "reference_calibration_sha256": calibrated["calibration_sha256"], "actual_calibration_sha256": actual["calibration_sha256"],
                  "training_windows": actual["training_windows"], "calibration_cohort_windows": actual["calibration_cohort_windows"],
                  "additional_diagnostic_fit_calls": store.actual_fit_calls, "counted_in_360_campaign": False,
                  "holdout_scored": False, "activation_attempted": False, "elapsed_seconds": time.monotonic() - start,
                  "code_fingerprint": fingerprint(), "completed_at_utc": timestamp()}
        write(output / "result.json", result)
        write(output / "progress.json", result)
        return result
    except Exception as failure:
        write(output / "progress.json", {"status": "FAILED", "failure_type": type(failure).__name__,
              "failure_reason": str(failure), "quality_gate": "NOT_RUN", "holdout_scored": False,
              "activation_attempted": False, "updated_at_utc": timestamp()})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(canonical(reproduce(args.dataset, args.output, args.run_id)), flush=True)


if __name__ == "__main__": main()
