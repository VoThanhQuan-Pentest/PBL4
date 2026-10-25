"""Single-run workers for a separately versioned parallel HYBRID campaign.

Each invocation owns one approved run ID and one cache namespace. The parent
operator schedules distinct IDs concurrently and performs campaign-wide
receipt verification only after all workers in a phase have finished.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from app.contract import HYBRID_MODEL_KIND
from app.policy import canonical

SHA256 = re.compile(r"[a-f0-9]{64}")


def _private_dir(path: Path, *, create=False) -> Path:
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("canonical private worker directory required")
    if not path.exists() and create:
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for item in reversed(missing):
            item.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("worker directory must be owned and mode 0700")
    return path


def worker_cache_directory(root: Path, phase: str, worker_id: int) -> Path:
    if phase not in {"fit", "validation"} or type(worker_id) is not int or not 0 <= worker_id < 32:
        raise ValueError("bounded phase/worker identity required")
    return Path(root) / "hybrid-parallel-cache" / phase / f"worker-{worker_id:02d}"


def _checked_cache(root: Path, cache_directory: Path) -> Path:
    root = Path(root).resolve(strict=True)
    cache = Path(cache_directory).absolute()
    if any(item.is_symlink() for item in (cache, *cache.parents)):
        raise ValueError("cache directory cannot contain symlinks")
    if not cache.exists():
        _private_dir(cache, create=True)
    cache = _private_dir(cache)
    if not cache.resolve(strict=True).is_relative_to(root):
        raise ValueError("parallel cache must stay inside its campaign dataset")
    return cache


def _run_lock(directory: Path, phase: str, run_id: str):
    if phase not in {"fit", "validation"} or not re.fullmatch(r"[a-z0-9_-]{8,128}", run_id):
        raise ValueError("approved phase/run ID required")
    lock_root = _private_dir(directory / "hybrid-parallel-jobs" / "locks", create=True)
    path = lock_root / f"{phase}-{run_id}.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(descriptor, "a+")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        raise ValueError("this parallel run ID is already being handled") from None
    return stream


def _open_dataset(directory, dataset_sha256, archive_sha256):
    from app.owned_dataset import open_owned_dataset
    if not isinstance(dataset_sha256, str) or SHA256.fullmatch(dataset_sha256) is None:
        raise ValueError("frozen dataset SHA required")
    if not isinstance(archive_sha256, str) or SHA256.fullmatch(archive_sha256) is None:
        raise ValueError("frozen source archive SHA required")
    return open_owned_dataset(Path(directory), expected_sha256=dataset_sha256,
                              expected_archive_sha256=archive_sha256)


def _fit_with_worker_cache(strict_campaign, dataset_root, run_id, model_kind,
                           dataset_sha256, archive_sha256, cache):
    original_recalibrate = strict_campaign.recalibrate

    def worker_recalibrate(store, dataset_value, fold, source_version, target_version,
                           policy, _directory, *, progress=None):
        return original_recalibrate(store, dataset_value, fold, source_version,
                                    target_version, policy, cache, progress=progress)

    strict_campaign.recalibrate = worker_recalibrate
    try:
        return strict_campaign.fit_one(dataset_root, run_id, model_kind,
                                       expected_sha256=dataset_sha256,
                                       expected_archive_sha256=archive_sha256)
    finally:
        strict_campaign.recalibrate = original_recalibrate


def _fit(directory, run_id, worker_id, dataset_sha256, archive_sha256, cache_directory):
    from app import strict_campaign
    if type(worker_id) is not int or not 0 <= worker_id < 32:
        raise ValueError("bounded worker identity required")
    dataset = _open_dataset(directory, dataset_sha256, archive_sha256)
    strict_campaign.approved_run(run_id, HYBRID_MODEL_KIND)
    expected_cache = worker_cache_directory(dataset.root, "fit", worker_id)
    if Path(cache_directory).absolute() != expected_cache.absolute():
        raise ValueError("fit cache must be isolated to this worker slot")
    cache = _checked_cache(dataset.root, expected_cache)
    with _run_lock(dataset.root, "fit", run_id):
        # Keep the immutable serial fit source/fingerprint byte-for-byte. Route
        # only its recalibration cache argument to this worker's private cache.
        # Calibration caches are never model inputs; the wrapper itself is
        # pinned by the parallel campaign code inventory.
        result = _fit_with_worker_cache(strict_campaign, dataset.root, run_id,
                                        HYBRID_MODEL_KIND, dataset_sha256,
                                        archive_sha256, cache)
    if result.get("status") != "FITTED_CALIBRATED" or result.get("run_id") != run_id:
        raise ValueError("fit worker did not publish its exact calibrated run")
    return {"phase": "fit", "status": result["status"], "run_id": run_id,
            "model_version": result["model_version"], "model_sha256": result["model_sha256"],
            "worker_id": worker_id, "data_provenance": result.get("data_provenance"),
            "quality_gate": result.get("quality_gate")}


def _validate(directory, workspace, run_id, worker_id, dataset_sha256,
              archive_sha256, cache_directory):
    from app.model import ModelStore
    from app.selection import selection_identity
    from app.strict_campaign import approved_run, run_identity, timestamp, write
    from app.validation import validate_candidate
    if type(worker_id) is not int or not 0 <= worker_id < 32:
        raise ValueError("bounded worker identity required")
    dataset = _open_dataset(directory, dataset_sha256, archive_sha256)
    run = approved_run(run_id, HYBRID_MODEL_KIND)
    expected_cache = worker_cache_directory(dataset.root, "validation", worker_id)
    if Path(cache_directory).absolute() != expected_cache.absolute():
        raise ValueError("validation cache must be isolated to this worker slot")
    cache = _checked_cache(dataset.root, expected_cache)
    prefix = "hybrid"
    run_path = dataset.root / f"{prefix}-runs" / f"{run_id}.json"
    result_path = dataset.root / f"{prefix}-validations" / f"{run_id}.json"
    _private_dir(result_path.parent, create=True)
    job_root = _private_dir(dataset.root / "hybrid-parallel-jobs" / "validation-progress", create=True)
    progress_path = job_root / f"{run_id}.private.json"
    with _run_lock(dataset.root, "validation", run_id):
        fit_receipt = json.loads(run_path.read_text(encoding="utf-8"))
        identity = run_identity(dataset, run)
        if (fit_receipt.get("status") != "FITTED_CALIBRATED"
                or any(fit_receipt.get(key) != value for key, value in identity.items())):
            raise ValueError("validated run requires the exact completed frozen fit receipt")
        store = ModelStore(dataset.root / f"{prefix}-models")
        metadata, _ = store.load_candidate(fit_receipt["model_version"])
        if (metadata.get("sha256") != fit_receipt.get("model_sha256")
                or metadata.get("calibration_sha256") != fit_receipt.get("calibration_sha256")):
            raise ValueError("fit model/calibration bytes changed before validation")
        expected = selection_identity(dataset, Path(workspace), HYBRID_MODEL_KIND)
        if result_path.exists():
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if (result.get("status") != "VALIDATED" or result.get("selection_identity") != expected
                    or result.get("model_sha256") != metadata["sha256"]
                    or result.get("evaluation_scope") != "VALIDATION"):
                raise ValueError("existing validation receipt is not reusable under this campaign identity")
            return {"phase": "validation", "status": "VALIDATED", "run_id": run_id,
                    "model_sha256": metadata["sha256"], "worker_id": worker_id,
                    "selection_identity_sha256": hashlib.sha256(canonical(expected).encode()).hexdigest(),
                    "quality_gate": "NOT_RUN", "holdout_scored": False}

        def progress(value):
            write(progress_path, {"status": "RUNNING", "phase": "validation", "run_id": run_id,
                                  "worker_id": worker_id, "scoring_progress": value,
                                  "quality_gate": "NOT_RUN", "holdout_scored": False,
                                  "updated_at_utc": timestamp()})

        result = validate_candidate(dataset, store, fit_receipt["model_version"], run["fold"],
                                    cache, Path(workspace), progress=progress)
        result.update(selection_identity=expected, run_id=run_id, status="VALIDATED",
                      completed_at_utc=timestamp())
        write(result_path, result)
        write(progress_path, {"status": "SUCCEEDED", "phase": "validation", "run_id": run_id,
                              "worker_id": worker_id, "model_sha256": metadata["sha256"],
                              "quality_gate": "NOT_RUN", "holdout_scored": False,
                              "completed_at_utc": timestamp()})
    return {"phase": "validation", "status": "VALIDATED", "run_id": run_id,
            "model_sha256": metadata["sha256"], "worker_id": worker_id,
            "selection_identity_sha256": hashlib.sha256(canonical(expected).encode()).hexdigest(),
            "quality_gate": "NOT_RUN", "holdout_scored": False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("fit", "validation"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--worker-id", type=int, required=True)
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--cache-directory", type=Path, required=True)
    args = parser.parse_args()
    if args.phase == "validation" and args.workspace is None:
        parser.error("validation workers require the frozen Java workspace")
    if args.phase == "fit":
        result = _fit(args.dataset, args.run_id, args.worker_id, args.dataset_sha256,
                      args.archive_sha256, args.cache_directory)
    else:
        result = _validate(args.dataset, args.workspace, args.run_id, args.worker_id,
                           args.dataset_sha256, args.archive_sha256, args.cache_directory)
    print(canonical(result), flush=True)


if __name__ == "__main__":
    main()
