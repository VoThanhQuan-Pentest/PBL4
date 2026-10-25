#!/usr/bin/env python3
"""Versioned, resumable parallel runner for the frozen HYBRID lab campaign.

The previous serial campaign is never modified or merged into this campaign.
Workers receive disjoint approved run IDs, isolated per-worker score caches,
network-disabled containers, and a shared immutable source snapshot. Existing
fit/validation implementations and ranking gates remain the authorities.
"""

from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime"
LEGACY_OPERATOR = ROOT / "observability/scripts/continue-ueba-strict.py"
DEFAULT_SOURCE = RUNTIME / "hybrid-strict-source-20261004-pdSIQYiW/source"
DEFAULT_CODE_SOURCE = ROOT / "ueba-worker/app"
DEFAULT_RESUME_CODE_SOURCE = RUNTIME / "private-backups/hybrid-execution-code-20261005-3_7b4ra6/app"
DEFAULT_WORKSPACE = RUNTIME / "private-backups/hybrid-execution-java-20261005-d_gl_k__"
DEFAULT_WORKERS = 2
DEFAULT_MEMORY_MIB = 1280
DEFAULT_CPU = "1.0"
SOURCE_STATIC_DIRS = ("abandoned", "batches", "pending", "shards", "source-retirement", "verification")
SOURCE_STATIC_FILES = ("archives.private.json", "generation.identity.json", "generation.progress.json",
                       "java-export.log", "manifest.json", "source-archive-result.private.json")
SOURCE_MARKERS = ("predeclared.private.json", "state.private.json")
SHA256 = re.compile(r"[a-f0-9]{64}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def private_dir(path: Path, *, create=False) -> Path:
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private campaign directory required")
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
        raise ValueError("campaign directory must be owner-only mode 0700")
    return path


def write_private(path: Path, value) -> None:
    path = Path(path).absolute()
    private_dir(path.parent)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("existing private campaign state is not a single-link owner file")
    body = canonical(value).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def read_private(path: Path, maximum=8 * 1024 * 1024):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private campaign file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("bounded single-link owner-only state file required")
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(body) != before.st_size or signature(before) != signature(after) or signature(before) != signature(path.lstat()):
            raise ValueError("campaign state changed during read")
    value = json.loads(body)
    if type(value) is not dict:
        raise ValueError("campaign state must be an object")
    return value


def link_file(source: Path, target: Path) -> None:
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or source.is_symlink()):
        raise ValueError("static source must be an owner-controlled regular file")
    os.link(source, target, follow_symlinks=False)


def link_tree(source: Path, target: Path) -> None:
    info = source.lstat()
    if not stat.S_ISDIR(info.st_mode) or source.is_symlink() or info.st_uid != os.geteuid():
        raise ValueError("static source tree must be an owner-controlled directory")
    target.mkdir(mode=0o700)
    for child in sorted(source.iterdir()):
        destination = target / child.name
        if child.is_symlink():
            raise ValueError("static source tree cannot contain symlinks")
        child_info = child.lstat()
        if stat.S_ISDIR(child_info.st_mode):
            link_tree(child, destination)
        elif stat.S_ISREG(child_info.st_mode):
            link_file(child, destination)
        else:
            raise ValueError("static source tree contains a non-regular member")


def copy_static_source(source_root: Path, destination_root: Path) -> None:
    """Hard-link only frozen inputs; no prior campaign outputs are copied."""
    source_root = Path(source_root).resolve(strict=True)
    destination_root = Path(destination_root).absolute()
    if destination_root.exists() or destination_root.is_symlink():
        raise ValueError("parallel source destination must be new")
    destination_root.mkdir(mode=0o700, parents=True)
    for name in SOURCE_MARKERS:
        link_file(source_root / name, destination_root / name)
    for fold in (1, 2, 3):
        link_tree(source_root / f"labels-fold{fold}", destination_root / f"labels-fold{fold}")
    standard_source = source_root / "standard"
    standard_target = destination_root / "standard"
    standard_target.mkdir(mode=0o700)
    for name in SOURCE_STATIC_FILES:
        link_file(standard_source / name, standard_target / name)
    for name in SOURCE_STATIC_DIRS:
        link_tree(standard_source / name, standard_target / name)
    # A fresh lock inode is required; old lock bytes are intentionally not cloned.
    lock = os.open(standard_target / "generation.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(lock)


def verify_static_clone(source_root: Path, destination_root: Path) -> None:
    """Recover only our exact hard-link preparation, never adopt unknown output."""
    source_root = Path(source_root).resolve(strict=True)
    destination_root = Path(destination_root).resolve(strict=True)
    expected_top = set(SOURCE_MARKERS) | {"standard", *(f"labels-fold{fold}" for fold in (1, 2, 3))}
    if {item.name for item in destination_root.iterdir()} != expected_top:
        raise ValueError("partial parallel source has unknown members")
    def same_tree(source, target):
        source, target = Path(source), Path(target)
        if source.is_dir():
            if not target.is_dir() or {item.name for item in source.iterdir()} != {item.name for item in target.iterdir()}:
                return False
            return all(same_tree(item, target / item.name) for item in source.iterdir())
        if not source.is_file() or not target.is_file():
            return False
        left, right = source.stat(), target.stat()
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino and left.st_size == right.st_size
    for name in SOURCE_MARKERS:
        if not same_tree(source_root / name, destination_root / name):
            raise ValueError("partial parallel marker clone differs from frozen source")
    for fold in (1, 2, 3):
        name = f"labels-fold{fold}"
        if not same_tree(source_root / name, destination_root / name):
            raise ValueError("partial parallel labels differ from frozen source")
    source_standard, target_standard = source_root / "standard", destination_root / "standard"
    expected_standard = set(SOURCE_STATIC_DIRS) | set(SOURCE_STATIC_FILES) | {"generation.lock"}
    known_import_dirs = {"hybrid-runs", "hybrid-models", "hybrid-validations"}
    known_import_files = {"hybrid-campaign.identity.json", "hybrid-campaign.progress.json"}
    actual_standard = {item.name for item in target_standard.iterdir()}
    if (not expected_standard <= actual_standard
            or not actual_standard <= expected_standard | known_import_dirs | known_import_files):
        raise ValueError("partial parallel standard contains prior outputs or unknown members")
    for name in actual_standard & known_import_dirs:
        private_dir(target_standard / name)
    for name in actual_standard & known_import_files:
        _read_receipt(target_standard / name)
    for name in SOURCE_STATIC_FILES + SOURCE_STATIC_DIRS:
        if not same_tree(source_standard / name, target_standard / name):
            raise ValueError("partial parallel standard differs from frozen source")
    lock = target_standard / "generation.lock"
    if lock.is_symlink() or not lock.is_file() or lock.stat().st_size != 0 or lock.stat().st_nlink != 1:
        raise ValueError("parallel generation lock must be a fresh empty file")


def _code_overrides(compatibility_source: Path | None):
    if compatibility_source is None:
        return {}
    source = Path(compatibility_source).resolve(strict=True)
    return {name: source / name for name in ("strict_campaign.py", "selection.py")}


def verify_code_snapshot(source_app: Path, code_dir: Path,
                         compatibility_source: Path | None = None) -> None:
    source_app, code_dir = Path(source_app).resolve(strict=True), Path(code_dir).resolve(strict=True)
    target_app = code_dir / "app"
    if not target_app.is_dir() or target_app.is_symlink():
        raise ValueError("partial parallel code snapshot unavailable")
    expected = {item.name for item in source_app.iterdir()
                if item.name != "__pycache__" and item.is_file() and item.suffix == ".py"}
    actual = {item.name for item in target_app.iterdir()}
    if not expected or actual != expected:
        raise ValueError("partial parallel code snapshot has unexpected members")
    overrides = _code_overrides(compatibility_source)
    for name in expected:
        expected_sha = digest_file(source_app / name)
        actual_sha = digest_file(target_app / name)
        compatible_sha = digest_file(overrides[name]) if name in overrides else expected_sha
        if actual_sha not in {expected_sha, compatible_sha}:
            raise ValueError("partial parallel code snapshot differs from current source")


def apply_code_overrides(code_dir: Path, compatibility_source: Path | None) -> None:
    target_app = Path(code_dir) / "app"
    for name, source in _code_overrides(compatibility_source).items():
        source_info = source.lstat()
        if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != os.geteuid()
                or source_info.st_mode & 0o022 or source.is_symlink()):
            raise ValueError("frozen serial compatibility source must be owner-controlled")
        target = target_app / name
        if digest_file(target) == digest_file(source):
            continue
        temporary = target.with_name(f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream, source.open("rb") as original:
                shutil.copyfileobj(original, stream, 1024 * 1024)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def copy_code_snapshot(source_app: Path, target_code: Path,
                       compatibility_source: Path | None = None) -> None:
    source_app = Path(source_app).resolve(strict=True)
    target_code = Path(target_code).absolute()
    if target_code.exists() or target_code.is_symlink():
        raise ValueError("parallel code snapshot destination must be new")
    target_code.mkdir(mode=0o700, parents=True)
    app_target = target_code / "app"
    app_target.mkdir(mode=0o700)
    members = sorted(path for path in source_app.iterdir() if path.name != "__pycache__")
    if (not members or len(members) > 256
            or any(path.is_symlink() or not path.is_file() or path.suffix != ".py" for path in members)):
        raise ValueError("parallel code snapshot requires a flat set of Python sources only")
    for source in members:
        target = app_target / source.name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    apply_code_overrides(target_code, compatibility_source)


def _copy_private_file(source: Path, target: Path) -> str:
    source, target = Path(source), Path(target)
    source_info = source.lstat()
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != os.geteuid()
            or stat.S_IMODE(source_info.st_mode) != 0o600 or source.is_symlink()
            or source_info.st_size > 132 * 1024 ** 2):
        raise ValueError("imported run artifacts must be owner-only regular files")
    body = source.read_bytes()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists():
        if digest_file(target) != digest_bytes(body):
            raise ValueError("parallel recovery target already contains different bytes")
        return digest_bytes(body)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    return digest_bytes(body)


def import_interrupted_fit_sources(source_campaign_root: Path, plan, legacy):
    """Reuse only fit-complete/calibration-pending models with exact pins.

    The imported model bytes are never counted as fitted/calibrated until the
    new worker recovers, recalibrates, and writes a normal FITTED_CALIBRATED
    receipt under the new campaign.
    """
    source_campaign_root = private_dir(Path(source_campaign_root).absolute())
    source_identity = read_private(source_campaign_root / "parallel-campaign.identity.private.json")
    if (source_identity.get("campaign_type") != "HYBRID_STRICT_PARALLEL"
            or source_identity.get("data_provenance") != "DEMO_ONLY"
            or source_identity.get("continuation_identity", {}).get("dataset_sha256") != plan.identity["dataset_sha256"]
            or source_identity.get("continuation_identity", {}).get("code_inventory_sha256") != plan.identity["code_inventory_sha256"]
            or source_identity.get("continuation_identity", {}).get("java_snapshot_sha256") != plan.identity["java_snapshot_sha256"]
            or source_identity.get("continuation_identity", {}).get("image_id") != plan.identity["image_id"]):
        raise ValueError("recovery source campaign is not byte-compatible with the new parallel plan")
    source_standard = Path(source_identity["continuation_identity"]["dataset_directory"])
    old_state_dir = source_campaign_root / "state/fit"
    old_progress = read_private(source_campaign_root / "parallel-campaign.progress.private.json")
    serial_resume = source_identity.get("serial_resume_import")
    baseline_fit_ids = set()
    if serial_resume is not None:
        manifest_path = Path(serial_resume.get("manifest_path", ""))
        manifest = read_private(manifest_path)
        if (digest_file(manifest_path) != serial_resume.get("manifest_sha256")
                or manifest.get("fit_count") != serial_resume.get("fit_count")
                or manifest.get("validation_count") != serial_resume.get("validation_count")):
            raise ValueError("interrupted source serial-resume manifest changed")
        baseline_fit_ids = set(manifest.get("fit_run_ids", []))
    baseline_fits = serial_resume.get("fit_count", 0) if type(serial_resume) is dict else 0
    baseline_validations = serial_resume.get("validation_count", 0) if type(serial_resume) is dict else 0
    if (old_progress.get("completed_fits") != baseline_fits
            or old_progress.get("completed_validations") != baseline_validations
            or old_progress.get("quality_gate") != "NOT_RUN"
            or old_progress.get("holdout_scored") is not False):
        raise ValueError("interrupted campaign must have only the declared pre-holdout baseline and incomplete fit workers")
    protocol_runs = {item["run_id"]: item for item in plan.protocol["campaign"]}
    recoveries = []
    for path in sorted(old_state_dir.glob("*.private.json")):
        state = read_private(path)
        run_id = state.get("run_id")
        if (state.get("phase") != "fit" or state.get("campaign_id") != source_identity.get("campaign_id")
                or run_id not in protocol_runs):
            raise ValueError("interrupted parallel task state is not eligible for fit recovery")
        if state.get("status") == "SUCCEEDED":
            receipt_path = source_standard / "hybrid-runs" / f"{run_id}.json"
            receipt = _read_receipt(receipt_path)
            if (run_id not in baseline_fit_ids or receipt is None
                    or receipt.get("status") != "FITTED_CALIBRATED"
                    or digest_file(receipt_path) != state.get("receipt_sha256")):
                raise ValueError("completed parallel source task is not part of the verified serial baseline")
            continue
        if state.get("status") != "RUNNING":
            raise ValueError("only an exact running fit task may be reconciled")
        container = _docker_inspect(state.get("container_name", ""))
        if (container is None or container.get("Id") != state.get("container_id")
                or container.get("State", {}).get("Status") != "exited"
                or container.get("State", {}).get("ExitCode") != 137
                or container.get("State", {}).get("OOMKilled") is not False):
            raise ValueError("fit worker termination is not an exact non-OOM interrupted handle")
        labels = container.get("Config", {}).get("Labels", {}) or {}
        if (labels.get("flare.parallel.identity") != source_identity["campaign_id"]
                or labels.get("flare.parallel.phase") != "fit" or labels.get("flare.parallel.run_id") != run_id):
            raise ValueError("interrupted fit container labels do not match its receipt")
        run = protocol_runs[run_id]
        source_run_path = source_standard / "hybrid-runs" / f"{run_id}.json"
        receipt = _read_receipt(source_run_path)
        expected_fit_sources = {name: plan.identity["python_sources"][name] for name in legacy.FIT_SOURCES}
        code_fingerprint = receipt.get("code_fingerprint", {}) if receipt else {}
        dependencies = code_fingerprint.get("dependencies", {}) if type(code_fingerprint) is dict else {}
        expected_binding = {
            "run_id": run_id, "fold": run["fold"], "config": run["config"],
            "dataset_manifest_sha256": plan.identity["dataset_sha256"],
            "model_kind": legacy.HYBRID_KIND, "recipe_version": 1,
            "recipe_sha256": run["recipe_sha256"],
            "labeled_training_manifest_sha256": plan.identity["labeled_manifest_sha256_by_fold"][str(run["fold"])],
            "normal_fit_split_sha256": plan.catalog.split(f"fold{run['fold']}-fit")["sha256"],
            "fit_split_sha256": plan.catalog.split(f"fold{run['fold']}-fit")["sha256"],
            "training_windows": 50000, "fit_completed": True, "status": "CALIBRATING",
            "quality_gate": "NOT_RUN", "data_provenance": "DEMO_ONLY",
            "actual_composite_trials": 1, "actual_component_fit_calls": 2,
            "additional_component_fit_calls_this_attempt": 2, "fit_recovered_without_refit": False,
        }
        if (receipt is None or any(receipt.get(key) != value for key, value in expected_binding.items())
                or code_fingerprint.get("sources") != expected_fit_sources
                or set(dependencies) != {"scikit-learn", "numpy", "scipy", "joblib"}):
            raise ValueError("interrupted fit receipt lacks the exact completed run/source binding")
        version = receipt.get("source_model_version")
        if type(version) is not str or not re.fullmatch(r"hybrid_fit_[a-z0-9_-]{8,128}", version):
            raise ValueError("interrupted source model version is invalid")
        metadata_path = source_standard / "hybrid-models" / f"{version}.json"
        artifact_path = source_standard / "hybrid-models" / f"{version}.joblib"
        metadata = _read_receipt(metadata_path)
        if (metadata is None or metadata.get("sha256") != receipt.get("source_model_sha256")
                or digest_file(artifact_path) != metadata.get("sha256")
                or metadata.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
                or metadata.get("run_id") != run_id or metadata.get("fold") != run["fold"]
                or metadata.get("model_config") != run["config"]
                or metadata.get("model_kind") != legacy.HYBRID_KIND or metadata.get("recipe_version") != 1
                or metadata.get("data_provenance") != "DEMO_ONLY"
                or metadata.get("actual_component_fit_counts") != {
                    "normal_component_fit_calls": 1, "labeled_component_fit_calls": 1}):
            raise ValueError("interrupted source model bytes do not prove exactly one component pair")
        target_run_path = plan.dataset / "hybrid-runs" / f"{run_id}.json"
        target_metadata_path = plan.dataset / "hybrid-models" / f"{version}.json"
        target_artifact_path = plan.dataset / "hybrid-models" / f"{version}.joblib"
        receipt_hash = _copy_private_file(source_run_path, target_run_path)
        metadata_hash = _copy_private_file(metadata_path, target_metadata_path)
        artifact_hash = _copy_private_file(artifact_path, target_artifact_path)
        recoveries.append({"run_id": run_id, "source_campaign_id": source_identity["campaign_id"],
                           "source_container_id": container["Id"], "source_receipt_sha256": receipt_hash,
                           "source_model_metadata_sha256": metadata_hash, "source_model_artifact_sha256": artifact_hash,
                           "recovery_action": "RECALIBRATE_VERIFIED_FIT_WITHOUT_REFIT",
                           "fit_counted_complete": False})
    return recoveries


def import_completed_serial_outputs(source_root: Path, plan, legacy):
    """Copy only byte-verified terminal receipts/models from the stopped serial run."""
    source_root = private_dir(Path(source_root).absolute())
    source = source_root / "standard"
    target = plan.dataset
    source_identity_path = source / "hybrid-campaign.identity.json"
    source_progress_path = source / "hybrid-campaign.progress.json"
    source_identity = _read_receipt(source_identity_path)
    source_progress = _read_receipt(source_progress_path)
    if source_identity is None or source_progress is None:
        raise ValueError("serial continuation identity and stopped progress are required")
    fit_fingerprint = source_identity.get("code_fingerprint")
    expected_fit_sources = {name: plan.identity["python_sources"][name] for name in legacy.FIT_SOURCES}
    dependencies = fit_fingerprint.get("dependencies", {}) if type(fit_fingerprint) is dict else {}
    if (source_identity.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
            or source_identity.get("model_kind") != legacy.HYBRID_KIND
            or source_identity.get("recipe_version") != 1
            or source_identity.get("labeled_training_manifest_sha256_by_fold") != plan.identity["labeled_manifest_sha256_by_fold"]
            or fit_fingerprint.get("sources") != expected_fit_sources
            or set(dependencies) != {"scikit-learn", "numpy", "scipy", "joblib"}
            or source_progress.get("status") != "STOPPED_AT_RUN_BOUNDARY"
            or source_progress.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
            or source_progress.get("code_fingerprint") != fit_fingerprint
            or source_progress.get("quality_gate") != "NOT_RUN"
            or source_progress.get("holdout_scored") is not False):
        raise ValueError("serial campaign is not a stopped, compatible, pre-holdout source")

    protocol_runs = {item["run_id"]: item for item in plan.protocol["campaign"]}
    source_fits = source / "hybrid-runs"
    source_validations = source / "hybrid-validations"
    source_models = source / "hybrid-models"
    target_fits = private_dir(target / "hybrid-runs", create=True)
    target_validations = private_dir(target / "hybrid-validations", create=True)
    target_models = private_dir(target / "hybrid-models", create=True)

    fit_paths = sorted(source_fits.glob("*.json"))
    validation_paths = sorted(source_validations.glob("*.json"))
    if (len(fit_paths) != source_progress.get("actual_fits_completed")
            or source_progress.get("actual_fits_completed", 0) > 360
            or len(validation_paths) > len(fit_paths)):
        raise ValueError("serial progress and terminal receipt counts do not agree")
    fit_receipts = {}
    imported_files = []
    expected_fit_names, expected_validation_names, expected_model_names = set(), set(), set()

    def copy_verified(source_path: Path, target_path: Path):
        sha = digest_file(source_path)
        copied_sha = _copy_private_file(source_path, target_path)
        if copied_sha != sha or digest_file(target_path) != sha:
            raise ValueError("copied serial artifact failed byte-for-byte verification")
        imported_files.append({"path": str(target_path.relative_to(plan.dataset)), "sha256": sha})
        return sha

    for path in fit_paths:
        run_id = path.stem
        run = protocol_runs.get(run_id)
        fit = _read_receipt(path)
        if run is None or fit is None:
            raise ValueError("serial fit receipt is outside the frozen approved run list")
        fold = run["fold"]
        expected = {"status": "FITTED_CALIBRATED", "run_id": run_id, "fold": fold,
                    "config": run["config"], "dataset_manifest_sha256": plan.identity["dataset_sha256"],
                    "code_fingerprint": fit_fingerprint, "model_kind": legacy.HYBRID_KIND,
                    "recipe_version": 1, "recipe_sha256": run["recipe_sha256"],
                    "labeled_training_manifest_sha256": plan.identity["labeled_manifest_sha256_by_fold"][str(fold)],
                    "normal_fit_split_sha256": plan.catalog.split(f"fold{fold}-fit")["sha256"],
                    "fit_split_sha256": plan.catalog.split(f"fold{fold}-fit")["sha256"],
                    "training_windows": 50000, "calibration_scope": "STRICT",
                    "quality_gate": "NOT_RUN", "actual_composite_trials": 1,
                    "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0,
                    "data_provenance": "DEMO_ONLY"}
        if any(fit.get(key) != value for key, value in expected.items()):
            raise ValueError("serial fit receipt does not match the frozen model/data contract")

        source_version, model_version = fit.get("source_model_version"), fit.get("model_version")
        if (type(source_version) is not str or not re.fullmatch(r"hybrid_fit_[a-z0-9_-]{8,128}", source_version)
                or type(model_version) is not str or not re.fullmatch(r"hybrid_cal_[a-z0-9_-]{8,128}", model_version)
                or source_version == model_version):
            raise ValueError("serial fit model versions are not canonical")
        for version, expected_sha, calibrated in (
                (source_version, fit.get("source_model_sha256"), False),
                (model_version, fit.get("model_sha256"), True)):
            metadata_path = source_models / f"{version}.json"
            artifact_path = source_models / f"{version}.joblib"
            metadata = _read_receipt(metadata_path)
            if (metadata is None or type(expected_sha) is not str or metadata.get("sha256") != expected_sha
                    or digest_file(artifact_path) != expected_sha
                    or metadata.get("model_version") != version
                    or metadata.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
                    or metadata.get("run_id") != run_id or metadata.get("fold") != fold
                    or metadata.get("model_config") != run["config"]
                    or metadata.get("model_kind") != legacy.HYBRID_KIND
                    or metadata.get("recipe_version") != 1
                    or metadata.get("recipe_sha256") != run["recipe_sha256"]
                    or metadata.get("data_provenance") != "DEMO_ONLY"):
                raise ValueError("serial model metadata/artifact hash or run binding mismatch")
            if calibrated:
                if (metadata.get("source_model_version") != source_version
                        or metadata.get("source_model_sha256") != fit.get("source_model_sha256")
                        or metadata.get("calibration_sha256") != fit.get("calibration_sha256")
                        or metadata.get("score_policy") != fit.get("score_policy")
                        or metadata.get("calibration_scope") != "STRICT"):
                    raise ValueError("serial calibrated model does not bind its fitted source")
            elif (metadata.get("code_fingerprint") != fit_fingerprint
                  or metadata.get("actual_component_fit_counts") != {
                      "normal_component_fit_calls": 1, "labeled_component_fit_calls": 1}):
                raise ValueError("serial source model does not prove the exact component fit")
            expected_model_names.update((metadata_path.name, artifact_path.name))
            copy_verified(metadata_path, target_models / metadata_path.name)
            copy_verified(artifact_path, target_models / artifact_path.name)
        expected_fit_names.add(path.name)
        copy_verified(path, target_fits / path.name)
        fit_receipts[run_id] = fit

    for path in validation_paths:
        run_id = path.stem
        run = protocol_runs.get(run_id)
        fit = fit_receipts.get(run_id)
        validation = _read_receipt(path)
        if run is None or fit is None or validation is None:
            raise ValueError("serial validation receipt lacks its exact completed fit")
        expected = {"status": "VALIDATED", "evaluation_scope": "VALIDATION", "run_id": run_id,
                    "fold": run["fold"], "config": run["config"],
                    "model_version": fit["model_version"], "model_sha256": fit["model_sha256"],
                    "calibration_sha256": fit["calibration_sha256"],
                    "dataset_manifest_sha256": plan.identity["dataset_sha256"],
                    "model_kind": legacy.HYBRID_KIND, "recipe_version": 1,
                    "recipe_sha256": run["recipe_sha256"],
                    "validation_split_sha256": plan.catalog.split(f"fold{run['fold']}-validation")["sha256"],
                    "quality_gate": "NOT_APPLICABLE"}
        if (any(validation.get(key) != value for key, value in expected.items())
                or validation.get("selection_identity") is None):
            raise ValueError("serial validation receipt does not match its frozen fit/validation contract")
        legacy.selection_binding(plan, validation["selection_identity"], fit_fingerprint)
        expected_validation_names.add(path.name)
        copy_verified(path, target_validations / path.name)

    for directory, expected_names in ((target_fits, expected_fit_names),
                                      (target_validations, expected_validation_names),
                                      (target_models, expected_model_names)):
        if {item.name for item in directory.iterdir()} != expected_names:
            raise ValueError("parallel resume output directory contains unverified or missing members")

    copy_verified(source_identity_path, target / source_identity_path.name)
    copy_verified(source_progress_path, target / source_progress_path.name)
    manifest = {"source_campaign_identity_sha256": digest_file(source_identity_path),
                "source_progress_sha256": digest_file(source_progress_path),
                "dataset_sha256": plan.identity["dataset_sha256"],
                "fit_code_fingerprint_sha256": digest_bytes(canonical(fit_fingerprint).encode()),
                "fit_count": len(fit_receipts), "validation_count": len(validation_paths),
                "fit_run_ids": sorted(fit_receipts),
                "validation_run_ids": sorted(path.stem for path in validation_paths),
                "files": sorted(imported_files, key=lambda item: item["path"]),
                "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
    manifest_path = plan.dataset.parents[1] / "state" / "serial-reuse-manifest.private.json"
    write_private(manifest_path, manifest)
    return {"source_campaign_identity_sha256": manifest["source_campaign_identity_sha256"],
            "source_progress_sha256": manifest["source_progress_sha256"],
            "manifest_path": str(manifest_path), "manifest_sha256": digest_file(manifest_path),
            "fit_count": len(fit_receipts), "validation_count": len(validation_paths),
            "fit_run_ids_sha256": digest_bytes(canonical(sorted(fit_receipts)).encode()),
            "validation_run_ids_sha256": digest_bytes(canonical(sorted(path.stem for path in validation_paths)).encode()),
            "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}


def load_legacy_operator():
    spec = importlib.util.spec_from_file_location("pinned_serial_hybrid_operator", LEGACY_OPERATOR)
    if spec is None or spec.loader is None:
        raise ValueError("pinned source validator unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_pinned_operator():
    path = ROOT / "observability/scripts/strict-operator.py"
    spec = importlib.util.spec_from_file_location("pinned_strict_operator_constants", path)
    if spec is None or spec.loader is None:
        raise ValueError("pinned strict campaign constants unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def prepare_campaign(source_root: Path, campaign_root: Path | None, code_source: Path,
                     workspace: Path, workers=DEFAULT_WORKERS,
                     memory_mib=DEFAULT_MEMORY_MIB, cpu_per_worker=DEFAULT_CPU,
                     authorization_reference="User authorized transition to parallel campaign",
                     recovery_source: Path | None = None,
                     resume_from: Path | None = None,
                     resume_code_source: Path | None = None):
    legacy = load_legacy_operator()
    pinned = load_pinned_operator()
    frozen_source_root = Path(source_root).resolve(strict=True)
    code_source = Path(code_source).resolve(strict=True)
    workspace = Path(workspace).resolve(strict=True)
    if resume_from is not None and resume_code_source is None:
        resume_code_source = DEFAULT_RESUME_CODE_SOURCE
    if resume_from is None and resume_code_source is not None:
        raise ValueError("a serial compatibility code source requires --resume-from")
    compatibility_source = Path(resume_code_source).resolve(strict=True) if resume_code_source is not None else None
    if type(workers) is not int or not 2 <= workers <= 4:
        raise ValueError("parallel campaign worker count must be 2 through 4")
    if type(memory_mib) is not int or not 1024 <= memory_mib <= 2048:
        raise ValueError("each parallel worker memory limit must be 1024..2048 MiB")
    if cpu_per_worker not in ("1.0", "1.5", "2.0"):
        raise ValueError("approved per-worker CPU limit required")
    if (type(authorization_reference) is not str or not authorization_reference.strip()
            or len(authorization_reference) > 2000):
        raise ValueError("bounded user authorization reference required")
    if campaign_root is None:
        campaign_root = Path(tempfile.mkdtemp(prefix="hybrid-strict-source-20261013-parallel-", dir=RUNTIME))
    campaign_root = Path(campaign_root).absolute()
    if campaign_root.parent != RUNTIME.absolute() or legacy.SOURCE_ROOT.fullmatch(campaign_root.name) is None:
        raise ValueError("parallel source root must be a new canonical observability/runtime child")
    created = not campaign_root.exists()
    if created:
        campaign_root.mkdir(mode=0o700, parents=True)
    elif any(campaign_root.iterdir()):
        expected_root = {"source", "code", "state", "logs"}
        children = {item.name for item in campaign_root.iterdir()}
        if (not {"source", "code"} <= children or not children <= expected_root
                or (campaign_root / "parallel-campaign.identity.private.json").exists()
                or (campaign_root / "parallel-campaign.progress.private.json").exists()):
            raise ValueError("campaign root contains state from another preparation")
        for name in ("state", "logs"):
            directory = private_dir(campaign_root / name, create=True)
            if any(directory.iterdir()):
                raise ValueError("partial campaign preparation has unexpected state/log files")
        verify_static_clone(frozen_source_root, campaign_root / "source")
        verify_code_snapshot(code_source, campaign_root / "code", compatibility_source)
        apply_code_overrides(campaign_root / "code", compatibility_source)
    else:
        campaign_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_dir(campaign_root)
    new_source_root = campaign_root / "source"
    code_dir = campaign_root / "code"
    if created or not (new_source_root.exists() and code_dir.exists()):
        copy_static_source(frozen_source_root, new_source_root)
        copy_code_snapshot(code_source, code_dir, compatibility_source)
        private_dir(campaign_root / "state", create=True)
        private_dir(campaign_root / "logs", create=True)
    else:
        verify_static_clone(frozen_source_root, new_source_root)
        verify_code_snapshot(code_source, code_dir, compatibility_source)
        apply_code_overrides(code_dir, compatibility_source)
        verify_code_snapshot(code_source, code_dir, compatibility_source)
    image = pinned.IMAGE
    _, code_sha = legacy.hybrid_code_identity(code_dir, image)
    dataset = new_source_root / "standard"
    pins = pinned.PINS
    plan = legacy.HybridPlan(dataset, dataset_sha=pins["dataset_sha"], archive_sha=pins["archive_sha"],
                            marker_sha=pins["marker_sha"], terminal_sha=pins["terminal_sha"],
                            code=code_dir, code_sha=code_sha, workspace=workspace,
                            workspace_sha=pins["workspace_sha"], image=image)
    plan.recheck()
    preflight = plan.preflight()
    serial_resume = (import_completed_serial_outputs(resume_from, plan, legacy)
                     if resume_from is not None else None)
    recovered_fits = (import_interrupted_fit_sources(recovery_source, plan, legacy)
                      if recovery_source is not None else [])
    controller_sha = digest_file(Path(__file__).resolve())
    def count_receipts(path):
        return sum(1 for entry in path.iterdir() if entry.is_file() and entry.suffix == ".json") if path.is_dir() else 0
    prior_standard = frozen_source_root / "standard"
    reference = {"source_root": str(frozen_source_root), "fit_receipts": count_receipts(prior_standard / "hybrid-runs"),
                "validation_receipts": count_receipts(prior_standard / "hybrid-validations"),
                "reused_by_parallel_campaign": serial_resume is not None}
    identity = {"schema_version": 1, "campaign_type": "HYBRID_STRICT_PARALLEL",
                "campaign_id": None, "continuation_identity": plan.identity,
                "continuation_identity_sha256": plan.identity_sha256,
                "controller_sha256": controller_sha,
                "resource_policy": {"workers": workers, "memory_mib_per_worker": memory_mib,
                                    "cpu_per_worker": cpu_per_worker, "network": "NONE",
                                    "worker_cache_scope": "PER_WORKER_AND_PHASE"},
                "legacy_campaign_reference": reference,
                "serial_code_overrides": ({"source_directory": str(compatibility_source),
                                           "sha256_by_file": {name: digest_file(path) for name, path in
                                                               _code_overrides(compatibility_source).items()}}
                                          if compatibility_source is not None else None),
                "parallel_recovery_imports": recovered_fits,
                "serial_resume_import": serial_resume,
                "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_RUN",
                "holdout_scored": False, "aws_changed": False,
                "authorized_by": authorization_reference.strip(),
                "created_at_utc": utc_now()}
    identity["campaign_id"] = hashlib.sha256(canonical(identity).encode()).hexdigest()[:24]
    private_dir(campaign_root / "state", create=True)
    private_dir(campaign_root / "logs", create=True)
    write_private(campaign_root / "parallel-campaign.identity.private.json", identity)
    write_private(campaign_root / "parallel-campaign.progress.private.json", {
        "campaign_id": identity["campaign_id"], "status": "PREPARED", "phase": "NOT_STARTED",
        "completed_fits": serial_resume["fit_count"] if serial_resume else 0, "required_fits": 360,
        "completed_validations": serial_resume["validation_count"] if serial_resume else 0,
        "required_validations": 360, "quality_gate": "NOT_RUN", "holdout_scored": False,
        "aws_changed": False, "preflight": preflight, "updated_at_utc": utc_now()})
    return {"campaign_root": str(campaign_root), "campaign_id": identity["campaign_id"],
            "dataset_sha256": pins["dataset_sha"], "archive_sha256": pins["archive_sha"],
            "code_inventory_sha256": code_sha, "workers": workers, "memory_mib_per_worker": memory_mib,
            "legacy_reference": reference, "status": "PREPARED", "quality_gate": "NOT_RUN",
            "holdout_scored": False, "aws_changed": False}


def load_campaign(campaign_root: Path):
    legacy = load_legacy_operator()
    pinned = load_pinned_operator()
    campaign_root = private_dir(Path(campaign_root).absolute())
    identity = read_private(campaign_root / "parallel-campaign.identity.private.json")
    if identity.get("controller_sha256") != digest_file(Path(__file__).resolve()):
        raise ValueError("parallel controller changed after campaign preparation")
    plan_identity = identity.get("continuation_identity")
    if type(plan_identity) is not dict or type(plan_identity.get("dataset_directory")) is not str:
        raise ValueError("frozen continuation plan identity required")
    plan = legacy.HybridPlan(Path(plan_identity["dataset_directory"]),
                             dataset_sha=pinned.PINS["dataset_sha"], archive_sha=pinned.PINS["archive_sha"],
                             marker_sha=pinned.PINS["marker_sha"], terminal_sha=pinned.PINS["terminal_sha"],
                             code=Path(plan_identity["code_directory"]),
                             code_sha=plan_identity["code_inventory_sha256"],
                             workspace=Path(plan_identity["workspace_directory"]),
                             workspace_sha=pinned.PINS["workspace_sha"], image=pinned.IMAGE)
    plan.recheck()
    if (plan.identity != plan_identity or plan.identity_sha256 != identity.get("continuation_identity_sha256")
            or campaign_root != Path(plan.dataset).parents[1]):
        raise ValueError("parallel campaign source/code/workspace identity drifted")
    resource = identity.get("resource_policy")
    recalculated_identity = dict(identity)
    campaign_id = recalculated_identity.get("campaign_id")
    recalculated_identity["campaign_id"] = None
    recalculated_id = hashlib.sha256(canonical(recalculated_identity).encode()).hexdigest()[:24]
    if (identity.get("campaign_type") != "HYBRID_STRICT_PARALLEL"
            or identity.get("data_provenance") != "DEMO_ONLY"
            or identity.get("holdout_scored") is not False or identity.get("aws_changed") is not False
            or campaign_id != recalculated_id
            or type(resource) is not dict or type(resource.get("workers")) is not int
            or not 2 <= resource["workers"] <= 4
            or type(resource.get("memory_mib_per_worker")) is not int
            or not 1024 <= resource["memory_mib_per_worker"] <= 2048
            or resource.get("cpu_per_worker") not in {"1.0", "1.5", "2.0"}
            or resource.get("network") != "NONE"):
        raise ValueError("parallel campaign identity/scope/resource policy mismatch")
    return legacy, campaign_root, identity, plan


def _receipt_path(plan, phase: str, run_id: str) -> Path:
    directory = plan.dataset / ("hybrid-runs" if phase == "fit" else "hybrid-validations")
    return directory / f"{run_id}.json"


def _read_receipt(path: Path, maximum=4 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.exists():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > maximum):
        raise ValueError("bounded single-link owner-only run receipt required")
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("run receipt must be an object")
    return value


def _verify_receipt(plan, phase, run_id):
    receipt = _read_receipt(_receipt_path(plan, phase, run_id))
    if receipt is None:
        return None
    if phase == "fit":
        common = (receipt.get("run_id") == run_id
                  and receipt.get("dataset_manifest_sha256") == plan.identity["dataset_sha256"]
                  and receipt.get("model_kind") == "normal_plus_incident_research"
                  and receipt.get("recipe_version") == 1 and receipt.get("actual_composite_trials") == 1
                  and receipt.get("actual_component_fit_calls") == 2 and receipt.get("quality_gate") == "NOT_RUN")
        if not common:
            raise ValueError("parallel fit receipt does not satisfy the strict HYBRID run contract")
        if receipt.get("status") == "CALIBRATING":
            version = receipt.get("source_model_version")
            if type(version) is not str or not re.fullmatch(r"hybrid_fit_[a-z0-9_-]{8,128}", version):
                raise ValueError("recoverable fit receipt has no canonical source model version")
            model_root = plan.dataset / "hybrid-models"
            metadata = _read_receipt(model_root / f"{version}.json")
            artifact = model_root / f"{version}.joblib"
            if (metadata is None or metadata.get("sha256") != receipt.get("source_model_sha256")
                    or digest_file(artifact) != metadata.get("sha256")
                    or metadata.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
                    or metadata.get("run_id") != run_id or metadata.get("fold") != receipt.get("fold")
                    or metadata.get("model_config") != receipt.get("config")
                    or metadata.get("code_fingerprint") != receipt.get("code_fingerprint")
                    or metadata.get("model_kind") != "normal_plus_incident_research"
                    or metadata.get("recipe_version") != 1
                    or metadata.get("actual_component_fit_counts") != {
                        "normal_component_fit_calls": 1, "labeled_component_fit_calls": 1}):
                raise ValueError("calibration-pending receipt lacks a verified completed component-pair fit")
            return {**receipt, "status": "RECOVERABLE_CALIBRATION"}
        if receipt.get("status") != "FITTED_CALIBRATED":
            raise ValueError("fit receipt is neither complete nor safely calibration-recoverable")
    elif phase == "validation":
        fit = _read_receipt(_receipt_path(plan, "fit", run_id))
        if (fit is None or receipt.get("status") != "VALIDATED" or receipt.get("run_id") != run_id
                or receipt.get("evaluation_scope") != "VALIDATION"
                or receipt.get("model_sha256") != fit.get("model_sha256")
                or receipt.get("calibration_sha256") != fit.get("calibration_sha256")
                or receipt.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
                or receipt.get("quality_gate") != "NOT_APPLICABLE"):
            raise ValueError("parallel validation receipt does not match its strict fit")
    else:
        raise ValueError("known parallel phase required")
    return receipt


def _worker_state_path(campaign_root, phase, run_id):
    directory = private_dir(campaign_root / "state" / phase, create=True)
    return directory / f"{run_id}.private.json"


def _container_name(campaign_id, phase, worker_id, run_id):
    suffix = hashlib.sha256(run_id.encode()).hexdigest()[:12]
    return f"flare-ph-{campaign_id[:8]}-{phase}-w{worker_id}-{suffix}"


def _docker_inspect(name):
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=15)
    if result.returncode:
        return None
    values = json.loads(result.stdout)
    if type(values) is not list or len(values) != 1:
        raise ValueError("one exact worker container required")
    return values[0]


def _worker_command(identity, plan, phase, worker_id, run_id, name):
    resource = identity["resource_policy"]
    cache_path = f"/source/standard/hybrid-parallel-cache/{phase}/worker-{worker_id:02d}"
    command = ["docker", "run", "--detach", "--name", name, "--network", "none", "--user", "1000:1000",
               "--memory", f"{resource['memory_mib_per_worker']}m", "--cpus", resource["cpu_per_worker"],
               "--pids-limit", "128", "--entrypoint", "python",
               "--label", "flare.parallel.identity=" + identity["campaign_id"],
               "--label", "flare.parallel.phase=" + phase,
               "--label", "flare.parallel.run_id=" + run_id,
               "-v", str(plan.code) + ":/code:ro", "-v", str(plan.dataset.parent) + ":/source:rw",
               "-v", str(plan.workspace) + ":/workspace:ro", "-v", str(plan.workspace) + ":" + str(plan.workspace) + ":ro",
               "-w", "/code", "-e", "PYTHONPATH=/code", "-e", "PYTHONDONTWRITEBYTECODE=1",
               "-e", "PYTHONPYCACHEPREFIX=/tmp/parallel-hybrid-bytecode", "-e", "OPENBLAS_NUM_THREADS=1",
               "-e", "OMP_NUM_THREADS=1", plan.image, "-B", "-m", "app.parallel_worker", phase,
               "--dataset", "/source/standard", "--run-id", run_id, "--worker-id", str(worker_id),
               "--dataset-sha256", plan.identity["dataset_sha256"], "--archive-sha256", plan.identity["archive_sha256"],
               "--cache-directory", cache_path]
    if phase == "validation":
        command.extend(["--workspace", "/workspace"])
    return command


def _save_log(campaign_root, phase, run_id, text):
    directory = private_dir(campaign_root / "logs" / phase, create=True)
    path = directory / f"{run_id}.log"
    body = text.encode("utf-8", errors="replace")
    if len(body) > 4 * 1024 * 1024:
        body = body[-4 * 1024 * 1024:]
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    return path


def _execute_one(plan, campaign_root, identity, phase, worker_id, run_id, timeout_seconds=7200):
    receipt = _verify_receipt(plan, phase, run_id)
    state_path = _worker_state_path(campaign_root, phase, run_id)
    old_state = read_private(state_path) if state_path.exists() else None
    completed_status = "FITTED_CALIBRATED" if phase == "fit" else "VALIDATED"
    if old_state and old_state.get("status") == "FAILED":
        raise ValueError("failed parallel worker needs diagnosis; automatic retry is disabled")
    if receipt is not None and receipt.get("status") == completed_status and old_state and old_state.get("status") == "SUCCEEDED":
        if digest_file(_receipt_path(plan, phase, run_id)) != old_state.get("receipt_sha256"):
            raise ValueError("successful worker receipt changed after verification")
        return {"status": "SUCCEEDED", "run_id": run_id, "phase": phase, "worker_id": old_state["worker_id"]}
    if receipt is not None and receipt.get("status") == completed_status and old_state is None:
        receipt_sha = digest_file(_receipt_path(plan, phase, run_id))
        write_private(state_path, {"campaign_id": identity["campaign_id"], "phase": phase, "run_id": run_id,
                                   "worker_id": worker_id, "status": "SUCCEEDED", "receipt_sha256": receipt_sha,
                                   "container_name": None, "container_id": None, "recovered_from_receipt": True,
                                   "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False})
        return {"status": "SUCCEEDED", "run_id": run_id, "phase": phase, "worker_id": worker_id}
    if old_state:
        prior_worker = old_state.get("worker_id")
        if type(prior_worker) is not int or not 0 <= prior_worker < identity["resource_policy"]["workers"]:
            raise ValueError("retained worker slot identity is invalid")
        worker_id = prior_worker
    name = old_state.get("container_name") if old_state else _container_name(identity["campaign_id"], phase, worker_id, run_id)
    state = old_state or {"campaign_id": identity["campaign_id"], "phase": phase, "run_id": run_id,
                          "worker_id": worker_id, "status": "DISPATCH_INTENT", "container_name": name,
                          "container_id": None, "quality_gate": "NOT_RUN", "holdout_scored": False,
                          "aws_changed": False, "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if state.get("campaign_id") != identity["campaign_id"] or state.get("container_name") != name:
        raise ValueError("parallel worker state is bound to another campaign")
    write_private(state_path, state)
    info = _docker_inspect(name)
    if receipt is not None and old_state is not None and info is None:
        receipt_sha = digest_file(_receipt_path(plan, phase, run_id))
        write_private(state_path, {**state, "status": "SUCCEEDED", "receipt_sha256": receipt_sha,
                                   "container_id": old_state.get("container_id"), "recovered_from_receipt": True,
                                   "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False})
        return {"status": "SUCCEEDED", "run_id": run_id, "phase": phase, "worker_id": worker_id,
                "receipt_sha256": receipt_sha}
    if info is None:
        if old_state and old_state.get("status") not in {"DISPATCH_INTENT"}:
            raise ValueError("interrupted worker handle is missing; refusing automatic retry")
        launch = subprocess.run(_worker_command(identity, plan, phase, worker_id, run_id, name),
                                capture_output=True, text=True, timeout=30)
        if launch.returncode:
            info = _docker_inspect(name)
            if info is None:
                write_private(state_path, {**state, "status": "FAILED", "failure": "DOCKER_DISPATCH_FAILED"})
                raise RuntimeError("parallel worker dispatch failed; no container handle was created")
        else:
            state = {**state, "status": "RUNNING", "container_id": launch.stdout.strip()}
            write_private(state_path, state)
            info = _docker_inspect(name)
    if info is None:
        raise ValueError("worker container disappeared before reconciliation")
    labels = info.get("Config", {}).get("Labels", {}) or {}
    container_id = info.get("Id")
    if (info.get("Image") != plan.image
            or labels.get("flare.parallel.identity") != identity["campaign_id"]
            or labels.get("flare.parallel.phase") != phase or labels.get("flare.parallel.run_id") != run_id
            or type(container_id) is not str or not SHA256.fullmatch(container_id)):
        raise ValueError("worker container/image/labels differ from the frozen parallel plan")
    if state.get("container_id") not in (None, container_id):
        raise ValueError("worker container ID changed; automatic adoption is forbidden")
    if state.get("container_id") is None:
        state = {**state, "status": "RUNNING", "container_id": container_id}
        write_private(state_path, state)
    started = time.monotonic()
    while True:
        info = _docker_inspect(name)
        if info is None or info.get("Id") != container_id:
            raise ValueError("exact worker container disappeared or changed ID")
        status = info.get("State", {}).get("Status")
        if status == "exited":
            docker_state = info["State"]
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=30)
            _save_log(campaign_root, phase, run_id, logs.stdout + logs.stderr)
            if docker_state.get("ExitCode") != 0 or docker_state.get("OOMKilled") is True:
                write_private(state_path, {**state, "status": "FAILED", "exit_code": docker_state.get("ExitCode"),
                                           "oom_killed": docker_state.get("OOMKilled")})
                raise RuntimeError("parallel worker failed; receipt/log retained, automatic retry is disabled")
            receipt = _verify_receipt(plan, phase, run_id)
            if receipt is not None and receipt.get("status") == "RECOVERABLE_CALIBRATION":
                receipt = None
            if receipt is None:
                write_private(state_path, {**state, "status": "FAILED", "exit_code": 0,
                                           "failure": "SUCCESS_WITHOUT_RECEIPT"})
                raise ValueError("worker exited successfully without its bound receipt")
            receipt_sha = digest_file(_receipt_path(plan, phase, run_id))
            success = {**state, "status": "SUCCEEDED", "exit_code": 0, "receipt_sha256": receipt_sha,
                       "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
            write_private(state_path, success)
            removed = subprocess.run(["docker", "rm", name], capture_output=True, text=True, timeout=30)
            if removed.returncode:
                raise RuntimeError("verified worker container cleanup failed; preserve and inspect its handle")
            return {"status": "SUCCEEDED", "run_id": run_id, "phase": phase, "worker_id": worker_id,
                    "receipt_sha256": receipt_sha}
        if status not in {"running", "created", "restarting"}:
            raise ValueError("parallel worker is in an unknown Docker state")
        if time.monotonic() - started > timeout_seconds:
            write_private(state_path, {**state, "status": "OBSERVATION_TIMEOUT", "container_id": container_id,
                                       "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False})
            raise TimeoutError("parallel worker remains live; reconcile the same container, never restart it")
        time.sleep(5)


def _write_progress(campaign_root, phase, completed, required, active):
    progress_path = campaign_root / "parallel-campaign.progress.private.json"
    current = read_private(progress_path)
    key = "completed_fits" if phase == "fit" else "completed_validations"
    required_key = "required_fits" if phase == "fit" else "required_validations"
    write_private(progress_path, {**current, "status": "RUNNING", "phase": phase,
                                  key: completed, required_key: required,
                                  "active_run_ids": sorted(active), "quality_gate": "NOT_RUN",
                                  "holdout_scored": False, "aws_changed": False,
                                  "updated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


def _run_phase(legacy, campaign_root, identity, plan, phase):
    if phase not in {"fit", "validation"}:
        raise ValueError("parallel phase must be fit or validation")
    if phase == "validation":
        fit_progress = json.loads((plan.dataset / "hybrid-campaign.progress.json").read_text(encoding="utf-8"))
        if fit_progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or fit_progress.get("actual_fits_completed") != 360:
            raise ValueError("all 360 verified fits must finish before parallel validation")
    runs = plan.protocol["campaign"]
    run_ids = [run["run_id"] for run in runs]
    if len(run_ids) != 360 or len(set(run_ids)) != 360:
        raise ValueError("exact 360 approved unique run IDs required")
    plan.require_headroom(plan.dataset, plan.unit_budgets()[phase] * identity["resource_policy"]["workers"])
    state_dir = private_dir(campaign_root / "state" / phase, create=True)
    succeeded = set()
    resume_by_worker = {worker: [] for worker in range(identity["resource_policy"]["workers"])}
    pending = []
    for run_id in run_ids:
        path = state_dir / f"{run_id}.private.json"
        if path.exists():
            state = read_private(path)
            if state.get("campaign_id") != identity["campaign_id"] or state.get("phase") != phase or state.get("run_id") != run_id:
                raise ValueError("parallel worker state binding mismatch")
            if state.get("status") == "SUCCEEDED":
                receipt = _verify_receipt(plan, phase, run_id)
                if (receipt is None or receipt.get("status") != ("FITTED_CALIBRATED" if phase == "fit" else "VALIDATED")
                        or digest_file(_receipt_path(plan, phase, run_id)) != state.get("receipt_sha256")):
                    raise ValueError("successful parallel receipt changed")
                succeeded.add(run_id)
            elif state.get("status") in {"DISPATCH_INTENT", "RUNNING", "OBSERVATION_TIMEOUT"}:
                worker = state.get("worker_id")
                if type(worker) is not int or worker not in resume_by_worker:
                    raise ValueError("retained parallel worker slot is outside the frozen worker count")
                resume_by_worker[worker].append(run_id)
            else:
                raise ValueError("failed/unknown parallel worker requires diagnosis; automatic retry is disabled")
        else:
            receipt = _verify_receipt(plan, phase, run_id)
            if receipt is not None:
                complete_status = "FITTED_CALIBRATED" if phase == "fit" else "VALIDATED"
                if receipt.get("status") == complete_status:
                    receipt_sha = digest_file(_receipt_path(plan, phase, run_id))
                    write_private(path, {"campaign_id": identity["campaign_id"], "phase": phase, "run_id": run_id,
                                         "worker_id": 0, "status": "SUCCEEDED", "receipt_sha256": receipt_sha,
                                         "container_name": None, "container_id": None, "recovered_from_receipt": True,
                                         "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False})
                    succeeded.add(run_id)
                elif phase == "fit" and receipt.get("status") == "RECOVERABLE_CALIBRATION":
                    pending.append(run_id)
                else:
                    raise ValueError("retained receipt is neither complete nor a verified calibration recovery")
            else:
                pending.append(run_id)
    for worker, tasks in resume_by_worker.items():
        if len(tasks) > 1:
            raise ValueError("multiple unfinished tasks bound to the same worker slot; reconcile one at a time")
    completed = len(succeeded)
    progress_lock = threading.Lock()
    active = set()
    stop = threading.Event()
    task_cursor = 0
    task_lock = threading.Lock()
    errors = []
    def take_task():
        nonlocal task_cursor
        with task_lock:
            if task_cursor >= len(pending): return None
            value = pending[task_cursor]
            task_cursor += 1
            return value
    def worker_loop(worker_id):
        nonlocal completed
        assigned = list(resume_by_worker[worker_id])
        while not stop.is_set():
            run_id = assigned.pop(0) if assigned else take_task()
            if run_id is None: return
            with progress_lock:
                active.add(run_id)
                _write_progress(campaign_root, phase, completed, 360, active)
            try:
                _execute_one(plan, campaign_root, identity, phase, worker_id, run_id)
            except BaseException as error:
                with progress_lock:
                    active.discard(run_id)
                    errors.append((run_id, type(error).__name__, str(error)))
                    stop.set()
                    _write_progress(campaign_root, phase, completed, 360, active)
                return
            with progress_lock:
                active.discard(run_id)
                completed += 1
                _write_progress(campaign_root, phase, completed, 360, active)
                print(f"PARALLEL {phase.upper()} {completed}/360 {run_id}; worker={worker_id}; quality NOT_RUN", flush=True)
    with ThreadPoolExecutor(max_workers=identity["resource_policy"]["workers"]) as executor:
        futures = [executor.submit(worker_loop, worker) for worker in range(identity["resource_policy"]["workers"])]
        for future in futures:
            future.result()
    if errors:
        run_id, error_type, message = errors[0]
        raise RuntimeError(f"parallel {phase} stopped at {run_id}: {error_type}: {message}")
    if completed != 360:
        raise ValueError(f"parallel {phase} completed {completed}/360 tasks")
    return completed


def _run_finalizer(plan, identity, phase, campaign_root):
    legacy = load_legacy_operator()
    if phase == "fit":
        module, command = "app.strict_campaign", ["search"]
    elif phase == "validation":
        module, command = "app.selection", ["validate"]
    else:
        raise ValueError("known finalizer phase required")
    name = f"flare-ph-{identity['campaign_id'][:8]}-{phase}-verify-{uuid.uuid4().hex[:8]}"
    dataset = plan.dataset
    workspace = plan.workspace
    args = ["--dataset", "/source/standard", "--model-kind", "normal_plus_incident_research",
            "--dataset-sha256", plan.identity["dataset_sha256"], "--archive-sha256", plan.identity["archive_sha256"],
            "--coordinated"]
    if phase == "validation": args.extend(["--workspace", "/workspace"])
    command_line = ["docker", "run", "--rm", "--name", name, "--network", "none", "--user", "1000:1000",
                    "--memory", "2g", "--cpus", "1", "--pids-limit", "128", "--entrypoint", "python",
                    "--label", "flare.parallel.identity=" + identity["campaign_id"],
                    "--label", "flare.parallel.phase=" + phase + "-verify",
                    "-v", str(plan.code) + ":/code:ro", "-v", str(dataset.parent) + ":/source:rw",
                    "-v", str(workspace) + ":/workspace:ro", "-v", str(workspace) + ":" + str(workspace) + ":ro",
                    "-w", "/code", "-e", "PYTHONPATH=/code", "-e", "PYTHONDONTWRITEBYTECODE=1",
                    "-e", "PYTHONPYCACHEPREFIX=/tmp/parallel-finalizer-bytecode", "-e", "OPENBLAS_NUM_THREADS=1",
                    "-e", "OMP_NUM_THREADS=1", plan.image, "-B", "-m", module, *command, *args]
    result = subprocess.run(command_line, capture_output=True, text=True, timeout=7200)
    _save_log(campaign_root, phase + "-verify", name, result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"parallel {phase} receipt finalization failed; verifier output retained")
    if phase == "fit":
        progress = json.loads((dataset / "hybrid-campaign.progress.json").read_text(encoding="utf-8"))
        if progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or progress.get("actual_fits_completed") != 360:
            raise ValueError("parallel fit finalizer did not prove all 360 fits")
        records = legacy.hybrid_records(plan)
        expected_prior_validations = ((identity.get("serial_resume_import") or {}).get("validation_count", 0))
        if (records["counts"]["actual_fits_completed"] != 360
                or records["counts"]["validation_runs_completed"] != expected_prior_validations):
            raise ValueError("metadata-only parallel fit audit count mismatch")
    else:
        progress = json.loads((dataset / "hybrid-validation.progress.json").read_text(encoding="utf-8"))
        ranking = json.loads((dataset / "hybrid-ranking.json").read_text(encoding="utf-8"))
        if (progress.get("status") != "COMPLETED" or progress.get("completed_runs") != 360
                or ranking.get("validation_runs_completed") != 360 or ranking.get("data_provenance") != "DEMO_ONLY"):
            raise ValueError("parallel validation finalizer did not produce the complete DEMO_ONLY ranking")
        records = legacy.hybrid_records(plan)
        if (records["counts"]["actual_fits_completed"] != 360
                or records["counts"]["validation_runs_completed"] != 360):
            raise ValueError("metadata-only parallel fit/validation audit count mismatch")


def run_campaign(campaign_root: Path, phase="all"):
    legacy, campaign_root, identity, plan = load_campaign(campaign_root)
    if phase not in {"all", "fit", "validation"}:
        raise ValueError("phase must be all, fit, or validation")
    lock_path = campaign_root / "state" / "parallel-campaign.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another parallel coordinator already owns this campaign") from None
        progress_path = campaign_root / "parallel-campaign.progress.private.json"
        progress = read_private(progress_path)
        if phase in ("fit", "all"):
            if progress.get("fit_phase") != "COMPLETED":
                write_private(progress_path, {**progress, "status": "RUNNING", "phase": "fit",
                                               "quality_gate": "NOT_RUN", "holdout_scored": False})
                _run_phase(legacy, campaign_root, identity, plan, "fit")
                _run_finalizer(plan, identity, "fit", campaign_root)
                progress = {**read_private(progress_path), "status": "RUNNING", "phase": "fit",
                            "fit_phase": "COMPLETED", "completed_fits": 360,
                            "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
                write_private(progress_path, progress)
            if phase == "fit":
                return progress
        if phase in ("validation", "all"):
            fit_progress = json.loads((plan.dataset / "hybrid-campaign.progress.json").read_text(encoding="utf-8"))
            if fit_progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or fit_progress.get("actual_fits_completed") != 360:
                raise ValueError("all 360 parallel fits must finish before validation")
            if progress.get("validation_phase") != "COMPLETED":
                write_private(progress_path, {**progress, "status": "RUNNING", "phase": "validation",
                                               "quality_gate": "NOT_RUN", "holdout_scored": False})
                _run_phase(legacy, campaign_root, identity, plan, "validation")
                _run_finalizer(plan, identity, "validation", campaign_root)
                progress = {**read_private(progress_path), "status": "RUNNING", "phase": "validation",
                            "validation_phase": "COMPLETED", "completed_validations": 360,
                            "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
                write_private(progress_path, progress)
        if phase == "all":
            complete = {**read_private(progress_path), "status": "PARALLEL_FIT_VALIDATION_COMPLETE",
                        "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
            write_private(progress_path, complete)
            return complete
        return read_private(progress_path)


def _coordinator_is_alive(pid, campaign_root):
    if type(pid) is not int or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace")
    except (OSError, ProcessLookupError):
        return False
    return str(Path(__file__).resolve()) in command and str(Path(campaign_root).absolute()) in command


def launch_campaign(campaign_root: Path, phase="all"):
    _, campaign_root, identity, _ = load_campaign(campaign_root)
    if phase not in {"all", "fit", "validation"}:
        raise ValueError("phase must be all, fit, or validation")
    pid_path = campaign_root / "state" / "coordinator.private.json"
    if pid_path.exists():
        previous = read_private(pid_path)
        if previous.get("campaign_id") != identity["campaign_id"]:
            raise ValueError("coordinator PID is bound to another campaign")
        if _coordinator_is_alive(previous.get("pid"), campaign_root):
            return {"status": "ALREADY_RUNNING", "pid": previous["pid"],
                    "campaign_id": identity["campaign_id"], "phase": previous.get("phase")}
    log_path = campaign_root / "logs" / "parallel-coordinator.log"
    if log_path.exists():
        info = log_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("coordinator log must be an owner-only single-link file")
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    host_env = {key: os.environ[key] for key in
                ("PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "HOME", "LANG", "LC_ALL")
                if key in os.environ}
    host_env["PYTHONUNBUFFERED"] = "1"
    command = [sys.executable, str(Path(__file__).resolve()), "run", "--campaign-root", str(campaign_root), "--phase", phase]
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd,
                                   close_fds=True, start_new_session=True, env=host_env)
    finally:
        os.close(log_fd)
    state = {"campaign_id": identity["campaign_id"], "pid": process.pid, "phase": phase,
             "status": "RUNNING", "controller_sha256": identity["controller_sha256"],
             "started_at_utc": utc_now()}
    write_private(pid_path, state)
    return {"status": "LAUNCHED", "pid": process.pid, "campaign_id": identity["campaign_id"], "phase": phase,
            "log_path": str(log_path)}


def campaign_status(campaign_root: Path):
    _, campaign_root, identity, plan = load_campaign(campaign_root)
    progress = read_private(campaign_root / "parallel-campaign.progress.private.json")
    pid_path = campaign_root / "state" / "coordinator.private.json"
    coordinator = read_private(pid_path) if pid_path.exists() else None
    progress = {key: value for key, value in progress.items() if key != "preflight"}
    return {"campaign_id": identity["campaign_id"], "campaign_type": identity["campaign_type"],
            "progress": progress, "legacy_reference": identity["legacy_campaign_reference"],
            "serial_resume_import": identity.get("serial_resume_import"),
            "parallel_recovery_imports": identity.get("parallel_recovery_imports", []),
            "coordinator_alive": bool(coordinator and _coordinator_is_alive(coordinator.get("pid"), campaign_root)),
            "coordinator_pid": coordinator.get("pid") if coordinator else None,
            "quality_gate": progress.get("quality_gate", "NOT_RUN"),
            "holdout_scored": progress.get("holdout_scored", False), "aws_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    prepare.add_argument("--campaign-root", type=Path)
    prepare.add_argument("--code-source", type=Path, default=DEFAULT_CODE_SOURCE)
    prepare.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    prepare.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    prepare.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB)
    prepare.add_argument("--cpu-per-worker", choices=("1.0", "1.5", "2.0"), default=DEFAULT_CPU)
    prepare.add_argument("--recover-from", type=Path,
                         help="reconcile fit-complete/calibration-pending runs from an interrupted compatible parallel campaign")
    prepare.add_argument("--resume-from", type=Path,
                         help="resume verified completed fits/validations from a stopped compatible serial campaign")
    prepare.add_argument("--resume-code-source", type=Path,
                         help="archived frozen app source used by the serial campaign; defaults to the pinned local copy")
    prepare.add_argument("--reference", default="User authorized transition to parallel campaign")
    run = sub.add_parser("run")
    run.add_argument("--campaign-root", type=Path, required=True)
    run.add_argument("--phase", choices=("fit", "validation", "all"), default="all")
    launch = sub.add_parser("launch")
    launch.add_argument("--campaign-root", type=Path, required=True)
    launch.add_argument("--phase", choices=("fit", "validation", "all"), default="all")
    status = sub.add_parser("status")
    status.add_argument("--campaign-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            result = prepare_campaign(args.source_root, args.campaign_root, args.code_source,
                                      args.workspace, args.workers, args.memory_mib,
                                      args.cpu_per_worker, args.reference, args.recover_from,
                                      args.resume_from, args.resume_code_source)
        elif args.action == "run":
            result = run_campaign(args.campaign_root, args.phase)
        elif args.action == "launch":
            result = launch_campaign(args.campaign_root, args.phase)
        else:
            result = campaign_status(args.campaign_root)
        print(canonical(result), flush=True)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"parallel campaign refused; immutable campaign data retained ({type(error).__name__})") from None


if __name__ == "__main__": main()
