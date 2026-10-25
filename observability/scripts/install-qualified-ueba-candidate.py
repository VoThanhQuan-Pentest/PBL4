#!/usr/bin/env python3
"""Package and install the exact selected strict candidate without refitting.

``package`` runs in the pinned local recovery environment. ``install`` runs as
the UEBA worker UID in an isolated pinned image with a read-only package mount
and only the model-data volume writable. Neither command changes the primary.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
WORKER_ROOT = ROOT / "ueba-worker"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
RESERVE = 5_000_000_000
MAX_DOCUMENT = 8 * 1024 * 1024
MAX_MODEL = 128 * 1024 * 1024
MAX_JOURNAL = 8 * 1024 ** 3
SHA = re.compile(r"[a-f0-9]{64}")
VERSION = re.compile(r"[a-z0-9_-]{8,64}")
PACKAGE_FIELDS = {"format", "schema_version", "status", "model_version", "data_provenance", "quality_gate",
    "feature_schema_version", "recipe_id", "original_dataset_id", "original_training_manifest_sha256",
    "selection_receipt_sha256", "fresh_holdout_dataset_id", "fresh_holdout_manifest_sha256",
    "holdout_split_sha256", "model_sha256", "model_state_sha256", "calibration_sha256", "policy_sha256",
    "artifact_sha256", "selection_proof", "strict_reference"}
ARTIFACT_KEYS = {"joblib", "metadata", "evaluation", "evaluation_identity", "metrics"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def parse_document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate package metadata key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite package metadata")))


def private_path(path, *, owner=None, modes=(0o600,), maximum_links=1, maximum=MAX_DOCUMENT):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical nonsymlink package path required")
    value = path.lstat()
    expected_owner = os.geteuid() if owner is None else owner
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != expected_owner
            or stat.S_IMODE(value.st_mode) not in modes or not 0 < value.st_size <= maximum
            or not 1 <= value.st_nlink <= maximum_links):
        raise ValueError("bounded owner-controlled regular package file required")
    return path, value


def private_json(path, *, expected_sha=None, owner=None, modes=(0o600,), maximum=MAX_DOCUMENT):
    path, before = private_path(path, owner=owner, modes=modes, maximum=maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(current) != signature(before):
            raise ValueError("package proof changed before read")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or signature(after) != signature(before)
                or signature(path.lstat()) != signature(before)):
            raise ValueError("package proof changed during read")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha is not None and digest != expected_sha:
        raise ValueError("package proof checksum mismatch")
    return digest, parse_document(raw)


def stream_sha(path, *, maximum):
    path, before = private_path(path, maximum=maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        initial = os.fstat(source.fileno())
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(initial) != signature(before):
            raise ValueError("artifact changed before package copy")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
        if signature(os.fstat(source.fileno())) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError("artifact changed while hashing")
    return digest.hexdigest(), before.st_size


def validate_fresh_holdout_manifest(manifest_sha, manifest):
    """Require the exact post-selection DEMO_ONLY evaluation population."""
    if not isinstance(manifest_sha, str) or not SHA.fullmatch(manifest_sha) or not isinstance(manifest, dict):
        raise ValueError("checksum-bound fresh holdout manifest required")
    holdout = manifest.get("splits", {}).get("holdout")
    if (manifest.get("data_provenance") != "DEMO_ONLY"
            or not isinstance(manifest.get("dataset_id"), str) or not manifest["dataset_id"]
            or not isinstance(holdout, dict)
            or holdout.get("normal") != 10_000_000
            or holdout.get("positive") != 10_000
            or not isinstance(holdout.get("sha256"), str)
            or not SHA.fullmatch(holdout["sha256"])):
        raise ValueError("exact DEMO_ONLY fresh holdout populations and split identity required")
    return holdout


def require_verified_holdout_quality(evaluation, expected_population=10_010_000):
    """Consume the evaluation document returned by verify_quality and enforce acceptance metrics."""
    if (not isinstance(evaluation, dict) or evaluation.get("status") != "SUCCEEDED"
            or evaluation.get("quality_gate") != "PASS"
            or evaluation.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or evaluation.get("actual_scored_episodes") != expected_population):
        raise ValueError("verified fresh holdout quality result and population required")
    scopes = evaluation.get("scopes")
    if not isinstance(scopes, dict) or set(scopes) != {"MODEL_ONLY", "SIEM_FINAL"}:
        raise ValueError("both verified quality scopes are required")
    for name, scope in scopes.items():
        if not isinstance(scope, dict) or scope.get("quality_gate") != "PASS":
            raise ValueError("every verified quality scope must pass")
        counters = [scope.get(key) for key in ("tp", "fn", "fp", "tn")]
        if any(type(value) is not int or value < 0 for value in counters) or sum(counters) != expected_population:
            raise ValueError("verified scope confusion counters must cover the exact holdout population")
        accuracy = (scope["tp"] + scope["tn"]) / expected_population
        if accuracy <= 0.98:
            raise ValueError("strict scope accuracy did not exceed the accepted threshold: " + name)
    return expected_population


def write_new(path, raw, *, mode=0o600, gid=None):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        if gid is not None and os.getgid() != gid:
            os.fchown(descriptor, os.geteuid(), gid)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def copy_exact(source, destination, expected_sha, *, maximum, mode=0o640, gid=1000, bundle=False):
    source = package_file(source, maximum) if bundle else private_path(source, maximum=maximum)[0]
    before = source.lstat()
    if not SHA.fullmatch(expected_sha):
        raise ValueError("explicit artifact checksum required")
    target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    digest = hashlib.sha256()
    try:
        if os.getgid() != gid:
            os.fchown(target_fd, os.geteuid(), gid)
        os.fchmod(target_fd, mode)
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(source_fd, "rb") as origin, os.fdopen(target_fd, "wb") as target:
            signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if signature(os.fstat(origin.fileno())) != signature(before):
                raise ValueError("artifact changed before copy")
            for block in iter(lambda: origin.read(1024 * 1024), b""):
                digest.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
            if signature(os.fstat(origin.fileno())) != signature(before) or signature(source.lstat()) != signature(before):
                raise ValueError("artifact changed during copy")
        if digest.hexdigest() != expected_sha:
            raise ValueError("copied artifact differs from its pinned checksum")
        destination.chmod(mode)
        return before.st_size
    except Exception:
        try:
            os.close(target_fd)
        except OSError:
            pass
        raise


def package_candidate(*, source, fresh_holdout, workspace, receipt_path, receipt_sha,
                      manifest_sha, output, allow_package):
    if allow_package is not True:
        raise ValueError("explicit package authorization flag required")
    from app import fresh_holdout_recovery as recovery
    from app.frozen_evaluation import model_binding
    from app.hybrid_strict_dataset import validate_standard_manifest
    from app.model import ModelStore
    from app.policy import ScorePolicy
    from app.quality_proof import verify_quality

    if os.geteuid() != 1000 or os.getgid() != 1000 or os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE:
        raise ValueError("pinned UID-1000 package builder required")
    recovery.require_execution_environment()
    source = recovery.private_directory(source)
    workspace = recovery.checked_path(workspace)
    output = recovery.checked_path(output)
    recovery.require_separate_location(output, source, file=False)
    recovery.private_directory(output.parent)
    receipt = recovery.load_frozen_receipt(receipt_path, receipt_sha)
    recovery.verify_frozen_receipt(receipt, source, workspace, receipt_path=receipt_path)
    fresh_root = recovery.private_directory(fresh_holdout)
    manifest_sha_actual, manifest = recovery.private_read(fresh_root / "manifest.json", recovery.MAX_MANIFEST_BYTES)
    if manifest_sha_actual != manifest_sha or manifest.get("dataset_id") is None:
        raise ValueError("fresh post-selection manifest pin differs")
    recovery.require_unblocked_holdout(fresh_root)
    selected = receipt["selection"]
    version = selected["model_version"]
    if not VERSION.fullmatch(version) or output.exists() or output.is_symlink():
        raise ValueError("new exact selected-version package path required")
    result_sha, result = recovery.private_read(fresh_root / "fresh-holdout-result.json", 4 * 1024 * 1024)
    if (result.get("status") != "SUCCEEDED" or result.get("quality_gate") != "PASS"
            or result.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or result.get("model_version") != version or result.get("model_sha256") != selected["model_sha256"]
            or result.get("data_provenance") != "DEMO_ONLY"
            or result.get("actual_scored_episodes") != 10_010_000):
        raise ValueError("complete fresh holdout PASS result bound to selected model required")
    holdout = validate_fresh_holdout_manifest(manifest_sha_actual, manifest)
    source_manifest_sha = receipt["source"]["manifest_sha256"]
    original_manifest_sha, original_manifest = recovery.private_read(
        source / "manifest.json", recovery.MAX_MANIFEST_BYTES, maximum_links=2)
    validate_standard_manifest(original_manifest, receipt["source"]["dataset_id"])
    if original_manifest_sha != source_manifest_sha:
        raise ValueError("original training manifest identity changed")
    store = ModelStore(source / "hybrid-models")
    metadata, payload = store.load_candidate(version)
    policy = ScorePolicy.from_wire(selected["policy"])
    binding = model_binding(metadata, policy)
    if (binding.get("model_sha256") != selected["model_sha256"]
            or binding.get("dataset_sha256") != source_manifest_sha
            or binding.get("calibration_sha256") != selected["calibration_sha256"]
            or selected.get("holdout_scored") is not False):
        raise ValueError("frozen selected artifact or original training binding changed")
    evidence_dir = recovery.private_directory(fresh_root / "evidence")
    evaluation_path = evidence_dir / f"{version}.evaluation.json"
    identity_path = evidence_dir / f"{version}.evaluation-identity.json"
    journal_path = evidence_dir / f"{version}.metrics.sqlite"
    evaluation_sha, evaluation = recovery.private_read(evaluation_path, 4 * 1024 * 1024)
    identity_sha, identity = recovery.private_read(identity_path, 4 * 1024 * 1024)
    journal_sha, journal_bytes = stream_sha(journal_path, maximum=MAX_JOURNAL)
    verified_evaluation = verify_quality(evidence_dir, version, policy, binding)
    verified_rows = require_verified_holdout_quality(verified_evaluation)
    if (verified_rows != 10_010_000 or verified_evaluation != evaluation
            or evaluation.get("evaluation_identity") != identity
            or identity.get("fresh_holdout_manifest_sha256") != manifest_sha_actual
            or identity.get("holdout_split_sha256") != holdout["sha256"]
            or identity.get("frozen_selection_receipt_sha256") != receipt_sha
            or identity.get("original_training_manifest_sha256") != source_manifest_sha
            or evaluation.get("scored_journal_sha256") != journal_sha
            or result.get("scored_journal_sha256") != journal_sha):
        raise ValueError("fresh report, evidence, recovery receipt or actual scored journal binding differs")
    if output.exists() or output.is_symlink():
        raise ValueError("candidate package destination already exists")
    source_files = {
        "joblib": (store.directory / f"{version}.joblib", MAX_MODEL),
        "metadata": (store.directory / f"{version}.json", 4 * 1024 * 1024),
        "evaluation": (evaluation_path, 4 * 1024 * 1024),
        "evaluation_identity": (identity_path, 4 * 1024 * 1024),
        "metrics": (journal_path, MAX_JOURNAL),
    }
    planned_copy_bytes = sum(private_path(path, maximum=limit)[1].st_size
                             for path, limit in source_files.values())
    if shutil.disk_usage(output.parent).free < planned_copy_bytes + RESERVE:
        raise ValueError("source package volume lacks exact copy bytes plus fixed 5GB reserve")
    output.mkdir(mode=0o700)
    gid = os.getgid()
    files = {"joblib": (source_files["joblib"][0], selected["model_sha256"], source_files["joblib"][1]),
        "metadata": (source_files["metadata"][0], recovery.code_sha256(source_files["metadata"][0]), source_files["metadata"][1]),
        "evaluation": (evaluation_path, evaluation_sha, source_files["evaluation"][1]),
        "evaluation_identity": (identity_path, identity_sha, source_files["evaluation_identity"][1]),
        "metrics": (journal_path, journal_sha, source_files["metrics"][1])}
    archive = {}
    for kind, (original, expected, maximum) in files.items():
        archive[kind] = {"name": original.name, "sha256": expected,
                         "bytes": copy_exact(original, output / original.name, expected, maximum=maximum, mode=0o640, gid=gid)}
    model_state = metadata.get("model_state_sha256")
    selection_proof = receipt["hybrid_proof"]
    recipe_id = source_manifest_sha and original_manifest["dataset_id"] + "-champion"
    selected_proof = receipt["selection"]
    source_labels = selection_proof["source_label_manifests"]
    strict_reference = {"recipe_id": recipe_id, "dataset_id": original_manifest["dataset_id"],
        "data_provenance": "DEMO_ONLY", "feature_schema_version": 4,
        "training_windows": 50000, "calibration_windows": 2000000,
        "from_utc": original_manifest["splits"]["fold3-fit"]["from"],
        "to_utc": original_manifest["splits"]["fold3-fit"]["to"],
        "completed_search_fits": 360, "manifest_sha256": source_manifest_sha,
        "policy_sha256": selected_proof["policy_sha256"],
        "blocked_holdout_split_sha256": receipt["source"]["blocked_holdout_split_sha256"],
        "selected_model_sha256": selected_proof["model_sha256"],
        "selected_calibration_sha256": selected_proof["calibration_sha256"],
        "model_state_sha256": selected_proof["model_state_sha256"],
        "model_state_verifier_sha256": selected_proof["model_state_verifier_sha256"],
        "model_state_format": selected_proof["model_state_format"],
        "model_kind": selected_proof["model_kind"], "recipe_version": selected_proof["recipe_version"],
        "fold": 3, "random_state": 42,
        "recipe_sha256": selected_proof["recipe_sha256"],
        "strict_proof_sha256": selection_proof["proof_sha256"],
        "selection_sha256": receipt["selection_sha256"],
        "source_label_manifest_sha256_by_fold": {fold: value["manifest_sha256"]
            for fold, value in source_labels.items()},
        "zero_fit_recalibrations": selection_proof["zero_fit_recalibrations"]}
    proof = {"format": "UEBA_QUALIFIED_ADOPTION_PACKAGE_V1", "schema_version": 1, "status": "READY",
        "model_version": version, "data_provenance": "DEMO_ONLY", "quality_gate": "PASS", "feature_schema_version": 4,
        "recipe_id": recipe_id, "original_dataset_id": original_manifest["dataset_id"],
        "original_training_manifest_sha256": source_manifest_sha,
        "selection_receipt_sha256": receipt["selection_sha256"],
        "fresh_holdout_dataset_id": manifest["dataset_id"], "fresh_holdout_manifest_sha256": manifest_sha_actual,
        "holdout_split_sha256": manifest["splits"]["holdout"]["sha256"], "model_sha256": metadata["sha256"],
        "model_state_sha256": model_state, "calibration_sha256": metadata["calibration_sha256"],
        "policy_sha256": policy.sha256, "artifact_sha256": {key: value["sha256"] for key, value in archive.items()},
        "selection_proof": {"actual_composite_trials": selection_proof["actual_composite_trials"],
            "actual_component_fit_calls": selection_proof["actual_component_fit_calls"],
            "validation_runs": selection_proof["validation_runs"],
            "zero_fit_recalibrations": selection_proof["zero_fit_recalibrations"], "holdout_scored": False},
        "strict_reference": strict_reference}
    manifest_raw = canonical(proof).encode()
    write_new(output / "candidate-package.json", manifest_raw, mode=0o640, gid=gid)
    os.chmod(output, 0o750)
    digest = hashlib.sha256(manifest_raw).hexdigest()
    return {"status": "PACKAGED", "model_version": version, "package_directory": str(output),
            "package_manifest_sha256": digest, "artifact_bytes": sum(value["bytes"] for value in archive.values()),
            "free_bytes_after": shutil.disk_usage(output).free, "data_provenance": "DEMO_ONLY", "aws_changed": False}


def package_file(path, maximum):
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("candidate package path cannot contain symlinks")
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 1000 or value.st_gid != 1000
            or stat.S_IMODE(value.st_mode) != 0o640 or value.st_nlink != 1 or not 0 < value.st_size <= maximum):
        raise ValueError("group-readable package file with pinned owner/mode required")
    return path


def package_sha(path, maximum):
    path = package_file(path, maximum)
    before = path.lstat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if signature(before) != signature(after) or signature(before) != signature(path.lstat()):
        raise ValueError("candidate package changed during checksum")
    return digest.hexdigest()


def worker_file_sha(path, maximum, *, links=(1,)):
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("worker artifact path cannot contain symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink not in links
                or not 1 <= before.st_size <= maximum):
            raise ValueError("private worker artifact with known hardlink count required")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(before) != signature(os.fstat(stream.fileno())) or signature(before) != signature(path.lstat()):
            raise ValueError("worker artifact changed while hashing")
    return digest.hexdigest()


def worker_json(path, maximum):
    _, document = private_json(path, owner=os.geteuid(), modes=(0o600,), maximum=maximum)
    return document


def fsync_directory(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install_candidate(package_directory, *, allow_install):
    if allow_install is not True or os.geteuid() != 10001 or os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE:
        raise ValueError("explicit pinned worker-UID installation required")
    directory = Path(package_directory).absolute()
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
            or stat.S_IMODE(info.st_mode) != 0o750 or any(item.is_symlink() for item in (directory, *directory.parents))):
        raise ValueError("private read-only selected-candidate package directory required")
    package_path = package_file(directory / "candidate-package.json", 2 * 1024 * 1024)
    package_sha, package = private_json(package_path, owner=1000, modes=(0o640,), maximum=2 * 1024 * 1024)
    if set(package) != PACKAGE_FIELDS or package.get("format") != "UEBA_QUALIFIED_ADOPTION_PACKAGE_V1" or package.get("status") != "READY":
        raise ValueError("exact strict selected-candidate package manifest required")
    version = package.get("model_version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("valid selected model version required")
    artifacts = package.get("artifact_sha256")
    if not isinstance(artifacts, dict) or set(artifacts) != ARTIFACT_KEYS or any(
            not isinstance(value, str) or not SHA.fullmatch(value) for value in artifacts.values()):
        raise ValueError("complete checksum-bound model/evaluation artifact set required")
    names = {"joblib": f"{version}.joblib", "metadata": f"{version}.json",
             "evaluation": f"{version}.evaluation.json", "evaluation_identity": f"{version}.evaluation-identity.json",
             "metrics": f"{version}.metrics.sqlite"}
    package_files = {item.name for item in directory.iterdir()}
    if package_files != {"candidate-package.json", *names.values()}:
        raise ValueError("candidate package contains missing or unapproved files")
    for key, name in names.items():
        path = package_file(directory / name, MAX_JOURNAL if key == "metrics" else MAX_MODEL if key == "joblib" else MAX_DOCUMENT)
        if package_sha(path, MAX_JOURNAL if key == "metrics" else MAX_MODEL if key == "joblib" else MAX_DOCUMENT) != artifacts[key]:
            raise ValueError("candidate package artifact checksum mismatch")

    from app.frozen_evaluation import model_binding
    from app.model import ModelStore
    from app.policy import ScorePolicy
    from app.quality_proof import verify_quality
    store = ModelStore(Path(os.environ.get("UEBA_MODEL_DIR", "/var/lib/ueba")))
    os.environ["UEBA_MODEL_DIR"] = str(store.directory)
    store_info = store.directory.lstat()
    if (not stat.S_ISDIR(store_info.st_mode) or store_info.st_uid != os.geteuid()
            or store_info.st_mode & 0o022):
        raise ValueError("owner-controlled worker model volume required")
    lock_path = store.directory / ".operator-adoption.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    staging = None
    try:
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600 or lock_info.st_nlink != 1):
            raise ValueError("private candidate installation lock required")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operator_directory = store.directory / "operator-adoptions"
        operator_directory.mkdir(mode=0o700, exist_ok=True)
        operator_info = operator_directory.lstat()
        if (not stat.S_ISDIR(operator_info.st_mode) or operator_info.st_uid != os.geteuid()
                or stat.S_IMODE(operator_info.st_mode) != 0o700):
            raise ValueError("worker operator-adoption directory must be private")
        receipt_path = operator_directory / f"{version}.private.json"
        if receipt_path.exists() or receipt_path.is_symlink():
            receipt = worker_json(receipt_path, 1024 * 1024)
            if (receipt.get("format") != "UEBA_QUALIFIED_ADOPTION_V1"
                    or receipt.get("package_manifest_sha256") != package_sha
                    or receipt.get("artifact_sha256") != artifacts):
                raise ValueError("existing worker adoption receipt conflicts with this package")
            metadata, _ = store.load_candidate(version)
            policy = ScorePolicy.from_wire(metadata["score_policy"])
            verify_quality(store.directory, version, policy, model_binding(metadata, policy))
            return {"status": "ALREADY_INSTALLED", "model_version": version,
                    "adoption_receipt_sha256": worker_file_sha(receipt_path, 1024 * 1024),
                    "package_manifest_sha256": package_sha, "quality_gate": "PASS",
                    "data_provenance": "DEMO_ONLY"}
        intent_path = operator_directory / f"{version}.install.private.json"

        primary_before = {"model_version": store.active_version, "model_sha256": None}
        if store.active_version is not None:
            previous, _ = store.load_candidate(store.active_version)
            primary_before["model_sha256"] = previous["sha256"]
        version_files = [store.directory / name for name in names.values()]
        root_present = [path.exists() or path.is_symlink() for path in version_files]
        staging = store.directory / f".adoption-stage-{version}"
        if any(root_present) and not all(root_present) and not intent_path.exists():
            raise ValueError("unreceipted partial candidate publication requires inspection")

        intent = {"format": "UEBA_CANDIDATE_INSTALL_INTENT_V1", "model_version": version,
            "package_manifest_sha256": package_sha, "artifact_sha256": artifacts,
            "primary_before": primary_before}
        if intent_path.exists() or intent_path.is_symlink():
            previous_intent = worker_json(intent_path, 1024 * 1024)
            if previous_intent != intent:
                raise ValueError("existing install intent differs from package or primary binding")
        else:
            write_new(intent_path, canonical(intent).encode(), mode=0o600)
            fsync_directory(operator_directory)

        if staging.exists() or staging.is_symlink():
            stage_info = staging.lstat()
            if (not stat.S_ISDIR(stage_info.st_mode) or stage_info.st_uid != os.geteuid()
                    or stat.S_IMODE(stage_info.st_mode) != 0o700):
                raise ValueError("bounded private adoption staging directory required")
        else:
            staging.mkdir(mode=0o700)
        allowed_stage = set(names.values()) | {"stage.private.json"} | {".incoming-" + key for key in names}
        if any(item.name not in allowed_stage or item.is_symlink() for item in staging.iterdir()):
            raise ValueError("unknown candidate staging member refused")
        stage_marker = staging / "stage.private.json"
        expected_marker = {"format": "UEBA_CANDIDATE_STAGE_V1", "model_version": version,
                           "package_manifest_sha256": package_sha, "artifact_sha256": artifacts}
        if stage_marker.exists():
            if worker_json(stage_marker, 1024 * 1024) != expected_marker:
                raise ValueError("existing staging marker differs from candidate package")
        else:
            write_new(stage_marker, canonical(expected_marker).encode(), mode=0o600)

        missing_bytes = 0
        staged_paths = {key: staging / name for key, name in names.items()}
        for key, name in names.items():
            staged = staged_paths[key]
            maximum = MAX_JOURNAL if key == "metrics" else MAX_MODEL if key == "joblib" else MAX_DOCUMENT
            if staged.exists():
                if worker_file_sha(staged, maximum) != artifacts[key]:
                    raise ValueError("staged candidate artifact checksum mismatch")
            else:
                destination = store.directory / name
                if destination.exists() and worker_file_sha(destination, maximum, links=(1, 2)) == artifacts[key]:
                    pass  # Recovery links a previous exact publication into the staging set below.
                else:
                    missing_bytes += package_file(directory / name, maximum).stat().st_size
        if not all(root_present) and shutil.disk_usage(store.directory).free < missing_bytes + RESERVE:
            raise ValueError("worker model volume lacks remaining copy bytes plus fixed 5GB reserve")
        for key, name in names.items():
            staged = staged_paths[key]; destination = store.directory / name
            maximum = MAX_JOURNAL if key == "metrics" else MAX_MODEL if key == "joblib" else MAX_DOCUMENT
            incoming = staging / (".incoming-" + key)
            if not staged.exists() and destination.exists():
                if worker_file_sha(destination, maximum, links=(1, 2)) != artifacts[key]:
                    raise ValueError("published candidate artifact differs from package")
                os.link(destination, staged, follow_symlinks=False)
                fsync_directory(staging)
            if staged.exists():
                continue
            if incoming.exists():
                try:
                    partial_sha = worker_file_sha(incoming, maximum)
                except ValueError:
                    incoming_info = incoming.lstat()
                    if (not stat.S_ISREG(incoming_info.st_mode) or incoming_info.st_uid != os.geteuid()
                            or stat.S_IMODE(incoming_info.st_mode) != 0o600 or incoming_info.st_nlink != 1):
                        raise ValueError("unrecognized interrupted artifact copy refused") from None
                    incoming.unlink(); fsync_directory(staging)
                    partial_sha = None
                if partial_sha == artifacts[key]:
                    os.replace(incoming, staged); fsync_directory(staging)
                    continue
            if incoming.exists() or incoming.is_symlink():
                raise ValueError("unexpected incomplete artifact copy remains")
            copy_exact(package_file(directory / name, maximum), incoming, artifacts[key],
                       maximum=maximum, mode=0o600, bundle=True, gid=os.getgid())
            os.replace(incoming, staged); fsync_directory(staging)

        meta = worker_json(staged_paths["metadata"], MAX_DOCUMENT)
        if (meta.get("model_version") != version or meta.get("sha256") != package["model_sha256"]
                or meta.get("feature_schema_version") != 4 or meta.get("calibration_scope") != "STRICT"
                or meta.get("dataset_manifest_sha256") != package["original_training_manifest_sha256"]
                or meta.get("calibration_sha256") != package["calibration_sha256"]):
            raise ValueError("selected training metadata differs from package proof")
        candidate_store = ModelStore(staging)
        loaded, _ = candidate_store.load_candidate(version)
        policy = ScorePolicy.from_wire(loaded["score_policy"])
        binding = model_binding(loaded, policy)
        if binding["model_sha256"] != package["model_sha256"] or binding["policy_sha256"] != package["policy_sha256"]:
            raise ValueError("candidate serving/calibration binding differs from the frozen package")
        verified_evaluation = verify_quality(staging, version, policy, binding)
        verified_count = require_verified_holdout_quality(verified_evaluation)
        if (verified_count != 10_010_000
                or package["selection_proof"].get("actual_composite_trials") != 360
                or package["selection_proof"].get("actual_component_fit_calls") != 720
                or package["selection_proof"].get("validation_runs") != 360
                or not 45 <= package["selection_proof"].get("zero_fit_recalibrations", 0) <= 360
                or package["selection_proof"].get("holdout_scored") is not False):
            raise ValueError("candidate must pass the complete verified strict selection and journal")
        # Hardlink publication is atomic per file and keeps enough recovery data in staging.
        for key in ("joblib", "evaluation", "evaluation_identity", "metrics", "metadata"):
            name = names[key]; staged = staged_paths[key]; destination = store.directory / name
            maximum = MAX_JOURNAL if key == "metrics" else MAX_MODEL if key == "joblib" else MAX_DOCUMENT
            if destination.exists():
                left, right = staged.lstat(), destination.lstat()
                if ((left.st_dev, left.st_ino) != (right.st_dev, right.st_ino)
                        or worker_file_sha(destination, maximum, links=(2,)) != artifacts[key]):
                    raise ValueError("previous candidate publication differs from verified stage")
            else:
                os.link(staged, destination, follow_symlinks=False)
                fsync_directory(store.directory)
        if ModelStore(store.directory).active_version != primary_before["model_version"]:
            raise ValueError("primary model changed while installing an inactive candidate")
        installed_store = ModelStore(store.directory)
        installed_metadata, _ = installed_store.load_candidate(version)
        if installed_metadata["sha256"] != package["model_sha256"]:
            raise ValueError("installed candidate readback differs from package")
        installed_policy = ScorePolicy.from_wire(installed_metadata["score_policy"])
        verify_quality(store.directory, version, installed_policy, model_binding(installed_metadata, installed_policy))
        # Remove only our private hardlink staging names after the exact worker-store copies pass readback.
        for name in names.values():
            staged = staging / name; destination = store.directory / name
            if staged.exists():
                left, right = staged.lstat(), destination.lstat()
                if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino) or left.st_nlink != 2:
                    raise ValueError("candidate staging hardlink identity changed")
                staged.unlink()
        fsync_directory(store.directory)
        staging.rmdir()
        fsync_directory(store.directory)
        # A final journal audit now sees single-link worker-owned files exactly as the running service will.
        installed_metadata, _ = ModelStore(store.directory).load_candidate(version)
        installed_policy = ScorePolicy.from_wire(installed_metadata["score_policy"])
        verify_quality(store.directory, version, installed_policy, model_binding(installed_metadata, installed_policy))
        operator_directory = store.directory / "operator-adoptions"
        operator_directory.mkdir(mode=0o700, exist_ok=True)
        operator_info = operator_directory.lstat()
        if (not stat.S_ISDIR(operator_info.st_mode) or operator_info.st_uid != os.geteuid()
                or stat.S_IMODE(operator_info.st_mode) != 0o700):
            raise ValueError("worker operator-adoption directory must be private")
        evaluation_identity = worker_json(store.directory / names["evaluation_identity"], MAX_DOCUMENT)
        receipt = {"format": "UEBA_QUALIFIED_ADOPTION_V1", "status": "CANDIDATE_INSTALLED",
            "model_version": version, "data_provenance": "DEMO_ONLY", "recipe_id": package["recipe_id"],
            "original_dataset_id": package["original_dataset_id"],
            "original_training_manifest_sha256": package["original_training_manifest_sha256"],
            "selection_receipt_sha256": package["selection_receipt_sha256"],
            "selected_reference_model_sha256": package["model_sha256"],
            "fresh_holdout_dataset_id": package["fresh_holdout_dataset_id"],
            "fresh_holdout_manifest_sha256": package["fresh_holdout_manifest_sha256"],
            "holdout_split_sha256": package["holdout_split_sha256"],
            "model_sha256": package["model_sha256"], "model_state_sha256": package["model_state_sha256"],
            "model_state_verifier_sha256": installed_metadata["model_state_verifier_sha256"],
            "model_state_format": installed_metadata["model_state_format"],
            "strict_reference": package["strict_reference"],
            "calibration_sha256": package["calibration_sha256"], "policy_sha256": package["policy_sha256"],
            "artifact_sha256": artifacts, "selection_proof": package["selection_proof"],
            "primary_before": primary_before, "package_manifest_sha256": package_sha,
            "producer_identity_sha256": evaluation_identity.get("producer_identity", {}).get("identity_sha256")}
        receipt_path = operator_directory / f"{version}.private.json"
        receipt_raw = canonical(receipt).encode()
        write_new(receipt_path, receipt_raw, mode=0o600)
        fsync_directory(operator_directory)
        receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
        # Read back all installed artifact/evidence files before returning the operator receipt.
        current = ModelStore(store.directory)
        installed_metadata, _ = current.load_candidate(version)
        installed_policy = ScorePolicy.from_wire(installed_metadata["score_policy"])
        verify_quality(store.directory, version, installed_policy, model_binding(installed_metadata, installed_policy))
        if current.active_version != primary_before["model_version"]:
            raise ValueError("active.json changed during candidate publication")
        return {"status": "INSTALLED", "model_version": version, "adoption_receipt_sha256": receipt_sha,
                "package_manifest_sha256": package_sha, "primary_before": primary_before,
                "quality_gate": "PASS", "data_provenance": "DEMO_ONLY"}
    finally:
        if staging is not None:
            try:
                staging.rmdir()  # Only remove our own now-empty staging directory.
            except OSError:
                pass
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("package")
    for name in ("source", "fresh-holdout", "workspace", "receipt", "output"):
        build.add_argument("--" + name, type=Path, required=True)
    build.add_argument("--receipt-sha256", required=True)
    build.add_argument("--manifest-sha256", required=True)
    build.add_argument("--allow-package", action="store_true", required=True)
    install = sub.add_parser("install")
    install.add_argument("--package-directory", type=Path, required=True)
    install.add_argument("--allow-install", action="store_true", required=True)
    args = parser.parse_args()
    try:
        if args.command == "package":
            result = package_candidate(source=args.source, fresh_holdout=args.fresh_holdout, workspace=args.workspace,
                receipt_path=args.receipt, receipt_sha=args.receipt_sha256, manifest_sha=args.manifest_sha256,
                output=args.output, allow_package=args.allow_package)
        else:
            result = install_candidate(args.package_directory, allow_install=args.allow_install)
        print(canonical(result), flush=True)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("candidate packaging or installation refused; primary model was not changed") from None


if __name__ == "__main__":
    main()
