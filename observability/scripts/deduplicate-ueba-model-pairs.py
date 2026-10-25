#!/usr/bin/env python3
"""Bounded storage maintenance for exact duplicate cal/top model binaries.

This tool is deliberately fixed to the completed r2 campaign. It never imports
the ML application, deserializes a model, fits, scores, reads holdout rows,
changes metadata/receipts, or discovers deletion targets recursively.

Apply keeps both model paths and atomically replaces only the duplicate top
pathname with a hard link to its byte-identical cal artifact. The original
independent top inode is the only data block retired. All changes require a
separate, SHA-pinned authorization record and held campaign/worker locks.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime"
CAMPAIGN = RUNTIME / "hybrid-strict-source-20261013-parallel-resume-r2"
SOURCE = CAMPAIGN / "source"
STANDARD = SOURCE / "standard"
MODELS = STANDARD / "hybrid-models"
RUNS = STANDARD / "hybrid-runs"
VALIDATIONS = STANDARD / "hybrid-validations"
TOP_RECEIPTS = STANDARD / "hybrid-top-recalibrations"
WORKER_LOCKS = STANDARD / "hybrid-parallel-jobs/locks"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 128 * 1024 * 1024
MAX_PAIRS = 360
MAX_BATCH = 25
RESERVE_BYTES = 5_000_000_000
UNIT_MARGIN_BYTES = 256 * 1024 * 1024
SHA = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"hybrid_(?:fit|cal|top)_[a-z0-9_-]{8,128}\Z")
RUN_ID = re.compile(r"hybrid-v1-iterations-(?:100|200|400)-leaves-(?:15|31|63|127)-l2-[01]-seed-(?:11|23|42|73|101)-fold-[123]\Z")
MODEL_FILE = re.compile(r"hybrid_(fit|cal|top)_([a-z0-9_-]{8,128})\.json\Z")
SESSION = re.compile(r"storage-reclamation-r2-[A-Za-z0-9_-]{8,80}\Z")
AUTH_FIELDS = {
    "schema_version", "scope", "manifest_sha256", "helper_sha256", "dataset_sha256",
    "pair_ids", "reclamation_approved", "authorization_reference",
}
PAIR_FIELDS = {
    "pair_id", "run_id", "sha256", "bytes", "cal_version", "top_version",
    "cal_path", "top_path", "cal_signature", "top_signature",
    "cal_metadata_path", "top_metadata_path", "cal_metadata_sha256",
    "top_metadata_sha256", "cal_metadata_signature", "top_metadata_signature",
    "fit_receipt_path", "fit_receipt_sha256", "fit_receipt_signature",
    "validation_receipt_path", "validation_receipt_sha256", "validation_receipt_signature",
    "recalibration_receipt_path", "recalibration_receipt_sha256",
    "recalibration_receipt_signature", "allocated_bytes_reclaimable", "temporary_name",
}
SIGNATURE_FIELDS = {
    "dev", "ino", "size", "blocks", "mode", "uid", "nlink", "mtime_ns", "ctime_ns",
}


class ReclaimError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReclaimError("duplicate JSON key")
        result[key] = value
    return result


def _parse_json(raw: bytes) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ReclaimError("invalid JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReclaimError("invalid bounded JSON") from None


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_absolute(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ReclaimError("symlink in protected path")
    return path


def _safe_regular(path: Path, *, max_bytes: int, mode: int = 0o600,
                  links: int | None = None) -> os.stat_result:
    path = _canonical_absolute(path)
    try:
        info = path.lstat()
    except OSError:
        raise ReclaimError("required private file unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != mode or not 0 < info.st_size <= max_bytes
            or (links is not None and info.st_nlink != links)):
        raise ReclaimError("private regular file identity/mode/size mismatch")
    return info


def _file_signature(info: os.stat_result) -> dict:
    return {
        "dev": info.st_dev, "ino": info.st_ino, "size": info.st_size,
        "blocks": info.st_blocks, "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid, "nlink": info.st_nlink,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }


def _signature_matches(info: os.stat_result, expected: dict, *, link_count: int | None = None) -> bool:
    actual = _file_signature(info)
    keys = ("dev", "ino", "size", "mode", "uid", "mtime_ns")
    if any(actual[key] != expected[key] for key in keys):
        return False
    if link_count is not None:
        return actual["nlink"] == link_count
    return actual["nlink"] == expected["nlink"] and actual["ctime_ns"] == expected["ctime_ns"]


def _read_bytes(path: Path, *, max_bytes: int, links: int | None = None) -> tuple[bytes, dict]:
    path = _canonical_absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > max_bytes
                or before.st_size <= 0 or (links is not None and before.st_nlink != links)):
            raise ReclaimError("bounded owner-only regular file required")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        named = path.lstat()
        if (len(raw) != before.st_size or len(raw) > max_bytes
                or _file_signature(before) != _file_signature(after)
                or _file_signature(before) != _file_signature(named)):
            raise ReclaimError("file changed during bounded read")
        return raw, _file_signature(before)
    finally:
        os.close(fd)


def _read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES,
               links: int | None = None) -> tuple[dict, dict, str]:
    raw, signature = _read_bytes(path, max_bytes=max_bytes, links=links)
    value = _parse_json(raw)
    if type(value) is not dict:
        raise ReclaimError("JSON object required")
    return value, signature, sha256_bytes(raw)


def _hash_regular(path: Path, *, expected: dict | None = None,
                  max_bytes: int = MAX_MODEL_BYTES) -> tuple[str, dict]:
    path = _canonical_absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > max_bytes
                or before.st_size <= 0):
            raise ReclaimError("bounded owner-only model artifact required")
        if expected is not None and not _signature_matches(before, expected):
            raise ReclaimError("model artifact changed since allowlist creation")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        named = path.lstat()
        if (_file_signature(before) != _file_signature(after)
                or _file_signature(before) != _file_signature(named)):
            raise ReclaimError("model artifact changed while hashing")
        return digest.hexdigest(), _file_signature(after)
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> None:
    path = _canonical_absolute(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


def _replace_record(path: Path, value: dict) -> None:
    raw = canonical(value) + b"\n"
    temp = path.parent / ("." + path.name + ".write-" + uuid.uuid4().hex + ".pending")
    _write_new(temp, raw)
    os.replace(temp, path)
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_private_record(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict, str]:
    value, _, digest = _read_json(path, max_bytes=max_bytes, links=1)
    return value, digest


def _model_directory() -> dict:
    path = _canonical_absolute(MODELS)
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ReclaimError("owner-only canonical model directory required")
    return _file_signature(info)


def _authority_snapshot() -> dict:
    progress, _, progress_sha = _read_json(CAMPAIGN / "parallel-campaign.progress.private.json")
    fit_progress, _, fit_sha = _read_json(STANDARD / "hybrid-campaign.progress.json")
    validation_progress, _, validation_sha = _read_json(STANDARD / "hybrid-validation.progress.json")
    recal_progress, _, recal_sha = _read_json(STANDARD / "hybrid-recalibration.progress.json")
    selection, _, selection_sha = _read_json(STANDARD / "hybrid-selection.json")
    ranking, _, ranking_sha = _read_json(STANDARD / "hybrid-ranking.json")
    source_terminal, _, terminal_sha = _read_json(SOURCE / "state.private.json")
    source_marker, _, marker_sha = _read_json(SOURCE / "predeclared.private.json")
    manifest, _, dataset_sha = _read_json(STANDARD / "manifest.json", max_bytes=4 * 1024 * 1024)
    sidecar, _, archive_sha = _read_json(STANDARD / "archives.private.json", max_bytes=4 * 1024 * 1024)
    source_archive, _, archive_result_sha = _read_json(STANDARD / "source-archive-result.private.json")

    if (progress.get("status") != "PARALLEL_FIT_VALIDATION_COMPLETE"
            or progress.get("completed_fits") != 360 or progress.get("required_fits") != 360
            or progress.get("completed_validations") != 360 or progress.get("required_validations") != 360
            or progress.get("quality_gate") != "NOT_RUN" or progress.get("holdout_scored") is not False
            or progress.get("aws_changed") is not False or progress.get("active_run_ids") != []):
        raise ReclaimError("terminal parallel campaign checkpoint required")
    if (fit_progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE"
            or fit_progress.get("actual_fits_completed") != 360
            or validation_progress.get("status") != "COMPLETED"
            or validation_progress.get("completed_runs") != 360
            or recal_progress.get("completed_recalibrations") != 360
            or recal_progress.get("quality_gate") != "NOT_RUN"):
        raise ReclaimError("complete fit/validation/recalibration receipts required")
    if (selection.get("status") != "NO_QUALIFIED_CONFIG"
            or selection.get("actual_fits_completed") != 360
            or selection.get("validation_runs_completed") != 360
            or selection.get("completed_recalibrations") != 360
            or selection.get("holdout_scored") is not False
            or selection.get("quality_gate") != "NOT_RUN"
            or selection.get("data_provenance") != "DEMO_ONLY"):
        raise ReclaimError("exact unqualified closed selection required")
    if (ranking.get("status") != "NO_QUALIFIED_CONFIG"
            or ranking.get("validation_runs_completed") != 360
            or ranking.get("holdout_scored") is not False
            or ranking.get("quality_gate") != "NOT_RUN"
            or ranking.get("data_provenance") != "DEMO_ONLY"
            or len(ranking.get("configurations", [])) != 24):
        raise ReclaimError("exact closed 24-configuration ranking required")
    if (source_marker.get("scope") != "FULL_STRICT_SOURCE"
            or source_terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE"
            or source_terminal.get("scope") != "FULL_STRICT_SOURCE"
            or source_terminal.get("holdout_numeric_records_read") != 0
            or source_terminal.get("downstream_holdout_numeric_records_read") != 0
            or source_terminal.get("fit_or_score_calls") != 0
            or source_terminal.get("quality_gate") != "NOT_EVALUATED"):
        raise ReclaimError("closed source and unopened holdout metadata required")
    if (manifest.get("stage") != "STRICT" or manifest.get("data_provenance") != "DEMO_ONLY"
            or manifest.get("quality_gate") != "NOT_EVALUATED"
            or manifest.get("feature_schema_version") != 4
            or manifest.get("fit_or_score_calls") != 0
            or sidecar.get("dataset_manifest_sha256") != dataset_sha):
        raise ReclaimError("strict schema-4 source identity changed")
    if (source_archive.get("status") != "COMPLETED"
            or source_archive.get("scope") != "STORAGE_ONLY"
            or source_archive.get("dataset_manifest_sha256") != dataset_sha
            or source_archive.get("original_files_deleted_or_renamed") != 0):
        raise ReclaimError("current source archive receipt changed")

    return {
        "campaign_id": progress.get("campaign_id"),
        "progress_sha256": progress_sha,
        "fit_progress_sha256": fit_sha,
        "validation_progress_sha256": validation_sha,
        "recalibration_progress_sha256": recal_sha,
        "selection_sha256": selection_sha,
        "ranking_sha256": ranking_sha,
        "source_terminal_sha256": terminal_sha,
        "source_marker_sha256": marker_sha,
        "dataset_sha256": dataset_sha,
        "archive_sidecar_sha256": archive_sha,
        "source_archive_result_sha256": archive_result_sha,
    }


def _json_files(directory: Path) -> list[Path]:
    _canonical_absolute(directory)
    info = directory.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ReclaimError("owner-only receipt directory required")
    result = []
    for entry in directory.iterdir():
        value = entry.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise ReclaimError("symlink in fixed receipt directory")
        if entry.suffix == ".json":
            if not stat.S_ISREG(value.st_mode):
                raise ReclaimError("nonregular receipt entry")
            result.append(entry)
    return sorted(result)


def _validate_pair_binding(cal: dict, top: dict, fit: dict, recal: dict,
                           validation: dict, run_id: str, dataset_sha256: str) -> None:
    if not RUN_ID.fullmatch(run_id):
        raise ReclaimError("approved run id required")
    stable_fields = (
        "run_id", "source_model_version", "source_model_sha256",
        "calibration_sha256", "fold", "config", "recipe_sha256",
    )
    if cal.get("run_id") != run_id or top.get("run_id") != run_id:
        raise ReclaimError("calibration/top metadata run mismatch")
    if any(cal.get(key) != top.get(key) for key in stable_fields):
        raise ReclaimError("calibration/top semantic binding mismatch")
    if (cal.get("model_kind") != "normal_plus_incident_research"
            or top.get("model_kind") != cal.get("model_kind")
            or cal.get("feature_schema_version") != 4 or top.get("feature_schema_version") != 4
            or cal.get("recipe_version") != 1 or top.get("recipe_version") != 1
            or cal.get("data_provenance") != "DEMO_ONLY"
            or top.get("data_provenance") != "DEMO_ONLY"
            or cal.get("dataset_manifest_sha256") != dataset_sha256
            or top.get("dataset_manifest_sha256") != dataset_sha256):
        raise ReclaimError("calibration/top schema/provenance binding mismatch")
    for metadata in (cal, top):
        if (metadata.get("artifact_compression") != {"codec": "lzma", "level": 3}
                or metadata.get("model_state_sha256") != cal.get("model_state_sha256")
                or metadata.get("model_state_format") != cal.get("model_state_format")
                or metadata.get("model_state_verifier_sha256") != cal.get("model_state_verifier_sha256")
                or not SHA.fullmatch(str(metadata.get("sha256", "")))
                or not SHA.fullmatch(str(metadata.get("calibration_sha256", "")))):
            raise ReclaimError("model state/compression metadata mismatch")
    if (fit.get("status") != "FITTED_CALIBRATED" or fit.get("run_id") != run_id
            or fit.get("model_version") != cal.get("model_version")
            or fit.get("model_sha256") != cal.get("sha256")
            or fit.get("source_model_version") != cal.get("source_model_version")
            or fit.get("source_model_sha256") != cal.get("source_model_sha256")
            or fit.get("calibration_sha256") != cal.get("calibration_sha256")
            or fit.get("fold") != cal.get("fold") or fit.get("config") != cal.get("config")):
        raise ReclaimError("frozen fit receipt/cal model binding mismatch")
    if (recal.get("run_id") != run_id or recal.get("model_version") != top.get("model_version")
            or recal.get("model_sha256") != top.get("sha256")
            or recal.get("source_model_version") != top.get("source_model_version")
            or recal.get("source_model_sha256") != top.get("source_model_sha256")
            or recal.get("calibration_sha256") != top.get("calibration_sha256")
            or recal.get("fold") != top.get("fold") or recal.get("config") != top.get("config")
            or recal.get("additional_fit_calls") != 0):
        raise ReclaimError("recalibration receipt/top model binding mismatch")
    if (validation.get("status") != "VALIDATED" or validation.get("run_id") != run_id
            or validation.get("model_sha256") != fit.get("model_sha256")
            or validation.get("evaluation_scope") != "VALIDATION"):
        raise ReclaimError("validation receipt binding mismatch")


def _build_manifest(output: Path) -> dict:
    authority = _authority_snapshot()
    directory_sig = _model_directory()
    json_paths = _json_files(MODELS)
    expected_files = []
    metadata_by_version = {}
    fit_artifacts = []
    for path in json_paths:
        match = MODEL_FILE.fullmatch(path.name)
        if not match:
            raise ReclaimError("unexpected model JSON filename")
        role = match.group(1)
        version = path.stem
        if not VERSION.fullmatch(version):
            raise ReclaimError("unexpected model version")
        metadata, signature, digest = _read_json(path, max_bytes=MAX_JSON_BYTES, links=1)
        binary = MODELS / (version + ".joblib")
        binary_sig = _safe_regular(binary, max_bytes=MAX_MODEL_BYTES, links=1)
        if (metadata.get("model_version") != version or metadata.get("data_provenance") != "DEMO_ONLY"
                or not SHA.fullmatch(str(metadata.get("sha256", "")))
                or not RUN_ID.fullmatch(str(metadata.get("run_id", "")))):
            raise ReclaimError("model JSON identity/provenance mismatch")
        if (role == "fit" and version.startswith("hybrid_fit_")
                or role == "cal" and version.startswith("hybrid_cal_")
                or role == "top" and version.startswith("hybrid_top_")) is False:
            raise ReclaimError("model role/version mismatch")
        metadata_by_version[version] = {
            "path": path.name, "metadata": metadata, "metadata_sha256": digest,
            "metadata_signature": signature, "binary": binary.name,
            "binary_signature": _file_signature(binary_sig),
        }
        if role == "fit":
            binary_sha, binary_final = _hash_regular(binary, expected=_file_signature(binary_sig))
            if binary_sha != metadata["sha256"]:
                raise ReclaimError("fit binary SHA differs from immutable model metadata")
            fit_artifacts.append({
                "version": version,
                "binary_path": binary.name,
                "binary_sha256": binary_sha,
                "binary_signature": binary_final,
                "metadata_path": path.name,
                "metadata_sha256": digest,
                "metadata_signature": signature,
            })
        expected_files.append(version + ".joblib")
    if len(json_paths) != 1080 or len(expected_files) != 1080 or len(set(expected_files)) != 1080:
        raise ReclaimError("exact 1,080 model JSON/binary pairs required")
    if any(not (MODELS / name).is_file() for name in expected_files):
        raise ReclaimError("model binary population mismatch")
    binaries = sorted(MODELS.glob("*.joblib"))
    if len(binaries) != 1080 or {path.name for path in binaries} != set(expected_files):
        raise ReclaimError("unexpected model binary population")
    role_counts = {role: sum(name.startswith("hybrid_" + role + "_") for name in expected_files)
                   for role in ("fit", "cal", "top")}
    if role_counts != {"fit": 360, "cal": 360, "top": 360}:
        raise ReclaimError("expected 360 fit/cal/top models")

    runs = _json_files(RUNS)
    validations = _json_files(VALIDATIONS)
    top_receipts = _json_files(TOP_RECEIPTS)
    if (len(runs) != 360 or len(validations) != 360 or len(top_receipts) != 360
            or {p.name for p in runs} != {p.name for p in validations}
            or {p.name for p in runs} != {p.name for p in top_receipts}):
        raise ReclaimError("exact 360 fit/validation/recalibration receipts required")

    role_groups: dict[str, dict[str, list[str]]] = {}
    for version, entry in metadata_by_version.items():
        metadata = entry["metadata"]
        role = version.split("_", 2)[1]
        digest = metadata["sha256"]
        role_groups.setdefault(digest, {}).setdefault(role, []).append(version)

    pairs = []
    paired_versions = set()
    run_ids = set()
    for digest, roles in role_groups.items():
        if set(roles) == {"fit"}:
            if len(roles["fit"]) != 1:
                raise ReclaimError("duplicate fit binary group is outside allowlist")
            continue
        if set(roles) != {"cal", "top"} or len(roles["cal"]) != 1 or len(roles["top"]) != 1:
            raise ReclaimError("unexpected model hash group; allow only one cal/top pair")
        cal_version, top_version = roles["cal"][0], roles["top"][0]
        cal_entry, top_entry = metadata_by_version[cal_version], metadata_by_version[top_version]
        cal_meta, top_meta = cal_entry["metadata"], top_entry["metadata"]
        run_id = cal_meta.get("run_id")
        if run_id in run_ids:
            raise ReclaimError("duplicate model run id")
        run_ids.add(run_id)
        if run_id != top_meta.get("run_id"):
            raise ReclaimError("cal/top run ids differ")

        fit_path = RUNS / (run_id + ".json")
        validation_path = VALIDATIONS / (run_id + ".json")
        recal_path = TOP_RECEIPTS / (run_id + ".json")
        fit, fit_sig, fit_sha = _read_json(fit_path)
        validation, validation_sig, validation_sha = _read_json(validation_path)
        recal, recal_sig, recal_sha = _read_json(recal_path)
        _validate_pair_binding(cal_meta, top_meta, fit, recal, validation,
                               run_id, authority["dataset_sha256"])
        if (fit.get("model_sha256") != digest or recal.get("model_sha256") != digest
                or cal_meta.get("sha256") != top_meta.get("sha256")):
            raise ReclaimError("metadata hash group differs from frozen receipts")

        cal_path, top_path = MODELS / cal_entry["binary"], MODELS / top_entry["binary"]
        cal_sha, cal_final_sig = _hash_regular(cal_path, expected=cal_entry["binary_signature"])
        top_sha, top_final_sig = _hash_regular(top_path, expected=top_entry["binary_signature"])
        if (cal_sha != digest or top_sha != digest or cal_sha != top_sha):
            raise ReclaimError("model binary bytes do not match both pinned SHA values")
        if (cal_final_sig["nlink"] != 1 or top_final_sig["nlink"] != 1
                or cal_final_sig["ino"] == top_final_sig["ino"]
                or cal_final_sig["dev"] != top_final_sig["dev"]):
            raise ReclaimError("model pair must begin as two independent same-filesystem files")

        pair_id = sha256_bytes((cal_version + "\0" + top_version).encode())[:24]
        pairs.append({
            "pair_id": pair_id,
            "run_id": run_id,
            "sha256": digest,
            "bytes": cal_final_sig["size"],
            "cal_version": cal_version,
            "top_version": top_version,
            "cal_path": cal_entry["binary"],
            "top_path": top_entry["binary"],
            "cal_signature": cal_final_sig,
            "top_signature": top_final_sig,
            "cal_metadata_path": cal_entry["path"],
            "top_metadata_path": top_entry["path"],
            "cal_metadata_sha256": cal_entry["metadata_sha256"],
            "top_metadata_sha256": top_entry["metadata_sha256"],
            "cal_metadata_signature": cal_entry["metadata_signature"],
            "top_metadata_signature": top_entry["metadata_signature"],
            "fit_receipt_path": fit_path.name,
            "fit_receipt_sha256": fit_sha,
            "fit_receipt_signature": fit_sig,
            "validation_receipt_path": validation_path.name,
            "validation_receipt_sha256": validation_sha,
            "validation_receipt_signature": validation_sig,
            "recalibration_receipt_path": recal_path.name,
            "recalibration_receipt_sha256": recal_sha,
            "recalibration_receipt_signature": recal_sig,
            "allocated_bytes_reclaimable": top_final_sig["blocks"] * 512,
            "temporary_name": ".storage-dedup-" + pair_id + ".pending",
        })
        paired_versions.update((cal_version, top_version))

    pairs.sort(key=lambda value: value["pair_id"])
    if (len(pairs) != 360 or len(run_ids) != 360
            or len(paired_versions) != 720
            or sum(item["bytes"] for item in pairs) != 4_743_834_239):
        raise ReclaimError("expected exact 360 byte-identical cal/top pairs")
    for version, entry in metadata_by_version.items():
        if version not in paired_versions and not version.startswith("hybrid_fit_"):
            raise ReclaimError("unpaired non-fit model is outside allowlist")
    if len({item["pair_id"] for item in pairs}) != len(pairs):
        raise ReclaimError("pair id collision")

    protected_files = [
        ("parallel-campaign.progress.private.json", CAMPAIGN / "parallel-campaign.progress.private.json"),
        ("hybrid-campaign.progress.json", STANDARD / "hybrid-campaign.progress.json"),
        ("hybrid-validation.progress.json", STANDARD / "hybrid-validation.progress.json"),
        ("hybrid-recalibration.progress.json", STANDARD / "hybrid-recalibration.progress.json"),
        ("hybrid-selection.json", STANDARD / "hybrid-selection.json"),
        ("hybrid-ranking.json", STANDARD / "hybrid-ranking.json"),
        ("source-state.private.json", SOURCE / "state.private.json"),
        ("source-predeclared.private.json", SOURCE / "predeclared.private.json"),
        ("manifest.json", STANDARD / "manifest.json"),
        ("archives.private.json", STANDARD / "archives.private.json"),
        ("source-archive-result.private.json", STANDARD / "source-archive-result.private.json"),
    ]
    protected = []
    for label, path in protected_files:
        _, signature, digest = _read_json(path, max_bytes=4 * 1024 * 1024)
        protected.append({"label": label, "sha256": digest, "signature": signature})
    if _model_directory() != directory_sig:
        # Directory mtime can change only during an unauthorized model publish;
        # compare identity and ownership while allowing its atime to vary.
        current = _model_directory()
        if any(current[key] != directory_sig[key] for key in ("dev", "ino", "uid", "mode")):
            raise ReclaimError("model directory identity changed during audit")
    return {
        "schema_version": 1,
        "scope": "R2_CAL_TOP_IDENTICAL_BINARY_HARDLINK",
        "session_path": str(output),
        "campaign_root": str(CAMPAIGN),
        "standard_root": str(STANDARD),
        "model_root": str(MODELS),
        "dataset_sha256": authority["dataset_sha256"],
        "source_archive_sha256": authority["archive_sidecar_sha256"],
        "campaign_id": authority["campaign_id"],
        "authority": authority,
        "protected_files": protected,
        "fit_artifacts": sorted(fit_artifacts, key=lambda item: item["version"]),
        "model_counts": {"fit": 360, "cal": 360, "top": 360, "json": 1080, "binary": 1080},
        "pair_count": len(pairs),
        "total_pair_logical_bytes": sum(item["bytes"] for item in pairs),
        "expected_unique_blocks_reclaimable": sum(item["allocated_bytes_reclaimable"] for item in pairs),
        "pairs": pairs,
        "holdout_scored": False,
        "quality_gate": "NOT_RUN",
        "aws_changed": False,
        "provenance": "DEMO_ONLY",
    }


def _check_private_dir(path: Path) -> None:
    path = _canonical_absolute(path)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ReclaimError("private owner-controlled work directory required")


@contextmanager
def _held_lock(stack: ExitStack, path: Path, *, create: bool = False):
    path = _canonical_absolute(path)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise ReclaimError("required campaign lock unavailable") from None
    stream = stack.enter_context(os.fdopen(fd, "a+b"))
    info = os.fstat(stream.fileno())
    named = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > MAX_JSON_BYTES
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
        raise ReclaimError("single-link owner-only campaign lock required")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ReclaimError("campaign/selection/worker lock is busy") from None
    yield stream, _file_signature(info)
    final = path.lstat()
    current = os.fstat(stream.fileno())
    if (current.st_dev, current.st_ino) != (final.st_dev, final.st_ino):
        raise ReclaimError("campaign lock pathname changed while held")


def _run_ids() -> list[str]:
    paths = _json_files(RUNS)
    ids = [path.stem for path in paths]
    if len(ids) != 360 or any(not RUN_ID.fullmatch(value) for value in ids) or len(set(ids)) != 360:
        raise ReclaimError("exact completed run-id set required for worker locks")
    return sorted(ids)


def _active_docker_workers(campaign_id: str) -> None:
    systemctl = shutil.which("systemctl")
    docker = shutil.which("docker")
    if not systemctl or not docker:
        raise ReclaimError("cannot prove Docker worker state")
    service = subprocess.run([systemctl, "is-active", "--quiet", "docker.service"],
                             capture_output=True, timeout=10)
    if service.returncode != 0:
        # Do not activate the Docker socket just to perform this check.
        return
    result = subprocess.run([docker, "ps", "-q", "--filter",
                             "label=flare.parallel.identity=" + campaign_id],
                            capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise ReclaimError("Docker worker query failed")
    if result.stdout.strip():
        raise ReclaimError("live campaign worker container exists")


def _open_files_under_models() -> None:
    lsof = shutil.which("lsof")
    if not lsof:
        raise ReclaimError("lsof is required to check model readers")
    result = subprocess.run([lsof, "-nP", "-t", "+D", str(MODELS)],
                            capture_output=True, text=True, timeout=90)
    if result.returncode == 0 and result.stdout.strip():
        raise ReclaimError("model file has an open process reader")
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise ReclaimError("model open-file check was inconclusive")


@contextmanager
def _maintenance_window():
    _check_private_dir(SOURCE)
    _check_private_dir(STANDARD)
    _check_private_dir(WORKER_LOCKS)
    # The parallel coordinator lock is checked first: it cannot dispatch new
    # workers while source-stage and existing per-run locks are acquired.
    fixed = [
        CAMPAIGN / "state/parallel-campaign.lock",
        SOURCE / "campaign.lock",
        SOURCE / "selection.lock",
        SOURCE / "evaluation.lock",
        STANDARD / "generation.lock",
    ]
    run_ids = _run_ids()
    allowed_run_locks = {
        phase + "-" + run_id + ".lock"
        for run_id in run_ids for phase in ("fit", "validation")
    }
    present_run_locks = []
    for path in WORKER_LOCKS.iterdir():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReclaimError("unexpected worker lock entry")
        if path.name not in allowed_run_locks:
            raise ReclaimError("unknown worker lock outside the completed run set")
        present_run_locks.append(path)
    lock_paths = fixed + sorted(present_run_locks)
    # evaluation.lock is a real coordinated-stage path in frozen pipeline_lock.
    # Creating only that exact absent lock closes a race; it is retained.
    with ExitStack() as stack:
        for path in lock_paths:
            stack.enter_context(
                _held_lock(stack, path, create=(path == SOURCE / "evaluation.lock" and not path.exists()))
            )
        _active_docker_workers(_authority_snapshot()["campaign_id"])
        _open_files_under_models()
        yield


def _session_dir(path: Path, *, create: bool) -> Path:
    absolute = _canonical_absolute(path)
    if absolute.parent != RUNTIME or not SESSION.fullmatch(absolute.name):
        raise ReclaimError("session directory must be a fixed private runtime child")
    if create:
        absolute.mkdir(mode=0o700)
        _fsync_dir(RUNTIME)
    _check_private_dir(absolute)
    return absolute


def create_plan(output: Path) -> tuple[Path, str]:
    output = _session_dir(output, create=True)
    with _maintenance_window():
        manifest = _build_manifest(output)
    raw = canonical(manifest) + b"\n"
    if len(raw) > 64 * 1024 * 1024:
        raise ReclaimError("candidate manifest exceeds fixed bound")
    path = output / "candidate-pairs.private.json"
    _write_new(path, raw)
    return path, sha256_bytes(raw)


def _load_manifest(path: Path, expected_sha: str) -> tuple[dict, dict, str]:
    if not SHA.fullmatch(expected_sha):
        raise ReclaimError("manifest SHA pin required")
    path = _canonical_absolute(path)
    _session_dir(path.parent, create=False)
    if path.name != "candidate-pairs.private.json":
        raise ReclaimError("fixed session manifest path required")
    manifest, signature, digest = _read_json(path, max_bytes=64 * 1024 * 1024, links=1)
    if (digest != expected_sha or manifest.get("schema_version") != 1
            or manifest.get("session_path") != str(path.parent)):
        raise ReclaimError("manifest SHA/schema mismatch")
    if (manifest.get("scope") != "R2_CAL_TOP_IDENTICAL_BINARY_HARDLINK"
            or manifest.get("campaign_root") != str(CAMPAIGN)
            or manifest.get("model_root") != str(MODELS)
            or manifest.get("pair_count") != MAX_PAIRS
            or len(manifest.get("pairs", [])) != MAX_PAIRS
            or manifest.get("dataset_sha256") != _authority_snapshot()["dataset_sha256"]
            or manifest.get("holdout_scored") is not False
            or manifest.get("quality_gate") != "NOT_RUN"
            or manifest.get("aws_changed") is not False):
        raise ReclaimError("fixed completed r2 model-pair manifest required")
    ids = [item.get("pair_id") for item in manifest["pairs"]]
    if len(set(ids)) != MAX_PAIRS or any(not re.fullmatch(r"[a-f0-9]{24}", str(value)) for value in ids):
        raise ReclaimError("unique explicit pair ids required")
    if (not SHA.fullmatch(str(manifest.get("source_archive_sha256", "")))
            or type(manifest.get("authority")) is not dict
            or type(manifest.get("fit_artifacts")) is not list
            or len(manifest["fit_artifacts"]) != 360):
        raise ReclaimError("complete pinned dataset/source/fit manifest required")
    fit_versions = set()
    fit_fields = {"version", "binary_path", "binary_sha256", "binary_signature",
                  "metadata_path", "metadata_sha256", "metadata_signature"}
    for item in manifest["fit_artifacts"]:
        if (type(item) is not dict or set(item) != fit_fields
                or not VERSION.fullmatch(str(item["version"]))
                or not item["version"].startswith("hybrid_fit_")
                or item["binary_path"] != item["version"] + ".joblib"
                or item["metadata_path"] != item["version"] + ".json"
                or item["version"] in fit_versions
                or not SHA.fullmatch(str(item["binary_sha256"]))
                or not SHA.fullmatch(str(item["metadata_sha256"]))):
            raise ReclaimError("protected fit artifact path/hash binding invalid")
        fit_versions.add(item["version"])
        for key in ("binary_signature", "metadata_signature"):
            signature = item[key]
            if (type(signature) is not dict or set(signature) != SIGNATURE_FIELDS
                    or any(type(value) is not int or value < 0 for value in signature.values())
                    or signature["uid"] != os.geteuid() or signature["mode"] != 0o600
                    or signature["nlink"] != 1 or signature["size"] <= 0
                    or signature["ino"] <= 0):
                raise ReclaimError("protected fit file signature invalid")
        if item["binary_signature"]["size"] > MAX_MODEL_BYTES:
            raise ReclaimError("protected fit artifact exceeds model bound")
    seen_versions = set()
    seen_runs = set()
    for pair in manifest["pairs"]:
        if type(pair) is not dict or set(pair) != PAIR_FIELDS:
            raise ReclaimError("exact pair manifest fields required")
        cal_version, top_version, run_id = pair["cal_version"], pair["top_version"], pair["run_id"]
        if (not VERSION.fullmatch(str(cal_version)) or not VERSION.fullmatch(str(top_version))
                or not cal_version.startswith("hybrid_cal_") or not top_version.startswith("hybrid_top_")
                or not RUN_ID.fullmatch(str(run_id))
                or pair["cal_path"] != cal_version + ".joblib"
                or pair["top_path"] != top_version + ".joblib"
                or pair["cal_metadata_path"] != cal_version + ".json"
                or pair["top_metadata_path"] != top_version + ".json"
                or pair["fit_receipt_path"] != run_id + ".json"
                or pair["validation_receipt_path"] != run_id + ".json"
                or pair["recalibration_receipt_path"] != run_id + ".json"
                or pair["temporary_name"] != ".storage-dedup-" + pair["pair_id"] + ".pending"
                or pair["pair_id"] != sha256_bytes((cal_version + "\0" + top_version).encode())[:24]):
            raise ReclaimError("pair path/version/run binding mismatch")
        if cal_version in seen_versions or top_version in seen_versions or run_id in seen_runs:
            raise ReclaimError("duplicate model path or run id in allowlist")
        seen_versions.update((cal_version, top_version))
        seen_runs.add(run_id)
        if (not SHA.fullmatch(str(pair["sha256"]))
                or any(not SHA.fullmatch(str(pair[key])) for key in (
                    "cal_metadata_sha256", "top_metadata_sha256", "fit_receipt_sha256",
                    "validation_receipt_sha256", "recalibration_receipt_sha256"))
                or type(pair["bytes"]) is not int or not 0 < pair["bytes"] <= MAX_MODEL_BYTES
                or type(pair["allocated_bytes_reclaimable"]) is not int
                or pair["allocated_bytes_reclaimable"] < 0):
            raise ReclaimError("bounded pair bytes/hashes required")
        for key in ("cal_signature", "top_signature", "cal_metadata_signature",
                    "top_metadata_signature", "fit_receipt_signature",
                    "validation_receipt_signature", "recalibration_receipt_signature"):
            signature = pair[key]
            if (type(signature) is not dict or set(signature) != SIGNATURE_FIELDS
                    or any(type(value) is not int or value < 0 for value in signature.values())
                    or signature["uid"] != os.geteuid() or signature["mode"] != 0o600
                    or signature["size"] <= 0 or signature["dev"] < 0 or signature["ino"] <= 0
                    or signature["nlink"] < 1):
                raise ReclaimError("private file signature invalid in allowlist")
        cal_sig, top_sig = pair["cal_signature"], pair["top_signature"]
        if (cal_sig["nlink"] != 1 or top_sig["nlink"] != 1
                or cal_sig["dev"] != top_sig["dev"] or cal_sig["ino"] == top_sig["ino"]
                or cal_sig["size"] != pair["bytes"] or top_sig["size"] != pair["bytes"]
                or cal_sig["blocks"] < 0 or top_sig["blocks"] < 0
                or top_sig["blocks"] * 512 != pair["allocated_bytes_reclaimable"]):
            raise ReclaimError("independent same-filesystem model inode signatures required")
    if (len(seen_versions) != 720 or len(seen_runs) != 360 or len(fit_versions) != 360
            or manifest.get("model_counts") != {
                "fit": 360, "cal": 360, "top": 360, "json": 1080, "binary": 1080
            }
            or manifest.get("total_pair_logical_bytes") != sum(pair["bytes"] for pair in manifest["pairs"])
            or manifest.get("expected_unique_blocks_reclaimable")
            != sum(pair["allocated_bytes_reclaimable"] for pair in manifest["pairs"])):
        raise ReclaimError("pair counts/aggregate space binding mismatch")
    return manifest, signature, digest


def create_approval(manifest_path: Path, manifest_sha: str,
                    authorization_reference: str, destination: Path) -> tuple[Path, str]:
    manifest, _, digest = _load_manifest(manifest_path, manifest_sha)
    _current_authority_matches(manifest)
    if (type(authorization_reference) is not str or not authorization_reference.strip()
            or len(authorization_reference) > 2000):
        raise ReclaimError("explicit human authorization reference required")
    destination = _canonical_absolute(destination)
    session = _session_dir(manifest_path.parent, create=False)
    if destination != session / "approval.private.json":
        raise ReclaimError("approval must be a new file in the pinned session")
    record = {
        "schema_version": 1,
        "scope": "EXACT_VERIFIED_R2_CAL_TOP_PAIRS",
        "manifest_sha256": digest,
        "helper_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "dataset_sha256": manifest["dataset_sha256"],
        "pair_ids": sorted(item["pair_id"] for item in manifest["pairs"]),
        "reclamation_approved": True,
        "authorization_reference": authorization_reference.strip(),
    }
    raw = canonical(record) + b"\n"
    _write_new(destination, raw)
    return destination, sha256_bytes(raw)


def _load_authority(manifest: dict, manifest_sha: str, approval_path: Path,
                    approval_sha: str) -> tuple[dict, str]:
    approval_path = _canonical_absolute(approval_path)
    if (approval_path != Path(manifest["session_path"]) / "approval.private.json"
            or approval_path.name != "approval.private.json"):
        raise ReclaimError("fixed session approval path required")
    approval, digest = _read_private_record(approval_path)
    if digest != approval_sha or set(approval) != AUTH_FIELDS:
        raise ReclaimError("approval SHA/schema mismatch")
    if (approval.get("scope") != "EXACT_VERIFIED_R2_CAL_TOP_PAIRS"
            or approval.get("manifest_sha256") != manifest_sha
            or approval.get("helper_sha256") != sha256_bytes(Path(__file__).read_bytes())
            or approval.get("dataset_sha256") != manifest.get("dataset_sha256")
            or approval.get("pair_ids") != sorted(item["pair_id"] for item in manifest["pairs"])
            or approval.get("reclamation_approved") is not True
            or not str(approval.get("authorization_reference", "")).strip()):
        raise ReclaimError("approval is not bound to this exact helper and model allowlist")
    return approval, digest


def _model_fd(directory_fd: int, name: str, expected: dict | None = None,
              *, link_count: int | None = None) -> tuple[int, os.stat_result]:
    if not re.fullmatch(r"hybrid_(?:fit|cal|top)_[a-z0-9_-]{8,128}\.joblib", name):
        raise ReclaimError("exact model artifact basename required")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_MODEL_BYTES
            or info.st_size <= 0 or (link_count is not None and info.st_nlink != link_count)):
        os.close(fd)
        raise ReclaimError("private model file type/mode/owner/size/link mismatch")
    if expected is not None and not _signature_matches(info, expected, link_count=link_count):
        os.close(fd)
        raise ReclaimError("model file changed since verified manifest")
    return fd, info


def _digest_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            return digest.hexdigest()
        digest.update(block)


def _pair_records(session: Path, pair_id: str) -> tuple[Path, Path, Path, Path]:
    journal = session / "journal"
    if not journal.exists():
        journal.mkdir(mode=0o700)
        _fsync_dir(session)
    _check_private_dir(journal)
    return (
        journal / (pair_id + ".intent.private.json"),
        journal / (pair_id + ".done.private.json"),
        journal / (pair_id + ".rollback-intent.private.json"),
        journal / (pair_id + ".rolled-back.private.json"),
    )


def _record_identity(manifest_sha: str, approval_sha: str, pair: dict) -> dict:
    return {
        "scope": "EXACT_R2_MODEL_PAIR",
        "manifest_sha256": manifest_sha,
        "approval_sha256": approval_sha,
        "pair_id": pair["pair_id"],
        "run_id": pair["run_id"],
        "cal_path": pair["cal_path"],
        "top_path": pair["top_path"],
        "sha256": pair["sha256"],
        "bytes": pair["bytes"],
    }


def _read_journal(path: Path, identity: dict) -> dict | None:
    if not path.exists():
        return None
    record, _ = _read_private_record(path)
    if any(record.get(key) != value for key, value in identity.items()):
        raise ReclaimError("journal identity mismatch")
    return record


def _write_journal(path: Path, identity: dict, state: str, extra: dict | None = None) -> dict:
    record = {**identity, "state": state, **(extra or {})}
    if path.exists():
        _replace_record(path, record)
    else:
        _write_new(path, canonical(record) + b"\n")
    return record


def _current_authority_matches(manifest: dict) -> None:
    current = _authority_snapshot()
    if current != manifest["authority"]:
        raise ReclaimError("protected ML checkpoint/identity changed")


def _manifest_pair(manifest: dict, pair_id: str) -> dict:
    matches = [item for item in manifest["pairs"] if item["pair_id"] == pair_id]
    if len(matches) != 1:
        raise ReclaimError("pair id is outside the approved manifest")
    return matches[0]


def _verify_pair_frozen_inputs(pair: dict, dataset_sha256: str) -> None:
    cal_meta, _, cal_meta_sha = _read_json(MODELS / pair["cal_metadata_path"], links=1)
    top_meta, _, top_meta_sha = _read_json(MODELS / pair["top_metadata_path"], links=1)
    fit, _, fit_sha = _read_json(RUNS / pair["fit_receipt_path"])
    validation, _, validation_sha = _read_json(VALIDATIONS / pair["validation_receipt_path"])
    recal, _, recal_sha = _read_json(TOP_RECEIPTS / pair["recalibration_receipt_path"])
    if (cal_meta_sha != pair["cal_metadata_sha256"]
            or top_meta_sha != pair["top_metadata_sha256"]
            or fit_sha != pair["fit_receipt_sha256"]
            or validation_sha != pair["validation_receipt_sha256"]
            or recal_sha != pair["recalibration_receipt_sha256"]):
        raise ReclaimError("model metadata or a pinned fit/validation/recalibration receipt changed")
    _validate_pair_binding(cal_meta, top_meta, fit, recal, validation,
                           pair["run_id"], dataset_sha256)
    if (cal_meta.get("sha256") != pair["sha256"]
            or top_meta.get("sha256") != pair["sha256"]
            or fit.get("model_sha256") != pair["sha256"]
            or recal.get("model_sha256") != pair["sha256"]):
        raise ReclaimError("frozen receipts no longer bind to the approved model SHA")


def _verify_fit_artifacts(manifest: dict, *, hash_bytes: bool) -> None:
    for item in manifest.get("fit_artifacts", []):
        metadata, _, metadata_sha = _read_json(MODELS / item["metadata_path"], links=1)
        if (metadata_sha != item["metadata_sha256"]
                or metadata.get("model_version") != item["version"]
                or metadata.get("sha256") != item["binary_sha256"]):
            raise ReclaimError("protected fit metadata changed")
        path = MODELS / item["binary_path"]
        if hash_bytes:
            digest, signature = _hash_regular(path, expected=item["binary_signature"])
            if digest != item["binary_sha256"]:
                raise ReclaimError("protected fit binary changed")
        else:
            info = _safe_regular(path, max_bytes=MAX_MODEL_BYTES, links=1)
            if not _signature_matches(info, item["binary_signature"]):
                raise ReclaimError("protected fit binary signature changed")


def _verify_pair_completed(pair: dict, done_path: Path, identity: dict) -> dict:
    done = _read_journal(done_path, identity)
    if done is None or done.get("state") != "VERIFIED_DONE":
        raise ReclaimError("completed dedup journal required")
    model_dir_fd = os.open(MODELS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        cal_fd, cal_info = _model_fd(model_dir_fd, pair["cal_path"], link_count=2)
        top_fd, top_info = _model_fd(model_dir_fd, pair["top_path"], link_count=2)
        try:
            if (cal_info.st_dev, cal_info.st_ino) != (top_info.st_dev, top_info.st_ino):
                raise ReclaimError("completed model names no longer share the approved inode")
            if _digest_fd(cal_fd) != pair["sha256"]:
                raise ReclaimError("completed model bytes differ from approved SHA")
        finally:
            os.close(cal_fd)
            os.close(top_fd)
    finally:
        os.close(model_dir_fd)
    return done


def _deduplicate_one(pair: dict, session: Path, manifest_sha: str,
                     approval_sha: str) -> dict:
    intent_path, done_path, rollback_path, rolled_path = _pair_records(session, pair["pair_id"])
    identity = _record_identity(manifest_sha, approval_sha, pair)
    if rolled_path.exists() or rollback_path.exists():
        raise ReclaimError("pair has rollback state and cannot be deduplicated again")
    done = _read_journal(done_path, identity)
    if done is not None:
        _verify_pair_frozen_inputs(pair, _authority_snapshot()["dataset_sha256"])
        return _verify_pair_completed(pair, done_path, identity)

    _verify_pair_frozen_inputs(pair, _authority_snapshot()["dataset_sha256"])
    temp_name = pair["temporary_name"]
    if temp_name != ".storage-dedup-" + pair["pair_id"] + ".pending":
        raise ReclaimError("temporary basename does not match pinned pair id")
    intent = _read_journal(intent_path, identity)
    model_dir_fd = os.open(MODELS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if intent is None:
            if (MODELS / temp_name).exists():
                raise ReclaimError("unjournaled temporary model link exists")
            cal_fd, cal_info = _model_fd(model_dir_fd, pair["cal_path"],
                                         pair["cal_signature"], link_count=1)
            top_fd, top_info = _model_fd(model_dir_fd, pair["top_path"],
                                         pair["top_signature"], link_count=1)
            try:
                if _digest_fd(cal_fd) != pair["sha256"] or _digest_fd(top_fd) != pair["sha256"]:
                    raise ReclaimError("pre-apply full model SHA verification failed")
            finally:
                os.close(cal_fd)
                os.close(top_fd)
            intent = _write_journal(intent_path, identity, "INTENT_DURABLE", {
                "temporary_name": temp_name,
                "canonical_signature": _file_signature(cal_info),
                "target_signature": _file_signature(top_info),
            })
        elif (intent.get("temporary_name") != temp_name
              or intent.get("state") not in {"INTENT_DURABLE", "TEMP_LINK_CREATED", "TARGET_REPLACED"}):
            raise ReclaimError("unrecognized model transaction intent")

        cal_fd, cal_info = _model_fd(model_dir_fd, pair["cal_path"])
        try:
            temp_path = MODELS / temp_name
            target_path = MODELS / pair["top_path"]
            if not temp_path.exists() and not target_path.exists():
                raise ReclaimError("model paths missing during dedup transaction")
            if not temp_path.exists():
                target_info = target_path.lstat()
                if ((target_info.st_dev, target_info.st_ino) == (cal_info.st_dev, cal_info.st_ino)
                        and target_info.st_nlink == 2 and cal_info.st_nlink == 2):
                    # Recovery after atomic replace but before its journal update.
                    pass
                else:
                    if intent["state"] not in {"INTENT_DURABLE", "TEMP_LINK_CREATED"}:
                        raise ReclaimError("dedup temp is missing after its recorded creation")
                    if ((target_info.st_dev, target_info.st_ino)
                            != (intent["target_signature"]["dev"], intent["target_signature"]["ino"])
                            or target_info.st_nlink != 1 or cal_info.st_nlink != 1):
                        raise ReclaimError("target inode changed before temporary hard-link creation")
                    os.link(pair["cal_path"], temp_name, src_dir_fd=model_dir_fd,
                            dst_dir_fd=model_dir_fd, follow_symlinks=False)
                    _fsync_dir(MODELS)
            if temp_path.exists():
                temp_info = temp_path.lstat()
                if (not stat.S_ISREG(temp_info.st_mode) or stat.S_ISLNK(temp_info.st_mode)
                        or (temp_info.st_dev, temp_info.st_ino) != (cal_info.st_dev, cal_info.st_ino)
                        or temp_info.st_nlink != 2):
                    raise ReclaimError("temporary path is not the pinned canonical hard link")
                target_info = target_path.lstat()
                if intent["state"] in {"INTENT_DURABLE", "TEMP_LINK_CREATED"}:
                    if ((target_info.st_dev, target_info.st_ino)
                            != (intent["target_signature"]["dev"], intent["target_signature"]["ino"])
                            or target_info.st_nlink != 1):
                        raise ReclaimError("target inode changed before atomic replacement")
                    _write_journal(intent_path, identity, "TEMP_LINK_CREATED", {
                        "temporary_name": temp_name,
                        "canonical_signature_before_link": intent["canonical_signature"],
                        "target_signature": intent["target_signature"],
                        "temporary_signature": _file_signature(temp_info),
                    })
                    os.replace(temp_name, pair["top_path"], src_dir_fd=model_dir_fd,
                               dst_dir_fd=model_dir_fd)
                    _fsync_dir(MODELS)
                else:
                    raise ReclaimError("unexpected temp link after target-replaced state")
            else:
                top_info = target_path.lstat()
                if ((top_info.st_dev, top_info.st_ino) != (cal_info.st_dev, cal_info.st_ino)
                        or top_info.st_nlink != 2):
                    raise ReclaimError("target replacement state is not recognized")

            final_cal_fd, final_cal = _model_fd(model_dir_fd, pair["cal_path"], link_count=2)
            final_top_fd, final_top = _model_fd(model_dir_fd, pair["top_path"], link_count=2)
            try:
                if ((final_cal.st_dev, final_cal.st_ino) != (final_top.st_dev, final_top.st_ino)
                        or _digest_fd(final_cal_fd) != pair["sha256"]):
                    raise ReclaimError("post-apply pair SHA/inode verification failed")
                final_signature = _file_signature(final_cal)
            finally:
                os.close(final_cal_fd)
                os.close(final_top_fd)
            intent = _read_journal(intent_path, identity)
            if intent is None:
                raise ReclaimError("durable model intent lost")
            _write_journal(intent_path, identity, "TARGET_REPLACED", {
                "temporary_name": temp_name,
                "target_shared_signature": final_signature,
                "target_original_signature": intent.get("target_signature"),
            })
            done_record = _write_journal(done_path, identity, "VERIFIED_DONE", {
                "temporary_name": temp_name,
                "target_original_signature": intent.get("target_signature"),
                "shared_signature": final_signature,
                "expected_reclaimed_blocks": pair["allocated_bytes_reclaimable"],
                "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            return done_record
        finally:
            os.close(cal_fd)
    finally:
        os.close(model_dir_fd)


def _apply(session: Path, manifest_path: Path, manifest_sha: str,
           approval_path: Path, approval_sha: str, *,
           max_pairs: int, pair_id: str | None = None) -> dict:
    if type(max_pairs) is not int or not 1 <= max_pairs <= MAX_BATCH:
        raise ReclaimError("bounded batch size 1 through 25 required")
    session = _session_dir(session, create=False)
    manifest, _, digest = _load_manifest(manifest_path, manifest_sha)
    _load_authority(manifest, digest, approval_path, approval_sha)
    _current_authority_matches(manifest)
    _verify_fit_artifacts(manifest, hash_bytes=False)
    with _maintenance_window():
        _current_authority_matches(manifest)
        _verify_fit_artifacts(manifest, hash_bytes=False)
        if pair_id is not None:
            selected = [_manifest_pair(manifest, pair_id)]
            max_pairs = 1
        else:
            selected = []
            for pair in manifest["pairs"]:
                _, done_path, rollback_path, rolled_path = _pair_records(session, pair["pair_id"])
                if rolled_path.exists() or rollback_path.exists():
                    raise ReclaimError("rollback transaction exists in approved apply batch")
                if done_path.exists():
                    _verify_pair_completed(pair, done_path,
                                           _record_identity(digest, approval_sha, pair))
                    continue
                selected.append(pair)
                if len(selected) == max_pairs:
                    break
        if not selected:
            return {"status": "ALREADY_COMPLETE", "pairs_done": len(manifest["pairs"]),
                    "bytes_logical_reclaimed": manifest["total_pair_logical_bytes"]}
        free_before = shutil.disk_usage(MODELS).free
        expected_peak = max(pair["bytes"] for pair in selected) + UNIT_MARGIN_BYTES
        if free_before < RESERVE_BYTES + expected_peak:
            raise ReclaimError("insufficient free space for reserve and bounded unit margin")
        applied = []
        for pair in selected:
            applied.append(_deduplicate_one(pair, session, digest, approval_sha))
        # All helper descriptors to the replaced target inodes are closed before
        # measuring free blocks; outside processes were checked with lsof.
        free_after = shutil.disk_usage(MODELS).free
        completed = sum(1 for pair in manifest["pairs"]
                        if (_pair_records(session, pair["pair_id"])[1]).exists())
        return {
            "status": "BATCH_COMPLETED",
            "pairs_this_batch": len(applied),
            "pairs_completed": completed,
            "pairs_remaining": len(manifest["pairs"]) - completed,
            "expected_logical_bytes_retired": sum(pair["bytes"] for pair in selected),
            "expected_allocated_bytes_retired": sum(pair["allocated_bytes_reclaimable"] for pair in selected),
            "free_before_bytes": free_before,
            "free_after_bytes": free_after,
            "free_delta_observed_bytes": free_after - free_before,
            "note": "Free-space delta includes filesystem activity; per-inode bytes are journaled separately.",
        }


def _independent_pair_signatures(model_dir_fd: int, pair: dict) -> tuple[dict, dict]:
    cal_fd, cal_info = _model_fd(model_dir_fd, pair["cal_path"], link_count=1)
    top_fd, top_info = _model_fd(model_dir_fd, pair["top_path"], link_count=1)
    try:
        if ((cal_info.st_dev, cal_info.st_ino) == (top_info.st_dev, top_info.st_ino)
                or _digest_fd(cal_fd) != pair["sha256"]
                or _digest_fd(top_fd) != pair["sha256"]):
            raise ReclaimError("independent rollback bytes/inodes do not match")
        return _file_signature(cal_info), _file_signature(top_info)
    finally:
        os.close(cal_fd)
        os.close(top_fd)


def _rollback_one(pair: dict, session: Path, manifest_sha: str,
                  approval_sha: str, dataset_sha256: str) -> dict:
    _, done_path, rollback_path, rolled_path = _pair_records(session, pair["pair_id"])
    identity = _record_identity(manifest_sha, approval_sha, pair)
    done = _read_journal(done_path, identity)
    if done is None or done.get("state") != "VERIFIED_DONE":
        raise ReclaimError("only a completed approved pair can be rolled back")
    temp_name = ".storage-rollback-" + pair["pair_id"] + ".pending"
    rollback = _read_journal(rollback_path, identity)
    if rollback is not None and rollback.get("temporary_name") != temp_name:
        raise ReclaimError("rollback temp path differs from pinned intent")
    model_dir_fd = os.open(MODELS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if rolled_path.exists():
            record = _read_journal(rolled_path, identity)
            if record is None or record.get("state") != "ROLLED_BACK":
                raise ReclaimError("rollback completion journal mismatch")
            _independent_pair_signatures(model_dir_fd, pair)
            return record

        target_path = MODELS / pair["top_path"]
        temp_path = MODELS / temp_name
        temp_exists = temp_path.exists()
        if rollback is not None and (
                rollback.get("state") == "ROLLBACK_TARGET_REPLACED"
                or (rollback.get("state") == "ROLLBACK_TEMP_VERIFIED" and not temp_exists)):
            # Crash after atomic replace and before the final journal write.
            canonical_signature, target_signature = _independent_pair_signatures(model_dir_fd, pair)
            _write_journal(rollback_path, identity, "ROLLBACK_TARGET_REPLACED", {
                "temporary_name": temp_name,
                "target_restored_signature": target_signature,
                "expected_sha256": pair["sha256"],
            })
            return _write_journal(rolled_path, identity, "ROLLED_BACK", {
                "canonical_signature": canonical_signature,
                "target_restored_signature": target_signature,
                "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        if rollback is None:
            _verify_pair_completed(pair, done_path, identity)
            free = shutil.disk_usage(MODELS).free
            if free < RESERVE_BYTES + pair["bytes"] + UNIT_MARGIN_BYTES:
                raise ReclaimError("rollback requires space for one independent model plus reserve")
            target_info = target_path.lstat()
            rollback = _write_journal(rollback_path, identity, "ROLLBACK_INTENT_DURABLE", {
                "temporary_name": temp_name,
                "target_shared_signature": _file_signature(target_info),
            })
        elif rollback.get("state") not in {"ROLLBACK_INTENT_DURABLE", "ROLLBACK_TEMP_VERIFIED"}:
            raise ReclaimError("unrecognized rollback intent")

        cal_fd, cal_info = _model_fd(model_dir_fd, pair["cal_path"], link_count=2)
        top_fd, top_info = _model_fd(model_dir_fd, pair["top_path"], link_count=2)
        try:
            if ((cal_info.st_dev, cal_info.st_ino) != (top_info.st_dev, top_info.st_ino)
                    or _digest_fd(cal_fd) != pair["sha256"]):
                raise ReclaimError("shared canonical model changed before rollback")
        finally:
            os.close(cal_fd)
            os.close(top_fd)

        if temp_exists:
            temp_sha, temp_sig = _hash_regular(temp_path)
            if (temp_sha != pair["sha256"] or temp_sig["size"] != pair["bytes"]
                    or temp_sig["nlink"] != 1):
                raise ReclaimError("rollback temporary bytes do not match canonical SHA")
            if rollback.get("state") == "ROLLBACK_INTENT_DURABLE":
                rollback = _write_journal(rollback_path, identity, "ROLLBACK_TEMP_VERIFIED", {
                    "temporary_name": temp_name,
                    "temporary_signature": temp_sig,
                    "target_shared_signature": _file_signature(target_path.stat(follow_symlinks=False)),
                })
        else:
            if rollback.get("state") != "ROLLBACK_INTENT_DURABLE":
                raise ReclaimError("rollback temp disappeared before replacement")
            if shutil.disk_usage(MODELS).free < RESERVE_BYTES + pair["bytes"] + UNIT_MARGIN_BYTES:
                raise ReclaimError("insufficient free space for rollback temp")
            temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=model_dir_fd)
            try:
                source_fd, _ = _model_fd(model_dir_fd, pair["cal_path"], link_count=2)
                try:
                    digest = hashlib.sha256()
                    copied = 0
                    while True:
                        block = os.read(source_fd, 1024 * 1024)
                        if not block:
                            break
                        copied += len(block)
                        if copied > pair["bytes"]:
                            raise ReclaimError("rollback copy exceeded approved size")
                        digest.update(block)
                        view = memoryview(block)
                        while view:
                            written = os.write(temp_fd, view)
                            view = view[written:]
                    if copied != pair["bytes"] or digest.hexdigest() != pair["sha256"]:
                        raise ReclaimError("rollback copy SHA mismatch")
                    os.fsync(temp_fd)
                finally:
                    os.close(source_fd)
            finally:
                os.close(temp_fd)
            _fsync_dir(MODELS)
            temp_sha, temp_sig = _hash_regular(temp_path)
            if temp_sha != pair["sha256"] or temp_sig["size"] != pair["bytes"]:
                raise ReclaimError("rollback temp read-back mismatch")
            rollback = _write_journal(rollback_path, identity, "ROLLBACK_TEMP_VERIFIED", {
                "temporary_name": temp_name,
                "temporary_signature": temp_sig,
                "target_shared_signature": _file_signature(target_path.stat(follow_symlinks=False)),
            })

        target_stat = target_path.lstat()
        canonical_stat = (MODELS / pair["cal_path"]).lstat()
        if ((target_stat.st_dev, target_stat.st_ino) != (canonical_stat.st_dev, canonical_stat.st_ino)
                or target_stat.st_nlink != 2):
            raise ReclaimError("rollback target changed before independent restore")
        os.replace(temp_name, pair["top_path"], src_dir_fd=model_dir_fd,
                   dst_dir_fd=model_dir_fd)
        _fsync_dir(MODELS)
        canonical_signature, target_signature = _independent_pair_signatures(model_dir_fd, pair)
        _write_journal(rollback_path, identity, "ROLLBACK_TARGET_REPLACED", {
            "temporary_name": temp_name,
            "target_restored_signature": target_signature,
            "expected_sha256": pair["sha256"],
        })
        return _write_journal(rolled_path, identity, "ROLLED_BACK", {
            "canonical_signature": canonical_signature,
            "target_restored_signature": target_signature,
            "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    finally:
        os.close(model_dir_fd)


def rollback_one(session: Path, manifest_path: Path, manifest_sha: str,
                 approval_path: Path, approval_sha: str, pair_id: str) -> dict:
    session = _session_dir(session, create=False)
    manifest, _, digest = _load_manifest(manifest_path, manifest_sha)
    _load_authority(manifest, digest, approval_path, approval_sha)
    _current_authority_matches(manifest)
    _verify_fit_artifacts(manifest, hash_bytes=False)
    pair = _manifest_pair(manifest, pair_id)
    with _maintenance_window():
        _current_authority_matches(manifest)
        _verify_fit_artifacts(manifest, hash_bytes=False)
        return _rollback_one(pair, session, digest, approval_sha,
                             manifest["dataset_sha256"])


def verify_session(session: Path, manifest_path: Path, manifest_sha: str,
                   approval_path: Path, approval_sha: str, mode: str) -> dict:
    session = _session_dir(session, create=False)
    if mode not in {"before", "after"}:
        raise ReclaimError("verification mode must be before or after")
    manifest, _, digest = _load_manifest(manifest_path, manifest_sha)
    _load_authority(manifest, digest, approval_path, approval_sha)
    _current_authority_matches(manifest)
    _verify_fit_artifacts(manifest, hash_bytes=False)
    with _maintenance_window():
        _current_authority_matches(manifest)
        _verify_fit_artifacts(manifest, hash_bytes=False)
        completed = 0
        verified_bytes = 0
        for pair in manifest["pairs"]:
            intent_path, done_path, rollback_path, rolled_path = _pair_records(session, pair["pair_id"])
            identity = _record_identity(digest, approval_sha, pair)
            if rolled_path.exists():
                if mode == "after":
                    raise ReclaimError("a rolled-back pair is not in the deduplicated final state")
                _verify_pair_frozen_inputs(pair, manifest["dataset_sha256"])
                model_dir_fd = os.open(MODELS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _, target = _independent_pair_signatures(model_dir_fd, pair)
                finally:
                    os.close(model_dir_fd)
                record = _read_journal(rolled_path, identity)
                if record is None or record.get("state") != "ROLLED_BACK":
                    raise ReclaimError("rollback journal mismatch")
                if (target["ino"] != record.get("target_restored_signature", {}).get("ino")
                        or target["size"] != pair["bytes"]):
                    raise ReclaimError("rolled-back target differs from journal")
                continue
            if done_path.exists():
                _verify_pair_frozen_inputs(pair, manifest["dataset_sha256"])
                _verify_pair_completed(pair, done_path, identity)
                completed += 1
                verified_bytes += pair["bytes"]
            elif mode == "after":
                raise ReclaimError("not all approved pairs are deduplicated")
            else:
                if intent_path.exists() or rollback_path.exists():
                    raise ReclaimError("pending transaction requires explicit resume/rollback")
                for path, expected in ((MODELS / pair["cal_path"], pair["cal_signature"]),
                                       (MODELS / pair["top_path"], pair["top_signature"])):
                    actual, signature = _hash_regular(path, expected=expected)
                    if actual != pair["sha256"] or signature["nlink"] != 1:
                        raise ReclaimError("pre-apply model pair differs from verified manifest")
        if mode == "after" and completed != len(manifest["pairs"]):
            raise ReclaimError("completed-pair count mismatch")
        if mode == "after":
            _verify_fit_artifacts(manifest, hash_bytes=True)
        return {
            "status": "VERIFIED_" + mode.upper(),
            "pairs_total": len(manifest["pairs"]),
            "pairs_deduplicated": completed,
            "logical_bytes_with_two_names": verified_bytes,
            "holdout_scored": False,
            "quality_gate": "NOT_RUN",
            "aws_changed": False,
        }


def _parse_args(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="read-only inventory and full SHA verification")
    plan.add_argument("--output", type=Path, required=True)

    authorize = sub.add_parser("authorize", help="write approval bound to this exact manifest/helper")
    authorize.add_argument("--manifest", type=Path, required=True)
    authorize.add_argument("--manifest-sha256", required=True)
    authorize.add_argument("--authorization-reference", required=True)

    for name in ("apply", "resume"):
        command = sub.add_parser(name, help="apply or resume one bounded explicit batch")
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--manifest-sha256", required=True)
        command.add_argument("--approval", type=Path, required=True)
        command.add_argument("--approval-sha256", required=True)
        command.add_argument("--max-pairs", type=int, default=1)
        command.add_argument("--pair-id")

    rollback = sub.add_parser("rollback", help="restore one model alias as independent bytes")
    rollback.add_argument("--manifest", type=Path, required=True)
    rollback.add_argument("--manifest-sha256", required=True)
    rollback.add_argument("--approval", type=Path, required=True)
    rollback.add_argument("--approval-sha256", required=True)
    rollback.add_argument("--pair-id", required=True)

    verify = sub.add_parser("verify", help="verify all pairs without fitting or scoring")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--manifest-sha256", required=True)
    verify.add_argument("--approval", type=Path, required=True)
    verify.add_argument("--approval-sha256", required=True)
    verify.add_argument("--mode", choices=("before", "after"), required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "plan":
            path, digest = create_plan(args.output)
            manifest, _, _ = _read_json(path, max_bytes=64 * 1024 * 1024, links=1)
            print(canonical({
                "status": "VERIFIED_ALLOWLIST",
                "manifest": str(path),
                "manifest_sha256": digest,
                "pair_count": manifest["pair_count"],
                "logical_bytes": manifest["total_pair_logical_bytes"],
                "allocated_bytes_estimate": manifest["expected_unique_blocks_reclaimable"],
                "holdout_scored": False,
                "quality_gate": "NOT_RUN",
                "aws_changed": False,
            }).decode())
            return 0
        if args.command == "authorize":
            session = _session_dir(args.manifest.parent, create=False)
            path, digest = create_approval(args.manifest, args.manifest_sha256,
                                           args.authorization_reference,
                                           session / "approval.private.json")
            print(canonical({"status": "APPROVED_EXACT_ALLOWLIST",
                             "approval": str(path), "approval_sha256": digest}).decode())
            return 0
        if args.command in {"apply", "resume"}:
            session = _session_dir(args.manifest.parent, create=False)
            result = _apply(session, args.manifest, args.manifest_sha256,
                            args.approval, args.approval_sha256,
                            max_pairs=args.max_pairs, pair_id=args.pair_id)
        elif args.command == "rollback":
            session = _session_dir(args.manifest.parent, create=False)
            result = rollback_one(session, args.manifest, args.manifest_sha256,
                                 args.approval, args.approval_sha256, args.pair_id)
        else:
            session = _session_dir(args.manifest.parent, create=False)
            result = verify_session(session, args.manifest, args.manifest_sha256,
                                   args.approval, args.approval_sha256, args.mode)
        print(canonical(result).decode())
        return 0
    except (OSError, ReclaimError, subprocess.SubprocessError) as failure:
        print("Deduplication refused/failed: " + type(failure).__name__ +
              "; preserve the session journal and model files.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
