#!/usr/bin/env python3
"""STORAGE_ONLY archives of SHA-pinned completed PILOT source/cache bytes.

No original is changed, removed, renamed, or unpickled. No model fitting,
scoring, qualification, live STRICT-source access, or holdout access occurs.
The bounded archive reader is a future-coordinator building block, not a
change to catalog.py, ModelStore, calibration, or any serving interface.
"""
import argparse
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import sqlite3
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
CATALOG = ROOT / "observability/runtime/hybrid-bulk-20261004-Y6aJhfoH/normal-catalog-v2"
CATALOG_SHA = "6bc1961168954a7a53287bf4a4eedcd56b94ab3f22c6625803f2cb94b85a9788"
GRID = ROOT / "observability/runtime/hybrid-bulk-grid-20261004-hqYCI8wc/grid"
GRID_SHA = "9bb44c4aa7294f32bb7d5d55b74a616a73a97b87675a3adc313c0f0f39e564c5"
MODEL_PROBE = ROOT / "observability/runtime/hybrid-strict-storage-20261004-DvnwrvCQ/probe/result.private.json"
MODEL_PROBE_SHA = "32592bea58e3a4fd487d8b2e8e98e89c8f070c561fbd7d9ad46b367bb385630d"
MAX_JSON_BYTES = 8 * 1024 ** 2
POPULATIONS = {"fold1-fit": 50_000, "fold1-calibration-ready": 60_000,
               "fold1-calibration-cold": 60_000, "fold1-validation": 21_000}
SHARDS = {"fold1-fit": 391, "fold1-calibration-ready": 14,
          "fold1-calibration-cold": 24, "fold1-validation": 7}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def private_path(path, *, directory=False):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink path refused")
    mode = path.stat().st_mode
    if mode & 0o077 or not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError("private regular path required")
    return path


def trusted_source(path, digest, maximum=MAX_JSON_BYTES):
    path = private_path(path)
    if not 0 < path.stat().st_size <= maximum or checksum(path) != digest:
        raise ValueError("trusted source size/hash mismatch")
    return path


def trusted_json(path, digest):
    return json.loads(trusted_source(path, digest).read_text(encoding="utf-8"))


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        target.write(canonical(value)); target.flush(); os.fsync(target.fileno())


def archive_bytes(source, digest, path, maximum=MAX_JSON_BYTES):
    source = trusted_source(source, digest, maximum)
    private_path(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        raise ValueError("new private archive required")
    started = time.monotonic()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target, source.open("rb") as original:
        with lzma.LZMAFile(target, "w", preset=3) as compressed:
            for block in iter(lambda: original.read(65536), b""):
                compressed.write(block)
        target.flush(); os.fsync(target.fileno())
    receipt = {"original_sha256": digest, "original_bytes": source.stat().st_size,
               "archive_sha256": checksum(path), "archive_bytes": path.stat().st_size,
               "archive_path": str(path), "save_seconds": time.monotonic() - started}
    started = time.monotonic()
    restored = read_verified_archive(receipt, maximum=maximum)
    receipt.update(restore_hash_seconds=time.monotonic() - started,
                   restored_sha256=hashlib.sha256(restored).hexdigest(), byte_for_byte_identical=True)
    if checksum(source) != digest:
        raise ValueError("original source changed during archive")
    return receipt


def read_verified_archive(receipt, maximum=MAX_JSON_BYTES):
    """Restore one bounded byte blob in memory; never rewrites source paths."""
    if (type(maximum) is not int or not 1 <= maximum <= MAX_JSON_BYTES
            or type(receipt.get("original_bytes")) is not int
            or not 0 < receipt["original_bytes"] <= maximum):
        raise ValueError("bounded archive size required")
    path = trusted_source(receipt["archive_path"], receipt["archive_sha256"], maximum + 65536)
    raw = bytearray()
    with lzma.open(path, "rb") as source:
        while True:
            block = source.read(min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > maximum:
                raise ValueError("archive exceeds bounded restore budget")
    if len(raw) != receipt["original_bytes"] or hashlib.sha256(raw).hexdigest() != receipt["original_sha256"]:
        raise ValueError("restored byte hash/size mismatch")
    return bytes(raw)


def source_path(relative):
    if type(relative) is not str:
        raise ValueError("plain relative shard path required")
    path = (CATALOG / relative).absolute()
    if not path.is_relative_to(CATALOG) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("catalog shard path escape refused")
    return path


def collect_sources():
    manifest = trusted_json(CATALOG / "manifest.json", CATALOG_SHA)
    grid = trusted_json(GRID / "result.private.json", GRID_SHA)
    previous = trusted_json(MODEL_PROBE, MODEL_PROBE_SHA)
    if (manifest.get("stage") != "PILOT" or manifest.get("feature_schema_version") != 4
            or grid.get("status") != "COMPLETED" or len(grid.get("configurations", [])) != 24
            or previous.get("status") != "COMPLETED" or previous.get("artifacts") != 24
            or previous.get("fit_calls") != 0):
        raise ValueError("fixed completed PILOT provenance required")
    sources = {CATALOG / "manifest.json": CATALOG_SHA, GRID / "result.private.json": GRID_SHA,
               MODEL_PROBE: MODEL_PROBE_SHA}
    contract_path = ROOT / "ueba-worker/app/contract.py"
    contract_sha = grid["integrity_before"]["sources"]["ueba-worker/app/contract.py"]
    if contract_path.is_symlink() or checksum(contract_path) != contract_sha:
        raise ValueError("existing numeric feature boundary source drift")
    sources[contract_path] = contract_sha
    for role, records in POPULATIONS.items():
        split = manifest["splits"][role]
        if (split["records"] != records or len(split["shards"]) != SHARDS[role]
                or sum(item["records"] for item in split["shards"]) != records):
            raise ValueError("exact actual PILOT descriptor population required")
        for descriptor in split["shards"]:
            path = source_path(descriptor["path"])
            trusted_source(path, descriptor["sha256"])
            sources[path] = descriptor["sha256"]
    for trial in grid["configurations"]:
        folder = GRID / f"candidate-{trial['ordinal']:02d}"
        for relative in ("calibration.private.json", "scores-decisions.private.jsonl"):
            path = folder / relative
            trusted_source(path, trial["private_artifacts"][relative])
            sources[path] = trial["private_artifacts"][relative]
    for kind, receipt in previous["journal_evidence"].items():
        relative = {"uniqueness_journal": "integrity-abec3f8947209b80b5a2dabf/episodes.sqlite",
                    "rule_journal": "rules-69016ef1191b8385879d23c8/rules.sqlite",
                    "rule_decisions": "rules-69016ef1191b8385879d23c8/rules.u8"}[kind]
        path = GRID / "descriptive-rule-cache" / relative
        trusted_source(path, receipt["sha256"])
        if path.suffix == ".sqlite":
            if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal", "-shm")):
                raise ValueError("only closed checkpointed SQLite journals may be archived")
            with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                binding = json.loads(db.execute("SELECT payload FROM identity").fetchone()[0])
                if binding.get("dataset_sha256") != CATALOG_SHA or binding.get("split_sha256") != manifest["splits"]["fold1-validation"]["sha256"]:
                    raise ValueError("cache journal catalog binding mismatch")
        sources[path] = receipt["sha256"]
    return manifest, grid, previous, sources


def new_binary(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def validation_tensor(archived_shards, path):
    sys.path.insert(0, str(ROOT / "ueba-worker"))
    from app.contract import feature_array
    count = 0; cohorts = {}
    with new_binary(path) as target:
        for descriptor, receipt in archived_shards:
            rows = json.loads(read_verified_archive(receipt))
            if type(rows) is not list or len(rows) != descriptor["records"]:
                raise ValueError("archived shard descriptor/body population mismatch")
            actual_features = feature_array([row["features"] for row in rows], 5000, 4)
            shard_cohorts = {}
            for row in rows:
                cohort = row["cohort"]
                if cohort not in ("READY", "UNSEEN_READY", "COLD"):
                    raise ValueError("exact source cohort required")
                cohorts[cohort] = cohorts.get(cohort, 0) + 1
                shard_cohorts[cohort] = shard_cohorts.get(cohort, 0) + 1
                count += 1
            if shard_cohorts != descriptor["cohorts"]:
                raise ValueError("archived source cohort descriptor changed")
            target.write(actual_features.astype("<f8", copy=False).tobytes())
        target.flush(); os.fsync(target.fileno())
    if (count != 21_000 or path.stat().st_size != count * 37 * 8
            or cohorts != {"READY": 14_700, "UNSEEN_READY": 4_200, "COLD": 2_100}):
        raise ValueError("complete actual validation tensor required")
    return {"rows": count, "columns": 37, "bytes": path.stat().st_size,
            "sha256": checksum(path), "dtype": "little_endian_float64", "cohorts_checked_from_immutable_source": cohorts,
            "labels_or_identifiers_in_tensor": False}


def actual_raw_scores(trial, path):
    source = GRID / f"candidate-{trial['ordinal']:02d}/scores-decisions.private.jsonl"
    digest = trial["private_artifacts"]["scores-decisions.private.jsonl"]
    trusted_source(source, digest)
    count = 0
    with new_binary(path) as target, source.open("r", encoding="utf-8") as saved:
        for line in saved:
            if len(line) > 8192:
                raise ValueError("bounded trusted score record required")
            value = json.loads(line)["raw_anomaly_score"]
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("finite actual recorded score required")
            target.write(struct.pack("<d", value)); count += 1
        target.flush(); os.fsync(target.fileno())
    if count != 21_000 or checksum(path) != trial["raw_score_sha256"] or checksum(source) != digest:
        raise ValueError("existing genuine recorded score correspondence/hash changed")
    return {"ordinal": trial["ordinal"], "rows": count, "bytes": path.stat().st_size,
            "sha256": checksum(path), "source_journal_sha256": digest, "score_calls": 0}


def run(output):
    if (os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE or not Path("/.dockerenv").exists()
            or any(os.environ.get(name) != "1" for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"))):
        raise ValueError("pinned single-thread Docker context required")
    output = Path(output).absolute(); private_path(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise ValueError("new private archive probe output required")
    manifest, grid, previous, sources = collect_sources()
    output.mkdir(mode=0o700); blobs = output / "archives"; blobs.mkdir(mode=0o700)
    declaration = {"scope": "STORAGE_ONLY", "data_scope": "COMPLETED_PILOT_ONLY",
        "quality_gate": "NOT_APPLICABLE", "catalog_sha256": CATALOG_SHA, "grid_sha256": GRID_SHA,
        "image_id": IMAGE, "populations": POPULATIONS, "shards": SHARDS,
        "fit_calls": 0, "score_calls": 0, "holdout_rows_read": 0, "live_strict_source_rows_read": 0,
        "maximum_restored_json_bytes": MAX_JSON_BYTES, "originals_modified_or_deleted": False}
    write_new(output / "predeclared.private.json", declaration)
    receipts = {}
    def archive(source, digest):
        if digest not in receipts:
            receipts[digest] = archive_bytes(source, digest, blobs / (digest + ".xz"))
        return receipts[digest]
    archive(CATALOG / "manifest.json", CATALOG_SHA)
    roles = {}; validation = []
    for role, population in POPULATIONS.items():
        rows = []
        for descriptor in manifest["splits"][role]["shards"]:
            receipt = archive(source_path(descriptor["path"]), descriptor["sha256"])
            body = json.loads(read_verified_archive(receipt))
            if type(body) is not list or len(body) != descriptor["records"]:
                raise ValueError("actual archived descriptor/body row count mismatch")
            row = {"descriptor": descriptor, "archive": receipt,
                   "compressed_bytes_per_row": receipt["archive_bytes"] / descriptor["records"]}
            rows.append(row)
            if role == "fold1-validation": validation.append((descriptor, receipt))
        roles[role] = {"records": population, "shards": len(rows),
            "original_bytes": sum(row["archive"]["original_bytes"] for row in rows),
            "archive_bytes": sum(row["archive"]["archive_bytes"] for row in rows),
            "worst_empirical_compressed_bytes_per_row": max(row["compressed_bytes_per_row"] for row in rows),
            "shard_receipts": rows}
        print(canonical({"archived_role": role, **{key: value for key, value in roles[role].items() if key != "shard_receipts"}}), flush=True)
    cache_receipts = {}
    for source, digest in sources.items():
        if "descriptive-rule-cache" in source.parts:
            cache_receipts[source.name] = archive(source, digest)
    calibration = []
    for trial in grid["configurations"]:
        source = GRID / f"candidate-{trial['ordinal']:02d}/calibration.private.json"
        calibration.append({"ordinal": trial["ordinal"],
                            "archive": archive(source, trial["private_artifacts"]["calibration.private.json"])})
    tensor_path = output / "actual-validation-features.f64"
    tensor = validation_tensor(validation, tensor_path)
    tensor["archive"] = archive(tensor_path, tensor["sha256"])
    raw_scores = []
    for ordinal in (0, 23):
        path = output / f"candidate-{ordinal:02d}-actual-validation-raw.f64"
        row = actual_raw_scores(grid["configurations"][ordinal], path)
        row["archive"] = archive(path, row["sha256"]); raw_scores.append(row)
    if any(checksum(source) != digest for source, digest in sources.items()):
        raise ValueError("original source changed during archive probe")
    worst_row_bytes = max(role["worst_empirical_compressed_bytes_per_row"] for role in roles.values())
    journal_ratio = max(receipt["archive_bytes"] / receipt["original_bytes"]
                        for name, receipt in cache_receipts.items() if name.endswith(".sqlite"))
    staged = {"765_model_archives_empirical_upper": 765 * previous["worst_empirical_million_compressed_bytes"],
        "source_json_archives_empirical_upper": math.ceil(19_257_500 * worst_row_bytes),
        "raw_score_caches_retained_without_compression_assumption": 8_640_000_000,
        "separate_sorted_arrays_already_inside_model_archive": 0,
        "one_active_maximum_split_numeric_tensor": 10_010_000 * 37 * 8,
        "cold_journal_archives_empirical_upper": math.ceil(10 * 1024 ** 3 * journal_ratio),
        "one_hot_uniqueness_journal_headroom_assumption": 3 * 1024 ** 3,
        "reserve": 5_000_000_000}
    result = {**declaration, "status": "COMPLETED", "roles": roles, "cache_archives": cache_receipts,
        "calibration_json_archives": calibration, "calibration_json_is_redundant_with_calibrated_model_arrays": True,
        "actual_validation_numeric_tensor": tensor, "actual_recorded_raw_score_cache_samples": raw_scores,
        "total_source_json_original_bytes": sum(role["original_bytes"] for role in roles.values()),
        "total_source_json_archive_bytes": sum(role["archive_bytes"] for role in roles.values()),
        "worst_empirical_source_compressed_bytes_per_row": worst_row_bytes,
        "staged_retention_forecast_bytes": staged, "staged_retention_total_bytes": sum(staged.values()),
        "all_original_source_hashes_unchanged": True, "all_archives_byte_for_byte_restorable": True,
        "source_or_future_seed_compression_formal_maximum_proven": False,
        "forecast_scope": "EMPIRICAL_COMPLETED_PILOT_AND_DECLARED_FULL_POPULATIONS_NOT_A_CAPACITY_GUARANTEE",
        "future_coordinator_requirements": ["KEEP_ORIGINAL_PLAIN_BLOB_SHA_AND_ARCHIVE_SHA_IN_RECEIPTS",
            "RESTORE_ONE_BOUNDED_SHARD_WITH8MIB_LIMIT_AND_CHECK_BOTH_BYTE_HASHES",
            "DO_NOT_REWRITE_MANIFEST_MODELSTORE_OR_FROZEN_SOURCE",
            "RETIRE_ONLY_OWN_NEW_TEMPORARY_PLAIN_BYTES_AFTER_EXACT_ARCHIVE_RESTORE_PROOF",
            "STOP_BEFORE_FREE_SPACE_FALLS_BELOW5GB_AND_REQUEST_STORAGE_IF_ACTUAL_BYTES_EXCEED_FORECAST"]}
    write_new(output / "result.private.json", result)
    print(canonical({"status": "COMPLETED", "output": str(output), "result_sha256": checksum(output / "result.private.json"),
                     "source_json_original_bytes": result["total_source_json_original_bytes"],
                     "source_json_archive_bytes": result["total_source_json_archive_bytes"],
                     "staged_retention_total_bytes": result["staged_retention_total_bytes"], "quality_gate": "NOT_APPLICABLE"}), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.output)
    except Exception as failure:
        raise SystemExit("Source archive probe refused/failed: " + type(failure).__name__ + "; original sources unchanged") from None
