#!/usr/bin/env python3
"""Create a NEW protected archive-only PILOT view; no delete or retire mode.

Original manifest bytes, shard descriptors, numeric rows and byte hashes stay
unchanged. The archive sidecar is a separate explicit trust binding, not a new
dataset or model admission. STRICT sources and any holdout split are refused.
"""
import argparse
import lzma
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.archived_catalog import (FORMAT, SIDECAR, ArchivedShardedDataset, owned_root,
                                 private_bytes, restore_xz)
from app.catalog import MAX_MANIFEST_BYTES, MAX_SHARD_BYTES, ShardedDataset, sha256
from app.policy import canonical


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw); target.flush(); os.fsync(target.fileno())


def archive_owned_catalog(source, expected_sha256, output):
    source = owned_root(source)
    original_manifest = private_bytes(source, "manifest.json", MAX_MANIFEST_BYTES)
    if sha256(original_manifest) != expected_sha256:
        raise ValueError("trusted original manifest SHA required")
    dataset = ShardedDataset(source, expected_sha256=expected_sha256)
    if dataset.manifest["stage"] != "PILOT" or any("holdout" in name for name in dataset.manifest["splits"]):
        raise ValueError("completed PILOT without holdout only; STRICT archive authority is separate")
    output = Path(output).absolute(); owned_root(output.parent)
    if output.exists() or output.is_symlink() or ".." in output.parts:
        raise ValueError("new canonical private archive view required")
    before = {}
    for split in dataset.manifest["splits"].values():
        for item in split["shards"]:
            raw = private_bytes(source, item["path"], MAX_SHARD_BYTES)
            if sha256(raw) != item["sha256"]:
                raise ValueError("original source shard checksum mismatch")
            before[item["path"]] = (item["sha256"], len(raw))
    output.mkdir(mode=0o700); (output / "shards").mkdir(mode=0o700)
    entries = {}; started = time.monotonic(); totals = {}
    for name, split in dataset.manifest["splits"].items():
        records = original_bytes = archive_bytes = 0
        for number, item in enumerate(split["shards"]):
            _, rows = dataset.load_shard(name, number)  # Existing actual row/count/feature/cohort checks.
            raw = private_bytes(source, item["path"], MAX_SHARD_BYTES)
            if (sha256(raw), len(raw)) != before[item["path"]]:
                raise ValueError("original source shard changed before compression")
            relative = item["path"] + ".xz"
            encoded = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=3)
            write_new(output / relative, encoded)
            entry = {"original_sha256": item["sha256"], "original_bytes": len(raw),
                     "archive_path": relative, "archive_sha256": sha256(encoded), "archive_bytes": len(encoded)}
            if restore_xz(output, entry) != raw:
                raise ValueError("archive must restore byte-identical original shard")
            entries[item["path"]] = entry
            records += len(rows); original_bytes += len(raw); archive_bytes += len(encoded)
        totals[name] = {"records": records, "shards": len(split["shards"]),
                        "original_bytes": original_bytes, "archive_bytes": archive_bytes}
    if private_bytes(source, "manifest.json", MAX_MANIFEST_BYTES) != original_manifest:
        raise ValueError("original source changed before archive metadata publication")
    for relative, identity in before.items():
        raw = private_bytes(source, relative, MAX_SHARD_BYTES)
        if (sha256(raw), len(raw)) != identity:
            raise ValueError("original source changed before archive metadata publication")
    sidecar = {"archive_schema_version": 1, "archive_format": FORMAT,
               "dataset_manifest_sha256": expected_sha256, "shards": entries}
    encoded_sidecar = canonical(sidecar).encode()
    # Metadata is published only after every archive's exact restoration proof.
    write_new(output / "manifest.json", original_manifest)
    write_new(output / SIDECAR, encoded_sidecar)
    sidecar_sha = sha256(encoded_sidecar)
    archived = ArchivedShardedDataset(output, expected_sha256=expected_sha256, expected_archive_sha256=sidecar_sha)
    actual_readback = 0
    for name, split in dataset.manifest["splits"].items():
        for number in range(len(split["shards"])):
            original_descriptor, original_rows = dataset.load_shard(name, number)
            restored_descriptor, restored_rows = archived.load_shard(name, number)
            if original_descriptor != restored_descriptor or original_rows != restored_rows:
                raise ValueError("archive catalogue changed exact descriptors or numeric rows")
            actual_readback += len(restored_rows)
    if private_bytes(source, "manifest.json", MAX_MANIFEST_BYTES) != original_manifest:
        raise ValueError("original manifest changed during archive readback")
    for relative, identity in before.items():
        raw = private_bytes(source, relative, MAX_SHARD_BYTES)
        if (sha256(raw), len(raw)) != identity:
            raise ValueError("original shard changed during archive readback")
    result = {"status": "COMPLETED", "scope": "STORAGE_ONLY", "quality_gate": "NOT_APPLICABLE",
        "dataset_manifest_sha256": expected_sha256, "archive_sidecar_sha256": sidecar_sha,
        "ordinary_manifest_bytes_identical": private_bytes(output, "manifest.json", MAX_MANIFEST_BYTES) == original_manifest,
        "original_shard_descriptors_unchanged": True, "actual_rows_read_back_identically": actual_readback,
        "archive_only_view_has_no_plain_shards": not any((output / relative).exists() for relative in before),
        "all_original_source_bytes_unchanged": True, "source_files_deleted_or_renamed": 0,
        "fit_calls": 0, "score_calls": 0, "holdout_rows_read": 0, "strict_source_rows_read": 0,
        "splits": totals, "original_shard_bytes": sum(item["original_bytes"] for item in totals.values()),
        "compressed_shard_bytes": sum(item["archive_bytes"] for item in totals.values()),
        "elapsed_seconds": time.monotonic() - started}
    write_new(output / "archive-result.private.json", canonical(result).encode())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = archive_owned_catalog(args.source, args.sha256, args.output)
        print(canonical(result), flush=True)
    except Exception as failure:
        raise SystemExit("Owned catalogue archive refused/failed: " + type(failure).__name__ + "; originals retained") from None
