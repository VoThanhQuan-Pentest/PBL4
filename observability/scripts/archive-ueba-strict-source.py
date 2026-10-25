#!/usr/bin/env python3
"""Opt-in byte-only archives for a pinned COMPLETE new STRICT source.

Original manifest, shards, committed hardlinks and producer receipts remain
untouched. No delete, retire, resume, numeric JSON parser or implicit fallback
exists. An interrupted archive attempt leaves derived artifacts for inspection.
"""
import argparse
from contextlib import ExitStack
import fcntl
from itertools import islice
import lzma
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime"
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.archived_catalog import (FORMAT, SIDECAR, MAX_XZ_BYTES, ArchivedShardedDataset,
                                 owned_root, resource_path, restore_xz)
from app.catalog import MAX_MANIFEST_BYTES, MAX_SHARD_BYTES, ShardedDataset, parse_json, sha256
from app.hybrid_strict_dataset import validate_standard_manifest
from app.hybrid_strict_protocol import protocol_sha256
from app.policy import canonical
from app.storage_budget import require_headroom

MAX_METADATA = 2 * 1024 * 1024
MAX_SHARDS = 10000
RESULT = "source-archive-result.private.json"
NEW_ROOT = re.compile(r"hybrid-strict-source-[A-Za-z0-9_-]{8,128}")
SHA = re.compile(r"[a-f0-9]{64}")


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def private_stream(path, maximum, *, empty=False):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private source file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(descriptor, "rb"); info = os.fstat(source.fileno())
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid() or not (0 if empty else 1) <= info.st_size <= maximum):
        source.close(); raise ValueError("bounded private owner-controlled source file required")
    # Producer-projected JSON deliberately has committed/verification hardlinks.
    return source


def read_bytes(path, maximum):
    with private_stream(path, maximum) as source:
        before = os.fstat(source.fileno()); raw = source.read(maximum + 1)
        if (len(raw) != before.st_size or len(raw) > maximum
                or _signature(before) != _signature(os.fstat(source.fileno()))
                or _signature(before) != _signature(path.lstat())):
            raise ValueError("source bytes/topology changed during read")
    return raw, _signature(before)


def metadata(path, maximum, expected_sha256=None):
    raw, signature = read_bytes(path, maximum); digest = sha256(raw)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("trusted source metadata SHA mismatch")
    return parse_json(raw), (raw, signature)


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)


def lock_existing(stack, path):
    path = Path(path).absolute()
    source = stack.enter_context(private_stream(path, MAX_METADATA, empty=True))
    held = os.fstat(source.fileno()); identity = (held.st_dev, held.st_ino)

    def validate_lock():
        try:
            held = os.fstat(source.fileno()); named = path.lstat()
            if (any(part.is_symlink() for part in (path, *path.parents))
                    or any(not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                           or info.st_uid != os.geteuid() or info.st_nlink != 1
                           or not 0 <= info.st_size <= MAX_METADATA for info in (held, named))
                    or (held.st_dev, held.st_ino) != identity or (named.st_dev, named.st_ino) != identity):
                raise ValueError("private single-link unchanged source lock required")
        except OSError:
            raise ValueError("private single-link unchanged source lock required") from None

    validate_lock()
    try: fcntl.flock(source, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise ValueError("live source generator/writer lock refused") from None
    validate_lock()
    stack.callback(validate_lock)  # Check while the held description is still open.
    return validate_lock


def source_path(value):
    source = owned_root(value); parent = owned_root(source.parent); run = owned_root(parent.parent)
    if (source.name != "standard" or parent.name != "source" or run.parent != RUNTIME.absolute()
            or NEW_ROOT.fullmatch(run.name) is None):
        raise ValueError("only the exact NEW strict-source standard layout is allowed")
    owned_root(source / "shards")
    return source


def archive_strict_source(source, manifest_sha256, marker_sha256, terminal_sha256):
    """Metadata topology + opaque byte restoration only, while both locks hold."""
    if any(type(value) is not str or SHA.fullmatch(value) is None for value in
           (manifest_sha256, marker_sha256, terminal_sha256)):
        raise ValueError("three explicit trusted source hashes required")
    source = source_path(source)
    with ExitStack() as stack:
        lock_existing(stack, source.parent / "writer.lock")
        lock_existing(stack, source / "generation.lock")
        return _archive_locked(source, manifest_sha256, marker_sha256, terminal_sha256)


def _archive_locked(source, manifest_sha256, marker_sha256, terminal_sha256):
    marker_path = source.parent / "predeclared.private.json"; terminal_path = source.parent / "state.private.json"
    marker, marker_before = metadata(marker_path, MAX_METADATA, marker_sha256)
    terminal, terminal_before = metadata(terminal_path, MAX_METADATA, terminal_sha256)
    if (type(marker) is not dict or type(terminal) is not dict or marker.get("scope") != "FULL_STRICT_SOURCE"
            or type(marker.get("protocol")) is not dict or marker.get("protocol_sha256") != protocol_sha256(marker["protocol"])
            or marker["protocol"].get("stage") != "STRICT_SOURCE" or marker["protocol"].get("quality_gate") != "NOT_EVALUATED"
            or terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE" or terminal.get("stage") != "STRICT_SOURCE"
            or terminal.get("scope") != "FULL_STRICT_SOURCE" or terminal.get("quality_gate") != "NOT_EVALUATED"
            or terminal.get("folds_completed") != [1, 2, 3] or type(marker.get("source_identity")) is not dict
            or not marker["source_identity"] or terminal.get("source_identity_before") != marker["source_identity"]
            or terminal.get("source_identity_after") != marker["source_identity"]
            or any(type(record.get(key)) is not int or record[key] != 0 for record, key in (
                (marker, "fit_or_score_calls"), (marker, "holdout_numeric_records_read"),
                (terminal, "fit_or_score_calls"), (terminal, "holdout_numeric_records_read"),
                (terminal, "downstream_holdout_numeric_records_read")))):
        raise ValueError("pinned COMPLETE_UNQUALIFIED_SOURCE/FULL_STRICT_SOURCE required")
    manifest_path = resource_path(source, "manifest.json")
    manifest_raw, manifest_signature = read_bytes(manifest_path, MAX_MANIFEST_BYTES)
    if sha256(manifest_raw) != manifest_sha256: raise ValueError("trusted original manifest SHA mismatch")
    dataset = ShardedDataset(source, expected_sha256=manifest_sha256)  # Metadata only, never any row iterator.
    validate_standard_manifest(dataset.manifest, marker["protocol"]["dataset_id"])
    if dataset.manifest["stage"] != "STRICT": raise ValueError("only completed STRICT standard sources may be archived")
    generation_path = source / "generation.identity.json"; progress_path = source / "generation.progress.json"
    generation_sha256 = dataset.manifest.get("generation_identity_sha256")
    if (type(generation_sha256) is not str or SHA.fullmatch(generation_sha256) is None
            or type(dataset.manifest.get("source_binding")) is not dict or not dataset.manifest["source_binding"]):
        raise ValueError("manifest-bound fresh producer identity required")
    generation, generation_before = metadata(generation_path, MAX_METADATA, generation_sha256)
    progress, progress_before = metadata(progress_path, MAX_METADATA)
    if (type(generation) is not dict or type(progress) is not dict or generation.get("stage") != "STRICT"
            or generation.get("dataset_id") != dataset.manifest["dataset_id"]
            or generation.get("source_binding") != dataset.manifest.get("source_binding")
            or generation.get("old_numeric_corpus_read") is not False or generation.get("authentic_capture") is not False
            or progress.get("status") != "COMPLETED" or progress.get("stage") != "STRICT"
            or progress.get("dataset_id") != dataset.manifest["dataset_id"] or progress.get("manifest_sha256") != manifest_sha256
            or progress.get("published_manifest") is False
            or any(type(record.get("fit_or_score_calls")) is not int or record["fit_or_score_calls"] != 0 for record in (generation, progress))):
        raise ValueError("matching completed fresh producer identity/progress required")
    descriptors = [item for split in dataset.manifest["splits"].values() for item in split["shards"]]
    if not 1 <= len(descriptors) <= MAX_SHARDS: raise ValueError("bounded complete source shard topology required")
    names = {Path(item["path"]).name for item in descriptors}
    present = list(islice((source / "shards").iterdir(), MAX_SHARDS + 1))
    if len(present) != len(names) or {path.name for path in present} != names:
        raise ValueError("fresh exact source shards required; unexpected/existing archive artifacts refused")
    for path in (source / SIDECAR, source / RESULT, *(source / (item["path"] + ".xz") for item in descriptors)):
        if path.exists() or path.is_symlink(): raise ValueError("existing archive artifact cannot be adopted or overwritten")
    snapshots = {marker_path: marker_before, terminal_path: terminal_before, manifest_path: (manifest_raw, manifest_signature),
                 generation_path: generation_before, progress_path: progress_before}
    before = {}
    for item in descriptors:
        path = resource_path(source, item["path"]); raw, signature = read_bytes(path, MAX_SHARD_BYTES)
        if sha256(raw) != item["sha256"]: raise ValueError("original source shard byte checksum mismatch")
        before[item["path"]] = (signature, len(raw))
    entries = {}; totals = {"original_bytes": 0, "archive_bytes": 0}
    for item in descriptors:
        path = resource_path(source, item["path"]); raw, signature = read_bytes(path, MAX_SHARD_BYTES)
        if (signature, len(raw)) != before[item["path"]] or sha256(raw) != item["sha256"]:
            raise ValueError("original source changed before compression")
        relative = item["path"] + ".xz"; encoded = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=3)
        if not 0 < len(encoded) <= MAX_XZ_BYTES: raise ValueError("compressed shard exceeds fixed byte bound")
        require_headroom(source, len(encoded))
        write_new(resource_path(source, relative), encoded)
        entry = {"original_sha256": item["sha256"], "original_bytes": len(raw), "archive_path": relative,
                 "archive_sha256": sha256(encoded), "archive_bytes": len(encoded)}
        if restore_xz(source, entry) != raw: raise ValueError("archive must restore exact original bytes")
        entries[item["path"]] = entry
        totals["original_bytes"] += len(raw); totals["archive_bytes"] += len(encoded)
    for path, snapshot in snapshots.items():
        if read_bytes(path, MAX_MANIFEST_BYTES if path == manifest_path else MAX_METADATA) != snapshot:
            raise ValueError("source metadata changed before archive publication")
    for item in descriptors:
        raw, signature = read_bytes(resource_path(source, item["path"]), MAX_SHARD_BYTES)
        if (signature, len(raw)) != before[item["path"]] or sha256(raw) != item["sha256"]:
            raise ValueError("original source changed during archive restoration")
    sidecar = {"archive_schema_version": 1, "archive_format": FORMAT,
               "dataset_manifest_sha256": manifest_sha256, "shards": entries}
    sidecar_raw = canonical(sidecar).encode()
    if len(sidecar_raw) > MAX_MANIFEST_BYTES: raise ValueError("archive sidecar exceeds unchanged metadata cap")
    require_headroom(source, len(sidecar_raw) + MAX_METADATA)
    sidecar_sha256 = sha256(sidecar_raw); write_new(source / SIDECAR, sidecar_raw)
    ArchivedShardedDataset(source, expected_sha256=manifest_sha256, expected_archive_sha256=sidecar_sha256)  # Metadata only.
    result = {"status": "COMPLETED", "scope": "STORAGE_ONLY", "quality_gate": "NOT_APPLICABLE",
        "dataset_manifest_sha256": manifest_sha256, "archive_sidecar_sha256": sidecar_sha256,
        "source_marker_sha256": marker_sha256, "source_terminal_sha256": terminal_sha256,
        "source_generation_identity_sha256": sha256(generation_before[0]), "source_generation_progress_sha256": sha256(progress_before[0]),
        "archived_shards": len(entries), **totals, "original_manifest_bytes_unchanged": True,
        "original_files_deleted_or_renamed": 0, "original_hardlink_topology_unchanged": True,
        "numeric_rows_parsed": 0, "holdout_numeric_records_read": 0, "fit_calls": 0, "score_calls": 0,
        "holdout_verification": "OPAQUE_BYTE_SHA256_AND_BOUNDED_XZ_RESTORE_ONLY"}
    write_new(source / RESULT, canonical(result).encode())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--marker-sha256", required=True)
    parser.add_argument("--terminal-sha256", required=True)
    args = parser.parse_args()
    try: print(canonical(archive_strict_source(args.source, args.manifest_sha256, args.marker_sha256, args.terminal_sha256)), flush=True)
    except Exception as failure:
        raise SystemExit("Strict source archive refused/failed: " + type(failure).__name__ + "; originals and partial derived artifacts retained") from None
