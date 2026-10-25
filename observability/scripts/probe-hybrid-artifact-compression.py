#!/usr/bin/env python3
"""Compression-only copy of one trusted private model, not a migration.

Rewrites no original artifact or metadata and performs no fit or activation.
Compressed copies have different binary SHA, but must decode to identical
numeric-model/calibration identity. They are not admitted by ModelStore here.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
import joblib
from app.model_state_dispatch import state_sha256
from app.policy import canonical


def checksum(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""): value.update(block)
    return value.hexdigest()


def probe(source, source_sha, output):
    source, output = Path(source).absolute(), Path(output).absolute()
    if (source.is_symlink() or not source.is_file() or source.stat().st_mode & 0o077
            or checksum(source) != source_sha or output.exists() or output.is_symlink()
            or not output.parent.is_dir() or output.parent.stat().st_mode & 0o077):
        raise ValueError("trusted original SHA and new private output required")
    output.mkdir(mode=0o700)
    payload = joblib.load(source)  # Only the fixed own-worker-created SHA-bound artifact.
    identity = state_sha256(payload)
    results = []
    for algorithm in ("zlib", "lzma"):
        path = output / (algorithm + ".joblib")
        started = time.monotonic()
        joblib.dump(payload, path, compress=(algorithm, 3)); path.chmod(0o600)
        saved = time.monotonic() - started
        started = time.monotonic()
        restored = joblib.load(path)
        loaded = time.monotonic() - started
        if state_sha256(restored) != identity:
            raise ValueError("compression changed exact calibrated numeric state")
        results.append({"algorithm": algorithm, "bytes": path.stat().st_size,
                        "sha256": checksum(path), "save_seconds": saved, "load_seconds": loaded,
                        "semantic_state_identical": True})
    if checksum(source) != source_sha:
        raise ValueError("original model file changed")
    result = {"status": "COMPLETED", "original_bytes": source.stat().st_size,
              "original_sha256": source_sha, "numeric_state_sha256": identity,
              "compressed_copies": results, "fit_or_activation_calls": 0,
              "original_or_model_metadata_modified": False, "quality_gate": "NOT_APPLICABLE"}
    fd = os.open(output / "result.private.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(canonical(result)); stream.flush(); os.fsync(stream.fileno())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(canonical(probe(args.source, args.sha256, args.output)))
    except Exception as failure:
        raise SystemExit("Compression probe failed: " + type(failure).__name__ + "; original unchanged") from None
