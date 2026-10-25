#!/usr/bin/env python3
"""Assemble real normal FIT/calibration/validation shards without relabeling.

The labeled supplement stays in its separate protected training artifact.
Only the actual 50k normal READY section becomes the normal catalogue FIT.
Hardlinks preserve bytes and avoid duplicate disk use; no source is overwritten,
registered, fitted, selected or promoted. Output remains non-activatable PILOT.
"""

import argparse
from collections import Counter
import hashlib
import errno
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.catalog import ShardedDataset, parse_json, utc
from app.contract import FEATURE_NAMES_V4
from app.expanded_calibration import load_expanded_calibration
from app.hybrid_bulk_dataset import load_hybrid_bulk_fit
from app.policy import canonical

ORIGINAL = ROOT / "observability/runtime/ueba-experiments/schema4-pilot-20261003-a01"
ORIGINAL_SHA = "3c127c1e57a4a436ecabef1c9fe9d40465fc9191313259560a85554b6d7b9f12"
CALIBRATION = ROOT / "observability/runtime/expanded-calibration-20261003-F4wITdBt/data"
CALIBRATION_SHA = "05253075440b741a010ceae9b497d62acfa2c007952f11a13b91b5ae7443432d"


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def link_or_copy(source, destination):
    """Docker bind mounts can prohibit links even on one underlying disk."""
    try:
        os.link(source, destination, follow_symlinks=False)
        return "HARDLINK"
    except OSError as failure:
        if failure.errno != errno.EXDEV:
            raise
    # Only cross-mount failure permits copying. Exclusive creation cannot
    # overwrite a previous attempt; the caller rechecks exact source SHA.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
        for block in iter(lambda: incoming.read(65536), b""):
            outgoing.write(block)
        outgoing.flush(); os.fsync(outgoing.fileno())
    return "BYTE_VERIFIED_COPY"


def verify_chronology(normal, calibration, validation):
    from datetime import timedelta
    phases = (normal, [row for group in calibration.values() for row in group], validation)
    frames, hours = set(), set()
    for phase in phases:
        for row in phase:
            at = utc(row["window_start"])
            key = (row["account_id"], at.strftime("%Y-%m-%dT%H"))
            if row["frame_id"] in frames or key in hours:
                raise ValueError("duplicate evaluated catalogue frame/account-hour")
            frames.add(row["frame_id"]); hours.add(key)
    for before, after in zip(phases, phases[1:]):
        if min(utc(row["window_start"]) for row in after) - max(utc(row["window_start"]) for row in before) <= timedelta(days=14):
            raise ValueError("actual catalogue history gaps must exceed14 days")
    fitted = {row["account_id"] for row in normal}
    if (any(row["account_id"] not in fitted for row in calibration["READY"])
            or fitted & {row["account_id"] for row in validation if row["cohort"] == "UNSEEN_READY"}):
        raise ValueError("READY coverage or UNSEEN account isolation failed")


def assemble(bulk_root, bulk_sha, output, dataset_id):
    if not isinstance(dataset_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset_id):
        raise ValueError("bounded fresh operator dataset ID required")
    normal, labeled, bulk = load_hybrid_bulk_fit(bulk_root, bulk_sha)
    calibration, cal_manifest = load_expanded_calibration(CALIBRATION, CALIBRATION_SHA)
    original = ShardedDataset(ORIGINAL, expected_sha256=ORIGINAL_SHA)
    validation = [row for _, group in original.iter_shards("fold1-validation") for row in group]
    if len(normal) != 50000 or len(labeled) != 81500 or len(validation) != 21000:
        raise ValueError("actual source populations changed")
    verify_chronology(normal, calibration, validation)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("new catalogue directory required")
    if any(parent.is_symlink() for parent in (output.parent, *output.parent.parents)):
        raise ValueError("symlinked catalogue path refused")
    if output.parent.stat().st_uid != os.geteuid() or output.parent.stat().st_mode & 0o077:
        raise ValueError("owned private output parent required")
    output.mkdir(mode=0o700); (output / "shards").mkdir(mode=0o700)
    sources = {
        "fold1-fit": (Path(bulk_root), bulk["training_sections"]["NORMAL_COMPONENT"]),
        "fold1-calibration-ready": (CALIBRATION, cal_manifest["splits"]["READY"]),
        "fold1-calibration-cold": (CALIBRATION, cal_manifest["splits"]["COLD"]),
        "fold1-validation": (ORIGINAL, original.split("fold1-validation")),
    }
    paths = set()
    for source, split in sources.values():
        for entry in split["shards"]:
            relative = entry["path"]
            if relative in paths or relative != "shards/" + entry["id"] + ".json":
                raise ValueError("unique exact source shard paths required")
            paths.add(relative)
            original_path = source / relative
            if original_path.is_symlink() or sha(original_path) != entry["sha256"]:
                raise ValueError("source shard changed before hardlink")
            link_or_copy(original_path, output / relative)
            if sha(output / relative) != entry["sha256"]:
                raise ValueError("linked catalogue shard identity changed")
    manifest = {"catalog_schema_version": 2, "dataset_id": dataset_id, "stage": "PILOT",
        "data_provenance": "DEMO_ONLY", "feature_schema_version": 4, "telemetry_contract_version": 3,
        "feature_names": list(FEATURE_NAMES_V4), "splits": {key: split for key, (_, split) in sources.items()},
        "assembly_scope": "ACTUAL_NORMAL50000_EXPANDED_CALIBRATION120000_UNCHANGED_VALIDATION21000",
        "labeled_training_manifest_sha256": bulk_sha, "original_pilot_manifest_sha256": ORIGINAL_SHA,
        "expanded_calibration_manifest_sha256": CALIBRATION_SHA,
        "labeled_training_rows_not_inserted_into_normal_fit": True, "fit_or_score_calls": 0,
        "quality_gate": "NOT_APPLICABLE", "holdout_numeric_records_read": 0}
    write_new(output / "manifest.json", manifest)
    checked = ShardedDataset(output, expected_sha256=sha(output / "manifest.json"))
    for name in sources:
        observed = Counter()
        for _, rows in checked.iter_shards(name):
            observed.update(records=len(rows), positive=sum(row["label"] for row in rows))
        if observed["records"] != checked.split(name)["records"] or observed["positive"] != checked.split(name)["positive"]:
            raise ValueError("assembled actual catalogue population failed verification")
    write_new(output / "assembly.private.json", {"status": "COMPLETED", "manifest_sha256": checked.sha256,
        "real_normal_fit_rows": 50000, "labeled_rows_kept_separate": 81500,
        "source_files_modified_or_registered": False, "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"})
    return checked


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bulk-training", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset-id", required=True)
    args = parser.parse_args()
    try:
        result = assemble(args.bulk_training, args.manifest_sha256, args.output, args.dataset_id)
        print(canonical({"status": "COMPLETED", "manifest_sha256": result.sha256, "quality_gate": "NOT_APPLICABLE"}))
    except Exception as failure:
        raise SystemExit("Hybrid catalogue assembly refused/failed: " + type(failure).__name__ + "; source files unchanged") from None
