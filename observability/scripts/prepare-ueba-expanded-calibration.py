#!/usr/bin/env python3
"""Frozen-source, 60000-normal-per-cohort replacement calibration PILOT only.

Uses the ORIGINAL actor namespace and unchanged causal producer/Java exporter.
This is neither training nor validation, does not merge the old small buckets,
and never changes old artifacts, labels, features, policy or serving state.
"""

import argparse
from dataclasses import asdict
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))

from app.catalog import ShardedDataset, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.expanded_calibration import (NAMESPACE, PILOT_SHA, TRAINING_SHA, ROWS_PER_COHORT,
                                     checksum, load_expanded_calibration, value_sha)
from app.hybrid_dataset import load_hybrid_fit
from app.policy import canonical

IMAGE_ID = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
PILOT = ROOT / "observability/runtime/ueba-experiments/schema4-pilot-20261003-a01"
TRAINING = ROOT / "observability/runtime/hybrid-training-20261003-TNVXAURk/data"
PRODUCER_PATH = ROOT / "observability/scripts/prepare-ueba-schema4.py"
GENERATOR_SHA = "6797225920eba88e6a26f1f1ff3ee28ee722105c6667e370eab378ce3cb34139"
SOURCE_FILES = (Path(__file__).resolve(), ROOT / "ueba-worker/app/expanded_calibration.py", PRODUCER_PATH,
                ROOT / "ueba-worker/app/schema4_episodes.py", ROOT / "ueba-worker/app/catalog.py",
                ROOT / "ueba-worker/app/contract.py", ROOT / "ueba-worker/app/policy.py",
                ROOT / "ueba-worker/app/strict_metrics.py", ROOT / "ueba-worker/app/hybrid_dataset.py")


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def producer_module():
    if checksum(ROOT / "ueba-worker/app/schema4_episodes.py") != GENERATOR_SHA:
        raise ValueError("unchanged frozen causal generator required")
    spec = importlib.util.spec_from_file_location("frozen_expanded_schema4_producer", PRODUCER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def calibration_parts(producer):
    return tuple(producer.Part("fold1-calibration-" + cohort.lower(), cohort, 33, 3, ROWS_PER_COHORT)
                 for cohort in ("READY", "COLD"))


def account_hour(row):
    return row["account_id"], utc(row["window_start"]).strftime("%Y-%m-%dT%H")


def protected_sources():
    original = ShardedDataset(PILOT, expected_sha256=PILOT_SHA)
    training, training_manifest = load_hybrid_fit(TRAINING, TRAINING_SHA)
    fit, validation, old = [], [], {}
    for name in original.manifest["splits"]:
        selected = [row for _, rows in original.iter_shards(name) for row in rows]
        if name == "fold1-fit":
            fit = selected
        elif name == "fold1-validation":
            validation = selected
        elif name in ("fold1-calibration-ready", "fold1-calibration-cold"):
            old[name.rsplit("-", 1)[1].upper()] = {row["frame_id"]: row for row in selected}
    if (len(fit) != 2000 or len({row["account_id"] for row in fit}) != 2000
            or any(row["label"] or row["cohort"] != "READY" for row in fit)
            or len(validation) != 21000 or set(old) != {"READY", "COLD"}):
        raise ValueError("fixed fitted actor pool and original score-only populations required")
    return original, training_manifest, {
        "training_frames": {row["frame_id"] for row in training}, "training_hours": {account_hour(row) for row in training},
        "validation_frames": {row["frame_id"] for row in validation}, "validation_hours": {account_hour(row) for row in validation},
        "ready_fit_accounts": {row["account_id"] for row in fit}, "old_calibration": old}


def source_identity(producer, original, training_manifest):
    _, java = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    original_shards = {shard["path"]: shard["sha256"] for split in original.manifest["splits"].values() for shard in split["shards"]}
    training_shards = {shard["path"]: shard["sha256"] for shard in training_manifest["split"]["shards"]}
    if (checksum(PILOT / "manifest.json") != PILOT_SHA or checksum(TRAINING / "manifest.private.json") != TRAINING_SHA
            or any(checksum(PILOT / name) != expected for name, expected in original_shards.items())
            or any(checksum(TRAINING / name) != expected for name, expected in training_shards.items())):
        raise ValueError("any frozen original or training artifact changed")
    return {"sources": {str(path.relative_to(ROOT)): checksum(path) for path in SOURCE_FILES},
            "original_pilot": {"manifest_sha256": PILOT_SHA, "shards": original_shards,
                               "generation_identity_sha256": checksum(PILOT / "generation.identity.json")},
            "hybrid_training": {"manifest_sha256": TRAINING_SHA, "shards": training_shards,
                                "predeclared_identity_sha256": checksum(TRAINING / "predeclared.private.json")},
            "frozen_java": {"snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256, **java},
            "endpoint_proof_sha256": checksum(producer.DEFAULT_ENDPOINT_PROOF), "execution_image_id": IMAGE_ID}


class CalibrationShards:
    def __init__(self, output, cohort, proof=None):
        self.output, self.cohort, self.proof = output, cohort, proof
        self.rows, self.descriptors = [], []
        self.frames, self.hours, self.accounts = set(), set(), set()
        self.old_overlap = 0
        self.history_min, self.history_max = None, None

    def append(self, row):
        validate_rows([row], 4)
        frame, hour = row["frame_id"], account_hour(row)
        if row["label"] or row["family"] != "normal" or row["cohort"] != self.cohort or frame in self.frames or hour in self.hours:
            raise ValueError("normal-only unique actual calibration rows required")
        if self.proof is not None:
            if (frame in self.proof["training_frames"] or hour in self.proof["training_hours"]
                    or frame in self.proof["validation_frames"] or hour in self.proof["validation_hours"]):
                raise ValueError("calibration evaluated frame/account-hour overlaps training or validation")
            if self.cohort == "READY" and row["account_id"] not in self.proof["ready_fit_accounts"]:
                raise ValueError("READY calibration account is outside the unchanged fitted population")
            old = self.proof["old_calibration"][self.cohort].get(frame)
            if old is not None:
                if old != row:
                    raise ValueError("overlapping old calibration frame changed features/history/labels")
                self.old_overlap += 1
        history = row["trusted_window_count"]
        if self.cohort == "COLD" and not 3 <= history <= 22:
            raise ValueError("COLD independent world history exceeded frozen applicability")
        self.history_min = history if self.history_min is None else min(self.history_min, history)
        self.history_max = history if self.history_max is None else max(self.history_max, history)
        self.frames.add(frame)
        self.hours.add(hour)
        self.accounts.add(row["account_id"])
        self.rows.append(row)
        if len(self.frames) > ROWS_PER_COHORT:
            raise ValueError("predeclared calibration row bound exceeded")
        if len(self.rows) == 5000:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        identifier = f"expanded-calibration-{self.cohort.lower()}-{len(self.descriptors):06d}"
        path = self.output / "shards" / (identifier + ".json")
        stats = validate_rows(self.rows, 4)
        write_new(path, self.rows)
        self.descriptors.append({"id": identifier, "path": "shards/" + path.name, "sha256": checksum(path), **stats})
        self.rows = []


def prepare(output=None):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE_ID or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only generation required")
    producer = producer_module()
    generator = producer.load_generator()
    original, training_manifest, proof = protected_sources()
    before = source_identity(producer, original, training_manifest)
    classpath, java = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    endpoint = producer.endpoint_identity(producer.DEFAULT_ENDPOINT_PROOF, producer.DEFAULT_ENDPOINT_SHA256,
                                         producer.DEFAULT_WORKSPACE_SHA256, java, generator)
    parts = calibration_parts(producer)
    layouts = {part.cohort: producer.actor_layout(part, 2000) for part in parts}
    if layouts["READY"][0] != 1667 or layouts["COLD"][0] != 3000:
        raise ValueError("frozen 1667 fitted READY / 3000 independent COLD actor layout required")
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="expanded-calibration-", dir=ROOT / "observability/runtime"))
    else:
        output = Path(output).absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
            raise ValueError("new protected calibration output directory required")
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    (output / "shards").mkdir(mode=0o700)
    declaration = {"artifact_id": "expanded-calibration-20261003-a01", "dataset_namespace": NAMESPACE,
                   "stage": "PILOT", "diagnostic_scope": "PILOT_DEMO_ONLY", "data_provenance": "DEMO_ONLY",
                   "seed": 42, "generator_blind_seeds": list(generator.BLIND_SEEDS), "parts": [asdict(part) for part in parts],
                   "actor_layouts": {key: list(value) for key, value in layouts.items()}, "ready_fit_actor_pool": 2000,
                   "feature_names": list(FEATURE_NAMES_V4), "batch_accounts": 128,
                   "replacement_calibration_only": True, "merge_old_calibration": False,
                   "new_frames_generated_before_declaration": 0, "fit_or_score_calls": 0,
                   "endpoint_proof": endpoint, "source_identity": before, "quality_gate": "NOT_APPLICABLE"}
    declared_path = output / "predeclared.private.json"
    write_new(declared_path, declaration)
    started, receipts, writers, splits = time.monotonic(), {}, {}, {}
    for part in parts:
        writer = CalibrationShards(output, part.cohort, proof)
        writers[part.cohort] = writer
        for batch in producer.actor_batches(part, ready_pool=2000, batch_accounts=128):
            ordinal = len(receipts)
            state = producer.export_batch(generator, NAMESPACE, part, batch, 0, classpath, output, writer, timeout=600)
            path = output / f"batch-{ordinal:04d}.private.json"
            write_new(path, {"ordinal": ordinal, "cohort": part.cohort, "assignment_sha256": value_sha(batch), **state})
            receipts[path.name] = checksum(path)
            print(canonical({"stage": "EXPANDED_CALIBRATION_EXTRACTION_ONLY", "cohort": part.cohort,
                             "actual_normal_rows": len(writer.frames), "planned_cohort_normal": ROWS_PER_COHORT,
                             "completed_batches": len(receipts), "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)
        writer.flush()
        if len(writer.frames) != ROWS_PER_COHORT or len(writer.accounts) != layouts[part.cohort][0]:
            raise ValueError("actual complete normal population/actor count differs from predeclared recipe")
        splits[part.cohort] = producer.split_descriptor(writer.descriptors)
    if writers["READY"].frames & writers["COLD"].frames or writers["READY"].hours & writers["COLD"].hours:
        raise ValueError("cross-cohort duplicate evaluated calibration rows")
    after = source_identity(producer, original, training_manifest)
    write_new(output / "source-after.private.json", after)
    if before != after:
        raise ValueError("frozen source/old artifacts/Java changed; retain incomplete protected output")
    manifest = {"expanded_calibration_schema_version": 1, "artifact_id": declaration["artifact_id"], "dataset_namespace": NAMESPACE,
                "stage": "PILOT", "diagnostic_scope": "PILOT_DEMO_ONLY", "data_provenance": "DEMO_ONLY",
                "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                "rows_per_cohort": ROWS_PER_COHORT, "splits": splits,
                "replacement_calibration_only": True, "merge_old_calibration": False,
                "overlap_with_old_small_calibration": {cohort: writer.old_overlap for cohort, writer in writers.items()},
                "actor_counts": {cohort: len(writer.accounts) for cohort, writer in writers.items()},
                "actual_trusted_history_range": {cohort: [writer.history_min, writer.history_max] for cohort, writer in writers.items()},
                "cold_world_provenance": "INDEPENDENT_FROZEN_CAUSAL_WORLDS_3_CONTEXT_PLUS_AT_MOST_20_EVALUATIONS_NOT_CONTINUOUS_LIVE_HISTORY",
                "isolation_proofs": {"ready_accounts_covered_by_original_fit": True,
                    "training_evaluated_frame_overlap": 0, "validation_evaluated_frame_overlap": 0,
                    "training_account_hour_overlap": 0, "validation_account_hour_overlap": 0},
                "temporal_isolation": {"latest_training": "2026-04-15T12:00:00Z", "earliest_validation": "2026-05-21T00:00:00Z",
                    "earliest_calibration": min(split["from"] for split in splits.values()),
                    "latest_calibration": max(split["to"] for split in splits.values()),
                    "calibration_to_validation_gap_seconds": (utc("2026-05-21T00:00:00Z") - max(utc(split["to"]) for split in splits.values())).total_seconds(),
                    "history_gap_strictly_exceeds_14_days": True},
                "workspace_snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256,
                "predeclared_identity_sha256": checksum(declared_path), "source_identity_before": before, "source_identity_after": after,
                "batch_receipt_sha256": receipts, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0,
                "quality_gate": "NOT_APPLICABLE", "elapsed_seconds": time.monotonic() - started,
                "limitations": ["120000_SIMULATED_NORMAL_WINDOWS_NOT_MILLION_ROW_STRICT_CALIBRATION",
                                "CALIBRATION_ONLY_NOT_VALIDATION_ACCURACY_OR_QUALIFICATION",
                                "ORIGINAL_SMALL_BUCKETS_OVERLAP_AND_MUST_NOT_BE_MERGED", "COLD_IS_INDEPENDENT_SIMULATED_HISTORY_NOT_LIVE_CONTINUOUS_TRAFFIC"]}
    path = output / "manifest.private.json"
    write_new(path, manifest)
    buckets, _ = load_expanded_calibration(output, checksum(path))
    write_new(output / "result.private.json", {"status": "COMPLETED", "manifest_sha256": checksum(path),
        "rows": {cohort: len(rows) for cohort, rows in buckets.items()}, "old_artifacts_unchanged": True,
        "source_identity_unchanged": True, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0,
        "diagnostic_scope": "PILOT_DEMO_ONLY", "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE"})
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output, _ = prepare(args.output)
    print(canonical({"status": "COMPLETED", "output": str(output), "manifest_sha256": checksum(output / "manifest.private.json"),
                     "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Expanded calibration refused/failed: " + type(failure).__name__ + "; protected evidence retained") from None
