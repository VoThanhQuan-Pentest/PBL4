#!/usr/bin/env python3
"""Generate a fresh protected labeled training PILOT before old calibration.

Reuses only old normal READY FIT rows for training components. New normal and
planned incident worlds pass through the actual immutable Java schema-4
exporter. This does not fit a model, read a holdout, confirm an attack, loosen
normal-only catalog contracts, or modify the old PILOT/calibration/validation.
"""

from collections import Counter
import argparse
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))

from app.catalog import ShardedDataset, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.hybrid_dataset import (CLASS_TARGETS, CLASS_TARGET_NAMES, PILOT_SHA, TRAINING_SPLIT,
                                checksum, load_hybrid_fit, validate_training_rows, value_sha)
from app.policy import canonical

PILOT = ROOT / "observability/runtime/ueba-experiments/schema4-pilot-20261003-a01"
IMAGE_ID = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
GENERATOR_SHA = "6797225920eba88e6a26f1f1ff3ee28ee722105c6667e370eab378ce3cb34139"
PREPARE_PATH = ROOT / "observability/scripts/prepare-ueba-schema4.py"
NEW_POPULATIONS = (("READY", 100, 700), ("UNSEEN_READY", 600, 200), ("COLD", 300, 100))
SOURCE_FILES = (Path(__file__).resolve(), PREPARE_PATH, ROOT / "ueba-worker/app/hybrid_dataset.py",
                ROOT / "ueba-worker/app/schema4_episodes.py", ROOT / "ueba-worker/app/catalog.py",
                ROOT / "ueba-worker/app/contract.py", ROOT / "ueba-worker/app/policy.py",
                ROOT / "ueba-worker/app/strict_metrics.py")


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def load_frozen_producer():
    if checksum(ROOT / "ueba-worker/app/schema4_episodes.py") != GENERATOR_SHA:
        raise ValueError("frozen causal generator source required")
    spec = importlib.util.spec_from_file_location("frozen_hybrid_schema4_producer", PREPARE_PATH)
    producer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = producer
    spec.loader.exec_module(producer)
    return producer


def protected_old_pilot():
    dataset = ShardedDataset(PILOT, expected_sha256=PILOT_SHA)
    if (dataset.manifest["stage"] != "PILOT" or dataset.manifest["feature_schema_version"] != 4
            or set(dataset.manifest["splits"]) != {"fold1-fit", "fold1-calibration-ready", "fold1-calibration-cold", "fold1-validation"}):
        raise ValueError("exact original complete score-only PILOT required")
    frames, episodes, fit, unseen_validation_accounts = set(), set(), [], set()
    for name in dataset.manifest["splits"]:
        for _, rows in dataset.iter_shards(name):
            for row in rows:
                episode = (row["account_id"], row["window_start"])
                if row["frame_id"] in frames or episode in episodes:
                    raise ValueError("original PILOT contains duplicate evaluated frames")
                frames.add(row["frame_id"])
                episodes.add(episode)
                if name == "fold1-validation" and row["cohort"] == "UNSEEN_READY":
                    unseen_validation_accounts.add(row["account_id"])
            if name == "fold1-fit":
                fit.extend(rows)
    if (len(fit) != 2000 or any(row["label"] != 0 or row["family"] != "normal"
            or row["cohort"] != "READY" or row["baseline_established"] is not True for row in fit)):
        raise ValueError("only existing normal READY FIT may be shared between training components")
    return dataset, fit, frames, episodes, unseen_validation_accounts


def source_identity(producer, dataset):
    _, package = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    shards = {descriptor["path"]: descriptor["sha256"] for split in dataset.manifest["splits"].values()
              for descriptor in split["shards"]}
    if checksum(PILOT / "manifest.json") != PILOT_SHA or any(checksum(PILOT / name) != sha for name, sha in shards.items()):
        raise ValueError("original PILOT manifest or any numeric shard changed")
    generation = PILOT / "generation.identity.json"
    if checksum(generation) != dataset.manifest["generation_identity_sha256"]:
        raise ValueError("original PILOT generation identity changed")
    return {"sources": {str(path.relative_to(ROOT)): checksum(path) for path in SOURCE_FILES},
            "original_pilot": {"manifest_sha256": PILOT_SHA, "generation_identity_sha256": checksum(generation), "shards": shards},
            "frozen_java": {"snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256, **package},
            "endpoint_proof_sha256": checksum(producer.DEFAULT_ENDPOINT_PROOF),
            "execution_image_id": IMAGE_ID}


def assignments(producer, cohort, normal, positive, batch_worlds):
    """All opaque actor ordinals precede generation and do not encode cause."""
    part = producer.Part(TRAINING_SPLIT, cohort, 15, 1, normal, positive)
    batch = []
    for actor in range(normal + positive):
        family_index = None if actor < normal else (actor - normal) % 5
        batch.append((actor, [(0, family_index)]))
        if len(batch) == batch_worlds:
            yield part, batch
            batch = []
    if batch:
        yield part, batch


class NewTrainingShards:
    def __init__(self, output):
        self.output, self.rows, self.descriptors, self.all_rows = output, [], [], []

    def append(self, row):
        self.rows.append(row)
        self.all_rows.append(row)
        if len(self.rows) == 500:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        identifier = f"{TRAINING_SPLIT}-new-{len(self.descriptors):06d}"
        path = self.output / "shards" / (identifier + ".json")
        stats = validate_rows(self.rows, 4)
        write_new(path, self.rows)
        self.descriptors.append({"id": identifier, "path": "shards/" + path.name, "sha256": checksum(path),
                                 "population": "INDEPENDENT_NEW_TRAINING", **stats})
        self.rows = []


def prepare(output, dataset_id="hybrid-pilot-20261003-a01", *, batch_worlds=32):
    if (not re.fullmatch(r"[a-z0-9_-]{8,32}", str(dataset_id)) or dataset_id == "schema4-pilot-20261003-a01"
            or type(batch_worlds) is not int or not 32 <= batch_worlds <= 64):
        raise ValueError("fresh bounded hybrid training identity required")
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE_ID or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only preparation required")
    producer = load_frozen_producer()
    generator = producer.load_generator()
    dataset, shared, old_frames, old_episodes, unseen_validation_accounts = protected_old_pilot()
    before = source_identity(producer, dataset)
    classpath, package = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    endpoint = producer.endpoint_identity(producer.DEFAULT_ENDPOINT_PROOF, producer.DEFAULT_ENDPOINT_SHA256,
                                         producer.DEFAULT_WORKSPACE_SHA256, package, generator)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="hybrid-training-pilot-", dir=ROOT / "observability/runtime"))
    else:
        output = Path(output).absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
            raise ValueError("new private hybrid output directory required")
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    (output / "shards").mkdir(mode=0o700)
    recipe = {"dataset_id": dataset_id, "stage": "PILOT", "data_provenance": "DEMO_ONLY",
              "seed": 42, "generator_blind_seeds": list(generator.BLIND_SEEDS),
              "new_populations": [{"cohort": cohort, "normal": normal, "positive": positive} for cohort, normal, positive in NEW_POPULATIONS],
              "new_positive_per_family": {"READY": 140, "UNSEEN_READY": 40, "COLD": 20},
              "shared_existing_normal_ready_training_rows": 2000,
              "shared_original_normal_rows_sha256": value_sha(shared),
              "unseen_validation_accounts_sha256": value_sha(sorted(unseen_validation_accounts)),
              "training_day": 15, "training_date": "2026-04-15", "evaluated_windows_per_new_actor": 1,
              "past_normal_context_windows": {"READY": 48, "UNSEEN_READY": 48, "COLD": 3},
              "actor_identity_recipe": "EXISTING_FROZEN_HASH_OF_DATASET_FOLD_COHORT_KIND_AND_ACTOR_ORDINAL_NOT_CAUSE",
              "feature_names": list(FEATURE_NAMES_V4), "class_targets": CLASS_TARGETS,
              "confirmed_attack_target_available": False, "batch_worlds": batch_worlds,
              "endpoint_proof": endpoint, "source_identity": before,
              "events_generated_before_declaration": 0, "new_labels_generated_before_declaration": 0,
              "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "quality_gate": "NOT_APPLICABLE"}
    declaration = output / "predeclared.private.json"
    write_new(declaration, recipe)  # Commit label/actor/source recipe before generating any new world.
    write_new(output / "feature-contract.safe.json", {
        "feature_schema_version": 4, "telemetry_contract_version": 3,
        "features": [{"index": index, "name": name} for index, name in enumerate(FEATURE_NAMES_V4)],
        "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES,
        "features_exclude": ["label", "family", "cohort", "account_id", "frame_id", "window_start", "scenario", "client_ledger"],
        "confirmed_attack_target_available": False, "quality_gate": "NOT_APPLICABLE"})
    shared_identifier = f"{TRAINING_SPLIT}-shared-000000"
    shared_path = output / "shards" / (shared_identifier + ".json")
    write_new(shared_path, shared)
    shared_descriptor = {"id": shared_identifier, "path": "shards/" + shared_path.name,
                         "sha256": checksum(shared_path), "population": "SHARED_NORMAL_READY_FIT", **validate_rows(shared, 4)}
    writer, batch_receipts = NewTrainingShards(output), []
    started = time.monotonic()
    for cohort, normal, positive in NEW_POPULATIONS:
        for part, batch in assignments(producer, cohort, normal, positive, batch_worlds):
            state = producer.export_batch(generator, dataset_id, part, batch, 0, classpath, output, writer, timeout=180)
            receipt = {"ordinal": len(batch_receipts), "cohort": cohort,
                       "actors": [actor for actor, _ in batch], "assignment_sha256": value_sha(batch), **state}
            write_new(output / f"batch-{len(batch_receipts):04d}.private.json", receipt)
            batch_receipts.append(receipt)
            print(canonical({"stage": "HYBRID_LABELED_TRAINING_EXTRACTION_ONLY", "new_training_rows": len(writer.all_rows),
                             "planned_new_training_rows": 2000, "batches": len(batch_receipts),
                             "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)
    writer.flush()
    fresh = writer.all_rows
    if len(fresh) != 2000 or any(row["frame_id"] in old_frames or (row["account_id"], row["window_start"]) in old_episodes for row in fresh):
        raise ValueError("new training identities must be disjoint from all original PILOT episodes")
    combined = [*shared, *fresh]
    stats = validate_training_rows(combined)
    if {row["account_id"] for row in combined} & unseen_validation_accounts:
        raise ValueError("all training accounts must remain disjoint from frozen unseen validation accounts")
    after = source_identity(producer, dataset)
    write_new(output / "source-after.private.json", after)
    if before != after:
        raise ValueError("immutable source/original PILOT/Java identity changed; retain failed private artifacts")
    split = {"name": TRAINING_SPLIT, **stats, "shards": [shared_descriptor, *writer.descriptors]}
    split["sha256"] = value_sha(split)
    manifest = {"hybrid_training_schema_version": 1, "dataset_id": dataset_id, "stage": "PILOT",
                "data_provenance": "DEMO_ONLY", "feature_schema_version": 4, "telemetry_contract_version": 3,
                "feature_names": list(FEATURE_NAMES_V4), "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES,
                "target_semantics": "FROZEN_PLANNED_SIMULATION_CAUSES_NOT_CONFIRMED_SECURITY_ATTACKS",
                "confirmed_attack_target_available": False, "predeclared_identity_sha256": checksum(declaration),
                "source_identity_before": before, "source_identity_after": after,
                "workspace_snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256,
                "shared_normal_component_source": {"manifest_sha256": PILOT_SHA, "split": "fold1-fit",
                    "split_sha256": dataset.split("fold1-fit")["sha256"], "original_shards": dataset.split("fold1-fit")["shards"],
                    "rows_sha256": value_sha(shared),
                    "rows": 2000, "normal_ready_only": True, "reuse_across_training_components_permitted": True},
                "frozen_score_only_dataset": {"manifest_sha256": PILOT_SHA, "fit_use": False,
                    "calibration_start": "2026-05-03T00:00:00Z", "validation_start": "2026-05-21T00:00:00Z",
                    "splits": {name: dataset.split(name)["sha256"] for name in ("fold1-calibration-ready", "fold1-calibration-cold", "fold1-validation")}},
                "split": split, "new_independent_training_rows": 2000, "source_worlds": 2000,
                "unseen_validation_accounts_disjoint_from_all_training": True,
                "unseen_validation_accounts_sha256": value_sha(sorted(unseen_validation_accounts)),
                "temporal_isolation": {"latest_training": stats["to"], "earliest_calibration": "2026-05-03T00:00:00Z",
                    "earliest_validation": "2026-05-21T00:00:00Z",
                    "training_to_calibration_gap_seconds": (utc("2026-05-03T00:00:00Z") - utc(stats["to"])).total_seconds(),
                    "strictly_exceeds_14_day_history_gap": True},
                "actual_java_raw_frames": sum(batch["raw_frames"] for batch in batch_receipts),
                "actual_java_evaluated_new_rows": sum(batch["evaluated_rows"] for batch in batch_receipts),
                "batch_receipt_sha256": {f"batch-{index:04d}.private.json": checksum(output / f"batch-{index:04d}.private.json") for index in range(len(batch_receipts))},
                "elapsed_seconds": time.monotonic() - started, "quality_gate": "NOT_APPLICABLE", "fit_or_score_calls": 0,
                "holdout_numeric_records_read": 0, "serving_or_primary_or_aws_changed": False,
                "limitations": ["SIMULATED_PLANNED_SECURITY_CONTEXT_IS_NOT_CONFIRMED_ATTACK", "HTTP_ERROR_IS_OPERATIONAL_CONTEXT",
                                "SMALL_TRAINING_PILOT_NOT_STRICT_QUALIFICATION", "NO_OLD_CALIBRATION_OR_VALIDATION_ROWS_USED_AS_TRAINING"]}
    manifest_path = output / "manifest.private.json"
    write_new(manifest_path, manifest)
    loaded, _ = load_hybrid_fit(output, checksum(manifest_path))
    if loaded != combined:
        raise ValueError("verified protected training loader changed row order/content")
    write_new(output / "result.private.json", {"status": "COMPLETED", "output": str(output), "manifest_sha256": checksum(manifest_path),
        "training_records": len(loaded), "new_independent_training_rows": len(fresh), "actual_java_raw_frames": manifest["actual_java_raw_frames"],
        "actual_java_evaluated_new_rows": manifest["actual_java_evaluated_new_rows"], "class_targets": dict(Counter(CLASS_TARGETS[row["family"]] for row in loaded)),
        "original_pilot_unchanged": True, "source_identity_unchanged": True, "fit_or_score_calls": 0,
        "holdout_numeric_records_read": 0, "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY"})
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dataset-id", default="hybrid-pilot-20261003-a01")
    parser.add_argument("--batch-worlds", type=int, default=32)
    args = parser.parse_args()
    output, manifest = prepare(args.output, args.dataset_id, batch_worlds=args.batch_worlds)
    print(canonical({"status": "COMPLETED", "output": str(output), "manifest_sha256": checksum(output / "manifest.private.json"),
                     "training_records": manifest["split"]["records"], "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Hybrid training PILOT refused/failed: " + type(failure).__name__ + "; private evidence retained") from None
