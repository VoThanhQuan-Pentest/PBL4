#!/usr/bin/env python3
"""Stream an immutable 81500-row BULK_PILOT; never fit, score or qualify.

Batch checkpoints reuse the existing schema4 producer's bounded exporter,
BatchShards and checksum-checked hard-link promotion. A stopped run resumes
only against the same predeclared source and deterministic assignment prefix.
Raw events are piped to Java, never retained as a disk corpus.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict
import fcntl
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))

from app.catalog import ShardedDataset, parse_json, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.expanded_calibration import load_expanded_calibration
from app.hybrid_bulk_dataset import (CLASS_TARGETS, CLASS_TARGET_NAMES, NORMAL_NAMESPACE,
    SUPPLEMENT_NAMESPACE, checksum, load_hybrid_bulk_fit, value_sha)
from app.policy import canonical

IMAGE_ID = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
PRODUCER_PATH = ROOT / "observability/scripts/prepare-ueba-schema4.py"
GENERATOR_SHA = "6797225920eba88e6a26f1f1ff3ee28ee722105c6667e370eab378ce3cb34139"
PILOT = ROOT / "observability/runtime/ueba-experiments/schema4-pilot-20261003-a01"
PILOT_SHA = "3c127c1e57a4a436ecabef1c9fe9d40465fc9191313259560a85554b6d7b9f12"
CALIBRATION = ROOT / "observability/runtime/expanded-calibration-20261003-F4wITdBt/data"
CALIBRATION_SHA = "05253075440b741a010ceae9b497d62acfa2c007952f11a13b91b5ae7443432d"
SUPPLEMENT = (("READY", 50, 7000), ("UNSEEN_READY", 14300, 2000), ("COLD", 7150, 1000))
ARTIFACT_ID = "hybrid-bulk-pilot-20261004-a01"
SOURCE_FILES = (Path(__file__).resolve(), ROOT / "ueba-worker/app/hybrid_bulk_dataset.py", PRODUCER_PATH,
    ROOT / "ueba-worker/app/schema4_episodes.py", ROOT / "ueba-worker/app/contract.py", ROOT / "ueba-worker/app/catalog.py",
    ROOT / "ueba-worker/app/policy.py", ROOT / "ueba-worker/app/strict_metrics.py", ROOT / "ueba-worker/app/hybrid_dataset.py",
    ROOT / "ueba-worker/app/expanded_calibration.py", ROOT / "ueba-worker/app/hybrid_incident.py")


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def producer_module():
    if checksum(ROOT / "ueba-worker/app/schema4_episodes.py") != GENERATOR_SHA:
        raise ValueError("unchanged frozen causal producer required")
    spec = importlib.util.spec_from_file_location("frozen_bulk_schema4_producer", PRODUCER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def account_hour(row):
    return row["account_id"], utc(row["window_start"]).strftime("%Y-%m-%dT%H")


def source_data():
    original = ShardedDataset(PILOT, expected_sha256=PILOT_SHA)
    prefix = [row for _, shard in original.iter_shards("fold1-fit") for row in shard]
    validation = [row for _, shard in original.iter_shards("fold1-validation") for row in shard]
    buckets, calibration_manifest = load_expanded_calibration(CALIBRATION, CALIBRATION_SHA)
    calibration = [row for rows in buckets.values() for row in rows]
    if len(prefix) != 2000 or any(row["label"] or row["cohort"] != "READY" for row in prefix):
        raise ValueError("original verified normal READY2000 prefix required")
    proof = {"original_prefix": {row["frame_id"]: row for row in prefix}, "original_prefix_sha256": value_sha(prefix),
        "calibration_frames": {row["frame_id"] for row in calibration}, "calibration_hours": {account_hour(row) for row in calibration},
        "validation_frames": {row["frame_id"] for row in validation}, "validation_hours": {account_hour(row) for row in validation},
        "unseen_validation_accounts": {row["account_id"] for row in validation if row["cohort"] == "UNSEEN_READY"}}
    return original, calibration_manifest, proof


def source_identity(producer, original, calibration_manifest):
    _, java = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    original_shards = {shard["path"]: shard["sha256"] for split in original.manifest["splits"].values() for shard in split["shards"]}
    cal_shards = {shard["path"]: shard["sha256"] for split in calibration_manifest["splits"].values() for shard in split["shards"]}
    if (checksum(PILOT / "manifest.json") != PILOT_SHA or checksum(CALIBRATION / "manifest.private.json") != CALIBRATION_SHA
            or any(checksum(PILOT / path) != expected for path, expected in original_shards.items())
            or any(checksum(CALIBRATION / path) != expected for path, expected in cal_shards.items())):
        raise ValueError("old source/calibration/validation artifact changed")
    return {"sources": {str(path.relative_to(ROOT)): checksum(path) for path in SOURCE_FILES},
        "original_pilot": {"manifest_sha256": PILOT_SHA, "shards": original_shards},
        "expanded_calibration": {"manifest_sha256": CALIBRATION_SHA, "shards": cal_shards},
        "frozen_java": {"snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256, **java},
        "endpoint_proof_sha256": checksum(producer.DEFAULT_ENDPOINT_PROOF), "execution_image_id": IMAGE_ID}


def jobs(producer, batch_accounts=128):
    normal = producer.Part("fold1-fit", "READY", 15, 1, 50000)
    for number, batch in enumerate(producer.actor_batches(normal, ready_pool=50000, batch_accounts=batch_accounts)):
        yield "NORMAL_COMPONENT", f"normal-b{number:06d}", NORMAL_NAMESPACE, normal, batch
    for cohort, count_normal, count_positive in SUPPLEMENT:
        part = producer.Part("incident-training", cohort, 15, 1, count_normal, count_positive)
        name = {"READY": "ready", "UNSEEN_READY": "unseen", "COLD": "cold"}[cohort]
        batch, number = [], 0
        for actor in range(count_normal + count_positive):
            positive = None if actor < count_normal else (actor - count_normal) % 5
            batch.append((actor, [(0, positive)]))
            if len(batch) == batch_accounts:
                yield "SUPPLEMENT", f"{name}-b{number:06d}", SUPPLEMENT_NAMESPACE, part, batch
                batch, number = [], number + 1
        if batch:
            yield "SUPPLEMENT", f"{name}-b{number:06d}", SUPPLEMENT_NAMESPACE, part, batch


class AuditedWriter:
    def __init__(self, writer, proof, normal_component):
        self.writer, self.proof, self.normal_component = writer, proof, normal_component

    def append(self, row):
        validate_rows([row], 4)
        hour, frame = account_hour(row), row["frame_id"]
        if (frame in self.proof["calibration_frames"] or hour in self.proof["calibration_hours"]
                or frame in self.proof["validation_frames"] or hour in self.proof["validation_hours"]
                or row["account_id"] in self.proof["unseen_validation_accounts"]):
            raise ValueError("bulk training overlaps frozen calibration/validation or unseen account")
        if (row["window_start"] < "2026-04-15T00:00:00Z" or row["window_start"] > "2026-04-15T12:00:00Z"
                or self.normal_component and (row["label"] or row["cohort"] != "READY")):
            raise ValueError("original normal READY FIT chronology required")
        old = self.proof["original_prefix"].get(frame)
        if old is not None and old != row:
            raise ValueError("actual Java changed the original normal2000 prefix")
        self.writer.append(row)

    def flush(self):
        self.writer.flush()


def check_committed(producer, directory, job_id, role, part, batch, identity_sha, proof):
    receipt = parse_json(producer.read_file(directory / "receipt.private.json", 1024 * 1024))
    if (not isinstance(receipt, dict) or receipt.get("job_id") != job_id or receipt.get("role") != role
            or receipt.get("source_identity_sha256") != identity_sha
            or receipt.get("assignment_sha256") != value_sha([asdict(part), batch])):
        raise ValueError("committed bulk batch does not match frozen source/assignment")
    split = "bulk-normal-ready" if role == "NORMAL_COMPONENT" else "bulk-supplement"
    expected_id = f"{split}-{job_id}-000"
    if (not isinstance(receipt.get("shards"), list) or len(receipt["shards"]) != 1
            or not isinstance(receipt["shards"][0], dict) or receipt["shards"][0].get("id") != expected_id
            or receipt["shards"][0].get("path") != "shards/" + expected_id + ".json"):
        raise ValueError("committed batch shard path differs from frozen assignment")
    rows = []
    for shard in receipt.get("shards", []):
        path = directory / (shard["id"] + ".json")
        raw = producer.read_file(path, producer.MAX_SHARD_BYTES)
        if checksum(path) != shard["sha256"]:
            raise ValueError("committed bulk numeric shard changed")
        selected = parse_json(raw)
        stats = validate_rows(selected, 4)
        if any(shard[key] != value for key, value in stats.items()):
            raise ValueError("committed bulk shard counts changed")
        rows.extend(selected)
    if len(rows) != sum(len(evaluations) for _, evaluations in batch):
        raise ValueError("committed bulk batch population is incomplete")
    class Sink:
        def append(self, row): pass
    auditor = AuditedWriter(Sink(), proof, role == "NORMAL_COMPONENT")
    for row in rows:
        auditor.append(row)
    return receipt


def _prepare(output=None, *, resume=False, batch_accounts=128, acquire_lock):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE_ID or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only BULK_PILOT generation required")
    if type(batch_accounts) is not int or batch_accounts not in (96, 128):
        raise ValueError("predeclared96 or128 actor bound required")
    if shutil.disk_usage(ROOT / "observability/runtime").free < 1024 * 1024 * 1024:
        raise ValueError("at least1GiB workspace headroom required for bounded numeric-only pilot")
    producer = producer_module()
    generator = producer.load_generator()
    original, calibration_manifest, proof = source_data()
    before = source_identity(producer, original, calibration_manifest)
    identity_sha = value_sha(before)
    classpath, java = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    endpoint = producer.endpoint_identity(producer.DEFAULT_ENDPOINT_PROOF, producer.DEFAULT_ENDPOINT_SHA256,
                                         producer.DEFAULT_WORKSPACE_SHA256, java, generator)
    declaration = {"artifact_id": ARTIFACT_ID, "stage": "BULK_PILOT", "data_provenance": "DEMO_ONLY", "seed": 42,
        "normal_component_rows": 50000, "supervised_rows": 81500, "supervised_normal": 71500, "supervised_positive": 10000,
        "normal_namespace": NORMAL_NAMESPACE, "supplement_namespace": SUPPLEMENT_NAMESPACE,
        "supplement_populations": [{"cohort": cohort, "normal": normal, "positive": positive} for cohort, normal, positive in SUPPLEMENT],
        "positive_per_family_cohorts": {"READY": 1400, "UNSEEN_READY": 400, "COLD": 200},
        "training_day": 15, "evaluations_per_actor": 1, "batch_accounts": batch_accounts,
        "source_identity": before, "generator_blind_seeds": list(generator.BLIND_SEEDS), "endpoint_proof": endpoint,
        "feature_names": list(FEATURE_NAMES_V4), "original_normal_2000_prefix_sha256": proof["original_prefix_sha256"],
        "class_targets": CLASS_TARGETS, "confirmed_attack_target_available": False,
        "new_frames_generated_before_declaration": 0, "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}
    if output is None:
        if resume:
            raise ValueError("existing output required to resume")
        output = Path(tempfile.mkdtemp(prefix="hybrid-bulk-pilot-", dir=ROOT / "observability/runtime"))
    else:
        output = Path(output).absolute()
        if resume:
            if not output.is_dir() or output.is_symlink() or (output / "manifest.private.json").exists():
                raise ValueError("only unpublished interrupted protected bulk output may resume")
        else:
            if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
                raise ValueError("new protected bulk output directory required")
            output.mkdir(mode=0o700)
    info = output.stat()
    if output.resolve(strict=True) != output or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("bulk output must be private and owner-controlled")
    acquire_lock(output)
    if not resume:
        output.chmod(0o700)
        for name in ("shards", "batches", "pending", "abandoned"):
            (output / name).mkdir(mode=0o700)
        write_new(output / "predeclared.private.json", declaration)
        write_new(output / "feature-contract.safe.json", {"feature_names": list(FEATURE_NAMES_V4),
            "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES,
            "features_exclude": ["label", "family", "cohort", "frame_id", "account_id", "scenario", "client_ledger"],
            "confirmed_attack_target_available": False, "quality_gate": "NOT_APPLICABLE"})
    elif parse_json(producer.read_file(output / "predeclared.private.json", 2 * 1024 * 1024)) != declaration:
        raise ValueError("resumed source/count/seed recipe changed")
    sections, receipts = {"NORMAL_COMPONENT": [], "SUPPLEMENT": []}, {}
    completed = 0
    started = time.monotonic()
    missing_seen = False
    for role, job_id, namespace, part, batch in jobs(producer, batch_accounts):
        committed = output / "batches" / job_id
        pending = output / "pending" / job_id
        if committed.exists():
            if missing_seen:
                raise ValueError("committed bulk batches must form deterministic prefix")
            receipt = check_committed(producer, committed, job_id, role, part, batch, identity_sha, proof)
        else:
            missing_seen = True
            if pending.exists():
                destination = output / "abandoned" / (job_id + "-" + str(time.time_ns()))
                os.rename(pending, destination)  # Preserve partial files; never restart valid committed batches.
            pending.mkdir(mode=0o700)
            split = "bulk-normal-ready" if role == "NORMAL_COMPONENT" else "bulk-supplement"
            writer = producer.BatchShards(pending, split, job_id)
            audited = AuditedWriter(writer, proof, role == "NORMAL_COMPONENT")
            state = producer.export_batch(generator, namespace, part, batch, 0, classpath, pending, audited, timeout=600)
            receipt = {"job_id": job_id, "role": role, "assignment_sha256": value_sha([asdict(part), batch]),
                "source_identity_sha256": identity_sha, "shards": writer.descriptors, **state}
            write_new(pending / "receipt.private.json", receipt)
            check_committed(producer, pending, job_id, role, part, batch, identity_sha, proof)
            os.rename(pending, committed)
        producer.promote(output, committed, receipt)
        sections[role].extend(receipt["shards"])
        receipts[str((committed / "receipt.private.json").relative_to(output))] = checksum(committed / "receipt.private.json")
        completed += receipt["evaluated_rows"]
        producer.replace_progress(output / "progress.private.json", {"stage": "BULK_PILOT", "status": "RUNNING",
            "completed_rows": completed, "planned_rows": 81500, "completed_batches": len(receipts),
            "last_job_id": job_id, "elapsed_seconds_this_process": time.monotonic() - started,
            "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"})
        print(canonical({"stage": "BULK_PILOT", "completed_rows": completed, "planned_rows": 81500,
            "completed_batches": len(receipts), "last_job_id": job_id, "fit_or_score_calls": 0,
            "quality_gate": "NOT_APPLICABLE"}), flush=True)
    if completed != 81500:
        raise ValueError("incomplete bulk population")
    after = source_identity(producer, original, calibration_manifest)
    if before != after:
        raise ValueError("source/old-data/Java identity changed; all committed evidence retained")
    manifest = {"hybrid_bulk_training_schema_version": 1, "artifact_id": ARTIFACT_ID, "dataset_id": ARTIFACT_ID,
        "stage": "BULK_PILOT", "data_provenance": "DEMO_ONLY",
        "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
        "normal_namespace": NORMAL_NAMESPACE, "supplement_namespace": SUPPLEMENT_NAMESPACE,
        "training_sections": {role: producer.split_descriptor(shards) for role, shards in sections.items()},
        "original_normal_2000_prefix_sha256": proof["original_prefix_sha256"],
        "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES, "confirmed_attack_target_available": False,
        "predeclared_identity_sha256": checksum(output / "predeclared.private.json"),
        "source_identity_before": before, "source_identity_after": after, "batch_receipt_sha256": receipts,
        "workspace_snapshot_sha256": producer.DEFAULT_WORKSPACE_SHA256,
        "isolation_proofs": {"unseen_validation_accounts_disjoint": True, "all_training_before_calibration_by_more_than14days": True,
            "calibration_frame_overlap": 0, "calibration_account_hour_overlap": 0, "validation_frame_overlap": 0, "validation_account_hour_overlap": 0},
        "temporal_isolation": {"latest_training": "2026-04-15T12:00:00Z", "earliest_calibration": "2026-05-03T00:00:00Z",
            "training_to_calibration_gap_seconds": 1512000}, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0,
        "quality_gate": "NOT_APPLICABLE", "raw_events_retained": False,
        "limitations": ["PLANNED_CONTEXTS_NOT_CONFIRMED_SECURITY_ATTACKS", "BULK_PILOT_NOT_STRICT_QUALIFICATION",
            "ONE_EVALUATION_PER_ACTOR_DOES_NOT_COVER_ALL_FUTURE_HISTORY_REGIMES", "NO_GUARANTEE_LARGER_TRAINING_PASSES_UNCHANGED_GATES"]}
    path = output / "manifest.private.json"
    write_new(path, manifest)
    normal, rows, _ = load_hybrid_bulk_fit(output, checksum(path))
    write_new(output / "result.private.json", {"status": "COMPLETED", "manifest_sha256": checksum(path),
        "normal_component_rows": len(normal), "supervised_rows": len(rows), "class_counts": dict(Counter(CLASS_TARGETS[row["family"]] for row in rows)),
        "source_identity_unchanged": True, "old_data_unchanged": True, "fit_or_score_calls": 0,
        "holdout_numeric_records_read": 0, "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE"})
    return output, manifest


def prepare(output=None, *, resume=False, batch_accounts=128):
    with ExitStack() as locks:
        def acquire(directory):
            descriptor = os.open(directory / "writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            stream = locks.enter_context(os.fdopen(descriptor, "a+"))
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("private regular owner-controlled batch lock required")
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _prepare(output, resume=resume, batch_accounts=batch_accounts, acquire_lock=acquire)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--batch-accounts", type=int, choices=(96, 128), default=128)
    args = parser.parse_args()
    output, _ = prepare(args.output, resume=args.resume, batch_accounts=args.batch_accounts)
    print(canonical({"status": "COMPLETED", "output": str(output), "manifest_sha256": checksum(output / "manifest.private.json"),
        "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Hybrid BULK_PILOT refused/failed: " + type(failure).__name__ + "; validated checkpoints retained") from None
