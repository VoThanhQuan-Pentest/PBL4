#!/usr/bin/env python3
"""Explicit pinned coordinator admission for exact NEW-source THREE-alias retirement.

Only explicit NEW-source calibration/validation/holdout groups are eligible.
FIT, labels, manifests, receipts and XZ stay intact. The internal deletion path
is separate from private fixtures; no discovery, recursive deletion or JSON row parse.
"""
import argparse
from contextlib import ExitStack
import importlib.util
from itertools import islice
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("strict_source_retirement_archiver", ROOT / "observability/scripts/archive-ueba-strict-source.py")
S = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = S; SPEC.loader.exec_module(S)
COORDINATOR_SPEC = importlib.util.spec_from_file_location("strict_source_retirement_coordinator", ROOT / "observability/scripts/continue-ueba-strict.py")
C = importlib.util.module_from_spec(COORDINATOR_SPEC); COORDINATOR_SPEC.loader.exec_module(C)

APPROVAL_FIELDS = {"approval_schema_version", "scope", "source_standard", "dataset_manifest_sha256",
    "archive_sidecar_sha256", "archive_result_sha256", "source_marker_sha256", "source_terminal_sha256",
    "targets", "retirement_approved", "user_approval_reference"}
TARGET_FIELDS = {"projection", "batch_alias", "verification_alias", "sha256", "bytes"}
PENDING_FIELDS = {"intent", "approval_sha256", "coordinator_checkpoint_sha256", "target", "archive_entry", "batch_receipt_sha256", "original_signature", "restored_sha256"}
DONE_FIELDS = {"status", "pending_sha256", "approval_sha256", "target", "deleted_aliases", "original_bytes_retired"}
COORDINATOR_LOCKS = ("campaign.lock", "selection.lock", "evaluation.lock")
SHARD_ID = re.compile(r"(?P<split>fold[123]-calibration-(?:ready|cold)|fold[123]-validation|holdout)-(?P<batch>part[0-9]{2}-batch[0-9]{6})-[0-9]{3}")
LEDGER = "source-retirement"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
SOURCE_PINS = ("dataset_manifest_sha256", "archive_sidecar_sha256", "archive_result_sha256", "source_marker_sha256", "source_terminal_sha256")
CHECKPOINT_FIELDS = {"checkpoint_schema_version", "scope", "status", "source_standard", "retirement_approval_sha256",
    *SOURCE_PINS, "continuation_identity_sha256", "identity", "commands", "lock_paths", "active_consumers", "code_sha256"}
CODE_FILES = ("observability/scripts/retire-ueba-strict-source-shards.py", "observability/scripts/archive-ueba-strict-source.py",
              "observability/scripts/continue-ueba-strict.py", "ueba-worker/app/pipeline_lock.py")
MAX_APPROVAL_BYTES = 8 * 1024 * 1024


def lock_paths(source):
    return (source.parent / "writer.lock", source / "generation.lock", *(source.parent / name for name in COORDINATOR_LOCKS))


def coordinator_admission(source, approval, approval_sha256, checkpoint_path, checkpoint_sha256, *, lock_checks,
                          expected_scope="NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR"):
    """Rebuild the source-only frozen plan; checkpoint booleans confer no authority."""
    if (expected_scope not in {"NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR", "NEW_STRICT_CACHE_RETIREMENT_COORDINATOR"}
            or type(lock_checks) not in (tuple, list) or len(lock_checks) != 5
            or type(approval_sha256) is not str or S.SHA.fullmatch(approval_sha256) is None
            or type(approval) is not dict or any(type(approval.get(key)) is not str or S.SHA.fullmatch(approval[key]) is None for key in SOURCE_PINS)):
        raise ValueError("exact scoped coordinator and five held lock validators required")
    code_files = CODE_FILES + (("observability/scripts/archive-ueba-staged-cache.py",)
                             if expected_scope == "NEW_STRICT_CACHE_RETIREMENT_COORDINATOR" else ())
    for check in lock_checks: check()
    if checkpoint_path is None or type(checkpoint_sha256) is not str or S.SHA.fullmatch(checkpoint_sha256) is None:
        raise ValueError("Material source deletion blocked: explicit pinned coordinator checkpoint required")
    checkpoint_path = Path(checkpoint_path)
    checkpoint, snapshot = S.metadata(checkpoint_path, S.MAX_METADATA, checkpoint_sha256)
    if (type(checkpoint) is not dict or set(checkpoint) != CHECKPOINT_FIELDS
            or type(checkpoint["checkpoint_schema_version"]) is not int or checkpoint["checkpoint_schema_version"] != 1
            or checkpoint["scope"] != expected_scope or checkpoint["status"] != "QUIESCENT"
            or checkpoint["source_standard"] != str(source) or checkpoint["retirement_approval_sha256"] != approval_sha256
            or any(checkpoint[key] != approval[key] for key in SOURCE_PINS)
            or type(checkpoint["active_consumers"]) is not list or checkpoint["active_consumers"] != []
            or checkpoint["lock_paths"] != [str(path) for path in lock_paths(source)]
            or type(checkpoint["identity"]) is not dict or type(checkpoint["commands"]) is not dict
            or set(checkpoint["commands"]) != {"campaign", "selection", "evaluation"}
            or type(checkpoint["code_sha256"]) is not dict or set(checkpoint["code_sha256"]) != set(code_files)):
        raise ValueError("exact quiescent NEW source coordinator checkpoint required")
    identity = checkpoint["identity"]
    if (identity.get("image_id") != IMAGE or os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE or not Path("/.dockerenv").is_file()
            or type(checkpoint["continuation_identity_sha256"]) is not str or S.SHA.fullmatch(checkpoint["continuation_identity_sha256"]) is None):
        raise ValueError("pinned Docker image and frozen continuation identity required")
    code_snapshots = {}
    for relative in code_files:
        path = ROOT / relative; raw = C.checked_bytes(path, 1024 * 1024, private=False)
        if type(checkpoint["code_sha256"][relative]) is not str or S.sha256(raw) != checkpoint["code_sha256"][relative]:
            raise ValueError("current retirement/archive/coordinator/lock code SHA changed")
        code_snapshots[path] = raw
    try:
        plan = C.HybridPlan(source, dataset_sha=approval["dataset_manifest_sha256"], archive_sha=approval["archive_sidecar_sha256"],
            marker_sha=approval["source_marker_sha256"], terminal_sha=approval["source_terminal_sha256"],
            code=identity["code_directory"], code_sha=identity["code_inventory_sha256"],
            workspace=identity["workspace_directory"], workspace_sha=identity["java_snapshot_sha256"], image=identity["image_id"])
    except (KeyError, TypeError):
        raise ValueError("complete pinned frozen continuation bindings required") from None
    commands = {name: plan.command(stage) for name, stage in (("campaign", "fit"), ("selection", "validation"), ("evaluation", "holdout"))}
    if (identity != plan.identity or checkpoint["continuation_identity_sha256"] != S.sha256(S.canonical(plan.identity).encode())
            or checkpoint["commands"] != commands
            or identity.get("continuation_script_sha256") != checkpoint["code_sha256"]["observability/scripts/continue-ueba-strict.py"]
            or identity.get("python_sources", {}).get("pipeline_lock.py") != checkpoint["code_sha256"]["ueba-worker/app/pipeline_lock.py"]):
        raise ValueError("recomputed source/archive/code/JVM/image commands differ from checkpoint")
    marker = S.metadata(source.parent / "predeclared.private.json", S.MAX_METADATA, approval["source_marker_sha256"])[0]
    if marker["source_identity"].get("execution_image_id") != IMAGE:
        raise ValueError("completed source image differs from retirement checkpoint")

    def validate_code():
        for path, raw in code_snapshots.items():
            if C.checked_bytes(path, 1024 * 1024, private=False) != raw: raise ValueError("admitted retirement code changed")
    for check in lock_checks: check()
    return (checkpoint_path, snapshot), validate_code


def load_approval(path, expected_sha256):
    if type(expected_sha256) is not str or S.SHA.fullmatch(expected_sha256) is None:
        raise ValueError("explicit trusted approval SHA required")
    approval, _ = S.metadata(Path(path), MAX_APPROVAL_BYTES, expected_sha256)
    if (type(approval) is not dict or set(approval) != APPROVAL_FIELDS
            or type(approval["approval_schema_version"]) is not int or approval["approval_schema_version"] != 1
            or approval["scope"] != "NEW_STRICT_SOURCE_SHARDS_ONLY" or type(approval["source_standard"]) is not str
            or type(approval["retirement_approved"]) is not bool or type(approval["user_approval_reference"]) is not str
            or not 1 <= len(approval["user_approval_reference"]) <= 2000 or not approval["user_approval_reference"].strip()
            or type(approval["targets"]) is not list or not 1 <= len(approval["targets"]) <= S.MAX_SHARDS
            or any(type(approval[key]) is not str or S.SHA.fullmatch(approval[key]) is None for key in
                   ("dataset_manifest_sha256", "archive_sidecar_sha256", "archive_result_sha256", "source_marker_sha256", "source_terminal_sha256"))):
        raise ValueError("exact explicit NEW source retirement approval required")
    projections = set()
    for target in approval["targets"]:
        if (type(target) is not dict or set(target) != TARGET_FIELDS
                or any(type(target[key]) is not str for key in ("projection", "batch_alias", "verification_alias", "sha256"))
                or S.SHA.fullmatch(target["sha256"]) is None or type(target["bytes"]) is not int
                or not 1 <= target["bytes"] <= S.MAX_SHARD_BYTES):
            raise ValueError("exact bounded three-alias target required")
        path = Path(target["projection"]); match = SHARD_ID.fullmatch(path.stem)
        if (match is None or target["projection"] != f"shards/{path.stem}.json"
                or target["batch_alias"] != f"batches/{match['batch']}/{path.stem}.json"
                or target["verification_alias"] != f"verification/shards/{path.stem}.json"
                or target["projection"] in projections):
            raise ValueError("only exact declared non-FIT three-alias groups are allowed")
        projections.add(target["projection"])
    return approval


def bound_source(source, approval):
    snapshots = {}
    def record(path, expected, maximum=S.MAX_METADATA):
        value, snapshot = S.metadata(path, maximum, expected); snapshots[path] = (snapshot, maximum); return value
    marker = record(source.parent / "predeclared.private.json", approval["source_marker_sha256"])
    terminal = record(source.parent / "state.private.json", approval["source_terminal_sha256"])
    if (marker.get("scope") != "FULL_STRICT_SOURCE" or type(marker.get("source_identity")) is not dict or not marker["source_identity"]
            or type(marker.get("protocol")) is not dict or marker.get("protocol_sha256") != S.protocol_sha256(marker["protocol"])
            or marker["protocol"].get("stage") != "STRICT_SOURCE" or marker["protocol"].get("quality_gate") != "NOT_EVALUATED"
            or terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE" or terminal.get("stage") != "STRICT_SOURCE"
            or terminal.get("scope") != "FULL_STRICT_SOURCE" or terminal.get("quality_gate") != "NOT_EVALUATED"
            or terminal.get("folds_completed") != [1, 2, 3] or any(type(fold) is not int for fold in terminal["folds_completed"])
            or terminal.get("source_identity_before") != marker["source_identity"]
            or terminal.get("source_identity_after") != marker["source_identity"]
            or any(type(record.get(key)) is not int or record[key] != 0 for record, key in (
                (marker, "fit_or_score_calls"), (marker, "holdout_numeric_records_read"), (terminal, "fit_or_score_calls"),
                (terminal, "holdout_numeric_records_read"), (terminal, "downstream_holdout_numeric_records_read")))):
        raise ValueError("completed pinned FULL_STRICT_SOURCE required")
    dataset = S.ArchivedShardedDataset(source, expected_sha256=approval["dataset_manifest_sha256"],
                                     expected_archive_sha256=approval["archive_sidecar_sha256"])
    S.validate_standard_manifest(dataset.manifest, marker["protocol"]["dataset_id"])
    if dataset.manifest["stage"] != "STRICT": raise ValueError("retirement requires actual STRICT source metadata")
    for path, sha in ((source / "manifest.json", approval["dataset_manifest_sha256"]),
                      (source / "verification/manifest.json", approval["dataset_manifest_sha256"]),
                      (source / S.SIDECAR, approval["archive_sidecar_sha256"])):
        record(path, sha, S.MAX_MANIFEST_BYTES)
    S.owned_root(source / "verification"); S.owned_root(source / "verification/shards"); S.owned_root(source / "batches")
    result = record(source / S.RESULT, approval["archive_result_sha256"])
    expected = {"status": "COMPLETED", "scope": "STORAGE_ONLY", "dataset_manifest_sha256": approval["dataset_manifest_sha256"],
                "archive_sidecar_sha256": approval["archive_sidecar_sha256"], "source_marker_sha256": approval["source_marker_sha256"],
                "source_terminal_sha256": approval["source_terminal_sha256"], "original_files_deleted_or_renamed": 0,
                "numeric_rows_parsed": 0, "holdout_numeric_records_read": 0, "fit_calls": 0, "score_calls": 0}
    if (any(result.get(key) != value for key, value in expected.items())
            or any(type(result.get(key)) is not int for key in ("original_files_deleted_or_renamed", "numeric_rows_parsed",
                       "holdout_numeric_records_read", "fit_calls", "score_calls"))):
        raise ValueError("exact completed archive result required")
    generation = record(source / "generation.identity.json", result["source_generation_identity_sha256"])
    progress = record(source / "generation.progress.json", result["source_generation_progress_sha256"])
    if (generation.get("stage") != "STRICT" or progress.get("status") != "COMPLETED" or progress.get("stage") != "STRICT"
            or generation.get("dataset_id") != dataset.manifest["dataset_id"] or progress.get("dataset_id") != dataset.manifest["dataset_id"]
            or generation.get("source_binding") != dataset.manifest.get("source_binding")
            or generation.get("old_numeric_corpus_read") is not False or generation.get("authentic_capture") is not False
            or any(type(record.get("fit_or_score_calls")) is not int or record["fit_or_score_calls"] != 0 for record in (generation, progress))
            or progress.get("manifest_sha256") != approval["dataset_manifest_sha256"]
            or result["source_generation_identity_sha256"] != dataset.manifest.get("generation_identity_sha256")):
        raise ValueError("completed producer metadata must remain archive-bound")
    descriptors = {item["path"]: (name, item) for name, split in dataset.manifest["splits"].items() for item in split["shards"]}
    if not 1 <= len(descriptors) <= S.MAX_SHARDS: raise ValueError("bounded declared source topology required")
    names = {Path(path).name for path in descriptors}
    for relative, known in (("shards", names | {name + ".xz" for name in names}), ("verification/shards", names)):
        files = list(islice((source / relative).iterdir(), 2 * S.MAX_SHARDS + 1))
        if len(files) > 2 * S.MAX_SHARDS or any(path.name not in known or path.is_symlink() or not path.is_file() for path in files):
            raise ValueError("unknown source/verification files or alias symlinks refused")
    for path, (name, descriptor) in descriptors.items():
        if name.endswith("-fit"):
            raw, _ = S.read_bytes(S.resource_path(source, path), S.MAX_SHARD_BYTES)
            if S.sha256(raw) != descriptor["sha256"]: raise ValueError("FIT originals must remain plain and unchanged")
    return dataset, descriptors, snapshots


def group_binding(source, target, dataset, descriptors):
    pair = descriptors.get(target["projection"])
    if pair is None or pair[0].endswith("-fit"): raise ValueError("only declared calibration/validation/holdout originals may retire")
    split, descriptor = pair; match = SHARD_ID.fullmatch(descriptor["id"])
    if match is None or match["split"] != split or descriptor["sha256"] != target["sha256"]:
        raise ValueError("approved target differs from manifest role/hash")
    entry = dataset._archive_entries[target["projection"]]
    if entry["original_bytes"] != target["bytes"]: raise ValueError("approved target size differs from archived original")
    batch = S.owned_root(source / "batches" / match["batch"])
    receipt, snapshot = S.metadata(batch / "receipt.json", S.MAX_METADATA)
    if (type(receipt) is not dict or receipt.get("batch_id") != match["batch"] or receipt.get("split") != split
            or receipt.get("generation_identity_sha256") != dataset.manifest["generation_identity_sha256"]
            or type(receipt.get("shards")) is not list or not 1 <= len(receipt["shards"]) <= S.MAX_SHARDS
            or sum(item == descriptor for item in receipt["shards"]) != 1):
        raise ValueError("exact committed batch receipt membership required")
    known = {"receipt.json"}
    for item in receipt["shards"]:
        if descriptors.get(item.get("path")) != (split, item): raise ValueError("receipt contains unapproved shard descriptors")
        own_match = SHARD_ID.fullmatch(item["id"])
        if own_match is None or own_match["batch"] != match["batch"]: raise ValueError("receipt alias escapes its fixed batch")
        known.add(item["id"] + ".json")
    files = list(islice(batch.iterdir(), S.MAX_SHARDS + 2))
    if any(path.name not in known or path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("unknown committed batch files/aliases refused")
    paths = [source / target[key] for key in ("projection", "batch_alias", "verification_alias")]
    return paths, entry, S.sha256(snapshot[0]), (batch / "receipt.json", snapshot)


def restore_scratch(source, entry, target):
    raw = S.restore_xz(source, entry)  # Opaque bounded bytes, never numeric JSON.
    if len(raw) != target["bytes"] or S.sha256(raw) != target["sha256"]:
        raise ValueError("restored original bytes differ from approved target")
    with tempfile.TemporaryDirectory(prefix="ueba-source-restore-") as temporary:
        S.require_headroom(Path(temporary), len(raw))
        path = Path(temporary) / "restored.bytes"; S.write_new(path, raw)
        actual, _ = S.read_bytes(path, S.MAX_SHARD_BYTES)
        if len(actual) != target["bytes"] or S.sha256(actual) != target["sha256"]:
            raise ValueError("private scratch restoration verification failed")


def original_group(paths, target, *, pending=None):
    present = []; signatures = []
    for path in paths:
        if path.is_symlink(): raise ValueError("source alias symlink refused")
        if not path.exists(): continue
        raw, signature = S.read_bytes(path, S.MAX_SHARD_BYTES)
        if len(raw) != target["bytes"] or S.sha256(raw) != target["sha256"]: raise ValueError("original alias bytes changed")
        present.append(path); signatures.append(signature)
    if pending is None and len(present) != 3: raise ValueError("all three original aliases required before retirement")
    if signatures:
        first = signatures[0]
        if any(value != first for value in signatures) or first[-1] != len(present):
            raise ValueError("exact shared inode/link-count required; unknown hardlinks refused")
        if pending is not None:
            original = pending["original_signature"]
            if list(first[:4]) != original[:4] or (len(present) == 3 and list(first) != original):
                raise ValueError("retained original inode/size changed after retirement intent")
    return present, signatures[0] if signatures else None


def validate_pending(record, expected):
    if (type(record) is not dict or set(record) != PENDING_FIELDS or any(record.get(key) != value for key, value in expected.items())
            or type(record.get("original_signature")) is not list or len(record["original_signature"]) != 6
            or any(type(value) is not int or value < 0 for value in record["original_signature"])
            or record["original_signature"][2] != expected["target"]["bytes"] or record["original_signature"][-1] != 3):
        raise ValueError("exact durable original three-alias retirement intent required")
    return record


def unchanged(snapshots):
    for path, (snapshot, maximum) in snapshots.items():
        if S.read_bytes(path, maximum) != snapshot: raise ValueError("protected source metadata changed")


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def run(approval_path, approval_sha256, *, retire=False, resume=False, coordinator_checkpoint=None, coordinator_checkpoint_sha256=None):
    if retire and (coordinator_checkpoint is None or coordinator_checkpoint_sha256 is None):
        raise ValueError("Material source deletion blocked: explicit pinned coordinator checkpoint required")
    if (coordinator_checkpoint is None) != (coordinator_checkpoint_sha256 is None): raise ValueError("checkpoint path and SHA required together")
    return _run(approval_path, approval_sha256, retire=retire, resume=resume,
                coordinator_checkpoint=coordinator_checkpoint, coordinator_checkpoint_sha256=coordinator_checkpoint_sha256)


def run_fixture(approval_path, approval_sha256, *, retire=False, resume=False):
    """Explicit temporary fixtures only; never called by the production CLI."""
    if S.RUNTIME == ROOT / "observability/runtime": raise ValueError("private temporary fixture runtime override required")
    return _run(approval_path, approval_sha256, retire=retire, resume=resume, fixture_only=True)


def _run(approval_path, approval_sha256, *, retire=False, resume=False, coordinator_checkpoint=None,
         coordinator_checkpoint_sha256=None, fixture_only=False):
    if any(type(value) is not bool for value in (retire, resume, fixture_only)): raise ValueError("explicit boolean operation flags required")
    if retire and not fixture_only and coordinator_checkpoint is None: raise ValueError("pinned retirement coordinator required")
    approval = load_approval(approval_path, approval_sha256)
    if retire and not approval["retirement_approved"]: raise ValueError("explicit per-source retirement approval required")
    source = S.source_path(approval["source_standard"])
    if str(source) != approval["source_standard"]: raise ValueError("approval must pin the exact canonical source root")
    with ExitStack() as stack:
        lock_checks = [S.lock_existing(stack, path) for path in lock_paths(source)]
        dataset, descriptors, snapshots = bound_source(source, approval)
        _, approval_snapshot = S.metadata(Path(approval_path), MAX_APPROVAL_BYTES, approval_sha256)
        snapshots[Path(approval_path)] = (approval_snapshot, MAX_APPROVAL_BYTES)
        if coordinator_checkpoint is not None:
            checkpoint_snapshot, code_check = coordinator_admission(source, approval, approval_sha256, coordinator_checkpoint, coordinator_checkpoint_sha256,
                                                                   lock_checks=lock_checks)
            snapshots[checkpoint_snapshot[0]] = (checkpoint_snapshot[1], S.MAX_METADATA)
            lock_checks.append(code_check)
        ledger = source / LEDGER / approval_sha256
        if ledger.exists():
            S.owned_root(source / LEDGER); S.owned_root(ledger)
            if not resume: raise ValueError("explicit identical approval resume required")
            names = {Path(target["projection"]).stem + suffix for target in approval["targets"]
                     for suffix in (".pending.private.json", ".completed.private.json")}
            if any(path.name not in names or path.is_symlink() or not path.is_file() for path in islice(ledger.iterdir(), 2 * S.MAX_SHARDS + 1)):
                raise ValueError("unknown durable retirement records refused")
        elif resume: raise ValueError("prior durable retirement intent required for resume")
        plans = []
        for target in approval["targets"]:
            paths, entry, receipt_sha, receipt_snapshot = group_binding(source, target, dataset, descriptors)
            snapshots[receipt_snapshot[0]] = (receipt_snapshot[1], S.MAX_METADATA)
            name = Path(target["projection"]).stem
            pending_path = ledger / (name + ".pending.private.json"); done_path = ledger / (name + ".completed.private.json")
            expected = {"intent": "RETIRE_EXACT_THREE_SHARD_ALIASES", "approval_sha256": approval_sha256,
                        "coordinator_checkpoint_sha256": coordinator_checkpoint_sha256,
                        "target": target, "archive_entry": entry, "batch_receipt_sha256": receipt_sha, "restored_sha256": target["sha256"]}
            pending = None
            if pending_path.exists(): pending = validate_pending(S.metadata(pending_path, S.MAX_METADATA)[0], expected)
            elif done_path.exists(): raise ValueError("completed retirement lacks durable intent")
            restore_scratch(source, entry, target)
            present, signature = original_group(paths, target, pending=pending)
            if done_path.exists():
                done = S.metadata(done_path, S.MAX_METADATA)[0]
                desired = {"status": "COMPLETED", "pending_sha256": S.sha256(S.canonical(pending).encode()), "approval_sha256": approval_sha256,
                           "target": target, "deleted_aliases": 3, "original_bytes_retired": target["bytes"]}
                if type(done) is not dict or set(done) != DONE_FIELDS or done != desired or present:
                    raise ValueError("retained retirement completion changed")
            plans.append((target, paths, entry, expected, pending, signature, pending_path, done_path))
        unchanged(snapshots)
        for check in lock_checks: check()
        if not retire:
            return {"status": "VERIFIED_ONLY", "groups_verified": len(plans), "original_aliases_deleted": 0, "numeric_rows_parsed": 0}
        if not ledger.exists():
            (source / LEDGER).mkdir(mode=0o700, exist_ok=True); S.owned_root(source / LEDGER); ledger.mkdir(mode=0o700)
            for directory in (ledger, ledger.parent, source): fsync_directory(directory)
        deleted = 0
        for target, paths, entry, expected, pending, signature, pending_path, done_path in plans:
            if done_path.exists(): continue
            restore_scratch(source, entry, target); unchanged(snapshots)
            if pending is None:
                present, signature = original_group(paths, target)
                pending = {**expected, "original_signature": list(signature)}
                S.write_new(pending_path, S.canonical(pending).encode())
            for path in paths:
                present, _ = original_group(paths, target, pending=pending)
                if path not in present: continue
                unchanged(snapshots)
                for check in lock_checks: check()
                path.unlink()  # Exact approved NEW alias, under all five still-bound locks.
                fsync_directory(path.parent)
                deleted += 1
            if original_group(paths, target, pending=pending)[0]: raise ValueError("not all exact aliases retired")
            done = {"status": "COMPLETED", "pending_sha256": S.sha256(S.canonical(pending).encode()), "approval_sha256": approval_sha256,
                    "target": target, "deleted_aliases": 3, "original_bytes_retired": target["bytes"]}
            S.write_new(done_path, S.canonical(done).encode())
        unchanged(snapshots)
        status = "RETIRED_FIXTURE_ONLY" if fixture_only else "NEW_STRICT_SOURCE_RETIRED"
        return {"status": status, "scope": status, "retirement_approval_sha256": approval_sha256,
                "coordinator_checkpoint_sha256": coordinator_checkpoint_sha256,
                "groups_completed": len(plans), "original_aliases_deleted_this_attempt": deleted,
                "numeric_rows_parsed": 0, "original_bytes_retired": sum(plan[0]["bytes"] for plan in plans)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", type=Path, required=True); parser.add_argument("--approval-sha256", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-only", action="store_true"); mode.add_argument("--retire-approved-files", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--coordinator-checkpoint", type=Path); parser.add_argument("--coordinator-checkpoint-sha256")
    args = parser.parse_args()
    if args.retire_approved_files and (args.coordinator_checkpoint is None or args.coordinator_checkpoint_sha256 is None):
        raise SystemExit("Material source deletion blocked: explicit pinned coordinator checkpoint required")
    try: print(S.canonical(run(args.approval, args.approval_sha256, retire=args.retire_approved_files, resume=args.resume,
        coordinator_checkpoint=args.coordinator_checkpoint, coordinator_checkpoint_sha256=args.coordinator_checkpoint_sha256)), flush=True)
    except Exception as failure:
        raise SystemExit("Strict source retirement refused/failed: " + type(failure).__name__ + "; bounded archives and durable intents retained") from None
