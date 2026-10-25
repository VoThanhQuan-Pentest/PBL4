#!/usr/bin/env python3
"""Freeze selection or generate bounded independent post-freeze holdout batches.

No original numeric row is read by this writer. Full source-proof readback may
read designated original TRAIN/VAL rows, never the blocked original holdout.
Generation requires an explicit pinned frozen receipt, Docker and opt-in.
"""
import argparse
from collections import Counter
from dataclasses import asdict
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

from app.catalog import ShardedDataset
from app.fresh_holdout_recovery import (FAMILIES, IMAGE, MANIFEST_FORMAT, MAX_RECEIPT_BYTES, checked_path,
    digest_document, freeze_selection, fresh_protocol, load_frozen_receipt, private_directory, private_read,
    code_sha256, project_root, recovery_code_binding, require_execution_environment, require_separate_location,
    verify_frozen_receipt, verify_recovery_authority, write_new)
from app.policy import canonical
from app.holdout_provenance import require_unblocked_holdout


def frozen_producer(receipt):
    root = project_root(); path = root / "observability/scripts/prepare-ueba-schema4.py"
    expected = receipt["source"]["generation_source_binding"]["source_sha256"]
    names = {"observability/scripts/prepare-ueba-schema4.py", "ueba-worker/app/schema4_episodes.py",
             "ueba-worker/app/catalog.py", "ueba-worker/app/contract.py", "ueba-worker/app/policy.py", "ueba-worker/app/strict_metrics.py"}
    if set(expected) != names or any(code_sha256(root / name) != expected[name] for name in names):
        raise ValueError("pre-execution frozen standard producer/generator code SHA mismatch")
    spec = importlib.util.spec_from_file_location("fresh_holdout_frozen_producer", path)
    producer = importlib.util.module_from_spec(spec); sys.modules[spec.name] = producer
    original_path = list(sys.path)
    try: spec.loader.exec_module(producer)
    finally: sys.path[:] = original_path
    producer.source_binding()
    return producer


def bind_producer(producer, receipt, workspace):
    if producer.source_binding() != receipt["source"]["generation_source_binding"]:
        raise ValueError("original frozen causal producer binding changed")
    classpath, package = producer.workspace_identity(workspace, receipt["source"]["workspace_snapshot_sha256"])
    generator = producer.load_generator()
    endpoint = producer.endpoint_identity(producer.DEFAULT_ENDPOINT_PROOF, producer.DEFAULT_ENDPOINT_SHA256,
        receipt["source"]["workspace_snapshot_sha256"], package, generator)
    return {"standard_producer": producer.source_binding(), "java": package, "endpoint_proof": endpoint,
        "workspace_snapshot_sha256": receipt["source"]["workspace_snapshot_sha256"],
        "execution_image_id": IMAGE, "recovery_project_root": str(project_root()), "recovery_code_sha256": recovery_code_binding()}, classpath, generator


def parts_for(producer, protocol):
    holdout = protocol["holdout"]
    return [producer.Part("holdout", cohort, holdout["start_day"], holdout["days"], normal, positive)
            for cohort, normal, positive in producer.proportions(holdout["normal"], holdout["positive"])]


class FreshCaseGenerator:
    """Frozen cause planner with independent case seeds, not relabelled rows.

    READY retains exactly the original fold3 FIT subject/profile namespace.
    Cases and frame identities use the fresh namespace for every cohort. The
    frozen builder assigns labels before producing events; cause is absent
    from all identity and seed calculations.
    """
    def __init__(self, generator, producer, protocol, receipt):
        self.generator = generator
        self.identity_worlds = {}
        for part in parts_for(producer, protocol):
            case_world = producer.namespace(protocol["seed_namespace"], part)
            identity_world = (producer.namespace(receipt["source"]["dataset_id"], part)
                              if part.cohort == "READY" else case_world)
            self.identity_worlds[case_world] = (identity_world, part.cohort)

    def __getattr__(self, name): return getattr(self.generator, name)

    def account_profile(self, case_world, account):
        identity_world, _ = self.identity_worlds[case_world]
        return self.generator.account_profile(identity_world, account)

    def make_frame(self, case_world, account, ordinal, window_start, *, planned_cause="normal", context=False, cohort="READY"):
        generator = self.generator
        generator._identity_inputs(case_world, account)
        generator._integer(ordinal, 0, generator.MAX_EPISODE_ORDINAL, "episode ordinal")
        identity_world, expected_cohort = self.identity_worlds[case_world]
        if cohort != expected_cohort or type(context) is not bool or context and planned_cause != "normal":
            raise ValueError("unchanged cohort and normal past-only context required")
        start = generator._start(window_start)
        at = generator._timestamp(start)
        subject = "acct-" + generator._digest([identity_world, account])[:32]
        master = generator.BLIND_SEEDS[generator.stable_seed("world", case_world, account) % len(generator.BLIND_SEEDS)]
        seed = generator.stable_seed(generator.PROTOCOL_VERSION, master, case_world, account, ordinal, at, context)
        frame = "frame-" + generator._digest(["fresh-holdout", case_world, account, ordinal, at, context])[:40]
        return generator.build_scenario(seed, self.account_profile(case_world, account), planned_cause, start, cohort,
            account_id=subject, frame_id=frame, context=context)


def jobs(producer, parts, batch_accounts):
    offsets = Counter()
    for number, part in enumerate(parts):
        for batch_number, batch in enumerate(producer.actor_batches(part, 50000, batch_accounts)):
            yield f"part{number:02d}-batch{batch_number:06d}", part, batch, offsets[part.split]
        offsets[part.split] += part.positive


def allocate_fresh_holdout(receipt_path, receipt_sha256, receipt, output, *, dataset_id=None, resume=False, scoped_test=False):
    """One write-once allocation per exact pinned receipt resource.

    This ledger forbids drawing another holdout for the same frozen selection
    after a failed result. An interruption resumes only this ID/root/entropy.
    Allocation is durable before the first causal raw frame is constructed.
    """
    ledger_path = checked_path(receipt_path).with_name(Path(receipt_path).name + ".allocation.private.json")
    authority = verify_recovery_authority(receipt, receipt_path)
    output = checked_path(output)
    if resume:
        allocation_sha, allocation = private_read(ledger_path, MAX_RECEIPT_BYTES)
        if (type(allocation) is not dict or set(allocation) != {"format", "frozen_selection_receipt_sha256", "recovery_authority", "output_root", "protocol"}
                or allocation["format"] != "FRESH_HOLDOUT_ALLOCATION_V1"
                or allocation["frozen_selection_receipt_sha256"] != receipt_sha256
                or allocation["recovery_authority"] != authority
                or allocation["output_root"] != str(output)):
            raise ValueError("same immutable fresh allocation receipt/root required")
        protocol = allocation["protocol"]
        expected = fresh_protocol(receipt, receipt_sha256, protocol["dataset_id"], protocol["postfreeze_entropy_hex"], scoped_test=scoped_test)
        if protocol != expected or dataset_id is not None and dataset_id != protocol["dataset_id"]:
            raise ValueError("same immutable fresh allocation dataset/entropy required")
    else:
        if ledger_path.exists(): raise ValueError("frozen selection already allocated its one fresh holdout; redraw refused")
        if output.exists(): raise ValueError("new independent fresh output root required")
        if dataset_id is None: raise ValueError("explicit distinct fresh dataset ID required")
        # All model/policy/source readback precedes this one fresh entropy draw.
        protocol = fresh_protocol(receipt, receipt_sha256, dataset_id, secrets.token_hex(32), scoped_test=scoped_test)
        allocation = {"format": "FRESH_HOLDOUT_ALLOCATION_V1", "frozen_selection_receipt_sha256": receipt_sha256,
            "recovery_authority": authority, "output_root": str(output), "protocol": protocol}
        # O_EXCL arbitrates concurrent callers; the loser never creates cases.
        allocation_sha = write_new(ledger_path, allocation)
    return allocation_sha, protocol


def _replace_progress(producer, output, value):
    producer.replace_progress(output / "state.private.json", value)


def _check_population(producer, descriptor, protocol):
    ShardedDataset._check_split(descriptor, set(), set())
    holdout = protocol["holdout"]; total = holdout["normal"] + holdout["positive"]
    if (descriptor["normal"] != holdout["normal"] or descriptor["positive"] != holdout["positive"]
            or descriptor["records"] != total
            or descriptor["families"] != {"normal": holdout["normal"], **{family: holdout["positive_per_family"] for family in FAMILIES}}
            or descriptor["cohorts"] != {"READY": total * 7 // 10, "UNSEEN_READY": total * 2 // 10,
                                         "COLD": total - total * 7 // 10 - total * 2 // 10}):
        raise ValueError("all fresh holdout normal/family/cohort populations required")


def verify_completed_generation(producer, output, protocol, declaration_sha, batch_accounts):
    """Metadata-only complete deterministic receipt-chain readback."""
    descriptors = []
    for batch_id, part, batch, positive_offset in jobs(producer, parts_for(producer, protocol), batch_accounts):
        committed = private_directory(output / "batches" / batch_id)
        _, receipt = private_read(committed / "receipt.json", producer.MAX_RECEIPT_BYTES)
        producer.check_receipt(receipt, batch_id, part, batch, positive_offset, declaration_sha)
        descriptors.extend(receipt["shards"])
    descriptor = producer.split_descriptor(descriptors)
    _check_population(producer, descriptor, protocol)
    return descriptor


def require_generation_bytes(output, planned_bytes, *, scoped_test=False):
    if type(planned_bytes) is not int or planned_bytes < 0:
        raise ValueError("bounded next-allocation byte budget required")
    reserve = 1024 * 1024 if scoped_test else 5_000_000_000
    scratch = 65536 if scoped_test else 2 * 8 * 1024 * 1024
    planned = planned_bytes + scratch
    free = shutil.disk_usage(output).free
    if free < reserve + planned: raise ValueError("next bounded fresh allocation plus unchanged reserve required")
    return {"planned_bytes": planned, "reserve_bytes": reserve, "actual_free_bytes": free}


def require_generation_headroom(output, planned_rows, *, scoped_test=False):
    if type(planned_rows) is not int or planned_rows < 0: raise ValueError("bounded next-allocation row budget required")
    return {"planned_rows": planned_rows,
        **require_generation_bytes(output, planned_rows * 600, scoped_test=scoped_test)}


def guarded_batch_writer(producer, pending, batch_id, *, scoped_test=False):
    """Check actual serialized bytes before each unchanged producer flush.

    The per-row admission estimate is not a byte bound. This guard prevents
    larger rows from spending the reserve while leaving the frozen producer's
    row validation, encoding, hashes and descriptors unchanged.
    """
    class GuardedBatchShards(producer.BatchShards):
        def flush(self):
            if not self.rows:
                return super().flush()
            raw_size = len(canonical(self.rows).encode())
            if raw_size > producer.MAX_SHARD_BYTES:
                raise ValueError("numeric schema4 shard exceeds catalogue byte bound before allocation")
            require_generation_bytes(self.pending, raw_size, scoped_test=scoped_test)
            return super().flush()
    return GuardedBatchShards(pending, "holdout", batch_id)


def run(receipt_path, receipt_sha256, source, workspace, output, *, dataset_id=None, resume=False,
        scoped_test=False, maximum_batches=1, batch_accounts=128, batch_timeout=1800, interrupt_before_commit=False):
    """One bounded generation call. Old holdout has no transport path here."""
    require_execution_environment()
    if (type(maximum_batches) is not int or not 1 <= maximum_batches <= 1000
            or type(batch_accounts) is not int or not 1 <= batch_accounts <= 128
            or type(batch_timeout) is not int or not 1 <= batch_timeout <= 3600):
        raise ValueError("explicit bounded fresh generation units required")
    receipt = load_frozen_receipt(receipt_path, receipt_sha256)
    verify_frozen_receipt(receipt, source, workspace, receipt_path=receipt_path)
    producer = frozen_producer(receipt)
    producer_identity, classpath, generator = bind_producer(producer, receipt, workspace)
    output = checked_path(output); private_directory(output.parent)
    require_unblocked_holdout(output)
    require_separate_location(output, source)
    require_separate_location(receipt_path, source, file=True)
    # No entropy/namespace/dataset identity is allocated before receipt readback.
    allocation_sha, protocol = allocate_fresh_holdout(receipt_path, receipt_sha256, receipt, output,
        dataset_id=dataset_id, resume=resume, scoped_test=scoped_test)
    if resume and (output / "predeclared.private.json").exists():
        private_directory(output)
        declaration_sha, declaration = private_read(output / "predeclared.private.json", MAX_RECEIPT_BYTES)
        if declaration["protocol"] != protocol:
            raise ValueError("same frozen recovery identity required for resume")
    else:
        # A crash between allocation and declaration has generated no case; it
        # can safely bootstrap only the exact already allocated directory.
        output.mkdir(mode=0o700, exist_ok=resume); private_directory(output)
        for name in ("shards", "batches", "pending", "abandoned"): (output / name).mkdir(mode=0o700, exist_ok=resume)
        declaration = {"protocol": protocol, "protocol_sha256": digest_document(protocol), "producer_identity": producer_identity,
            "frozen_selection_receipt_sha256": receipt_sha256, "allocation_sha256": allocation_sha,
            "batch_accounts": batch_accounts, "batch_timeout": batch_timeout,
            "declared_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "new_frames_before_declaration": 0,
            "fit_or_score_calls": 0, "old_holdout_numeric_records_read": 0}
        declaration_sha = write_new(output / "predeclared.private.json", declaration)
    if (declaration["producer_identity"] != producer_identity or declaration["frozen_selection_receipt_sha256"] != receipt_sha256
            or declaration["allocation_sha256"] != allocation_sha
            or declaration["protocol_sha256"] != digest_document(protocol)
            or declaration["batch_accounts"] != batch_accounts or declaration["batch_timeout"] != batch_timeout):
        raise ValueError("source/code/JVM/batch recovery declaration changed")
    lock_fd = os.open(output / "generation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        parts = parts_for(producer, protocol); proxy = FreshCaseGenerator(generator, producer, protocol, receipt)
        inventory = {path.name for path in (output / "batches").iterdir()}
        if any(not re.fullmatch(r"part[0-9]{2}-batch[0-9]{6}", name) for name in inventory):
            raise ValueError("invalid owned fresh committed receipt path")
        ordered = [identifier for identifier, _, _, _ in jobs(producer, parts, batch_accounts)]
        if inventory != set(ordered[:len(inventory)]): raise ValueError("contiguous committed fresh batch prefix required")
        for pending in (output / "pending").iterdir():
            private_directory(pending)
            pending.rename(output / "abandoned" / (pending.name + "-" + str(time.time_ns())))
        descriptors, new_batches, completed = [], 0, 0
        for batch_id, part, batch, positive_offset in jobs(producer, parts, batch_accounts):
            committed = output / "batches" / batch_id
            if batch_id in inventory:
                private_directory(committed)
                _, batch_receipt = private_read(committed / "receipt.json", producer.MAX_RECEIPT_BYTES)
            else:
                if new_batches >= maximum_batches: break
                if (output / "manifest.json").exists(): raise ValueError("published fresh holdout cannot allocate new cases")
                require_generation_headroom(output, sum(len(values) for _, values in batch), scoped_test=scoped_test)
                pending = output / "pending" / batch_id; pending.mkdir(mode=0o700)
                writer = guarded_batch_writer(producer, pending, batch_id, scoped_test=scoped_test)
                state = producer.export_batch(proxy, protocol["seed_namespace"], part, batch, positive_offset,
                    classpath, output, writer, batch_timeout)
                if interrupt_before_commit: raise RuntimeError("owned fresh fixture interruption before commit")
                if bind_producer(producer, receipt, workspace)[0] != producer_identity:
                    raise ValueError("frozen producer/JVM changed during fresh extraction")
                batch_receipt = {"batch_id": batch_id, "split": "holdout", "cohort": part.cohort,
                    "generation_identity_sha256": declaration_sha, "assignment_sha256": producer.object_digest([asdict(part), batch, positive_offset]),
                    "shards": writer.descriptors, "statistics": state}
                require_generation_headroom(output, 0, scoped_test=scoped_test)
                write_new(pending / "receipt.json", batch_receipt)
                pending.rename(committed); new_batches += 1
            producer.check_receipt(batch_receipt, batch_id, part, batch, positive_offset, declaration_sha)
            # Only this newly generated holdout is decoded for producer integrity.
            producer.promote(output, committed, batch_receipt)
            descriptors.extend(batch_receipt["shards"]); completed += 1
            _replace_progress(producer, output, {"status": "FRESH_HOLDOUT_GENERATING", "completed_batches": completed,
                "new_batches": new_batches, "required_batches": len(ordered), "frozen_selection_receipt_sha256": receipt_sha256,
                "old_holdout_numeric_records_read": 0, "fit_or_score_calls": 0, "quality_gate": "NOT_EVALUATED"})
        if completed != len(ordered):
            result = {"status": "STOPPED_AT_FRESH_HOLDOUT_BATCH_BOUNDARY", "completed_batches": completed,
                "new_batches": new_batches, "required_batches": len(ordered), "frozen_selection_receipt_sha256": receipt_sha256,
                "old_holdout_numeric_records_read": 0, "fit_or_score_calls": 0, "quality_gate": "NOT_EVALUATED"}
            _replace_progress(producer, output, result); return result
        descriptor = producer.split_descriptor(descriptors); _check_population(producer, descriptor, protocol)
        verify_frozen_receipt(receipt, source, workspace, receipt_path=receipt_path)
        if bind_producer(producer, receipt, workspace)[0] != producer_identity:
            raise ValueError("producer/code/JVM changed before fresh holdout publication")
        manifest = {"format": MANIFEST_FORMAT, "dataset_id": protocol["dataset_id"], "stage": "STRICT_FRESH_HOLDOUT",
            "scope": protocol["scope"], "quality_gate": "NOT_EVALUATED", "data_provenance": "DEMO_ONLY",
            "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(producer.FEATURE_NAMES_V4),
            "frozen_selection_receipt_sha256": receipt_sha256, "original_training_manifest_sha256": receipt["source"]["manifest_sha256"],
            "allocation_sha256": allocation_sha, "predeclared_sha256": declaration_sha,
            "protocol_sha256": digest_document(protocol), "producer_identity": producer_identity,
            "splits": {"holdout": descriptor}, "fit_or_score_calls": 0, "old_holdout_numeric_records_read": 0,
            "old_holdout_acceptance_allowed": False}
        manifest_path = output / "manifest.json"
        require_generation_headroom(output, 0, scoped_test=scoped_test)
        if manifest_path.exists():
            manifest_sha, previous = private_read(manifest_path, 8 * 1024 * 1024)
            if previous != manifest: raise ValueError("immutable published fresh holdout changed")
        else: manifest_sha = write_new(manifest_path, manifest)
        result = {"status": "COMPLETE_UNQUALIFIED_SCOPED_TEST" if scoped_test else "COMPLETE_UNQUALIFIED_FRESH_HOLDOUT",
            "dataset_id": protocol["dataset_id"], "manifest_sha256": manifest_sha, "completed_batches": completed,
            "new_batches": new_batches, "required_batches": len(ordered), "frozen_selection_receipt_sha256": receipt_sha256,
            "old_holdout_numeric_records_read": 0, "fit_or_score_calls": 0, "quality_gate": "NOT_EVALUATED"}
        _replace_progress(producer, output, result); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "generate")); parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True); parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256"); parser.add_argument("--output", type=Path); parser.add_argument("--dataset-id")
    parser.add_argument("--allow-generation", action="store_true"); parser.add_argument("--resume", action="store_true")
    parser.add_argument("--scoped-test", action="store_true"); parser.add_argument("--maximum-batches", type=int, default=1)
    args = parser.parse_args()
    try:
        if args.command == "freeze":
            if args.allow_generation or args.receipt_sha256 or args.output or args.dataset_id or args.resume or args.scoped_test:
                parser.error("freeze cannot allocate a new holdout identity or generation namespace")
            checksum, _ = freeze_selection(args.source, args.workspace, args.receipt)
            result = {"status": "FROZEN_BEFORE_FRESH_HOLDOUT", "frozen_selection_receipt_sha256": checksum,
                      "old_holdout_numeric_records_read": 0, "fit_or_score_calls": 0, "quality_gate": "NOT_RUN"}
        else:
            if not args.allow_generation or not args.receipt_sha256 or args.output is None:
                parser.error("generation requires --allow-generation, explicit --receipt-sha256 and --output")
            result = run(args.receipt, args.receipt_sha256, args.source, args.workspace, args.output,
                dataset_id=args.dataset_id, resume=args.resume, scoped_test=args.scoped_test, maximum_batches=args.maximum_batches)
        print(canonical(result), flush=True)
    except Exception as error:
        raise SystemExit("Fresh holdout recovery refused: " + type(error).__name__ + "; private artifacts retained") from None


if __name__ == "__main__": main()
