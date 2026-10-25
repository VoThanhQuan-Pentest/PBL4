"""Fabricated protected metadata/new tiny causal cases; never runtime rows."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_NAMES_V4, HYBRID_MODEL_KIND
from app.fresh_holdout_recovery import (AUTHORITY_DIRECTORY, DEPENDENCIES, FAMILIES, IMAGE, MANIFEST_FORMAT, PROJECT_ROOT_ENV,
    RECEIPT_FORMAT, TRAIN_VAL_SPLITS, FreshHoldoutDataset, authority_key, claim_recovery_authority,
    digest_document, evaluate_fresh, fresh_protocol, load_frozen_receipt, private_read, validate_frozen_receipt, write_new)
from app.policy import ScorePolicy, canonical

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault(PROJECT_ROOT_ENV, str(ROOT))
PATH = ROOT / "observability/scripts/generate-ueba-fresh-holdout.py"
SPEC = importlib.util.spec_from_file_location("bounded_fresh_holdout_fixture_writer", PATH)
writer = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = writer; SPEC.loader.exec_module(writer)


def receipt_fixture():
    """Counter fixtures are not source/model/proof/quality authority."""
    checksum = "a" * 64; policy = ScorePolicy.strict(schema=4)
    generator_sources = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "observability/scripts/prepare-ueba-schema4.py", "ueba-worker/app/schema4_episodes.py", "ueba-worker/app/catalog.py",
        "ueba-worker/app/contract.py", "ueba-worker/app/policy.py", "ueba-worker/app/strict_metrics.py")}
    source = {"dataset_id": "hybrid-strict-fixture-a01", "manifest_sha256": checksum,
        "blocked_holdout_split_sha256": "b" * 64, "blocked_audit_sha256": {"parent": "c" * 64},
        "train_validation_split_sha256": {name: "d" * 64 for name in TRAIN_VAL_SPLITS},
        "label_manifest_sha256": {str(fold): str(fold) * 64 for fold in (1, 2, 3)},
        "generation_source_binding": {"sha256": digest_document(generator_sources), "source_sha256": generator_sources},
        "workspace_snapshot_sha256": "9" * 64, "generation_identity_sha256": "8" * 64}
    selected = {"status": "SELECTED", "model_kind": HYBRID_MODEL_KIND, "recipe_version": 1,
        "recipe_sha256": "1" * 64, "model_version": "hybrid_fixture_selected", "model_sha256": "2" * 64,
        "model_state_sha256": "3" * 64, "model_state_verifier_sha256": "4" * 64,
        "model_state_format": "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1", "scoring_implementation": {"fixture": True},
        "model_config": {"max_iter": 100, "max_leaf_nodes": 7, "l2_regularization": 1.0, "random_state": 42},
        "calibration_sha256": "5" * 64, "policy_sha256": policy.sha256, "policy": policy.wire(),
        "dataset_sha256": checksum, "actual_fits_completed": 360, "validation_runs_completed": 360,
        "completed_recalibrations": 45, "additional_fit_calls_in_recalibration": 0,
        "holdout_scored": False, "quality_gate": "NOT_RUN", "data_provenance": "DEMO_ONLY",
        "frozen_at_utc": "2026-10-05T00:00:00+00:00", "selection_identity": {
            "dataset_manifest_sha256": checksum, "producer_workspace_snapshot_sha256": "9" * 64,
            "production_classes": {"fixture.class": "6" * 64}, "feature_producers": {"fixture.class": "7" * 64},
            "selection_sources": {"fixture.py": "8" * 64},
            "fit_code_fingerprint": {"sources": {"fixture.py": "9" * 64}, "dependencies": DEPENDENCIES}}}
    selection_sha = digest_document(selected)
    proof = {"format": "HYBRID_STRICT_PROOF_V1", "selection_sha256": selection_sha, "proof_sha256": "6" * 64,
        "actual_composite_trials": 360, "actual_component_fit_calls": 720, "validation_runs": 360,
        "zero_fit_recalibrations": 45, "source_label_manifests": {
            str(fold): {"artifact_id": f"labels-fold{fold}", "manifest_sha256": str(fold) * 64} for fold in (1, 2, 3)}}
    inventory = {name: "9" * 64 for name in ("__init__.py", "fresh_holdout_recovery.py", "frozen_evaluation.py", "quality_proof.py",
        "strict_metrics.py", "policy.py", "metric_journal.py", "selection.py", "strict_campaign.py", "contract.py", "catalog.py")}
    inventory["fresh_holdout_recovery.py"] = "7" * 64
    evaluation = {"app_source_sha256": inventory, "app_inventory_sha256": digest_document(inventory),
        "scorer_sha256": inventory["frozen_evaluation.py"], "metric_journal_sha256": inventory["metric_journal.py"],
        "quality_math_binding": {"sources": {name: inventory[name] for name in ("quality_proof.py", "strict_metrics.py", "policy.py", "metric_journal.py")},
            "dependencies": {name: DEPENDENCIES[name] for name in ("numpy", "scipy")}}}
    receipt = {"format": RECEIPT_FORMAT, "status": "FROZEN_BEFORE_FRESH_HOLDOUT",
        "recorded_at_utc": "2026-10-05T00:01:00+00:00", "source": source,
        "selection_sha256": selection_sha, "selection": selected, "hybrid_proof": proof,
        "recovery_code_sha256": {"ueba-worker/app/fresh_holdout_recovery.py": "7" * 64,
            "observability/scripts/generate-ueba-fresh-holdout.py": "8" * 64},
        "recovery_project_root": str(ROOT), "evaluation_code_binding": evaluation,
        "execution_image_id": IMAGE, "dependencies": DEPENDENCIES, "lifecycle_provenance_sha256": {},
        "new_holdout_generated": False, "old_holdout_scored": False, "quality_gate": "NOT_RUN", "data_provenance": "DEMO_ONLY"}
    receipt["recovery_authority"] = {"authority_key": authority_key(receipt),
        "canonical_receipt_path": "/fabricated/receipt.private.json", "claim_sha256": "9" * 64}
    return receipt


def install_fabricated_receipt(root, path, receipt):
    """Install tiny authority metadata under a temporary project, never runtime."""
    project = root / "project"; (project / "observability/runtime").mkdir(parents=True, mode=0o700)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    receipt["recovery_project_root"] = str(project)
    with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}):
        receipt["recovery_authority"] = claim_recovery_authority(receipt, path)
        checksum = write_new(path, receipt)
    return checksum, project


def flat_recovery_fixture(root):
    """Copied flat checkpoint and tiny project code tree; no numeric corpus."""
    project = root / "project"; active = root / "code/app"
    active.mkdir(parents=True, mode=0o700)
    (project / "ueba-worker/app").mkdir(parents=True, mode=0o700)
    (project / "observability/scripts").mkdir(parents=True, mode=0o700)
    (project / "observability/runtime").mkdir(mode=0o700)
    for path in (ROOT / "ueba-worker/app").glob("*.py"):
        shutil.copyfile(path, active / path.name)
        shutil.copyfile(path, project / "ueba-worker/app" / path.name)
    for name in ("generate-ueba-fresh-holdout.py", "prepare-ueba-schema4.py"):
        shutil.copyfile(ROOT / "observability/scripts" / name, project / "observability/scripts" / name)
    specification = importlib.util.spec_from_file_location("flat_fresh_recovery_fixture", active / "fresh_holdout_recovery.py")
    module = importlib.util.module_from_spec(specification); sys.modules[specification.name] = module
    with patch.object(sys, "dont_write_bytecode", True): specification.loader.exec_module(module)
    source = root / "old/standard"; source.mkdir(parents=True, mode=0o700)
    receipts = root / "receipts"; receipts.mkdir(mode=0o700)
    return module, project, active, source, receipts


class FrozenCodeAuthorityTest(unittest.TestCase):
    def frozen(self, root):
        module, project, active, source, receipts = flat_recovery_fixture(root)
        receipt = receipt_fixture()
        binding = {key: receipt[key] for key in ("source", "selection_sha256", "selection", "hybrid_proof")}
        versions = lambda name: DEPENDENCIES[name]
        contexts = (patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}),
            patch.object(module, "require_execution_environment"),
            patch.object(module, "collect_frozen_binding", return_value=binding),
            patch.object(module.importlib.metadata, "version", side_effect=versions))
        return module, project, active, source, receipts, contexts

    def test_flat_checkpoint_uses_explicit_project_and_active_module_parity(self):
        with tempfile.TemporaryDirectory() as temporary:
            module, project, active, _, _ = flat_recovery_fixture(Path(temporary))
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}):
                binding = module.recovery_code_binding()
                self.assertEqual(binding["ueba-worker/app/fresh_holdout_recovery.py"], hashlib.sha256((active / "fresh_holdout_recovery.py").read_bytes()).hexdigest())
                self.assertIn("__init__.py", module.evaluation_code_binding()["app_source_sha256"])
                copied = project / "ueba-worker/app/fresh_holdout_recovery.py"
                with copied.open("ab") as stream: stream.write(b"\n# changed project copy\n")
                with self.assertRaisesRegex(ValueError, "project copy"): module.recovery_code_binding()
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError): module.project_root()
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: "relative"}), self.assertRaises(ValueError): module.project_root()
            link = Path(temporary) / "project-link"; link.symlink_to(project)
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(link)}), self.assertRaises(ValueError): module.project_root()

    def test_same_selection_cannot_refreeze_copy_or_rename_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); module, project, active, source, receipts, contexts = self.frozen(root)
            with contexts[0], contexts[1], contexts[2], contexts[3]:
                path = receipts / "first.private.json"; checksum, receipt = module.freeze_selection(source, project, path)
                self.assertEqual(module.load_frozen_receipt(path, checksum), receipt)
                self.assertEqual(receipt["evaluation_code_binding"]["scorer_sha256"], hashlib.sha256((active / "frozen_evaluation.py").read_bytes()).hexdigest())
                with self.assertRaises(FileExistsError): module.freeze_selection(source, project, receipts / "second.private.json")
                self.assertFalse((receipts / "second.private.json").exists())
                copy = receipts / "copy.private.json"; shutil.copyfile(path, copy); copy.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "copied/renamed"): module.load_frozen_receipt(copy, checksum)
                with patch.object(writer.secrets, "token_hex") as entropy:
                    with self.assertRaises(ValueError): writer.allocate_fresh_holdout(copy, checksum, receipt, root / "redraw", dataset_id="fresh-holdout-fixture-a02")
                    entropy.assert_not_called()
                renamed = receipts / "renamed.private.json"; path.rename(renamed)
                with self.assertRaises(ValueError): module.load_frozen_receipt(renamed, checksum)

    def test_postfreeze_scorer_math_journal_or_extra_source_drift_fails_before_allocation(self):
        for name in ("frozen_evaluation.py", "quality_proof.py", "metric_journal.py", "unlisted_added.py"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); module, project, active, source, receipts, contexts = self.frozen(root)
                with contexts[0], contexts[1], contexts[2], contexts[3]:
                    path = receipts / "frozen.private.json"; checksum, receipt = module.freeze_selection(source, project, path)
                    module.verify_frozen_receipt(receipt, source, project, receipt_path=path)
                    changed = active / name
                    with changed.open("ab") as stream: stream.write(b"\n# postfreeze source drift\n")
                    with self.assertRaisesRegex(ValueError, "scorer/math/journal"):
                        module.verify_frozen_receipt(receipt, source, project, receipt_path=path)
                    with patch.object(writer, "require_execution_environment"), \
                            patch.object(writer, "verify_frozen_receipt", side_effect=lambda *args, **kwargs:
                                module.verify_frozen_receipt(receipt, source, project, receipt_path=path)), \
                            patch.object(writer, "frozen_producer") as producer, patch.object(writer.secrets, "token_hex") as entropy:
                        with self.assertRaises(ValueError): writer.run(path, checksum, source, project, root / "fresh", dataset_id="fresh-holdout-fixture-a01")
                        producer.assert_not_called(); entropy.assert_not_called()
                        self.assertFalse(path.with_name(path.name + ".allocation.private.json").exists())

    def test_receipt_cannot_be_created_inside_old_source_labels_or_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            module, project, _, source, receipts, contexts = self.frozen(Path(temporary))
            with contexts[0], contexts[1], contexts[2], contexts[3]:
                for path in (source / "receipt.private.json", source.parent / "receipt.private.json", source.parent.parent / "receipt.private.json"):
                    with self.subTest(path=path), self.assertRaisesRegex(ValueError, "overlap"):
                        module.freeze_selection(source, project, path)
                self.assertFalse((project / AUTHORITY_DIRECTORY).exists())

    def test_producer_hash_checked_before_import_and_restores_path_precedence(self):
        receipt = receipt_fixture(); before = list(sys.path)
        writer.frozen_producer(receipt)
        self.assertEqual(sys.path, before)
        changed = deepcopy(receipt)
        changed["source"]["generation_source_binding"]["source_sha256"]["observability/scripts/prepare-ueba-schema4.py"] = "0" * 64
        with patch.object(writer.importlib.util, "spec_from_file_location") as loader:
            with self.assertRaisesRegex(ValueError, "pre-execution"): writer.frozen_producer(changed)
            loader.assert_not_called()


class FrozenReceiptTest(unittest.TestCase):
    def test_complete_receipt_and_explicit_pin_are_required_before_namespace(self):
        receipt = receipt_fixture(); self.assertIs(validate_frozen_receipt(receipt), receipt)
        protocol = fresh_protocol(receipt, digest_document(receipt), "fresh-holdout-fixture-a01", "1" * 64)
        self.assertEqual(protocol["holdout"], {"start_day": 85, "days": 14, "normal": 10000000, "positive": 10000,
            "positive_per_family": 2000, "cohort_ratio": [70, 20, 10]})
        self.assertFalse(protocol["old_holdout_acceptance_allowed"])
        self.assertNotIn("seed_namespace", receipt)
        with self.assertRaises(ValueError): fresh_protocol(receipt, "0" * 64, "fresh-holdout-fixture-a01", "1" * 64)
        with self.assertRaises(ValueError): fresh_protocol(receipt, digest_document(receipt), receipt["source"]["dataset_id"], "1" * 64)
        with self.assertRaises(ValueError): fresh_protocol(receipt, digest_document(receipt), "fresh-holdout-pilot-a01", "1" * 64)
        changed = fresh_protocol(receipt, digest_document(receipt), "fresh-holdout-fixture-a01", "2" * 64)
        self.assertNotEqual(protocol["seed_namespace"], changed["seed_namespace"])

    def test_incomplete_bool_counts_changed_source_or_weakened_policy_refused(self):
        receipt = receipt_fixture()
        for key, value in (("actual_fits_completed", 359), ("actual_fits_completed", True),
                ("validation_runs_completed", 359), ("completed_recalibrations", 44),
                ("completed_recalibrations", 361), ("additional_fit_calls_in_recalibration", False),
                ("holdout_scored", True), ("dataset_sha256", "0" * 64)):
            changed = deepcopy(receipt); changed["selection"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): validate_frozen_receipt(changed)
        for key, value in (("actual_component_fit_calls", 719), ("actual_composite_trials", True), ("validation_runs", 359)):
            changed = deepcopy(receipt); changed["hybrid_proof"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate_frozen_receipt(changed)
        changed = deepcopy(receipt); changed["source"]["train_validation_split_sha256"].pop("fold3-validation")
        with self.assertRaises(ValueError): validate_frozen_receipt(changed)
        changed = deepcopy(receipt); changed["source"]["blocked_audit_sha256"] = {}
        with self.assertRaises(ValueError): validate_frozen_receipt(changed)
        changed = deepcopy(receipt)
        policy_document = ScorePolicy.from_wire(changed["selection"]["policy"]).document
        policy_document["quality"]["cluster_resamples"] = 1
        changed["selection"]["policy"]["policy_document_json"] = canonical(policy_document)
        with self.assertRaises(ValueError): validate_frozen_receipt(changed)

    def test_private_pinned_receipt_no_overwrite_symlink_public_or_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); path = root / "frozen.private.json"
            receipt = receipt_fixture(); checksum, project = install_fabricated_receipt(root, path, receipt)
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}):
                self.assertEqual(load_frozen_receipt(path, checksum), receipt)
            with self.assertRaises(FileExistsError): write_new(path, receipt)
            with self.assertRaises(ValueError): load_frozen_receipt(path, "0" * 64)
            path.chmod(0o644)
            with self.assertRaises(ValueError): load_frozen_receipt(path, checksum)
            path.chmod(0o600); link = root / "symlink.json"; link.symlink_to(path)
            with self.assertRaises(ValueError): load_frozen_receipt(link, checksum)
            with self.assertRaises(ValueError): private_read(path, 10)
            duplicate = root / "duplicate.json"; duplicate.write_text('{"a":1,"a":2}'); duplicate.chmod(0o600)
            with self.assertRaises(ValueError): private_read(duplicate, 100)


class CausalIdentityTest(unittest.TestCase):
    def setUp(self):
        self.receipt = receipt_fixture(); self.producer = writer.frozen_producer(self.receipt); self.generator = self.producer.load_generator()
        self.protocol = fresh_protocol(self.receipt, digest_document(self.receipt), "fresh-holdout-fixture-a01", "1" * 64, scoped_test=True)
        self.proxy = writer.FreshCaseGenerator(self.generator, self.producer, self.protocol, self.receipt)

    def episode(self, cohort, *, cause=None, context=False, ordinal=0, proxy=None):
        part = next(part for part in writer.parts_for(self.producer, self.protocol) if part.cohort == cohort)
        return self.producer.make_episode(proxy or self.proxy, self.protocol["seed_namespace"], part, 0, ordinal,
            positive_index=cause, context=context)

    def test_ready_subject_and_profile_preserved_unseen_and_cold_fresh(self):
        subjects = []
        for part in writer.parts_for(self.producer, self.protocol):
            world = self.producer.namespace(self.protocol["seed_namespace"], part)
            old_fit = self.producer.Part("fold3-fit", "READY", 29, 1, 50000)
            old_world = self.producer.namespace(self.receipt["source"]["dataset_id"], old_fit)
            expected_subject = "acct-" + self.generator._digest([old_world, 0])[:32]
            row = self.episode(part.cohort); subjects.append(row["frame"]["account_id"])
            if part.cohort == "READY":
                self.assertEqual(row["frame"]["account_id"], expected_subject)
                self.assertEqual(self.proxy.account_profile(world, 0), self.generator.account_profile(old_world, 0))
                self.assertLessEqual(self.producer.actor_layout(part, 50000)[0], 50000)
            else: self.assertNotEqual(row["frame"]["account_id"], expected_subject)
            self.assertEqual(row["frame"]["cohort"], self.generator._cohort(part.cohort))
            self.assertTrue(row["evidence"]["labels_assigned_before_events"])
            self.assertFalse(row["evidence"]["captured_sources_replayed_or_relabelled"])
        self.assertEqual(len(set(subjects)), 3)

    def test_entropy_changes_events_frames_not_ready_subject_and_cause_never_identity_seed(self):
        changed = fresh_protocol(self.receipt, digest_document(self.receipt), "fresh-holdout-fixture-a01", "2" * 64, scoped_test=True)
        proxy = writer.FreshCaseGenerator(self.generator, self.producer, changed, self.receipt)
        part = writer.parts_for(self.producer, changed)[0]
        after = self.producer.make_episode(proxy, changed["seed_namespace"], part, 0, 0)
        before = self.episode("READY")
        self.assertEqual(before["frame"]["account_id"], after["frame"]["account_id"])
        self.assertNotEqual(before["frame"]["frame_id"], after["frame"]["frame_id"])
        self.assertNotEqual(before["evidence"]["server_events_sha256"], after["evidence"]["server_events_sha256"])
        abnormal = self.episode("READY", cause=0)
        self.assertEqual(before["frame"]["frame_id"], abnormal["frame"]["frame_id"])
        self.assertEqual(before["scenario"]["plan"]["execution_seed"], abnormal["scenario"]["plan"]["execution_seed"])
        self.assertEqual(before["scenario"]["label"], 0); self.assertEqual(abnormal["scenario"]["label"], 1)
        self.assertNotIn("label", before["frame"])

    def test_temporal_context_and_actor_hour_isolation(self):
        subjects_hours, frames = set(), set()
        for cohort in ("READY", "UNSEEN_READY", "COLD"):
            evaluated = self.episode(cohort)
            first = self.episode(cohort, context=True)
            context_count = 3 if cohort == "COLD" else 48
            expected_first = self.generator._start(evaluated["frame"]["window_start"]) - timedelta(days=4 if cohort != "COLD" else 1)
            self.assertLess(self.generator._start(first["frame"]["window_start"]), self.generator._start(evaluated["frame"]["window_start"]))
            self.assertEqual(first["scenario"]["label"], 0)
            self.assertEqual(context_count, self.protocol["context_windows"][cohort])
            self.assertGreaterEqual(self.generator._start(first["frame"]["window_start"]), expected_first)
            for ordinal in range(10):
                row = self.episode(cohort, ordinal=ordinal)["frame"]
                key = (row["account_id"], row["window_start"][:13])
                self.assertNotIn(key, subjects_hours); subjects_hours.add(key)
                self.assertNotIn(row["frame_id"], frames); frames.add(row["frame_id"])
                self.assertGreaterEqual(row["day"], 85); self.assertLessEqual(row["day"], 98)


class BoundedWriterTest(unittest.TestCase):
    def test_actual_serialized_shard_guard_refuses_before_frozen_writer_allocates(self):
        class FrozenWriterFixture:
            def __init__(self, pending, split, batch_id):
                self.pending, self.rows, self.calls = pending, [], 0
            def flush(self):
                self.calls += 1
        producer = SimpleNamespace(BatchShards=FrozenWriterFixture, MAX_SHARD_BYTES=8 * 1024 * 1024)
        shard_writer = writer.guarded_batch_writer(producer, Path("/metadata-only"), "fixture")
        shard_writer.rows = [{"fixture": "x" * 4096}]
        required = 5_000_000_000 + 2 * 8 * 1024 * 1024 + len(canonical(shard_writer.rows).encode())
        with patch.object(writer.shutil, "disk_usage", return_value=SimpleNamespace(free=required - 1)), self.assertRaises(ValueError):
            shard_writer.flush()
        self.assertEqual(shard_writer.calls, 0)
        with patch.object(writer.shutil, "disk_usage", return_value=SimpleNamespace(free=required)):
            shard_writer.flush()
        self.assertEqual(shard_writer.calls, 1)
        shard_writer.rows = [{"fixture": "x" * producer.MAX_SHARD_BYTES}]
        with self.assertRaisesRegex(ValueError, "before allocation"):
            shard_writer.flush()
        self.assertEqual(shard_writer.calls, 1)

    def test_resume_headroom_budgets_only_next_allocation_preserving_5gb(self):
        next_rows = 21504; scratch = 2 * 8 * 1024 * 1024
        free = 5_000_000_000 + next_rows * 600 + scratch
        with patch.object(writer.shutil, "disk_usage", return_value=SimpleNamespace(free=free)):
            self.assertEqual(writer.require_generation_headroom(Path("/metadata-only"), next_rows)["reserve_bytes"], 5_000_000_000)
            writer.require_generation_headroom(Path("/metadata-only"), 0)
            with self.assertRaises(ValueError): writer.require_generation_headroom(Path("/metadata-only"), 10010000)
        with patch.object(writer.shutil, "disk_usage", return_value=SimpleNamespace(free=free - 1)), self.assertRaises(ValueError):
            writer.require_generation_headroom(Path("/metadata-only"), next_rows)
    def test_write_once_allocation_race_and_changed_root_id_entropy_cannot_redraw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); receipt = receipt_fixture()
            path = root / "frozen.private.json"; checksum, project = install_fabricated_receipt(root, path, receipt); output = root / "fresh"
            barrier = threading.Barrier(2)
            def entropy(count): barrier.wait(timeout=5); return "1" * 64
            def allocate():
                try:
                    return writer.allocate_fresh_holdout(path, checksum, receipt, output, dataset_id="fresh-holdout-fixture-a01")
                except FileExistsError: return "EXCLUSIVE_RACE_REFUSAL"
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}), patch.object(writer.secrets, "token_hex", side_effect=entropy), ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(allocate) for _ in range(2)]
                values = [future.result(timeout=10) for future in futures]
            self.assertEqual(values.count("EXCLUSIVE_RACE_REFUSAL"), 1)
            allocated = next(value for value in values if value != "EXCLUSIVE_RACE_REFUSAL")
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}):
                with self.assertRaisesRegex(ValueError, "redraw"):
                    writer.allocate_fresh_holdout(path, checksum, receipt, root / "redraw", dataset_id="fresh-holdout-fixture-a02")
                with self.assertRaises(ValueError): writer.allocate_fresh_holdout(path, checksum, receipt, root / "other", resume=True)
                with self.assertRaises(ValueError): writer.allocate_fresh_holdout(path, checksum, receipt, output, resume=True, dataset_id="fresh-holdout-fixture-a02")
                self.assertEqual(writer.allocate_fresh_holdout(path, checksum, receipt, output, resume=True), allocated)
            ledger = path.with_name(path.name + ".allocation.private.json")
            ledger_bytes_sha = hashlib.sha256(ledger.read_bytes()).hexdigest()
            self.assertEqual(ledger_bytes_sha, allocated[0])
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)
            initial = ledger.read_bytes()
            _, tampered = private_read(ledger, 4 * 1024 * 1024)
            tampered["protocol"]["postfreeze_entropy_hex"] = "2" * 64
            ledger.write_text(canonical(tampered))
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}), self.assertRaises(ValueError):
                writer.allocate_fresh_holdout(path, checksum, receipt, output, resume=True)
            ledger.write_bytes(initial)

    def test_host_refusal_and_missing_receipt_precede_entropy_or_producer(self):
        with patch.object(writer, "require_execution_environment", side_effect=ValueError("host")), \
                patch.object(writer, "frozen_producer") as producer, patch.object(writer.secrets, "token_hex") as entropy:
            with self.assertRaises(ValueError): writer.run(Path("/missing"), "0" * 64, Path("/missing"), Path("/missing"), Path("/missing"))
            producer.assert_not_called(); entropy.assert_not_called()
        with patch.object(writer, "require_execution_environment"), patch.object(writer, "frozen_producer") as producer, \
                patch.object(writer.secrets, "token_hex") as entropy:
            with self.assertRaises(OSError): writer.run(Path("/missing"), "0" * 64, Path("/missing"), Path("/missing"), Path("/missing"))
            producer.assert_not_called(); entropy.assert_not_called()

    def test_bounded_fabricated_rows_resume_and_tamper_do_not_touch_old_holdout(self):
        receipt = receipt_fixture(); producer = writer.frozen_producer(receipt); generator = producer.load_generator()
        identity = {"fixture": "CONTROL_ONLY_NOT_REAL_PRODUCER_PROOF"}
        def fabricated_export(proxy, namespace, part, batch, offset, classpath, output, shard_writer, timeout):
            for account, evaluations in batch:
                for ordinal, index in evaluations:
                    episode = producer.make_episode(proxy, namespace, part, account, ordinal,
                        positive_index=None if index is None else offset + index)
                    frame, scenario = episode["frame"], episode["scenario"]
                    # Deliberately fabricated features, not actual Java evidence.
                    row = {key: frame[key] for key in ("frame_id", "account_id", "window_start")}
                    row.update(cohort=part.cohort, label=scenario["label"], family=scenario["family"],
                        baseline_established=part.cohort != "COLD", trusted_window_count=3 if part.cohort == "COLD" else 48,
                        features=[0] * len(FEATURE_NAMES_V4)); validate_rows([row], 4); shard_writer.append(row)
            shard_writer.flush(); count = sum(len(values) for _, values in batch)
            return {"raw_frames": count + len(batch) * (3 if part.cohort == "COLD" else 48), "evaluated_rows": count,
                "elapsed_seconds": 1.0, "raw_stream_sha256": "1" * 64, "planned_scenarios_sha256": "2" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); (root / "old").mkdir(mode=0o700)
            source = root / "old/standard"; source.mkdir(mode=0o700)
            old = source / "blocked-numeric-fixture"; old.write_bytes(b"MUST NEVER READ OLD NUMERIC ROWS")
            old_sha = hashlib.sha256(old.read_bytes()).hexdigest()
            receipt_path = root / "receipts/frozen.private.json"; receipt_sha, project = install_fabricated_receipt(root, receipt_path, receipt); output = root / "fresh"
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}), patch.object(writer, "require_execution_environment"), patch.object(writer, "verify_frozen_receipt"), \
                    patch.object(writer, "bind_producer", return_value=(identity, "NO_REAL_JAVA", generator)), \
                    patch.object(writer, "frozen_producer", return_value=producer), \
                    patch.object(producer, "export_batch", side_effect=fabricated_export) as exporter:
                with self.assertRaises(RuntimeError): writer.run(receipt_path, receipt_sha, source, root, output,
                    dataset_id="fresh-holdout-fixture-a01", scoped_test=True, interrupt_before_commit=True)
                stopped = writer.run(receipt_path, receipt_sha, source, root, output, scoped_test=True, resume=True)
                self.assertEqual(stopped["new_batches"], 1); self.assertEqual(stopped["completed_batches"], 1)
                self.assertTrue(list((output / "abandoned").iterdir()))
                _, declaration = private_read(output / "predeclared.private.json", 4 * 1024 * 1024)
                namespace = declaration["protocol"]["seed_namespace"]
                writer.run(receipt_path, receipt_sha, source, root, output, scoped_test=True, resume=True)
                complete = writer.run(receipt_path, receipt_sha, source, root, output, scoped_test=True, resume=True)
                self.assertEqual(complete["status"], "COMPLETE_UNQUALIFIED_SCOPED_TEST")
                calls = exporter.call_count
                self.assertEqual(writer.run(receipt_path, receipt_sha, source, root, output, scoped_test=True, resume=True)["new_batches"], 0)
                self.assertEqual(exporter.call_count, calls)
                _, after = private_read(output / "predeclared.private.json", 4 * 1024 * 1024)
                self.assertEqual(namespace, after["protocol"]["seed_namespace"])
                self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(), old_sha)
                manifest_sha = complete["manifest_sha256"]
                with patch("app.fresh_holdout_recovery.verify_frozen_receipt"):
                    with self.assertRaisesRegex(ValueError, "full independent"):
                        FreshHoldoutDataset(source, output, root, receipt_path, receipt_sha256=receipt_sha, manifest_sha256=manifest_sha)
                shard = next((output / "shards").iterdir())
                with shard.open("ab") as stream: stream.write(b" ")
                with self.assertRaises(ValueError): writer.run(receipt_path, receipt_sha, source, root, output, scoped_test=True, resume=True)


class StandaloneAdapterTest(unittest.TestCase):
    def test_evaluation_reuses_unchanged_core_and_writes_only_fresh_evidence(self):
        if importlib.util.find_spec("sklearn") is None:
            self.skipTest("pinned image required for actual frozen scorer import")
        receipt = receipt_fixture(); selected = receipt["selection"]
        metadata = {"model_version": selected["model_version"], "sha256": selected["model_sha256"],
            "calibration_sha256": selected["calibration_sha256"], "dataset_manifest_sha256": selected["dataset_sha256"],
            "feature_schema_version": 4, "score_policy": selected["policy"]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); fresh = root / "fresh"; fresh.mkdir(mode=0o700)
            source = root / "original"; source.mkdir(mode=0o700)
            identity = {"frozen_selection_receipt_sha256": "1" * 64, "fresh_holdout_dataset_id": "fresh-holdout-fixture-a01",
                "fresh_holdout_manifest_sha256": "2" * 64, "holdout_split_sha256": "3" * 64,
                "allocation_sha256": "4" * 64, "original_training_manifest_sha256": selected["dataset_sha256"]}
            dataset = SimpleNamespace(root=fresh, receipt=receipt, recovery_identity=identity)
            original_store = SimpleNamespace(load_candidate=lambda version: (metadata, {"model": "MOCKED_NOT_EXECUTED"}))
            with patch("app.fresh_holdout_recovery.require_execution_environment"), \
                    patch("app.fresh_holdout_recovery.FreshHoldoutDataset", return_value=dataset), \
                    patch("app.model.ModelStore", return_value=original_store) as model_store, \
                    patch("app.frozen_evaluation.evaluate_bound", return_value={"quality_gate": "FAIL"}) as core:
                result = evaluate_fresh(source, fresh, root, root / "receipt", receipt_sha256="1" * 64, manifest_sha256="2" * 64)
                self.assertEqual(result["quality_gate"], "FAIL")
                self.assertEqual(model_store.call_args.args[0], source / "hybrid-models")
                args, options = core.call_args
                self.assertIs(args[0], dataset)
                self.assertEqual(args[1].directory, fresh / "evidence")
                self.assertEqual(args[5]["original_training_manifest_sha256"], selected["dataset_sha256"])
                self.assertEqual(args[5]["fresh_holdout_manifest_sha256"], "2" * 64)
                self.assertEqual(args[5]["hybrid_strict_proof"]["actual_component_fit_calls"], 720)
                self.assertEqual(options["result_file"], fresh / "fresh-holdout-result.json")
                self.assertIs(options["require_storage_guard"], True)
                self.assertEqual(list(source.iterdir()), [])

    def install_counter_only_manifest(self, root, receipt):
        """Full-size descriptor counters only; no full-size numeric rows exist."""
        (root / "old").mkdir(mode=0o700); source = root / "old/standard"; source.mkdir(mode=0o700)
        fresh = root / "fresh"; fresh.mkdir(mode=0o700)
        path = root / "receipts/frozen.private.json"; receipt_sha, project = install_fabricated_receipt(root, path, receipt)
        with patch.dict(os.environ, {PROJECT_ROOT_ENV: str(project)}):
            allocation_sha, protocol = writer.allocate_fresh_holdout(path, receipt_sha, receipt, root / "not-created", dataset_id="fresh-holdout-fixture-a01")
        # This fabricated control manifest models the exact ledger output path.
        ledger_path = path.with_name(path.name + ".allocation.private.json")
        _, allocation = private_read(ledger_path, 4 * 1024 * 1024); allocation["output_root"] = str(fresh)
        ledger_path.write_text(canonical(allocation)); allocation_sha = digest_document(allocation)
        producer_identity = {"standard_producer": receipt["source"]["generation_source_binding"],
            "recovery_project_root": receipt["recovery_project_root"],
            "workspace_snapshot_sha256": receipt["source"]["workspace_snapshot_sha256"], "execution_image_id": IMAGE,
            "recovery_code_sha256": receipt["recovery_code_sha256"], "java": {"fixture": "CONTROL_ONLY"}}
        declaration = {"protocol": protocol, "protocol_sha256": digest_document(protocol), "producer_identity": producer_identity,
            "frozen_selection_receipt_sha256": receipt_sha, "allocation_sha256": allocation_sha,
            "batch_accounts": 128, "batch_timeout": 1800, "new_frames_before_declaration": 0,
            "fit_or_score_calls": 0, "old_holdout_numeric_records_read": 0}
        declaration_sha = write_new(fresh / "predeclared.private.json", declaration)
        shards = []; counter = 0
        for cohort, normal, positive in (("READY", 7000000, 7000), ("UNSEEN_READY", 2000000, 2000), ("COLD", 1000000, 1000)):
            populations = [("normal", normal)] + [(family, positive // 5) for family in FAMILIES]
            for family, population in populations:
                for offset in range(0, population, 5000):
                    count = min(5000, population - offset); identifier = f"holdout-counter-only-{counter:06d}"; counter += 1
                    shards.append({"id": identifier, "path": "shards/" + identifier + ".json", "sha256": "0" * 64,
                        "records": count, "normal": count if family == "normal" else 0, "positive": 0 if family == "normal" else count,
                        "families": {family: count}, "cohorts": {cohort: count}, "from": "2026-06-24T00:00:00Z", "to": "2026-07-07T00:00:00Z"})
        producer = writer.frozen_producer(receipt); holdout = producer.split_descriptor(shards)
        manifest = {"format": MANIFEST_FORMAT, "dataset_id": protocol["dataset_id"], "stage": "STRICT_FRESH_HOLDOUT",
            "scope": "FULL_FRESH_HOLDOUT", "quality_gate": "NOT_EVALUATED", "data_provenance": "DEMO_ONLY",
            "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
            "frozen_selection_receipt_sha256": receipt_sha, "original_training_manifest_sha256": receipt["source"]["manifest_sha256"],
            "allocation_sha256": allocation_sha, "predeclared_sha256": declaration_sha, "protocol_sha256": digest_document(protocol),
            "producer_identity": producer_identity, "splits": {"holdout": holdout}, "fit_or_score_calls": 0,
            "old_holdout_numeric_records_read": 0, "old_holdout_acceptance_allowed": False}
        manifest_sha = write_new(fresh / "manifest.json", manifest)
        return source, fresh, path, receipt_sha, manifest_sha, holdout, producer_identity

    def test_adapter_pins_fresh_identity_and_never_transports_old_splits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); receipt = receipt_fixture()
            source, fresh, path, receipt_sha, manifest_sha, holdout, producer_identity = self.install_counter_only_manifest(root, receipt)
            class OriginalMetadataOnly:
                _check_split = staticmethod(ShardedDataset._check_split)
                def __init__(self, path):
                    self.sha256 = receipt["source"]["manifest_sha256"]
                    self.manifest = {"stage": "STRICT", "feature_schema_version": 4, "dataset_id": receipt["source"]["dataset_id"]}
                def iter_shards(self, name): raise AssertionError("old numeric transport forbidden")
            adapter_writer = SimpleNamespace(frozen_producer=lambda *args: object(),
                bind_producer=lambda *args: (producer_identity, "NO_JAVA", object()),
                verify_completed_generation=lambda *args: holdout)
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: receipt["recovery_project_root"]}), patch("app.fresh_holdout_recovery.verify_frozen_receipt"), \
                    patch("app.fresh_holdout_recovery.ShardedDataset", OriginalMetadataOnly), \
                    patch("app.fresh_holdout_recovery.recovery_writer", return_value=adapter_writer):
                dataset = FreshHoldoutDataset(source, fresh, root, path, receipt_sha256=receipt_sha, manifest_sha256=manifest_sha)
                self.assertEqual(dataset.sha256, receipt["source"]["manifest_sha256"])
                self.assertEqual(dataset.recovery_identity["fresh_holdout_manifest_sha256"], manifest_sha)
                self.assertEqual(dataset.recovery_identity["frozen_selection_receipt_sha256"], receipt_sha)
                self.assertEqual(dataset.split("holdout"), holdout)
                with self.assertRaises(ValueError): dataset.split("fold3-fit")
                with self.assertRaises(ValueError): list(dataset.iter_shards("fold3-validation"))
                with self.assertRaises(ValueError): FreshHoldoutDataset(source, fresh, root, path,
                    receipt_sha256=receipt_sha, manifest_sha256="0" * 64)
                adapter_writer.verify_completed_generation = lambda *args: holdout | {"sha256": "1" * 64}
                with self.assertRaisesRegex(ValueError, "actual committed"):
                    FreshHoldoutDataset(source, fresh, root, path, receipt_sha256=receipt_sha, manifest_sha256=manifest_sha)

    def test_original_blocked_marker_never_becomes_fresh_acceptance_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700); receipt = receipt_fixture()
            source, fresh, path, receipt_sha, manifest_sha, _, _ = self.install_counter_only_manifest(root, receipt)
            marker = {"audit_schema_version": 1, "status": "BLOCKED", "dataset_id": receipt["source"]["dataset_id"],
                "affected_split": "holdout", "reason": "INDETERMINATE_HOLDOUT_EXPOSURE", "acceptance_allowed": False,
                "audit_id": "blocked-fixture-a01", "recorded_at_utc": "2026-10-05T00:00:00Z"}
            write_new(root / "holdout-access-audit.private.json", marker)
            with patch.dict(os.environ, {PROJECT_ROOT_ENV: receipt["recovery_project_root"]}), patch("app.fresh_holdout_recovery.verify_frozen_receipt"), \
                    patch("app.fresh_holdout_recovery.recovery_writer") as producer:
                with self.assertRaisesRegex(ValueError, "BLOCKED"):
                    FreshHoldoutDataset(source, fresh, root, path, receipt_sha256=receipt_sha, manifest_sha256=manifest_sha)
                producer.assert_not_called()


if __name__ == "__main__": unittest.main()
