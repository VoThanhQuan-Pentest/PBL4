"""Fabricated metadata boundaries only; never real campaign/qualification proof."""
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

import test_continue_ueba_hybrid_one_unit as units

SPEC = importlib.util.spec_from_file_location("hybrid_approved_unit_builder",
    Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-hybrid-approved-unit.py")
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
M = units.M


class HybridApprovedUnitTest(unittest.TestCase):
    def setUp(self):
        self.unit = units.HybridOneUnitTest()
        self.unit.setUp()
        self.addCleanup(self.unit.doCleanups)
        self.fixture = self.unit.fixture
        self.output = self.fixture.base / "new-one-unit-approval.private.json"
        self.arguments = {"dataset": self.fixture.standard, **self.fixture.arguments,
            "user_approval_reference": "fabricated user-approved fixture only; not actual campaign authority",
            "helper": M}

    def context(self):
        stack = ExitStack()
        stack.enter_context(patch.object(M, "RUNTIME", self.fixture.base))
        stack.enter_context(patch.object(M, "__file__", str(self.fixture.coordinator)))
        stack.enter_context(patch("app.archived_catalog.ArchivedShardedDataset", return_value=self.fixture.catalog))
        stack.enter_context(patch.object(M.subprocess, "run", side_effect=AssertionError("builder cannot dispatch Docker")))
        stack.enter_context(patch.object(M, "write", side_effect=AssertionError("builder cannot write source state")))
        return stack

    def prepare(self, **changes):
        with self.context():
            return B.prepare(self.output, **(self.arguments | changes))

    def ledger_state(self, **changes):
        ledger = self.fixture.standard / "hybrid-one-unit"
        ledger.mkdir(mode=0o700, exist_ok=True)
        self.fixture.file(ledger / "coordinator.lock", b"")
        state = {"status": "SUCCEEDED", "identity_sha256": self.unit.plan.identity_sha256,
            "approval_sha256": self.unit.approval_sha, "stage": "fit", "unit_id": self.unit.run["run_id"],
            "before": self.unit.before, "container_id": "e" * 64,
            "result": {"counts": self.unit.before | {"actual_fits_completed": 1}, "quality_gate": "NOT_RUN"},
            "quality_gate": "NOT_RUN", "retirement_authority": False, "aws_changed": False}
        self.fixture.document(ledger / (self.unit.approval_sha + ".private.json"), state | changes)

    def blocked_audit(self, directory):
        return self.fixture.document(directory / "holdout-access-audit.private.json", {
            "audit_schema_version": 1, "status": "BLOCKED", "dataset_id": self.unit.plan.protocol["dataset_id"],
            "affected_split": "holdout", "reason": "INDETERMINATE_HOLDOUT_EXPOSURE",
            "acceptance_allowed": False, "audit_id": "fabricated_blocked_audit",
            "recorded_at_utc": "2026-10-05T00:00:00Z"})

    def fabricated_full_boundary(self, selected=None):
        """Inert records exercise stage routing, not full-campaign qualification."""
        campaign = self.unit.plan.protocol["campaign"]
        counts = {"actual_fits_completed": 360, "validation_runs_completed": 360,
                  "completed_recalibrations": 45 if selected else 0}
        records = {"fits": {run["run_id"]: {} for run in campaign},
            "validations": {run["run_id"]: {} for run in campaign}, "recalibrations": {},
            "counts": counts, "fingerprint": self.unit.fingerprint}
        fields = ("max_iter", "max_leaf_nodes", "l2_regularization")
        configurations = {M.canonical({key: run["config"][key] for key in fields}):
                          {"configuration": {key: run["config"][key] for key in fields}} for run in campaign}
        ranking = {"validation_runs_completed": 360, "configurations": list(configurations.values())}
        actual_receipt = M.private_receipt
        def receipt(path, maximum=4 * 1024 * 1024):
            if path.name == "hybrid-ranking.json": return ranking
            if path.name == "hybrid-selection.json": return selected
            if path.name in ("hybrid-holdout-result.json", "hybrid_selected_fixture_0001.evaluation.json"):
                raise AssertionError("blocked holdout cannot inspect evaluation evidence")
            return actual_receipt(path, maximum)
        stack = ExitStack()
        stack.enter_context(patch.object(M, "hybrid_records", return_value=records))
        stack.enter_context(patch.object(M, "selection_binding", return_value=None))
        stack.enter_context(patch.object(M, "hybrid_selected", return_value=None))
        stack.enter_context(patch.object(M, "private_receipt", side_effect=receipt))
        return stack, counts

    def test_clean_complete_source_writes_consumer_valid_exact_first_unit(self):
        result = self.prepare()
        approval = M.campaign_run_approval(self.unit.plan, self.output, result["approval_sha256"])
        self.assertEqual(set(approval), M.ONE_UNIT_APPROVAL_FIELDS)
        self.assertEqual(approval["stage"], "fit")
        self.assertEqual(approval["unit_id"], self.unit.run["run_id"])
        self.assertEqual(approval["expected_before"], self.unit.before)
        self.assertTrue(approval["execution_approved"])
        self.assertFalse(approval["retirement_approved"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(self.output.stat().st_uid, os.geteuid())
        self.assertEqual(self.output.stat().st_nlink, 1)
        self.assertFalse(result["execution_started"])
        self.assertEqual(result["quality_gate"], "NOT_RUN")
        self.assertEqual(result["holdout_numeric_records_read"], 0)
        self.assertFalse((self.fixture.standard / "hybrid-one-unit").exists())

    def test_retained_approved_fake_fit_derives_validation_not_a_forecast(self):
        self.unit.fit_completed()
        self.ledger_state()
        result = self.prepare()
        self.assertEqual(result["stage"], "validation")
        self.assertEqual(result["unit_id"], self.unit.run["run_id"])
        self.assertEqual(result["expected_before"], self.unit.before | {"actual_fits_completed": 1})
        self.assertEqual(result["quality_gate"], "NOT_RUN")
        approval = json.loads(self.output.read_bytes())
        self.assertEqual(result["approval_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(approval["expected_before"], result["expected_before"])

    def test_live_incomplete_or_source_drift_refuses_before_writing(self):
        for changes in ({"status": "RUNNING"}, {"folds_completed": [1, 2]},
                        {"source_identity_after": {"tampered": True}},
                        {"downstream_holdout_numeric_records_read": 1}):
            with self.subTest(changes=changes):
                sha = self.fixture.document(self.fixture.source / "state.private.json", self.fixture.terminal | changes)
                with self.assertRaises(ValueError):
                    self.prepare(terminal_sha=sha)
                self.assertFalse(self.output.exists())

    def test_wrong_pins_or_tampered_frozen_code_refuse_before_writing(self):
        for changes in ({"code_sha": "0" * 64}, {"workspace_sha": "0" * 64},
                        {"marker_sha": "0" * 64}, {"terminal_sha": "0" * 64},
                        {"image": "sha256:" + "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.prepare(**changes)
            self.assertFalse(self.output.exists())
        self.fixture.file(self.fixture.code / "app/strict_campaign.py", b"# changed inert fixture\n")
        with self.assertRaisesRegex(ValueError, "code inventory SHA"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_failed_live_unknown_or_foreign_ledger_refuses_before_writing(self):
        for changes in (*({"status": status} for status in (
                        "DISPATCH_INTENT", "DISPATCH_UNKNOWN", "DISPATCHED", "RUNNING", "OBSERVATION_UNAVAILABLE", "FAILED")),
                        {"identity_sha256": "0" * 64}, {"approval_sha256": "0" * 64}):
            with self.subTest(changes=changes):
                self.ledger_state(**changes)
                with self.assertRaisesRegex(ValueError, "one-unit approval boundary"):
                    self.prepare()
                self.assertFalse(self.output.exists())
        self.ledger_state()
        self.fixture.file(self.fixture.standard / "hybrid-one-unit/unknown.private.json", b"{}")
        with self.assertRaisesRegex(ValueError, "unknown one-unit ledger"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_tampered_fit_receipt_is_not_count_proof(self):
        self.unit.fit_completed()
        self.ledger_state()
        receipt = self.fixture.standard / "hybrid-runs" / (self.unit.run["run_id"] + ".json")
        value = json.loads(receipt.read_bytes())
        self.fixture.document(receipt, value | {"actual_component_fit_calls": 3})
        with self.assertRaisesRegex(ValueError, "changed retained HYBRID fit"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_nonblank_reference_is_required_before_source_reads(self):
        for reference in ("", " \n\t", "x" * 2001, None):
            with self.subTest(reference=reference), patch.object(M, "HybridPlan", side_effect=AssertionError("no source read")), \
                    self.assertRaisesRegex(ValueError, "nonblank explicit user"):
                self.prepare(user_approval_reference=reference)
        self.assertFalse(self.output.exists())

    def test_existing_symlink_and_nonprivate_destinations_are_not_changed(self):
        self.fixture.file(self.output, b"existing private operator artifact")
        before = self.output.read_bytes()
        with self.assertRaisesRegex(ValueError, "fresh exact"):
            self.prepare()
        self.assertEqual(self.output.read_bytes(), before)
        other = self.fixture.base / "link-target.private.json"
        self.fixture.file(other, b"target private artifact")
        linked = self.fixture.base / "symlink-approval.private.json"
        linked.symlink_to(other)
        with self.context(), self.assertRaises(ValueError):
            B.prepare(linked, **self.arguments)
        self.assertEqual(other.read_bytes(), b"target private artifact")
        public = self.fixture.base / "public"; public.mkdir(mode=0o755)
        with self.context(), self.assertRaisesRegex(ValueError, "owner-controlled"):
            B.prepare(public / "approval.private.json", **self.arguments)
        self.assertFalse((public / "approval.private.json").exists())

    def test_operator_output_cannot_mutate_source_or_ledger(self):
        self.ledger_state()
        for directory in (self.fixture.source, self.fixture.standard,
                          self.fixture.standard / "hybrid-one-unit"):
            with self.subTest(directory=directory.name):
                output = directory / "new-approval.private.json"
                with self.context(), self.assertRaisesRegex(ValueError, "outside the source subtree"):
                    B.prepare(output, **self.arguments)
                self.assertFalse(output.exists())

    def test_destination_created_at_publication_is_never_overwritten(self):
        actual_open = B.os.open
        def raced(path, flags, mode=0o777, **kwargs):
            if path == self.output.name and flags & os.O_EXCL:
                self.fixture.file(self.output, b"concurrent private operator artifact")
            return actual_open(path, flags, mode, **kwargs)
        with patch.object(B.os, "open", side_effect=raced), self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(self.output.read_bytes(), b"concurrent private operator artifact")

    def test_duplicate_field_oversized_and_symlink_terminal_are_refused(self):
        path = self.fixture.source / "state.private.json"
        self.fixture.file(path, b'{"status":"RUNNING","status":"COMPLETE_UNQUALIFIED_SOURCE"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.prepare(terminal_sha=M.digest(path))
        self.fixture.file(path, b" " * (2 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "bounded owner-controlled"):
            self.prepare(terminal_sha="0" * 64)
        target = self.fixture.base / "terminal-target.private.json"
        sha = self.fixture.document(target, self.fixture.terminal)
        # Only fabricated test metadata is unlinked; no project/runtime file.
        path.unlink(); path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "canonical owned"):
            self.prepare(terminal_sha=sha)
        self.assertFalse(self.output.exists())

    def test_receipt_boundary_drift_is_refused_before_writing(self):
        actual = M.next_hybrid_unit
        calls = 0
        def changed(plan):
            nonlocal calls
            unit = actual(plan); calls += 1
            return unit if calls == 1 else unit | {"unit_id": "changed-boundary"}
        with patch.object(M, "next_hybrid_unit", side_effect=changed), self.assertRaisesRegex(ValueError, "boundary changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_blocked_audit_does_not_block_training_or_validation_approval(self):
        self.blocked_audit(self.fixture.source)
        for fitted, expected_stage in ((False, "fit"), (True, "validation")):
            with self.subTest(stage=expected_stage):
                if fitted: self.unit.fit_completed()
                output = self.fixture.base / (expected_stage + "-approval.private.json")
                with self.context(), patch.object(M, "require_unblocked_holdout", side_effect=AssertionError("not holdout")):
                    result = B.prepare(output, **self.arguments)
                self.assertEqual(result["stage"], expected_stage)
                self.assertEqual(result["expected_before"], self.unit.before | {"actual_fits_completed": int(fitted)})

    def test_blocked_audit_does_not_block_zero_fit_recalibration_approval(self):
        self.blocked_audit(self.fixture.source)
        boundary, counts = self.fabricated_full_boundary()
        with boundary, patch.object(M, "require_unblocked_holdout", side_effect=AssertionError("not holdout")):
            result = self.prepare()
        self.assertEqual(result["stage"], "recalibration")
        self.assertEqual(result["expected_before"], counts)
        self.assertEqual(result["fit_or_score_calls"], 0)

    def test_selected_old_blocked_holdout_never_publishes_approval(self):
        selected = {"model_version": "hybrid_selected_fixture_0001"}
        for directory in (self.fixture.standard, self.fixture.source):
            with self.subTest(marker_directory=directory.name):
                marker = directory / "holdout-access-audit.private.json"
                self.blocked_audit(directory)
                before = marker.read_bytes()
                try:
                    boundary, _ = self.fabricated_full_boundary(selected)
                    with boundary, self.assertRaisesRegex(ValueError, "holdout provenance BLOCKED"):
                        self.prepare()
                    self.assertFalse(self.output.exists())
                    self.assertEqual(marker.read_bytes(), before)
                finally:
                    marker.unlink()  # Only this test's fabricated temporary audit.

    def test_existing_busy_coordinator_refuses_before_writing(self):
        self.ledger_state()
        lock = self.fixture.standard / "hybrid-one-unit/coordinator.lock"
        with lock.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_appearing_ledger_or_replaced_lock_refuses_before_writing(self):
        actual = M.next_hybrid_unit
        def appeared(plan):
            result = actual(plan)
            self.ledger_state()
            return result
        with patch.object(M, "next_hybrid_unit", side_effect=appeared), \
                self.assertRaisesRegex(ValueError, "ledger appeared"):
            self.prepare()
        self.assertFalse(self.output.exists())
        calls = 0
        def replaced(plan):
            nonlocal calls
            result = actual(plan); calls += 1
            if calls == 1:
                replacement = self.fixture.base / "replacement-fixture.lock"
                self.fixture.file(replacement, b"")
                os.replace(replacement, self.fixture.standard / "hybrid-one-unit/coordinator.lock")
            return result
        with patch.object(M, "next_hybrid_unit", side_effect=replaced), \
                self.assertRaisesRegex(ValueError, "continuation lock changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_retained_fit_approval_never_opens_model_or_numeric_bytes(self):
        self.unit.fit_completed()
        actual = M.checked_bytes
        reads = []
        def metadata_only(path, *args, **kwargs):
            path = Path(path); reads.append(path)
            if path.suffix in (".joblib", ".jsonl", ".npy", ".npz", ".gz"):
                raise AssertionError("builder cannot open model or numeric bytes")
            return actual(path, *args, **kwargs)
        with patch.object(M, "checked_bytes", side_effect=metadata_only), \
                patch("app.storage_budget.require_headroom", side_effect=AssertionError("builder cannot admit execution")):
            result = self.prepare()
        self.assertEqual(result["stage"], "validation")
        self.assertTrue(reads)
        self.assertFalse(result["execution_started"])

    def test_replaced_ledger_directory_refuses_before_writing(self):
        self.ledger_state()
        ledger = self.fixture.standard / "hybrid-one-unit"
        actual = M.next_hybrid_unit
        calls = 0
        def replaced(plan):
            nonlocal calls
            result = actual(plan); calls += 1
            if calls == 1:
                ledger.rename(self.fixture.base / "retained-fabricated-ledger")
                ledger.mkdir(mode=0o700)
                self.fixture.file(ledger / "coordinator.lock", b"")
            return result
        with patch.object(M, "next_hybrid_unit", side_effect=replaced), \
                self.assertRaisesRegex(ValueError, "one-unit ledger changed"):
            self.prepare()
        self.assertFalse(self.output.exists())


class HybridApprovedUnitCliTest(unittest.TestCase):
    def test_cli_requires_explicit_pins_without_reading_source(self):
        with patch("sys.argv", ["prepare", "--dataset", "/fixture", "--output", "/new"]), \
                patch.object(B, "continuation", side_effect=AssertionError("missing pins cannot read")), \
                self.assertRaises(SystemExit) as failure:
            B.main()
        self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
