"""Regression tests for the external one-unit strict campaign operator."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/strict-operator.py"
SPEC = importlib.util.spec_from_file_location("strict_operator_under_test", SCRIPT)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)


class StrictOperatorTest(unittest.TestCase):
    def test_selected_candidate_stops_before_legacy_holdout(self):
        selected = {"status": "SELECTED", "model_version": "selected-v1"}
        counts = {"actual_fits_completed": 360, "validation_runs_completed": 360, "completed_recalibrations": 45}
        module = SimpleNamespace(
            private_receipt=lambda _path: selected,
            hybrid_records=lambda _plan: {"counts": counts},
            hybrid_selected=lambda _plan, _selected, _records: None,
            next_hybrid_unit=lambda _plan: (_ for _ in ()).throw(AssertionError("old holdout path was called")),
        )
        unit, records, terminal = OP.next_unit_without_legacy_holdout(module, SimpleNamespace(dataset=Path("/private")))
        self.assertIsNone(unit)
        self.assertEqual(counts, records["counts"])
        self.assertIs(selected, terminal)

    def test_no_qualified_selection_is_terminal(self):
        progress = {"status": "NO_QUALIFIED_CONFIG"}
        module = SimpleNamespace(
            private_receipt=lambda path: progress if Path(path).name == "hybrid-selection.progress.json" else None,
            hybrid_records=lambda _plan: {"counts": {"actual_fits_completed": 360,
                                                     "validation_runs_completed": 360,
                                                     "completed_recalibrations": 45}},
            next_hybrid_unit=lambda _plan: (_ for _ in ()).throw(AssertionError("failed search was restarted")),
        )
        unit, _records, terminal = OP.next_unit_without_legacy_holdout(module, SimpleNamespace(dataset=Path("/private")))
        self.assertIsNone(unit)
        self.assertIs(progress, terminal)

    def test_one_unit_approval_is_private_idempotency_keyed_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "operator"
            state.mkdir(mode=0o700)
            state.chmod(0o700)
            before = {"actual_fits_completed": 12, "validation_runs_completed": 12,
                      "completed_recalibrations": 0}
            unit = {"stage": "fit", "unit_id": "campaign-run-13", "before": before}
            module = SimpleNamespace(
                private_receipt=lambda _path: None,
                hybrid_records=lambda _plan: {"counts": before},
                checked_bytes=lambda path, _maximum: Path(path).read_bytes(),
                next_hybrid_unit=lambda _plan: unit,
            )
            plan = SimpleNamespace(
                dataset=Path("/owned/source/standard"), identity_sha256="a" * 64,
                recheck=lambda: None,
                require_headroom=lambda _dataset, _budget: None,
                unit_budgets=lambda: {"fit": 1024},
            )
            result = OP.write_approval(module, plan, state, "user authorized this campaign")
            approval_path = Path(result["approval_path"])
            self.assertEqual(0o600, approval_path.stat().st_mode & 0o777)
            self.assertEqual(result["approval_sha256"], hashlib.sha256(approval_path.read_bytes()).hexdigest())
            document = json.loads(approval_path.read_text())
            self.assertEqual(OP.APPROVAL_FIELDS, set(document))
            self.assertTrue(document["execution_approved"])
            self.assertFalse(document["retirement_approved"])
            repeated = OP.write_approval(module, plan, state, "user authorized this campaign")
            self.assertTrue(repeated["approval_reused"])
            self.assertEqual(result["approval_sha256"], repeated["approval_sha256"])

    def test_validation_rejects_holdout_approval_and_checksum_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "approval.json"
            path.write_text(json.dumps({
                "approval_schema_version": 1,
                "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
                "source_standard": "/owned/source/standard",
                "continuation_identity_sha256": "a" * 64,
                "stage": "holdout",
                "unit_id": "selected-v1",
                "expected_before": {"actual_fits_completed": 360,
                                    "validation_runs_completed": 360,
                                    "completed_recalibrations": 45},
                "execution_approved": True,
                "retirement_approved": False,
                "user_approval_reference": "user authorization",
            }))
            path.chmod(0o600)
            module = SimpleNamespace(checked_bytes=lambda candidate, _limit: Path(candidate).read_bytes())
            plan = SimpleNamespace(dataset=Path("/owned/source/standard"), identity_sha256="a" * 64)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                OP.validate_approval(module, plan, path, sha)
            with self.assertRaises(ValueError):
                OP.validate_approval(module, plan, path, "0" * 64)

    def test_interrupted_unit_resumes_only_its_approved_docker_handle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset = root / "source" / "standard"
            ledger = dataset / "hybrid-one-unit"
            ledger.mkdir(parents=True, mode=0o700)
            ledger.chmod(0o700)
            approvals = root / "approvals"
            approvals.mkdir(mode=0o700)
            approvals.chmod(0o700)
            before = {"actual_fits_completed": 12, "validation_runs_completed": 12,
                      "completed_recalibrations": 0}
            approval_sha = "a" * 64
            approval = {"approval_schema_version": 1, "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
                "source_standard": str(dataset), "continuation_identity_sha256": "b" * 64,
                "stage": "fit", "unit_id": "campaign-run-13", "expected_before": before,
                "execution_approved": True, "retirement_approved": False,
                "user_approval_reference": "user authorized strict campaign"}
            approval_path = approvals / f"operator-{approval_sha}.private.json"
            approval_path.write_text(OP.canonical(approval)); approval_path.chmod(0o600)
            container_name = "flare-hybrid-fit-identity-013"
            state = {"status": "RUNNING", "identity_sha256": "b" * 64,
                "approval_sha256": approval_sha, "stage": "fit", "unit_id": "campaign-run-13",
                "before": before, "container_name": container_name, "container_id": "c" * 64,
                "quality_gate": "NOT_RUN", "retirement_authority": False, "aws_changed": False}
            (ledger / f"{approval_sha}.private.json").write_text(OP.canonical(state))
            (ledger / f"{approval_sha}.private.json").chmod(0o600)
            executed = []
            result = {"status": "SUCCEEDED", "stage": "fit", "unit_id": "campaign-run-13",
                      "result": {"counts": before}, "quality_gate": "NOT_RUN"}
            module = SimpleNamespace(
                checked_directory=lambda path: Path(path),
                private_receipt=lambda path: json.loads(Path(path).read_text()),
                campaign_run_approval=lambda _plan, path, sha: approval if
                    Path(path) == approval_path and sha == approval_sha else (_ for _ in ()).throw(ValueError()),
                execute_hybrid_one_unit=lambda _plan, path, sha: executed.append((Path(path), sha)) or result,
            )
            plan = SimpleNamespace(dataset=dataset, identity_sha256="b" * 64,
                command=lambda stage, ordinal: ["docker", "run", "--name",
                    f"flare-hybrid-{stage}-identity-{ordinal:03d}"])
            self.assertIs(result, OP.resume_interrupted_unit(module, plan, approvals))
            self.assertEqual([(approval_path, approval_sha)], executed)

    def test_interrupted_unit_refuses_mismatched_container_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset = root / "source" / "standard"
            ledger = dataset / "hybrid-one-unit"
            ledger.mkdir(parents=True, mode=0o700)
            ledger.chmod(0o700)
            approvals = root / "approvals"
            approvals.mkdir(mode=0o700)
            approvals.chmod(0o700)
            before = {"actual_fits_completed": 12, "validation_runs_completed": 12,
                      "completed_recalibrations": 0}
            approval_sha = "a" * 64
            approval = {"approval_schema_version": 1, "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
                "source_standard": str(dataset), "continuation_identity_sha256": "b" * 64,
                "stage": "fit", "unit_id": "campaign-run-13", "expected_before": before,
                "execution_approved": True, "retirement_approved": False,
                "user_approval_reference": "user authorized strict campaign"}
            approval_path = approvals / f"operator-{approval_sha}.private.json"
            approval_path.write_text(OP.canonical(approval)); approval_path.chmod(0o600)
            state = {"status": "RUNNING", "identity_sha256": "b" * 64,
                "approval_sha256": approval_sha, "stage": "fit", "unit_id": "campaign-run-13",
                "before": before, "container_name": "unrelated-container", "container_id": "c" * 64,
                "quality_gate": "NOT_RUN", "retirement_authority": False, "aws_changed": False}
            (ledger / f"{approval_sha}.private.json").write_text(OP.canonical(state))
            (ledger / f"{approval_sha}.private.json").chmod(0o600)
            module = SimpleNamespace(
                checked_directory=lambda path: Path(path),
                private_receipt=lambda path: json.loads(Path(path).read_text()),
                campaign_run_approval=lambda *_args: approval,
                execute_hybrid_one_unit=lambda *_args: self.fail("mismatched container must not resume"),
            )
            plan = SimpleNamespace(dataset=dataset, identity_sha256="b" * 64,
                command=lambda stage, ordinal: ["docker", "run", "--name",
                    f"flare-hybrid-{stage}-identity-{ordinal:03d}"])
            with self.assertRaises(ValueError):
                OP.resume_interrupted_unit(module, plan, approvals)

    def test_reference_is_bounded_and_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "operator"
            state.mkdir(mode=0o700)
            state.chmod(0o700)
            module = SimpleNamespace(
                private_receipt=lambda _path: None,
                hybrid_records=lambda _plan: {"counts": {}},
                next_hybrid_unit=lambda _plan: {"stage": "fit", "unit_id": "run", "before": OP.COUNTS.copy()},
            )
            plan = SimpleNamespace(dataset=Path("/owned/source/standard"), identity_sha256="a" * 64,
                                   recheck=lambda: None, require_headroom=lambda *_: None,
                                   unit_budgets=lambda: {"fit": 1})
            with self.assertRaises(ValueError):
                OP.write_approval(module, plan, state, "   ")
            with self.assertRaises(ValueError):
                OP.write_approval(module, plan, state, "x" * 2001)

    def test_long_runner_stops_at_selection_without_old_holdout(self):
        selected = {"stage": "SELECTED_STOP_BEFORE_OLD_HOLDOUT", "status": "SELECTED_STOP_BEFORE_OLD_HOLDOUT",
                    "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
        with patch.object(OP, "resume_interrupted_unit", return_value=None), \
             patch.object(OP, "safe_status", return_value=selected), \
             patch.object(OP, "write_approval") as prepare, \
             patch.object(OP, "execute") as run:
            result = OP.run_until_selection(SimpleNamespace(), SimpleNamespace(), Path("/private"), "authorized", 5)
        self.assertEqual("SELECTED_STOP_BEFORE_OLD_HOLDOUT", result["stage"])
        prepare.assert_not_called()
        run.assert_not_called()

    def test_long_runner_reuses_the_same_approval_after_observation_failure(self):
        ready = {"stage": "fit", "status": "READY", "unit_id": "run-13",
                 "actual_fits_completed": 12, "validation_runs_completed": 12,
                 "completed_recalibrations": 0}
        terminal = {"stage": "SELECTED_STOP_BEFORE_OLD_HOLDOUT", "status": "SELECTED_STOP_BEFORE_OLD_HOLDOUT",
                    "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}
        outputs = [
            {"status": "OBSERVATION_UNAVAILABLE", "stage": "fit", "unit_id": "run-13", "container_id": "child-1"},
            {"status": "SUCCEEDED", "stage": "fit", "unit_id": "run-13", "result": {"counts": ready}},
        ]
        approval = {"approval_path": Path("/private/approval.json"), "approval_sha256": "a" * 64}
        with patch.object(OP, "resume_interrupted_unit", return_value=None), \
             patch.object(OP, "safe_status", side_effect=[ready, ready, terminal]), \
             patch.object(OP, "write_approval", return_value=approval) as prepare, \
             patch.object(OP, "execute", side_effect=outputs) as run, \
             patch.object(OP.time, "sleep") as sleep:
            result = OP.run_until_selection(SimpleNamespace(), SimpleNamespace(), Path("/private"), "authorized", 5)
        self.assertEqual("SELECTED_STOP_BEFORE_OLD_HOLDOUT", result["stage"])
        self.assertEqual(1, result["units_completed_this_run"])
        self.assertEqual(2, prepare.call_count)
        self.assertEqual(2, run.call_count)
        self.assertEqual("a" * 64, run.call_args_list[0].args[3])
        self.assertEqual("a" * 64, run.call_args_list[1].args[3])
        sleep.assert_called_once_with(30)

    def test_long_runner_refuses_unbounded_unit_limit(self):
        with self.assertRaises(ValueError):
            OP.run_until_selection(SimpleNamespace(), SimpleNamespace(), Path("/private"), "authorized", 1082)


if __name__ == "__main__":
    unittest.main()
