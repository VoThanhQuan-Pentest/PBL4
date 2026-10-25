import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("strict_continuation", Path(__file__).resolve().parents[1] / "scripts/continue-ueba-strict.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class PipelineGuardTest(unittest.TestCase):
    def test_running_handle_waits_even_when_a_stale_file_claims_completion(self):
        self.assertFalse(module.fit_ready({"Status": "running", "ExitCode": 0}, {"actual_fits_completed": 360}, {}))

    def test_success_requires_terminal_process_and_complete_matching_receipt(self):
        identity = {"dataset_manifest_sha256": "a" * 64, "code_fingerprint": {"frozen": True}}
        progress = dict(identity, status="FIT_AND_CALIBRATION_COMPLETE", actual_fits_completed=360, required_fits=360, quality_gate="NOT_RUN")
        self.assertTrue(module.fit_ready({"Status": "exited", "ExitCode": 0, "OOMKilled": False}, progress, identity))
        for change in ({"actual_fits_completed": 359}, {"quality_gate": "PASS"}, {"dataset_manifest_sha256": "b" * 64}):
            with self.assertRaises(ValueError): module.fit_ready({"Status": "exited", "ExitCode": 0}, progress | change, identity)
        for state in ({"Status": "exited", "ExitCode": 137}, {"Status": "exited", "ExitCode": 0, "OOMKilled": True}):
            with self.assertRaises(ValueError): module.fit_ready(state, progress, identity)

    def test_holdout_is_never_opened_for_preview_or_unqualified_or_incomplete_selection(self):
        selected = {"status": "SELECTED", "actual_fits_completed": 360, "validation_runs_completed": 360,
                    "completed_recalibrations": 45, "additional_fit_calls_in_recalibration": 0, "dataset_sha256": "a" * 64, "holdout_scored": False}
        self.assertTrue(module.may_open_holdout(selected, "a" * 64))
        for change in ({"status": "NO_QUALIFIED_CONFIG"}, {"completed_recalibrations": 44}, {"holdout_scored": True},
                       {"additional_fit_calls_in_recalibration": 1}, {"dataset_sha256": "b" * 64}):
            self.assertFalse(module.may_open_holdout(selected | change, "a" * 64))

    def test_holdout_audit_gate_precedes_legacy_inventory_dispatch_and_state_updates(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); dataset = parent / "fabricated-experiment"; dataset.mkdir()
            runner = module.Runner.__new__(module.Runner)
            runner.dataset = dataset; runner.update = Mock(); runner.docker = Mock(); runner.observe = Mock()
            for directory in (dataset, parent):
                with self.subTest(marker_directory=directory.name):
                    marker = directory / "holdout-access-audit.private.json"
                    marker.write_bytes(b"{}"); marker.chmod(0o600)
                    try:
                        with patch.object(module.subprocess, "run", side_effect=AssertionError("no Docker inventory")) as inventory, \
                                self.assertRaises(ValueError):
                            runner.stage("holdout")
                        inventory.assert_not_called(); runner.update.assert_not_called()
                        runner.docker.assert_not_called(); runner.observe.assert_not_called()
                    finally:
                        marker.unlink()  # Only this test's temporary marker.

    def test_non_holdout_legacy_stages_keep_existing_mocked_dispatch_behavior(self):
        runner = module.Runner.__new__(module.Runner)
        runner.dataset = Path("/fabricated-experiment")
        runner.code = Path("/fabricated-code"); runner.workspace = Path("/fabricated-workspace")
        runner.image = "sha256:" + "a" * 64; runner.identity_sha = "b" * 64
        runner.state = {"containers": {}}; runner.update = Mock()
        runner.docker = Mock(return_value="c" * 64)
        runner.observe = Mock(return_value={"State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False}})
        with patch.object(module, "require_unblocked_holdout", side_effect=AssertionError("non-holdout stage")), \
                patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")) as inventory:
            for stage in ("validation", "selection"): runner.stage(stage)
        self.assertEqual(inventory.call_count, 2); self.assertEqual(runner.docker.call_count, 2)
        self.assertEqual(runner.state["containers"], {"validation": "c" * 64, "selection": "c" * 64})


if __name__ == "__main__": unittest.main()
