"""Mocked future boundary evidence only; no real campaign, fit, or holdout rows."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app import selection, strict_campaign
from app.contract import campaign_runs
from app.pipeline_lock import coordinated_stage
import test_hybrid_selection as hybrid_fixture
from test_pipeline_lock import fixture


class BoundedStrictStagesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = fixture(Path(self.temporary.name))
        self.runs = campaign_runs()
        self.dataset = SimpleNamespace(sha256="a" * 64, manifest={"stage": "STRICT"})
        self.expected = {"dataset_manifest_sha256": self.dataset.sha256, "fit_code_fingerprint": {}}
        (self.root / "strict-runs").mkdir(mode=0o700)
        (self.root / "strict-models").mkdir(mode=0o700)
        self.models = {}

    def identity(self, dataset, run):
        return {"run_id": run["run_id"], "fold": run["fold"]}

    def fit_receipt(self, run, status="FITTED_CALIBRATED"):
        version = "fixture-" + str(self.runs.index(run))
        artifact = self.root / "strict-models" / (version + ".joblib")
        artifact.write_bytes(b"NOT_A_MODEL_NO_REAL_FITS_" + run["run_id"].encode())
        digest = strict_campaign.sha(artifact)
        receipt = {**self.identity(self.dataset, run), "status": status, "model_version": version,
                   "model_sha256": digest, "calibration_sha256": "b" * 64}
        self.models[version] = {"sha256": digest, "calibration_sha256": "b" * 64}
        strict_campaign.write(self.root / "strict-runs" / (run["run_id"] + ".json"), receipt)
        return receipt

    def campaign_progress(self, count, status="STOPPED_AT_RUN_BOUNDARY"):
        strict_campaign.write(self.root / "strict-campaign.progress.json", {
            "dataset_manifest_sha256": self.dataset.sha256, "code_fingerprint": {},
            "status": status, "actual_fits_completed": count})

    def search_context(self, start):
        stack = ExitStack()
        for name, value in (("ShardedDataset", self.dataset), ("fingerprint", {})):
            stack.enter_context(patch.object(strict_campaign, name, return_value=value))
        stack.enter_context(patch.object(strict_campaign, "validate_fit_recipe"))
        stack.enter_context(patch.object(strict_campaign, "run_identity", side_effect=self.identity))
        stack.enter_context(patch.object(strict_campaign.subprocess, "Popen", side_effect=start))
        stack.enter_context(patch("builtins.print"))
        return stack

    def validation_context(self, validator):
        stack = ExitStack()
        stack.enter_context(patch.object(selection, "ShardedDataset", return_value=self.dataset))
        stack.enter_context(patch.object(selection, "selection_identity", return_value=self.expected))
        stack.enter_context(patch.object(selection, "run_identity", side_effect=self.identity))
        stack.enter_context(patch.object(strict_campaign, "run_identity", side_effect=self.identity))
        store = SimpleNamespace(load_candidate=lambda version: (self.models[version], {}))
        stack.enter_context(patch.object(selection, "ModelStore", return_value=store))
        stack.enter_context(patch.object(selection, "validate_candidate", side_effect=validator))
        stack.enter_context(patch("builtins.print"))
        return stack

    def validated(self, version):
        return {"evaluation_scope": "VALIDATION", "model_sha256": self.models[version]["sha256"]}

    def test_limits_are_explicit_positive_integers_before_any_consumer_io(self):
        for limit in (0, -1, 361, True, "1", 1.0):
            for consumer, args, option in ((strict_campaign.search, (self.root, 60), "max_new_runs"),
                                          (selection.validate_all, (self.root, self.root), "max_new_runs"),
                                          (selection.choose, (self.root, self.root), "max_new_recalibrations")):
                with self.subTest(limit=limit, consumer=consumer.__name__), \
                        patch("app.pipeline_lock._directory", side_effect=AssertionError("no filesystem access")), \
                        self.assertRaisesRegex(ValueError, "integer from 1 through 360"):
                    consumer(*args, **{option: limit}, coordinated=True)

    def test_search_yields_one_new_run_counts_verified_suffix_and_preserves_child_fd(self):
        self.fit_receipt(self.runs[1]); self.fit_receipt(self.runs[-1])
        commands = []
        def start(command, **options):
            commands.append(command)
            held = os.fstat(options["pass_fds"][0]); actual = (self.root.parent / "campaign.lock").stat()
            self.assertEqual((held.st_dev, held.st_ino), (actual.st_dev, actual.st_ino))
            self.assertNotIn("--coordinated", command)
            def wait(timeout):
                with self.assertRaisesRegex(ValueError, "already active"):
                    with coordinated_stage(self.root, "campaign", enabled=True): pass
                self.fit_receipt(self.runs[0])
                return 0
            return SimpleNamespace(pid=12345, wait=wait)
        with self.search_context(start):
            result = strict_campaign.search(self.root, 60, coordinated=True, max_new_runs=1)
        self.assertEqual(len(commands), 1)
        self.assertEqual(result["status"], "STOPPED_AT_RUN_BOUNDARY")
        self.assertEqual(result["actual_fits_completed"], 3)
        self.assertEqual(result["new_runs_completed"], 1)
        self.assertEqual(result["quality_gate"], "NOT_RUN")
        self.assertFalse(result["holdout_scored"])
        self.assertEqual(json.loads((self.root / "strict-campaign.progress.json").read_text()), result)
        with coordinated_stage(self.root, "campaign", enabled=True): pass

    def test_failed_retained_fit_anywhere_is_not_hidden_by_early_yield(self):
        self.fit_receipt(self.runs[-1], "FAILED")
        with self.search_context(lambda *args, **kwargs: self.fail("failed receipt cannot spawn a retry")), \
                self.assertRaisesRegex(ValueError, "retained failed fit"):
            strict_campaign.search(self.root, 60, max_new_runs=1)

    def test_partial_validation_yields_without_ranking_and_rejects_retained_failure(self):
        for run in self.runs[:3]: self.fit_receipt(run)
        self.campaign_progress(3)
        calls = []
        def validate(dataset, store, version, *args, **kwargs):
            calls.append(version)
            return self.validated(version)
        with self.validation_context(validate), patch.object(selection, "rank_configurations") as rank:
            for count in (1, 2):
                result = selection.validate_all(self.root, self.root, coordinated=True, max_new_runs=1)
                self.assertEqual(result["status"], "STOPPED_AT_VALIDATION_BOUNDARY")
                self.assertEqual(result["completed_runs"], count)
                self.assertEqual(result["new_runs_completed"], 1)
                self.assertFalse((self.root / "strict-ranking.json").exists())
                with coordinated_stage(self.root, "selection", enabled=True): pass
            rank.assert_not_called()
            bad = self.root / "strict-validations" / (self.runs[2]["run_id"] + ".json")
            strict_campaign.write(bad, {"status": "FAILED", "selection_identity": self.expected})
            with self.assertRaisesRegex(ValueError, "retained failed validation"):
                selection.validate_all(self.root, self.root, max_new_runs=1)
        self.assertEqual(len(calls), 2)

    def test_full_mocked_validation_emits_ranking_only_after_all360_receipts(self):
        # These fabricated receipts test orchestration, not any actual fit count.
        output = self.root / "strict-validations"; output.mkdir(mode=0o700)
        for run in self.runs:
            fit = self.fit_receipt(run)
            if run != self.runs[0]:
                strict_campaign.write(output / (run["run_id"] + ".json"), {
                    **self.validated(fit["model_version"]), "status": "VALIDATED", "selection_identity": self.expected})
        self.campaign_progress(360, "FIT_AND_CALIBRATION_COMPLETE")
        with self.validation_context(lambda dataset, store, version, *args, **kwargs: self.validated(version)), \
                patch.object(selection, "rank_configurations", return_value={"status": "RANKED", "configurations": []}) as rank:
            result = selection.validate_all(self.root, self.root, max_new_runs=1)
        self.assertEqual(result["validation_runs_completed"], 360)
        self.assertEqual(len(rank.call_args.args[0]), 360)
        self.assertTrue((self.root / "strict-ranking.json").exists())

    def test_failed_bounded_validation_is_durable_and_never_retried(self):
        self.fit_receipt(self.runs[0]); self.campaign_progress(1)
        calls = []
        def fail(*args, **kwargs):
            calls.append("failed-toy-validation")
            raise RuntimeError("fixture failure, no rows")
        with self.validation_context(fail):
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                selection.validate_all(self.root, self.root, coordinated=True, max_new_runs=1)
            with coordinated_stage(self.root, "selection", enabled=True): pass
            with self.assertRaisesRegex(ValueError, "retained failed validation"):
                selection.validate_all(self.root, self.root, max_new_runs=1)
        self.assertEqual(calls, ["failed-toy-validation"])
        path = self.root / "strict-validations" / (self.runs[0]["run_id"] + ".json")
        self.assertEqual(json.loads(path.read_text())["status"], "FAILED")

    def test_hybrid_choose_yields_each_zero_fit_clone_until_three_whole_configurations(self):
        actual_choose = selection.choose
        stopped_counts = []
        def bounded_choose(directory, workspace, kind):
            while True:
                result = actual_choose(directory, workspace, kind, max_new_recalibrations=1)
                if result["status"] != "STOPPED_AT_RECALIBRATION_BOUNDARY": return result
                stopped_counts.append(result["completed_recalibrations"])
                self.assertEqual(result["new_recalibrations_completed"], 1)
                self.assertEqual(result["additional_fit_calls_in_recalibration"], 0)
                self.assertEqual(result["completed_configurations"], result["completed_recalibrations"] // 15)
                self.assertFalse((directory / "hybrid-selection.json").exists())
                self.assertEqual(json.loads((directory / "hybrid-selection.progress.json").read_text()), result)
        # Reuse the explicitly mocked typed-hybrid fixture and its retained
        # source/configuration/policy/state tampering checks. Never opens rows.
        with patch("test_hybrid_selection.choose", side_effect=bounded_choose), \
                patch.object(selection, "bounded_run_identity", side_effect=lambda dataset, run, cache: selection.run_identity(dataset, run)):
            hybrid_fixture.HybridSelectionTest().exercise_choose(self.root)
        self.assertEqual(stopped_counts, list(range(1, 45)))

    def test_failed_bounded_recalibration_is_durable_and_never_retried(self):
        actual_choose = selection.choose
        first = True
        def bounded_choose(directory, workspace, kind):
            nonlocal first
            if first:
                first = False
                with patch.object(selection, "recalibrate", side_effect=RuntimeError("fixture recalibration failure")) as fail:
                    with self.assertRaisesRegex(RuntimeError, "fixture recalibration failure"):
                        actual_choose(directory, workspace, kind, coordinated=True, max_new_recalibrations=1)
                    with coordinated_stage(self.root, "selection", enabled=True): pass
                    with self.assertRaisesRegex(ValueError, "retained failed recalibration"):
                        actual_choose(directory, workspace, kind, max_new_recalibrations=1)
                    self.assertEqual(fail.call_count, 1)
                failed = list((directory / "hybrid-top-recalibrations").glob("*.json"))
                self.assertEqual(len(failed), 1)
                self.assertEqual(json.loads(failed[0].read_text())["status"], "FAILED")
                failed[0].unlink()  # Only this test's private failed fixture.
            return actual_choose(directory, workspace, kind)
        with patch("test_hybrid_selection.choose", side_effect=bounded_choose), \
                patch.object(selection, "bounded_run_identity", side_effect=lambda dataset, run, cache: selection.run_identity(dataset, run)):
            hybrid_fixture.HybridSelectionTest().exercise_choose(self.root)

    def test_cli_limits_reach_only_the_matching_command(self):
        cases = ((strict_campaign, "search", "search", "--max-new-runs", "max_new_runs"),
                 (selection, "validate", "validate_all", "--max-new-runs", "max_new_runs"),
                 (selection, "choose", "choose", "--max-new-recalibrations", "max_new_recalibrations"))
        for module, command, consumer, flag, keyword in cases:
            arguments = ["fixture-cli", command, "--dataset", str(self.root), flag, "1"]
            if module is selection: arguments.extend(["--workspace", str(self.root)])
            with patch("sys.argv", arguments), patch.object(module, consumer, return_value={}) as called, patch("builtins.print"):
                module.main()
            self.assertEqual(called.call_args.kwargs[keyword], 1)


if __name__ == "__main__": unittest.main()
