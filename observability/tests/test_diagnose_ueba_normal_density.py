"""Runner plumbing fixtures only: never scored accuracy or deployment evidence."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

PATH = Path(__file__).resolve().parents[1] / "scripts/diagnose-ueba-normal-density.py"
SPEC = importlib.util.spec_from_file_location("isolated_normal_density_diagnostic", PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NormalDensityDiagnosticTest(unittest.TestCase):
    def test_predeclared_grid_and_default_are_distinct_and_fixed(self):
        self.assertEqual(len(RUNNER.CONFIGURATIONS), 24)
        self.assertEqual(len(set(RUNNER.CONFIGURATIONS)), 24)
        self.assertEqual(RUNNER.DEFAULT, (8, 256, "euclidean"))
        self.assertIn(RUNNER.DEFAULT, RUNNER.CONFIGURATIONS)
        self.assertEqual(RUNNER.RECIPE_VERSION, 2)
        self.assertEqual(RUNNER.NormalDensityScorer().parameters()["raw_score_representation"], RUNNER.RAW_REPRESENTATION)

    def test_midrank_keeps_ties_inside_calibration_mass(self):
        np.testing.assert_array_equal(RUNNER.midrank([1, 1, 1, 3], [0, 1, 2, 3, 4]),
                                      [0, 37.5, 75, 87.5, 100])
        for calibration, query in (([2, 1], [1]), ([1], [float("nan")]), ([], [1])):
            with self.assertRaises(ValueError):
                RUNNER.midrank(calibration, query)

    def test_ready_and_unseen_share_ready_bucket_cold_is_independent(self):
        rows = [{"cohort": cohort} for cohort in ("READY", "UNSEEN_READY", "COLD")]
        policy = RUNNER.ScorePolicy.strict(schema=4)
        scores = RUNNER.calibrate_scores([5, 5, 5], rows, {"READY": [0, 1], "COLD": [10, 11]}, policy)
        self.assertEqual([score["normal_percentile"] for score in scores], [100, 100, 0])
        self.assertEqual([score["level"] for score in scores], ["VERY_UNUSUAL", "VERY_UNUSUAL", "NORMAL_RANGE"])

    def test_both_decisions_include_complete_family_cohort_confusion(self):
        rows = [
            {"label": 1, "family": "request_burst", "cohort": "READY",
             "predictions": {"MODEL_ONLY": True, "SIEM_FINAL": True}},
            {"label": 1, "family": "endpoint_scan", "cohort": "COLD",
             "predictions": {"MODEL_ONLY": False, "SIEM_FINAL": True}},
            {"label": 0, "family": "normal", "cohort": "UNSEEN_READY",
             "predictions": {"MODEL_ONLY": False, "SIEM_FINAL": True}},
            {"label": 0, "family": "normal", "cohort": "READY",
             "predictions": {"MODEL_ONLY": False, "SIEM_FINAL": False}},
        ]
        metrics = RUNNER.decision_metrics(rows)
        self.assertEqual(metrics["MODEL_ONLY"]["complete_validation"]["recall"], 0.5)
        self.assertEqual(metrics["SIEM_FINAL"]["complete_validation"]["precision"], 2 / 3)
        self.assertEqual(metrics["SIEM_FINAL"]["cohorts"]["UNSEEN_READY"]["fp"], 1)
        self.assertEqual(metrics["MODEL_ONLY"]["families"]["endpoint_scan"]["fn"], 1)
        self.assertEqual(metrics["SIEM_FINAL"]["family_cohort"]["endpoint_scan:COLD"]["tp"], 1)
        self.assertTrue(all(value["quality_gate"] == "NOT_APPLICABLE" for value in metrics.values()))

    def test_pilot_only_reader_refuses_holdout_before_io(self):
        dataset = object.__new__(RUNNER.PilotOnlyDataset)
        for name in ("holdout.json", "shards/holdout-000000.json", "shards/fold2-fit-000000.json", "../manifest.json"):
            with self.assertRaisesRegex(ValueError, "only fixed fold-1"):
                dataset._read(name, 1)

    def test_actual_frozen_pilot_conserves_all_rows_without_fitting_or_scoring(self):
        dataset, rows = RUNNER.load_pilot()
        self.assertEqual(dataset.sha256, RUNNER.PILOT_SHA)
        self.assertEqual({name: len(group) for name, group in rows.items()}, {
            "fold1-fit": 2000, "fold1-calibration-ready": 1000,
            "fold1-calibration-cold": 1000, "fold1-validation": 21000})
        self.assertEqual(sum(row["label"] for row in rows["fold1-validation"]), 1000)
        java = RUNNER.frozen_java()
        self.assertEqual(java["snapshot_sha256"], RUNNER.WORKSPACE_SHA)
        self.assertEqual(set(java["replay_classes"]), set(RUNNER.CLASS_FILES))

    def test_private_receipts_cannot_overwrite_and_have_restricted_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            RUNNER.write_private(path, {"status": "PLUMBING_FIXTURE"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                RUNNER.write_private(path, {})

    def test_refuses_host_execution_before_dataset_access(self):
        with patch.dict(os.environ, {"UEBA_DIAGNOSTIC_IMAGE_ID": ""}), patch.object(RUNNER, "load_pilot") as read:
            with self.assertRaisesRegex(ValueError, "pinned Docker"):
                RUNNER.run(None)
            read.assert_not_called()

    def test_grid_requires_complete_default_result(self):
        policy = RUNNER.ScorePolicy.strict(schema=4)
        with self.assertRaisesRegex(ValueError, "complete fixed-default"):
            RUNNER.verify_default(None, {}, policy)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.private.json"
            RUNNER.write_private(path, {"status": "COMPLETED", "mode": "FIXED_DEFAULT"})
            with self.assertRaisesRegex(ValueError, "same-source complete"):
                RUNNER.verify_default(path, {}, policy)


if __name__ == "__main__":
    unittest.main()
