"""Actual small fitting/recovery validates orchestration, never counts as the strict campaign."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sklearn.ensemble import IsolationForest

from app.contract import campaign_runs
from app.strict_campaign import approved_run, fit_one, search
from test_calibration import fixture


RUN = "trees-200-samples-128-features-100-seed-42-fold-1"


class StrictCampaignTest(unittest.TestCase):
    def test_completed_actual_small_fit_and_calibration_is_recovered_without_refit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            result = fit_one(root, RUN)
            self.assertEqual(result["status"], "FITTED_CALIBRATED")
            self.assertEqual(result["training_windows"], 600)
            self.assertEqual(result["calibration_scope"], "PILOT_ONLY")
            self.assertEqual(result["quality_gate"], "NOT_RUN")
            self.assertFalse(result["fit_recovered_without_refit"])
            with patch.object(IsolationForest, "fit", side_effect=AssertionError("completed identity cannot fit twice")):
                recovered = fit_one(root, RUN)
            self.assertTrue(recovered["fit_recovered_without_refit"])
            self.assertEqual(result["model_sha256"], recovered["model_sha256"])
            self.assertEqual(result["source_model_sha256"], recovered["source_model_sha256"])
            self.assertFalse((root / "strict-models/active.json").exists())

    def test_pilot_and_arbitrary_recipes_are_not_a_completed_360_fit_search(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            with self.assertRaisesRegex(ValueError, "PILOT"):
                search(root, 60)
            self.assertFalse((root / "strict-campaign.identity.json").exists())
        for run in ("../caller-selected-config", "trees-999-samples-1-features-100-seed-42-fold-1", None):
            with self.assertRaises(ValueError): approved_run(run)
        self.assertEqual(len(campaign_runs()), 360)
        self.assertEqual(len({item["run_id"] for item in campaign_runs()}), 360)


if __name__ == "__main__": unittest.main()
