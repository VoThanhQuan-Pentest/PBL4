"""Selection/anti-leakage unit fixtures do not claim fitted model accuracy."""

import unittest
from app.campaign import select_configuration, validate_fold, model_version
from app.contract import campaign_runs, validate_version


def receipts(recall=0.95, fpr=0.01):
    return [{"status": "SUCCEEDED", "run_id": run["run_id"], "fold": run["fold"],
             "config": {"n_estimators": run["config"].n_estimators, "max_samples": run["config"].max_samples,
                        "max_features": run["config"].max_features, "random_state": run["config"].random_state},
             "model_version": model_version(run["run_id"]),
             "metrics": {"recall": recall, "false_positive_rate": fpr}}
            for run in campaign_runs()]


class CampaignSelectionTest(unittest.TestCase):
    def test_fixed_seed42_fold3_representative_is_not_a_lucky_best_run(self):
        result = select_configuration(receipts())
        self.assertEqual(result["status"], "SELECTED")
        self.assertEqual(result["selected"]["candidate"]["fold"], 3)
        self.assertEqual(result["selected"]["candidate"]["config"]["random_state"], 42)
        self.assertEqual(result["selected"]["summary"]["configuration"]["n_estimators"], 200)
        self.assertEqual(len(result["configurations_considered"]), 24)

    def test_higher_fit_counts_cannot_override_quality_or_stability(self):
        for rows in (receipts(0.89, 0.01), receipts(0.95, 0.021)):
            self.assertEqual(select_configuration(rows)["status"], "NO_QUALIFIED_CONFIG")
        rows = receipts()
        for row in rows:
            if row["config"]["random_state"] == 11: row["metrics"]["recall"] = 0.86
        self.assertEqual(select_configuration(rows)["status"], "NO_QUALIFIED_CONFIG")

    def test_missing_fold_or_duplicate_receipt_cannot_satisfy_fifteen_cases(self):
        rows = receipts()[:15]
        self.assertEqual(select_configuration(rows[:14])["status"], "NO_QUALIFIED_CONFIG")
        duplicated = rows[:14] + [rows[0]]
        self.assertEqual(select_configuration(duplicated)["status"], "NO_QUALIFIED_CONFIG")

    def test_model_versions_are_bounded_and_reproducible_for_all_360_cases(self):
        versions = {model_version(run["run_id"]) for run in campaign_runs()}
        self.assertEqual(len(versions), 360)
        for version in versions: validate_version(version)

    def test_overlap_is_rejected_before_minimum_population_checks(self):
        row = {"frame_id": "fixed-window", "window_start": "2026-08-01T00:00:00Z"}
        with self.assertRaisesRegex(ValueError, "identity leakage"):
            validate_fold([row], [row], [row])


if __name__ == "__main__": unittest.main()
