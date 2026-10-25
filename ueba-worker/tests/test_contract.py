"""Contract cases are not training runs and never stand in for held-out accuracy."""

from collections import Counter
import unittest

from app.contract import TrainingConfig, campaign_runs, feature_array, validate_version


class FeatureContractTest(unittest.TestCase):
    def test_three_hundred_distinct_malformed_window_cases(self):
        checked = 0
        for index in range(25):
            requests = 10 + index
            failures = index % 5
            original = [requests, index % 3, 0, failures, 3, 0, 1 + index % 4,
                        2, 0, 0, 0, (index - 12) / 2, 0,
                        (index % 3) / requests, failures / max(1, failures + 3)]
            self.assertEqual(feature_array([original], 256, 2).shape, (1, 15))
            for kind in range(12):
                row = original.copy()
                schema = 2
                if kind == 0: row.pop()
                if kind == 1: row[0] = float("nan")
                if kind == 2: row[11] = float("inf")
                if kind == 3: row[0] = -1
                if kind == 4: row[5] = 0.5
                if kind == 5: row[1] = requests + 1
                if kind == 6: row[6] = requests + 1
                if kind == 7: row[8] = 2
                if kind == 8: row[11] = 21
                if kind == 9: row[13] += 0.01
                if kind == 10: row[14] += 0.01
                if kind == 11: schema = 3
                with self.subTest(window=index, fault=kind):
                    with self.assertRaises(ValueError): feature_array([row], 256, schema)
                checked += 1
        self.assertEqual(checked, 300)

    def test_campaign_has_exactly_360_unique_resumable_fit_identities(self):
        runs = campaign_runs()
        self.assertEqual(len(runs), 360)
        self.assertEqual(len({run["run_id"] for run in runs}), 360)
        configurations = Counter((run["config"].n_estimators, run["config"].max_samples,
                                  run["config"].max_features) for run in runs)
        self.assertEqual(len(configurations), 24)
        self.assertEqual(set(configurations.values()), {15})
        for run in runs:
            self.assertEqual(run["config"].parameters()["n_jobs"], 1)
            self.assertEqual(run["config"].parameters()["contamination"], "auto")

    def test_unapproved_resource_settings_and_model_paths_are_rejected(self):
        for options in ({"n_estimators": 100000}, {"max_samples": 50000},
                        {"random_state": True}, {"max_features": float("nan")}, {"max_features": 0}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError): TrainingConfig(**options)
        for version in ("../escape-model", "/tmp/model", "short", "A" * 10, "x" * 65):
            with self.subTest(version=version):
                with self.assertRaises(ValueError): validate_version(version)


if __name__ == "__main__": unittest.main()
