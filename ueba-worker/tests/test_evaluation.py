"""Engineered score fixtures verify metric/gate logic, not model detection performance."""

import unittest
import numpy as np
from app.evaluation import FAMILIES, evaluate_percentiles


class EvaluationGateTest(unittest.TestCase):
    def fixture(self, hits_per_family=180, false_positives=200):
        scores = [99.5] * false_positives + [50.0] * (10000 - false_positives)
        scores += ([99.5] * hits_per_family + [50.0] * (200 - hits_per_family)) * 5
        labels = [0] * 10000 + [1] * 1000
        families = ["normal"] * 10000 + [family for family in FAMILIES for _ in range(200)]
        groups = [f"account-{index % 200}/day-{index // 200 % 7}" for index in range(11000)]
        return scores, labels, families, groups

    def test_exact_user_recall_and_false_positive_boundary(self):
        result = evaluate_percentiles(*self.fixture(), bootstrap_samples=50)
        self.assertEqual(result["quality_gate"], "PASS")
        self.assertEqual(result["recall"], 0.90)
        self.assertEqual(result["false_positive_rate"], 0.02)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (900, 200, 9800, 100))
        self.assertEqual(result["confidence_95"]["method"], "account_day_cluster_bootstrap")

    def test_misses_or_false_positives_above_limits_fail(self):
        for scores in (self.fixture(179, 200), self.fixture(180, 201)):
            with self.subTest(kind=scores[0][:3]):
                self.assertEqual(evaluate_percentiles(*scores, bootstrap_samples=10)["quality_gate"], "FAIL")

    def test_large_total_cannot_hide_an_entire_missing_family(self):
        scores, labels, families, groups = self.fixture(200, 0)
        scores[-200:] = [50] * 200
        result = evaluate_percentiles(scores, labels, families, groups, bootstrap_samples=10)
        self.assertEqual(result["quality_gate"], "FAIL")
        self.assertEqual(result["families"][FAMILIES[-1]]["recall"], 0)

    def test_all_normal_predictions_do_not_become_fake_precision_one(self):
        scores, labels, families, groups = self.fixture()
        result = evaluate_percentiles(np.zeros(11000), labels, families)
        self.assertIsNone(result["precision"])
        self.assertEqual(result["recall"], 0)
        self.assertEqual(result["quality_gate"], "FAIL")

    def test_tiny_or_invalid_evaluation_cannot_pass_the_gate(self):
        result = evaluate_percentiles([99.5, 50], [1, 0], [FAMILIES[0], "normal"])
        self.assertEqual(result["quality_gate"], "FAIL")
        for scores, labels, families in (([float("nan")], [1], [FAMILIES[0]]),
                                         ([99], [2], [FAMILIES[0]]), ([99], [1], ["invented-family"]),
                                         ([101], [1], [FAMILIES[0]])):
            with self.subTest(scores=scores):
                with self.assertRaises(ValueError): evaluate_percentiles(scores, labels, families)


if __name__ == "__main__": unittest.main()
