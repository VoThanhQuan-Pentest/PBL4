"""Engineered counter fixtures prove numerical gates, NOT ten million scored observations."""

import unittest
from app.policy import ScorePolicy
from app.strict_metrics import Confusion, FAMILIES, confidence_for, exact_bounds, strict_gate


class StrictMetricsTest(unittest.TestCase):
    def test_old_pass_cannot_satisfy_new_precision_and_low_prevalence_gate(self):
        old = Confusion(1000, 0, 81, 9919)
        self.assertLess(old.metrics()["precision"], .998)
        bounds = confidence_for(old, ScorePolicy.strict())
        self.assertFalse(bounds["cluster_available"])

    def test_zero_false_positives_never_create_a_fake_zero_upper_bound(self):
        counts = Confusion(10000, 0, 0, 10000000)
        ci = confidence_for(counts, ScorePolicy.strict(), [[5000, 0, 0, 5000000], [5000, 0, 0, 5000000]])
        self.assertEqual(ci["cluster"]["false_positive_rate"]["upper"], 0)
        self.assertGreater(ci["conservative"]["false_positive_rate"]["upper"], 0)

    def test_six_global_comparisons_and_exact_boundary_are_enforced(self):
        counts = Confusion(10000, 0, 1, 9999999)
        policy = ScorePolicy.strict()
        ci = confidence_for(counts, policy, [[5000, 0, 1, 4999999], [5000, 0, 0, 5000000]])
        families = {name: Confusion(2000, 0, 0, 0) for name in FAMILIES}
        cohorts = {"READY": Confusion(7000, 0, 1, 6999999), "UNSEEN_READY": Confusion(2000, 0, 0, 2000000),
                   "COLD": Confusion(1000, 0, 0, 1000000)}
        result = strict_gate(counts, policy, families, cohorts, ci, scope="MODEL_ONLY")
        self.assertEqual(result["quality_gate"], "PASS")
        self.assertEqual(ci["comparisons"], 6)
        ci["conservative"]["recall"]["lower"] = .99
        self.assertEqual(strict_gate(counts, policy, families, cohorts, ci, scope="MODEL_ONLY")["quality_gate"], "FAIL")

    def test_undefined_precision_missing_clusters_or_missing_cohort_cannot_pass(self):
        self.assertIsNone(Confusion(0, 10000, 0, 10000000).metrics()["precision"])
        with self.assertRaises(ValueError): exact_bounds(1, 0, .05)
        with self.assertRaises(ValueError): Confusion(-1, 0, 0, 0)
        with self.assertRaises(ValueError): confidence_for(Confusion(1, 0, 0, 10), ScorePolicy.strict(), [[1, 0, 0, 1], [0, 0, 0, 1]])


if __name__ == "__main__": unittest.main()
