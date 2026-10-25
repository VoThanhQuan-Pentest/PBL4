"""Counter/CI fixtures do not represent a scored model benchmark."""
from copy import deepcopy
import unittest

from app.accuracy_proof import derive_accuracy
from app.strict_metrics import Confusion, exact_bounds


def confidence(counts):
    alpha = 0.05 / 6
    exact = {"recall": exact_bounds(counts.tp, counts.positives, alpha),
             "false_positive_rate": exact_bounds(counts.fp, counts.normals, alpha)}
    return {"comparisons": 6, "cluster_available": True, "familywise_confidence": 0.95,
            "one_sided_alpha": alpha, "exact": exact, "conservative": deepcopy(exact)}


class AccuracyProofTest(unittest.TestCase):
    def test_both_scopes_have_explicit_accuracy_without_changing_policy_or_claiming_quality(self):
        counts = Confusion(9950, 50, 0, 10000000)
        original = confidence(counts)
        for scope in ("MODEL_ONLY", "SIEM_FINAL"):
            result = derive_accuracy(counts, original, scope=scope)
            self.assertTrue(result["point_condition_satisfied"])
            self.assertTrue(result["derived_confidence_condition_satisfied"])
            self.assertGreater(result["derived_accuracy_lower_bound"], .98)
            self.assertEqual(result["additional_statistical_comparisons"], 0)
            self.assertEqual(result["quality_gate"], "NOT_APPLICABLE")
        self.assertEqual(original, confidence(counts))

    def test_point_condition_is_strict_even_at_exact98_percent(self):
        counts = Confusion(49, 1, 1, 49)
        self.assertFalse(derive_accuracy(counts, confidence(counts), scope="MODEL_ONLY")["point_condition_satisfied"])

    def test_no_cluster_confidence_or_empty_class_cannot_claim_derived_certainty(self):
        counts = Confusion(9950, 50, 0, 10000000)
        for change in ({"cluster_available": False}, {"comparisons": 8}, {"one_sided_alpha": .1}, {"familywise_confidence": .99}):
            with self.subTest(change=change):
                self.assertFalse(derive_accuracy(counts, {**confidence(counts), **change}, scope="MODEL_ONLY")["confidence_available"])
        for empty in (Confusion(0, 0, 0, 0), Confusion(0, 0, 0, 100), Confusion(100, 0, 0, 0)):
            self.assertFalse(derive_accuracy(empty, {}, scope="MODEL_ONLY")["confidence_available"])

    def test_mismatched_population_or_nonconservative_bounds_are_rejected(self):
        counts = Confusion(9950, 50, 0, 10000000)
        wrong = confidence(Confusion(9999, 1, 0, 10000000))
        with self.assertRaisesRegex(ValueError, "population"):
            derive_accuracy(counts, wrong, scope="MODEL_ONLY")
        wrong = confidence(counts)
        exact = wrong["exact"]["recall"]
        wrong["conservative"]["recall"]["lower"] = (exact["lower"] + exact["upper"]) / 2
        with self.assertRaisesRegex(ValueError, "conservativeness"):
            derive_accuracy(counts, wrong, scope="MODEL_ONLY")

    def test_invalid_bounds_never_produce_nan_or_invented_percentage(self):
        counts = Confusion(9950, 50, 0, 10000000)
        for value in (float("nan"), float("inf"), -1, 2, True, "1"):
            wrong = confidence(counts)
            wrong["conservative"]["recall"]["lower"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                derive_accuracy(counts, wrong, scope="MODEL_ONLY")


if __name__ == "__main__":
    unittest.main()
