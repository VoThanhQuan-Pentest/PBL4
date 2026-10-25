import tempfile
import unittest
from pathlib import Path

from app.model import FEATURE_NAMES, ModelStore, feature_array
from app.evaluation import FAMILIES


def normal(index: int) -> list[float]:
    return [8.0 + index % 5, 2.0 + index % 3, 0.0, 0.0, 0.0,
            float(index % 2), 0.0, 0.0, 0.0, 1.0, 0.0]


class ModelStoreTest(unittest.TestCase):
    def test_personal_candidate_is_scored_without_activation_and_requires_quality_gate(self):
        def personal(index):
            requests = 8.0 + index % 5
            failed = float(index % 2)
            return [requests, failed, 0, failed, 1, 0, 1 + index % 3, 1, 0, 0, 0,
                    (index % 5 - 2) / 2, (index % 3 - 1) / 3, failed / requests, failed / (failed + 1)]
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            metadata = store.train("personal_candidate_test", [personal(i) for i in range(600)],
                                   [personal(i) for i in range(600, 720)], schema_version=2)
            self.assertEqual(metadata["feature_schema_version"], 2)
            scored = store.score_candidate("personal_candidate_test", [personal(1)], 2)
            self.assertTrue(scored["available"])
            self.assertIsNone(store.active_version)
            with self.assertRaisesRegex(ValueError, "quality evaluation"):
                store.activate("personal_candidate_test")
            self.assertIsNone(store.active_version)
            with self.assertRaisesRegex(ValueError, "schema mismatch"):
                store.score_candidate("personal_candidate_test", [normal(0)], 1)

            # Deliberately indistinguishable vectors with different labels must
            # fail the real serving gate; this is NOT a detection benchmark.
            result = store.evaluate_candidate("personal_candidate_test", [personal(1)] * 11000,
                    [0] * 10000 + [1] * 1000,
                    ["normal"] * 10000 + [family for family in FAMILIES for _ in range(200)],
                    [f"account-{index % 200}/day-{index // 200 % 7}" for index in range(11000)])
            self.assertEqual(result["quality_gate"], "FAIL")
            self.assertEqual(result["status"], "SUCCEEDED")
            with self.assertRaisesRegex(ValueError, "quality evaluation"):
                store.activate("personal_candidate_test")
            self.assertIsNone(store.active_version)
            with self.assertRaisesRegex(ValueError, "already frozen"):
                store.evaluate_candidate("personal_candidate_test", [personal(1)] * 11000,
                        [0] * 10000 + [1] * 1000,
                        ["normal"] * 10000 + [family for family in FAMILIES for _ in range(200)],
                        ["cluster"] * 11000)

    def test_train_activate_score_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            store = ModelStore(path)
            self.assertFalse(store.score([normal(0)])["available"])
            metadata = store.train("candidate_2026", [normal(i) for i in range(600)],
                                   [normal(i) for i in range(600, 720)])
            self.assertEqual(metadata["feature_schema_version"], 1)
            self.assertEqual(tuple(metadata["feature_names"]), FEATURE_NAMES)
            store.activate("candidate_2026")
            result = store.score([normal(1), [500, 40, 1, 20, 10, 5, 1, 1, 1, 1, 1]])
            self.assertTrue(result["available"])
            self.assertEqual(result["model_version"], "candidate_2026")
            self.assertEqual(len(result["results"]), 2)
            self.assertGreaterEqual(result["results"][1]["normal_percentile"],
                                    result["results"][0]["normal_percentile"])
            restored = ModelStore(path)
            self.assertEqual(restored.active_version, "candidate_2026")

    def test_rejects_missing_and_non_finite_features(self):
        with self.assertRaises(ValueError):
            feature_array([[1.0] * 10], 256)
        with self.assertRaises(ValueError):
            feature_array([[float("nan")] * 11], 256)

    def test_identical_normal_windows_do_not_all_look_extreme(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            sample = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0]
            store.train("identical_normal_2026", [sample] * 600, [sample] * 120)
            store.activate("identical_normal_2026")
            result = store.score([sample])["results"][0]
            self.assertLessEqual(result["normal_percentile"], 50.0)
            self.assertEqual(result["level"], "NORMAL_RANGE")


if __name__ == "__main__":
    unittest.main()
