"""Policy tests verify the contract, not achievement of its numeric quality targets."""

import json
import unittest
from app.policy import DETECTION_GRID, ScorePolicy, canonical, strict_document


class ScorePolicyTest(unittest.TestCase):
    def test_immutable_policy_round_trip_and_legacy_thresholds(self):
        policy = ScorePolicy.strict()
        self.assertEqual(ScorePolicy.from_wire(policy.wire()), policy)
        self.assertEqual(len(policy.sha256), 64)
        self.assertEqual(ScorePolicy.legacy().level(99), "UNUSUAL")
        self.assertEqual(ScorePolicy.legacy().level(99.9), "VERY_UNUSUAL")
        self.assertTrue(ScorePolicy.legacy().detected(99))
        self.assertFalse(policy.detected(99.9))

    def test_all_grid_points_have_ordered_serving_levels(self):
        for detection in DETECTION_GRID:
            with self.subTest(detection=detection):
                policy = ScorePolicy.strict(detection)
                self.assertEqual(policy.level(99.9), "UNUSUAL")
                self.assertEqual(policy.level(detection / 1000000), "VERY_UNUSUAL")
                self.assertTrue(policy.detected(100))

    def test_tampering_looser_gates_unknown_fields_and_noncanonical_json_are_rejected(self):
        envelope = ScorePolicy.strict().wire()
        envelope["policy_sha256"] = "a" * 64
        with self.assertRaises(ValueError): ScorePolicy.from_wire(envelope)
        for mutation in (lambda doc: doc["quality"].update(precision_min_ppm=900000),
                         lambda doc: doc.update(untrusted_path="/private/model"),
                         lambda doc: doc["risk"].update(auto_containment=True),
                         lambda doc: doc["detection_percentile_micro"].update(READY=99000000)):
            document = strict_document()
            mutation(document)
            with self.subTest(document=document):
                with self.assertRaises(ValueError): ScorePolicy(canonical(document))
        with self.assertRaises(ValueError): ScorePolicy(json.dumps(strict_document(), indent=2))
        with self.assertRaises(ValueError): ScorePolicy('{"policy_id":"duplicate","policy_id":"another"}')

    def test_context_specific_detection_is_explicit_and_never_relabels_cold_as_ready(self):
        policy = ScorePolicy.strict(DETECTION_GRID[0], DETECTION_GRID[-1])
        self.assertTrue(policy.detected(99.99, "READY"))
        self.assertFalse(policy.detected(99.99, "COLD"))
        with self.assertRaises(ValueError): policy.level(99.99, "fake-baseline")
        with self.assertRaises(ValueError): policy.level(True)
        with self.assertRaises(ValueError): ScorePolicy.legacy(True)


if __name__ == "__main__": unittest.main()
