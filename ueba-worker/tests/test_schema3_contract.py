import unittest
import tempfile
from pathlib import Path
import numpy as np

from app.contract import FEATURE_NAMES_V2, FEATURE_NAMES_V3, feature_array
from app.policy import ScorePolicy
from app.model import ModelStore
from app.catalog import validate_rows


class Schema3ContractTest(unittest.TestCase):
    def vector(self):
        return [40, 2, 0, 0, 1, 0, 2, 1, 0, 0, 0, 0, 0, 0.05, 0,
                40, 0, 0, 1, 1 / 39, 0, 0, 0, 0, 2]

    def test_schema3_preserves_schema2_prefix_and_quality_gate(self):
        self.assertEqual(FEATURE_NAMES_V3[:15], FEATURE_NAMES_V2)
        self.assertEqual(feature_array([self.vector()], 256, 3).shape, (1, 25))
        self.assertEqual(ScorePolicy.strict(schema=3).document["quality"], ScorePolicy.strict().document["quality"])
        self.assertEqual(ScorePolicy.strict(schema=3).document["shadow"], ScorePolicy.strict().document["shadow"])
        self.assertNotEqual(ScorePolicy.strict(schema=3).sha256, ScorePolicy.strict().sha256)
        self.assertEqual(ScorePolicy.from_wire(ScorePolicy.strict(schema=3).wire()).document["feature_schema_version"], 3)

    def test_invalid_counts_durations_and_invented_rates_are_refused(self):
        for field, value in ((15, 41), (15, 0), (16, 900), (17, 21), (18, 40), (18, 0.5),
                             (19, 0.8), (20, 21), (22, 1), (23, 1), (24, 3)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                vector = self.vector(); vector[field] = value; feature_array([vector], 256, 3)

    def test_schema3_cannot_silently_enter_old_vector_or_legacy_policy_contract(self):
        with self.assertRaises(ValueError): feature_array([self.vector()], 256, 2)
        with self.assertRaises(ValueError): ScorePolicy.legacy(3)

    def test_numeric_shards_cannot_fabricate_cold_personal_history(self):
        row = {"frame_id": "schema3-owned-frame", "account_id": "schema3-owned-account", "window_start": "2026-04-01T00:00:00Z",
               "label": 0, "family": "normal", "cohort": "COLD", "baseline_established": False,
               "trusted_window_count": 3, "features": self.vector()}
        self.assertEqual(validate_rows([row], 3)["records"], 1)
        with self.assertRaises(ValueError): validate_rows([row], 2)
        row["features"][20] = 1
        with self.assertRaisesRegex(ValueError, "cold-start"): validate_rows([row], 3)

    def test_actual_schema3_fitting_scoring_cannot_skip_frozen_quality_or_shadow(self):
        # Deliberately repeated calibration arrays are only an activation-guard
        # fixture. They are NOT a million-window calibration/quality benchmark.
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory)); policy = ScorePolicy.strict(schema=3)
            rows = [self.vector() for _ in range(600)]
            meta = store.train("schema3_guard_source", rows, rows[:120], schema_version=3, policy=policy)
            self.assertTrue(store.score_candidate("schema3_guard_source", rows[:1], 3)["available"])
            with self.assertRaises(ValueError): store.activate("schema3_guard_source")
            buckets = {name: np.full(1000000, 0.5) for name in ("READY", "COLD")}
            candidate = store.recalibrated_candidate("schema3_guard_source", "schema3_guard_candidate", buckets, policy,
                    expected_source_sha256=meta["sha256"], dataset_sha256="a" * 64,
                    split_sha256={name: "b" * 64 for name in buckets}, calibration_scope="STRICT")
            self.assertEqual(candidate["feature_schema_version"], 3)
            with self.assertRaisesRegex(ValueError, "quality evaluation"): store.activate("schema3_guard_candidate")
            self.assertIsNone(store.active_version); self.assertFalse((store.directory / "active.json").exists())


if __name__ == "__main__": unittest.main()
