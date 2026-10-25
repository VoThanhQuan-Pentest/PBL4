"""Actual small schema-3 forest/cache/recipe fixtures, not accuracy evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import IsolationForest

from app.calibration import numeric_cache, recalibrate
from app.contract import TrainingConfig
from app.frozen_evaluation import actual_scores, model_binding
from app.model import ModelStore
from app.operator_catalog import OperatorCatalog, Recipe, train_recipe
from app.policy import ScorePolicy, canonical
from app.strict_campaign import fit_one
from app.validation import sweep
from test_calibration import fixture, fitted
from test_validation import arrays


class Schema3CalibrationTest(unittest.TestCase):
    def test_actual_25_column_cache_calibrates_without_refitting_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root / "data"; data.mkdir()
            dataset = fixture(data, schema=3); store = ModelStore(root / "models")
            source = fitted(store, dataset); policy = ScorePolicy.strict(schema=3)
            path = numeric_cache(dataset, "fold1-calibration-ready", root / "cache")
            tensor = np.memmap(path, dtype="<f8", mode="r", shape=(300, 25))
            expected = [row["features"] for _, rows in dataset.iter_shards("fold1-calibration-ready") for row in rows]
            self.assertTrue(np.array_equal(tensor, expected)); tensor._mmap.close()
            with patch.object(IsolationForest, "fit", side_effect=AssertionError("no calibration refit")):
                first = recalibrate(store, dataset, 1, "source_fitted_fixture", "schema3_recalibrated_a", policy, root / "cache")
                second = recalibrate(store, dataset, 1, "source_fitted_fixture", "schema3_recalibrated_b", policy, root / "cache")
            metadata, payload = store.load_candidate("schema3_recalibrated_a")
            self.assertEqual(metadata["feature_schema_version"], 3)
            self.assertEqual(metadata["source_model_sha256"], source["sha256"])
            self.assertEqual(first["additional_fit_calls"], 0)
            self.assertEqual(second["calibration_receipts"]["READY"]["reused_shards"], 2)
            self.assertEqual(metadata["calibration_scope"], "PILOT_ONLY")
            self.assertEqual(model_binding(metadata, policy)["feature_schema_version"], 3)
            rows = next(dataset.iter_shards("fold1-calibration-ready"))[1][:3]
            served = store.score_candidate("schema3_recalibrated_a", [row["features"] for row in rows], 3, ["READY"] * 3)
            self.assertEqual(actual_scores(payload, policy, rows), served["results"])
            with self.assertRaises(ValueError): store.activate("schema3_recalibrated_a")
            with self.assertRaises(ValueError):
                recalibrate(store, dataset, 1, "source_fitted_fixture", "schema3_wrong_policy", ScorePolicy.strict(), root / "cache")
            with path.open("r+b") as stream: stream.write(np.array([42.0], dtype="<f8").tobytes())
            with self.assertRaisesRegex(ValueError, "tensor/source checkpoint changed"):
                numeric_cache(dataset, "fold1-calibration-ready", root / "cache")
            self.assertIsNone(store.active_version)

    def test_registered_schema_is_used_by_real_recipe_and_pilot_campaign_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalog = root / "catalog"; catalog.mkdir()
            data = catalog / "calibration-owned-fixture"; data.mkdir(); dataset = fixture(data, schema=3)
            policy = ScorePolicy.strict(schema=3)
            config = TrainingConfig(n_estimators=200, max_samples=128, max_features=1.0, random_state=42)
            entry = {"recipe_id": "schema3-preview-recipe", "dataset_id": dataset.manifest["dataset_id"],
                     "mode": "PILOT", "fold": 1, "manifest_sha256": dataset.sha256,
                     "config": {key: config.parameters()[key] for key in
                                ("n_estimators", "max_samples", "max_features", "random_state")}, "score_policy": policy.wire()}
            (catalog / "catalog.json").write_text(canonical({"entries": [], "strict_entries": [entry]}))
            recipe = OperatorCatalog(catalog).recipe(entry["recipe_id"])
            store = ModelStore(root / "models")
            actual = train_recipe(store, recipe, "schema3_recipe_candidate", root / "cache")
            self.assertEqual(actual["feature_schema_version"], 3)
            self.assertEqual(actual["training_windows"], 600)
            self.assertEqual(actual["calibration_cohort_windows"], {"READY": 300, "COLD": 300})
            with self.assertRaises(ValueError): store.activate("schema3_recipe_candidate")
            entry["score_policy"] = ScorePolicy.strict().wire()
            (catalog / "catalog.json").write_text(canonical({"entries": [], "strict_entries": [entry]}))
            with self.assertRaisesRegex(ValueError, "schema"): OperatorCatalog(catalog).recipe(entry["recipe_id"])
            wrong = Recipe(recipe.recipe_id, dataset, config, ScorePolicy.strict(), 1, "PILOT")
            with self.assertRaisesRegex(ValueError, "schema"): train_recipe(store, wrong, "schema3_wrong_recipe", root / "cache")
            receipt = fit_one(data, "trees-200-samples-128-features-100-seed-42-fold-1")
            self.assertEqual(receipt["status"], "FITTED_CALIBRATED")
            self.assertEqual(ScorePolicy.from_wire(receipt["score_policy"]).document["feature_schema_version"], 3)
            self.assertEqual(receipt["calibration_scope"], "PILOT_ONLY")
            self.assertEqual(receipt["quality_gate"], "NOT_RUN")

    def test_validation_grid_preserves_schema_and_all_unchanged_thresholds(self):
        legacy = sweep(*arrays())
        contextual = sweep(*arrays(), schema=3)
        self.assertEqual(len(contextual), 192)
        for old, new in zip(legacy, contextual):
            a, b = ScorePolicy.from_wire(old["policy"]), ScorePolicy.from_wire(new["policy"])
            self.assertEqual(b.document["feature_schema_version"], 3)
            self.assertEqual(a.document["quality"], b.document["quality"])
            self.assertEqual(a.document["shadow"], b.document["shadow"])
            self.assertEqual(old["scopes"], new["scopes"])
            self.assertEqual(new["quality_gate"], "NOT_APPLICABLE")


if __name__ == "__main__": unittest.main()
