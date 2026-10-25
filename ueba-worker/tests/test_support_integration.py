"""Small real worker contracts; no fixture qualifies a model or counts as a campaign."""

from collections import Counter
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np

from app.calibration import recalibrate
from app.catalog import ShardedDataset
from app.contract import (IF_MODEL_KIND, SUPPORT_MODEL_KIND, SupportTrainingConfig, campaign_runs,
                          model_recipe_binding, recipe_binding)
from app.model import ModelStore
from app.normal_support import NormalSupportScorer
from app.operator_catalog import OperatorCatalog, train_recipe
from app.policy import ScorePolicy, canonical
from app.semantic_model import FORMAT, SUPPORT_FORMAT, state_format, state_sha256
from app.strict_campaign import approved_run, fit_one, write
from test_model import normal
from test_schema4_contract import vector, write_catalogue


CONFIG = SupportTrainingConfig(4, 128, "euclidean", 42)


def dataset_fixture(root):
    write_catalogue(root, populations=(("fold1-fit", 1100, False),
                                     ("fold1-calibration-ready", 300, False),
                                     ("fold1-calibration-cold", 300, True)))
    return ShardedDataset(root)


class SupportIntegrationTest(unittest.TestCase):
    def test_predeclared_support_grid_is_distinct_and_if_defaults_unchanged(self):
        old = campaign_runs(); runs = campaign_runs(SUPPORT_MODEL_KIND)
        self.assertEqual(len(old), 360)
        self.assertEqual(len(runs), 360)
        self.assertEqual(len({run["run_id"] for run in runs}), 360)
        self.assertFalse({run["run_id"] for run in runs} & {run["run_id"] for run in old})
        counts = Counter((run["config"].neighbor_count, run["config"].reference_count, run["config"].metric) for run in runs)
        self.assertEqual(len(counts), 24); self.assertEqual(set(counts.values()), {15})
        self.assertEqual(old[0]["run_id"], "trees-200-samples-128-features-75-seed-11-fold-1")
        with self.assertRaises(ValueError): approved_run(runs[0]["run_id"])
        self.assertEqual(approved_run(runs[0]["run_id"], SUPPORT_MODEL_KIND), runs[0])
        for options in ({"neighbor_count": True}, {"neighbor_count": 2}, {"reference_count": 50000},
                        {"metric": "untrusted"}, {"random_state": True}):
            with self.assertRaises(ValueError): SupportTrainingConfig(**options)

    def test_recipe_identity_is_canonical_and_never_partially_defaults(self):
        binding = recipe_binding(CONFIG)
        self.assertEqual(model_recipe_binding(binding), binding)
        self.assertEqual(model_recipe_binding({})["model_kind"], IF_MODEL_KIND)
        identity = {"model_kind": SUPPORT_MODEL_KIND, "recipe_version": 1, "config": CONFIG.parameters()}
        self.assertEqual(binding["recipe_sha256"], hashlib.sha256(canonical(identity).encode()).hexdigest())
        for value in ({"model_kind": SUPPORT_MODEL_KIND}, binding | {"recipe_version": True},
                      binding | {"model_kind": "caller_model"}, binding | {"recipe_sha256": "invalid"}):
            with self.assertRaises(ValueError): model_recipe_binding(value)

    def test_support_candidate_persists_numeric_state_and_preserves_legacy_active(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            store.train("legacy_active_fixture", [normal(index) for index in range(600)], [normal(index) for index in range(120)])
            store.activate("legacy_active_fixture")
            samples = [vector(index) for index in range(1100)]
            metadata = store.train("support_candidate_fixture", samples, samples[:120], schema_version=4,
                                   config=CONFIG, policy=ScorePolicy.strict(schema=4))
            self.assertEqual(metadata["training_windows"], 1100)
            self.assertEqual({key: metadata[key] for key in recipe_binding(CONFIG)}, recipe_binding(CONFIG))
            stored = joblib.load(Path(directory) / "support_candidate_fixture.joblib")
            self.assertIs(type(stored["model"]), dict)
            with patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("load cannot refit")):
                _, payload = store.load_candidate("support_candidate_fixture")
            self.assertIs(type(payload["model"]), NormalSupportScorer)
            self.assertEqual(payload["model"].to_state()["fit_count"], 1100)
            scored = store.score_candidate("support_candidate_fixture", samples[:2], 4)
            self.assertEqual(set(scored["results"][0]), {"raw_anomaly_score", "normal_percentile", "level", "scoring_cohort", "model_scope"})
            self.assertEqual(store.active_version, "legacy_active_fixture")
            self.assertEqual(ModelStore(Path(directory)).active_version, "legacy_active_fixture")
            with self.assertRaisesRegex(ValueError, "immutable dataset"):
                store.activate("support_candidate_fixture")
            path = Path(directory) / "support_candidate_fixture.json"
            for changed in (metadata | {"recipe_version": True}, metadata | {"recipe_sha256": "f" * 64},
                            metadata | {"scoring_implementation": {}}, metadata | {"training_windows": 50000}):
                write(path, changed)
                with self.assertRaises(ValueError): store.load_candidate("support_candidate_fixture")
            write(path, metadata)

    def test_exact_support_state_hash_includes_configuration_and_calibration(self):
        samples = [vector(index) for index in range(1100)]
        def payload(config):
            model = NormalSupportScorer(**config.parameters()).fit(samples)
            return {"model": model, "calibration_scores": np.sort(-model.score_samples(samples[:120]))}
        first = payload(CONFIG)
        self.assertEqual(state_format(first), SUPPORT_FORMAT)
        self.assertEqual(state_format(IF_MODEL_KIND), FORMAT)
        self.assertEqual(state_sha256(first), state_sha256(payload(CONFIG)))
        self.assertNotEqual(state_sha256(first), state_sha256(payload(SupportTrainingConfig(4, 128, "euclidean", 11))))
        changed = copy.deepcopy(first); changed["calibration_scores"][0] += 0.01
        self.assertNotEqual(state_sha256(first), state_sha256(changed))
        with self.assertRaises(ValueError): state_sha256(first | {"unknown": 1})

    def test_recalibration_reuses_support_and_implementation_bound_cache_without_fits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root / "data"; data.mkdir(); dataset = dataset_fixture(data)
            store = ModelStore(root / "models")
            samples = [row["features"] for _, rows in dataset.iter_shards("fold1-fit") for row in rows]
            source = store.train("support_source_fixture", samples, samples[:120], schema_version=4,
                                 config=CONFIG, policy=ScorePolicy.strict(schema=4))
            source.update(dataset_manifest_sha256=dataset.sha256, fit_split_sha256=dataset.split("fold1-fit")["sha256"])
            write(store.directory / "support_source_fixture.json", source)
            with patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("calibration cannot refit")):
                first = recalibrate(store, dataset, 1, "support_source_fixture", "support_calibrated_fixture_a",
                                    ScorePolicy.strict(schema=4), root / "cache")
                second = recalibrate(store, dataset, 1, "support_source_fixture", "support_calibrated_fixture_b",
                                     ScorePolicy.strict(99_999_000, schema=4), root / "cache")
            self.assertEqual(first["additional_fit_calls"], 0)
            self.assertEqual(first["metadata"]["calibration_scope"], "PILOT_ONLY")
            for cohort in ("READY", "COLD"):
                self.assertIn("scoring_implementation", first["calibration_receipts"][cohort])
                self.assertEqual(second["calibration_receipts"][cohort]["computed_shards"], 0)
                self.assertEqual(second["calibration_receipts"][cohort]["reused_shards"], 1)
            with self.assertRaisesRegex(ValueError, "independent cohort calibration"):
                store.activate("support_calibrated_fixture_a")
            self.assertIsNone(store.active_version)

    def test_id_only_operator_preview_binds_recipe_and_cannot_activate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root / "schema4-owned-fixture"; data.mkdir(); dataset = dataset_fixture(data)
            entry = {"recipe_id": "support-preview-fixture", "dataset_id": "schema4-owned-fixture", "mode": "PILOT", "fold": 1,
                     "manifest_sha256": dataset.sha256, "config": CONFIG.parameters(), "score_policy": ScorePolicy.strict(schema=4).wire(),
                     **recipe_binding(CONFIG)}
            write(root / "catalog.json", {"strict_entries": [entry]})
            recipe = OperatorCatalog(root).recipe(entry["recipe_id"])
            self.assertEqual(recipe.model_kind, SUPPORT_MODEL_KIND); self.assertEqual(recipe.model_state_format, SUPPORT_FORMAT)
            store = ModelStore(root / "models")
            metadata = train_recipe(store, recipe, "operator_support_preview_fixture", root / "cache")
            self.assertEqual(metadata["model_state_format"], SUPPORT_FORMAT)
            self.assertEqual(metadata["calibration_scope"], "PILOT_ONLY")
            self.assertNotIn("quality_gate", metadata); self.assertIsNone(store.active_version)
            for changed in (entry | {"recipe_sha256": "f" * 64}, entry | {"recipe_version": True},
                            {key: value for key, value in entry.items() if key != "model_kind"}):
                write(root / "catalog.json", {"strict_entries": [changed]})
                with self.assertRaises(ValueError): OperatorCatalog(root).recipe(entry["recipe_id"])

    def test_explicit_support_campaign_recovers_without_replacing_if_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset_fixture(root)
            run = next(run for run in campaign_runs(SUPPORT_MODEL_KIND) if run["fold"] == 1 and run["config"] == CONFIG)
            first = fit_one(root, run["run_id"], SUPPORT_MODEL_KIND)
            with patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("completed fit cannot repeat")):
                recovered = fit_one(root, run["run_id"], SUPPORT_MODEL_KIND)
            self.assertEqual(first["model_sha256"], recovered["model_sha256"])
            self.assertTrue(recovered["fit_recovered_without_refit"])
            self.assertEqual(first["quality_gate"], "NOT_RUN")
            self.assertTrue((root / "support-runs").is_dir()); self.assertFalse((root / "strict-runs").exists())
            self.assertFalse((root / "support-models/active.json").exists())


if __name__ == "__main__": unittest.main()
