"""Synthetic counters and mocked campaigns are not fit/quality evidence."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from app.contract import HYBRID_MODEL_KIND, IF_MODEL_KIND, campaign_runs, recipe_binding
from app.hybrid_incident import HybridIncidentScorer
from app.model_state_dispatch import HYBRID_FORMAT
from app.policy import ScorePolicy, canonical
from app.selection import choose, selection_identity
from app.strict_metrics import FAMILIES
from app.validation import config_document, rank_configurations, sweep, validate_candidate
from test_validation import arrays

FIELDS = ("max_iter", "max_leaf_nodes", "l2_regularization")


class HybridValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grid = sweep(*arrays(), schema=4)
        cls.receipts = [{"fold": run["fold"], "config": asdict(run["config"]), "policies": cls.grid,
                         **recipe_binding(run["config"])} for run in campaign_runs(HYBRID_MODEL_KIND)]

    def test_exact24by5by3_typed_hybrid_recipes_and_original192_policy_grid(self):
        self.assertFalse(hasattr(campaign_runs(HYBRID_MODEL_KIND)[0]["config"], "parameters"))
        ranking = rank_configurations(self.receipts, HYBRID_MODEL_KIND)
        self.assertEqual(ranking["model_kind"], HYBRID_MODEL_KIND)
        self.assertEqual(ranking["recipe_version"], 1)
        self.assertEqual(len(ranking["configurations"]), 24)
        self.assertTrue(all(set(case["configuration"]) == set(FIELDS) for case in ranking["configurations"]))
        self.assertEqual(ranking["quality_gate"], "NOT_RUN")
        self.assertFalse(ranking["holdout_scored"])
        self.assertEqual(len(self.grid), 192)
        self.assertTrue(all(set(case["scopes"]) == {"MODEL_ONLY", "SIEM_FINAL"} for case in self.grid))
        with self.assertRaisesRegex(ValueError, "model kind"):
            rank_configurations(self.receipts, IF_MODEL_KIND)

    def test_partial_recipe_duplicate_fold_seed_and_foreign_policy_fail_closed(self):
        variants = []
        for mutation in (lambda row: row.pop("recipe_sha256"),
                         lambda row: row.update(recipe_sha256="0" * 64),
                         lambda row: row.update(config={**row["config"], "max_iter": True}),
                         lambda row: row.update(fold=True),
                         lambda row: row.update(policies=sweep(*arrays(), schema=3)),
                         lambda row: row.update(policies=[*self.grid, self.grid[0]])):
            changed = list(self.receipts); changed[0] = deepcopy(changed[0]); mutation(changed[0]); variants.append(changed)
        for changed in variants:
            with self.subTest(config=changed[0]["config"]), self.assertRaises(ValueError):
                rank_configurations(changed, HYBRID_MODEL_KIND)
        changed = list(self.receipts); changed[0] = deepcopy(changed[1])
        with self.assertRaisesRegex(ValueError, "fifteen"):
            rank_configurations(changed, HYBRID_MODEL_KIND)
        with self.assertRaisesRegex(ValueError, "360"):
            rank_configurations(self.receipts[:-1], HYBRID_MODEL_KIND)

    def test_one_bad_seed_slice_cannot_hide_behind_global_metrics_or_final_scope(self):
        changed = list(self.receipts); changed[0] = deepcopy(changed[0])
        labels = np.array(([0] * 100 + [1] * 41) * 3, dtype="u1")
        families = np.array(([0] * 100 + [1] + [family for family in range(2, 6) for _ in range(10)]) * 3, dtype="u1")
        cohorts = np.repeat(np.arange(3, dtype="u1"), 141)
        percentiles = np.where((labels == 1) & (families != 1), 100.0, 50.0)
        changed[0]["policies"] = sweep(percentiles, labels, families, cohorts, np.zeros((423, 3), dtype=bool), schema=4)
        scope = changed[0]["policies"][0]["scopes"]["MODEL_ONLY"]
        self.assertGreater(scope["recall"], 0.9)
        self.assertEqual(scope["families"][FAMILIES[0]]["recall"], 0.0)
        ranking = rank_configurations(changed, HYBRID_MODEL_KIND)
        config = {key: changed[0]["config"][key] for key in FIELDS}
        self.assertFalse(next(case["qualified"] for case in ranking["configurations"] if case["configuration"] == config))
        self.assertEqual(sum(case["qualified"] for case in ranking["configurations"]), 23)

    def test_actual_validation_arrays_keep_cohort_correspondence_without_fit_or_holdout(self):
        run = campaign_runs(HYBRID_MODEL_KIND)[0]
        data = arrays(); rows = [{"label": int(label), "family": "normal" if family == 0 else FAMILIES[int(family) - 1],
                                 "cohort": ("READY", "UNSEEN_READY", "COLD")[int(cohort)]}
                                for label, family, cohort in zip(data[1], data[2], data[3])]
        class Dataset:
            sha256 = "a" * 64
            manifest = {"stage": "PILOT", "feature_schema_version": 4}
            def split(self, name):
                assert name == "fold1-validation", "holdout/calibration/training cannot be read"
                return {"records": 315, "normal": 300, "positive": 15, "sha256": "b" * 64}
            def iter_shards(self, name):
                assert name == "fold1-validation", "holdout cannot be read"
                yield {}, rows
        metadata = {"sha256": "c" * 64, "dataset_manifest_sha256": Dataset.sha256, "fold": 1,
                    "feature_schema_version": 4, "score_policy": ScorePolicy.strict(schema=4).wire(),
                    "model_config": asdict(run["config"]), "calibration_sha256": "d" * 64, **recipe_binding(run["config"])}
        class Store:
            def load_candidate(self, version):
                return metadata, {"model": object(), "calibration_by_cohort":
                                  {"READY": np.linspace(0, 1, 100), "COLD": np.linspace(0, 1, 100)}}
        with patch("app.validation.score_cache", return_value=(np.where(data[1] == 1, 2.0, 0.5), {"returned_order": "INPUT_CORRESPONDENCE"})) as scores, \
                patch("app.validation.java_rules", return_value=(data[4], {"rules": "synthetic"})), \
                patch.object(HybridIncidentScorer, "fit", side_effect=AssertionError("validation cannot fit")):
            result = validate_candidate(Dataset(), Store(), "hybrid_fixture", 1, Path("/unused"), Path("/unused"))
            self.assertEqual(result["config"], asdict(run["config"]))
            self.assertEqual(result["model_kind"], HYBRID_MODEL_KIND)
            self.assertEqual(len(result["policies"]), 192)
            self.assertFalse(scores.call_args.kwargs["sort_output"])
            self.assertEqual(result["quality_gate"], "NOT_APPLICABLE")
            self.assertEqual(result["policies"][0]["scopes"]["MODEL_ONLY"]["normal_samples"], 300)
            metadata["recipe_sha256"] = "0" * 64
            scores.reset_mock()
            with self.assertRaisesRegex(ValueError, "recipe/configuration"):
                validate_candidate(Dataset(), Store(), "hybrid_fixture", 1, Path("/unused"), Path("/unused"))
            scores.assert_not_called()

    def test_hybrid_selection_schema_is_checked_before_java_or_fingerprinting(self):
        class Dataset:
            manifest = {"feature_schema_version": 3}
        with patch("app.selection.class_binding", side_effect=AssertionError("not needed")), \
                self.assertRaisesRegex(ValueError, "schema 4"):
            selection_identity(Dataset(), Path("/unused"), HYBRID_MODEL_KIND)


class HybridSelectionTest(unittest.TestCase):
    def test_top_three_recalibrations_are45_distinct_zero_fit_runs_and_freeze_fold3_seed42(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.exercise_choose(Path(temporary))

    def exercise_choose(self, root):
        runs = campaign_runs(HYBRID_MODEL_KIND)
        expected = {"dataset_manifest_sha256": "a" * 64, "model_kind": HYBRID_MODEL_KIND, "recipe_version": 1}
        policy = ScorePolicy.strict(schema=4)
        configurations = [{"configuration": dict(zip(FIELDS, values)), "qualified": True,
                           "best_common_policy": {"policy": policy.wire()}}
                          for values in sorted({tuple(asdict(run["config"])[key] for key in FIELDS) for run in runs})]
        ranking = {"selection_identity": expected, "validation_runs_completed": 360,
                   "model_kind": HYBRID_MODEL_KIND, "recipe_version": 1, "configurations": configurations}
        (root / "hybrid-ranking.json").write_text(canonical(ranking))
        (root / "hybrid-runs").mkdir()
        sources, published, calls = {}, {}, []
        def identity(dataset, run):
            return {"run_id": run["run_id"], "fold": run["fold"], "config": config_document(run["config"]),
                    "dataset_manifest_sha256": dataset.sha256, **recipe_binding(run["config"])}
        class Dataset:
            sha256 = "a" * 64
            manifest = {"stage": "STRICT", "feature_schema_version": 4}
            def __init__(self, directory): pass
            def iter_shards(self, name): raise AssertionError("numeric rows and holdout must remain unopened")
        class Store:
            def __init__(self, directory): self.directory = directory
            def load_candidate(self, version): return published[version], {"model": object(), "digest": published[version]["model_state_sha256"]}
            @staticmethod
            def scoring_identity(model): return {"scorer": "synthetic"}
        for run in runs:
            source = "hybrid_source_" + hashlib.sha256(run["run_id"].encode()).hexdigest()[:24]
            receipt = {**identity(Dataset(root), run), "status": "FITTED_CALIBRATED", "source_model_version": source,
                       "source_model_sha256": "b" * 64}
            sources[source] = receipt
            (root / "hybrid-runs" / (run["run_id"] + ".json")).write_text(canonical(receipt))
        def recalibrate(store, dataset, fold, source, target, actual_policy, directory):
            fit = sources[source]; calls.append((fit["run_id"], fold, source))
            assert fold == fit["fold"]
            state = hashlib.sha256(target.encode()).hexdigest()
            metadata = {"sha256": state, "calibration_sha256": "c" * 64, "model_state_sha256": state,
                        "model_state_format": HYBRID_FORMAT, "model_state_verifier_sha256": "d" * 64,
                        "model_config": fit["config"], "fold": fold, "score_policy": actual_policy.wire(),
                        "source_model_version": source, "source_model_sha256": fit["source_model_sha256"],
                        **recipe_binding(next(run["config"] for run in runs if run["run_id"] == fit["run_id"]))}
            published[target] = metadata
            return {"metadata": metadata, "additional_fit_calls": 0, "calibration_receipts": {"READY": {}, "COLD": {}}}
        with patch("app.selection.ShardedDataset", Dataset), patch("app.selection.ModelStore", Store), \
                patch("app.selection.campaign_prefix", return_value="hybrid"), \
                patch("app.selection.selection_identity", return_value=expected), patch("app.selection.run_identity", side_effect=identity), \
                patch("app.selection.recalibrate", side_effect=recalibrate), \
                patch("app.selection.state_sha256", side_effect=lambda payload: payload["digest"]), \
                patch("app.selection.state_format", return_value=HYBRID_FORMAT), \
                patch("app.selection.verifier_sha256", return_value="d" * 64), \
                patch.object(HybridIncidentScorer, "fit", side_effect=AssertionError("recalibration cannot fit")):
            result = choose(root, root, HYBRID_MODEL_KIND)
            self.assertEqual(result["status"], "SELECTED")
            self.assertEqual(result["completed_recalibrations"], 45)
            self.assertEqual(len(calls), 45)
            self.assertEqual(len({call[0] for call in calls}), 45)
            self.assertEqual(result["model_kind"], HYBRID_MODEL_KIND)
            self.assertEqual(result["model_config"]["random_state"], 42)
            self.assertEqual(published[result["model_version"]]["fold"], 3)
            self.assertEqual(result["model_state_format"], HYBRID_FORMAT)
            self.assertEqual(result["additional_fit_calls_in_recalibration"], 0)
            self.assertEqual(result["quality_gate"], "NOT_RUN")
            self.assertFalse(result["holdout_scored"])
            self.assertEqual(choose(root, root, HYBRID_MODEL_KIND), result)
            self.assertEqual(len(calls), 45)
            selection_path = root / "hybrid-selection.json"
            selection_path.unlink()  # This test owns only its temporary fixture.
            receipt_path = root / "hybrid-top-recalibrations" / (calls[0][0] + ".json")
            receipt = json.loads(receipt_path.read_text()); receipt["model_state_sha256"] = "0" * 64
            receipt_path.write_text(canonical(receipt))
            with self.assertRaisesRegex(ValueError, "state identity"):
                choose(root, root, HYBRID_MODEL_KIND)
            ranking["configurations"][1] = ranking["configurations"][0]
            (root / "hybrid-ranking.json").write_text(canonical(ranking))
            with self.assertRaisesRegex(ValueError, "24 distinct"):
                choose(root, root, HYBRID_MODEL_KIND)


if __name__ == "__main__":
    unittest.main()
