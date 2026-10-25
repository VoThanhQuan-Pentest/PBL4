"""Typed support-selection counter fixtures are not real fit/quality evidence."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from app.contract import IF_MODEL_KIND, SUPPORT_MODEL_KIND, campaign_runs, recipe_binding
from app.frozen_evaluation import evaluate
from app.selection import choose, validate_all
from app.strict_campaign import campaign_prefix
from app.validation import rank_configurations, sweep
from test_calibration import fixture
from test_validation import arrays


class SupportSelectionTest(unittest.TestCase):
    def receipts(self):
        grid = sweep(*arrays(), schema=4)
        return [{"fold": run["fold"], "config": run["config"].parameters(),
                 "policies": grid, **recipe_binding(run["config"])} for run in campaign_runs(SUPPORT_MODEL_KIND)]

    def test_genuine24by5by3_typed_configurations_are_required(self):
        receipts = self.receipts()
        ranking = rank_configurations(receipts, SUPPORT_MODEL_KIND)
        self.assertEqual(ranking["model_kind"], SUPPORT_MODEL_KIND)
        self.assertEqual(len(ranking["configurations"]), 24)
        self.assertEqual(ranking["quality_gate"], "NOT_RUN")
        self.assertFalse(ranking["holdout_scored"])
        self.assertTrue(all(set(row["configuration"]) == {"neighbor_count", "reference_count", "metric"}
                            for row in ranking["configurations"]))
        with self.assertRaisesRegex(ValueError, "360"):
            rank_configurations(receipts[:-1], SUPPORT_MODEL_KIND)
        with self.assertRaisesRegex(ValueError, "model kind"):
            rank_configurations(receipts, IF_MODEL_KIND)

    def test_partial_identity_recipe_relabelling_and_duplicate_seed_cannot_pass(self):
        receipts = self.receipts()
        for mutate in (lambda row: row.pop("recipe_sha256"),
                       lambda row: row.update(recipe_sha256="0" * 64),
                       lambda row: row.update(config={**row["config"], "metric": "cosine"})):
            changed = list(receipts)
            changed[0] = deepcopy(receipts[0])
            mutate(changed[0])
            with self.assertRaises(ValueError):
                rank_configurations(changed, SUPPORT_MODEL_KIND)
        changed = list(receipts)
        changed[0] = deepcopy(receipts[1])
        with self.assertRaisesRegex(ValueError, "fifteen"):
            rank_configurations(changed, SUPPORT_MODEL_KIND)

    def test_pilot_never_becomes_support_selection_or_holdout_and_if_paths_stay_default(self):
        self.assertEqual(campaign_prefix(IF_MODEL_KIND), "strict")
        self.assertEqual(campaign_prefix(SUPPORT_MODEL_KIND), "support")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            for function in (choose, validate_all, evaluate):
                with self.subTest(function=function.__name__), self.assertRaisesRegex(ValueError, "pilot"):
                    function(root, root, SUPPORT_MODEL_KIND)
            self.assertFalse((root / "support-models").exists())
            self.assertFalse((root / "support-selection.json").exists())
            self.assertFalse((root / "strict-models").exists())


if __name__ == "__main__":
    unittest.main()
