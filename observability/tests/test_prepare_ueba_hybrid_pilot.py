"""Actual immutable Java extraction contract test; not training/model quality."""

from collections import Counter
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-hybrid-pilot.py"
SPEC = importlib.util.spec_from_file_location("hybrid_training_preparation", PATH)
PREPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREPARE
SPEC.loader.exec_module(PREPARE)


class HybridPilotPreparationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.producer = PREPARE.load_frozen_producer()
        cls.generator = cls.producer.load_generator()

    def test_assignment_conserves_fixed_population_without_generating_any_events(self):
        totals, families = Counter(), Counter()
        for cohort, normal, positive in PREPARE.NEW_POPULATIONS:
            for part, batch in PREPARE.assignments(self.producer, cohort, normal, positive, 32):
                self.assertEqual((part.day, part.days, part.split), (15, 1, "incident-training"))
                self.assertLessEqual(len(batch), 32)
                for actor, evaluations in batch:
                    self.assertEqual(len(evaluations), 1)
                    ordinal, cause = evaluations[0]
                    self.assertEqual(ordinal, 0)
                    totals[(cohort, cause is not None)] += 1
                    if cause is not None:
                        families[(cohort, self.producer.FAMILIES[cause])] += 1
        self.assertEqual(totals, Counter({("READY", False): 100, ("READY", True): 700,
                                         ("UNSEEN_READY", False): 600, ("UNSEEN_READY", True): 200,
                                         ("COLD", False): 300, ("COLD", True): 100}))
        for cohort, count in (("READY", 140), ("UNSEEN_READY", 40), ("COLD", 20)):
            self.assertTrue(all(families[(cohort, family)] == count for family in self.producer.FAMILIES))

    def test_actual_frozen_java_conserves_each_family_and_real_baseline(self):
        classpath, package = self.producer.workspace_identity(self.producer.DEFAULT_WORKSPACE, self.producer.DEFAULT_WORKSPACE_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "shards").mkdir(mode=0o700)
            PREPARE.write_new(output / "fixture-predeclared.private.json", {
                "scope": "CONTRACT_FIXTURE_NOT_PILOT_TRAINING_OR_MODEL_QUALITY", "seed": 42,
                "generator_sha256": PREPARE.GENERATOR_SHA, "java_snapshot_sha256": self.producer.DEFAULT_WORKSPACE_SHA256,
                "cohorts": ["READY", "UNSEEN_READY", "COLD"], "normal_per_cohort": 1,
                "positive_per_family_per_cohort": 1, "events_generated_before_declaration": 0, "fit_or_score_calls": 0})
            writer = PREPARE.NewTrainingShards(output)
            for cohort in ("READY", "UNSEEN_READY", "COLD"):
                part, batch = next(PREPARE.assignments(self.producer, cohort, 1, 5, 32))
                state = self.producer.export_batch(self.generator, "hybrid-contract-fixture", part, batch, 0,
                                                  classpath, output, writer, timeout=60)
                self.assertEqual(state["evaluated_rows"], 6)
                self.assertEqual(state["raw_frames"], 24 if cohort == "COLD" else 294)
            rows = writer.all_rows
            self.assertEqual(len(rows), 18)
            self.assertEqual(Counter(row["family"] for row in rows), Counter({"normal": 3, **{family: 3 for family in self.producer.FAMILIES}}))
            self.assertEqual(len({row["frame_id"] for row in rows}), 18)
            for row in rows:
                self.assertEqual(row["baseline_established"], row["cohort"] != "COLD")
                self.assertEqual(len(row["features"]), len(PREPARE.FEATURE_NAMES_V4))
                self.assertEqual(row["label"], int(row["family"] != "normal"))
                self.assertTrue(row["window_start"].startswith("2026-04-15T"))
            self.assertIn("ops/UebaFeatureExport.class", package["classes"])

    def test_existing_normal_only_catalog_part_cannot_be_relaxed(self):
        with self.assertRaises(ValueError):
            self.producer.Part("fold1-fit", "READY", 15, 1, 100, 100)


if __name__ == "__main__":
    unittest.main()
