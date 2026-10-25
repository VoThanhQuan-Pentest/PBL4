"""Frozen source calibration layout and tiny actual Java extraction contract."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-expanded-calibration.py"
SPEC = importlib.util.spec_from_file_location("expanded_calibration_preparation", PATH)
PREPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREPARE
SPEC.loader.exec_module(PREPARE)


class ExpandedPreparationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.producer = PREPARE.producer_module()
        cls.generator = cls.producer.load_generator()

    def test_predeclared_normal_only_layout_and_same_ready_namespace(self):
        ready, cold = PREPARE.calibration_parts(self.producer)
        self.assertEqual(self.producer.actor_layout(ready, 2000)[0], 1667)
        self.assertEqual(self.producer.actor_layout(cold, 2000), (3000, 20, 0))
        fit = self.producer.Part("fold1-fit", "READY", 15, 1, 2000)
        self.assertEqual(self.producer.namespace(PREPARE.NAMESPACE, fit), self.producer.namespace(PREPARE.NAMESPACE, ready))
        for part in (ready, cold):
            batches = list(self.producer.actor_batches(part, ready_pool=2000, batch_accounts=128))
            self.assertTrue(all(len(batch) <= 128 for batch in batches))
            self.assertEqual(sum(len(values) for batch in batches for _, values in batch), 60000)
            self.assertTrue(all(index is None for batch in batches for _, values in batch for _, index in values))
            self.assertEqual((part.day, part.days, part.positive), (33, 3, 0))

    def test_actual_java_prefix_matches_existing_calibration_without_modification(self):
        _, _, proof = PREPARE.protected_sources()
        classpath, _ = self.producer.workspace_identity(self.producer.DEFAULT_WORKSPACE, self.producer.DEFAULT_WORKSPACE_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "shards").mkdir(mode=0o700)
            PREPARE.write_new(output / "fixture-predeclared.private.json", {
                "scope": "TINY_ACTUAL_JAVA_CONTRACT_NOT_EXPANDED_POPULATION_OR_MODEL_QUALITY",
                "dataset_namespace": PREPARE.NAMESPACE, "normal_rows_per_cohort": 8,
                "new_frames_generated_before_declaration": 0, "fit_or_score_calls": 0,
                "generator_sha256": PREPARE.GENERATOR_SHA, "workspace_sha256": self.producer.DEFAULT_WORKSPACE_SHA256})
            for cohort in ("READY", "COLD"):
                part = self.producer.Part("fold1-calibration-" + cohort.lower(), cohort, 33, 3, 8)
                batch = next(self.producer.actor_batches(part, ready_pool=2000, batch_accounts=128))
                writer = PREPARE.CalibrationShards(output, cohort, proof)
                state = self.producer.export_batch(self.generator, PREPARE.NAMESPACE, part, batch, 0,
                                                  classpath, output, writer, timeout=60)
                self.assertEqual((state["evaluated_rows"], len(writer.frames), writer.old_overlap), (8, 8, 8))
                self.assertEqual(state["raw_frames"], 56 if cohort == "READY" else 11)
                self.assertEqual(len(writer.accounts), 1)
                if cohort == "COLD":
                    self.assertEqual((writer.history_min, writer.history_max), (3, 8))
                else:
                    # Trusted history follows the frozen server eligibility
                    # policy, not the number of emitted normal-labeled frames.
                    # Every prefix row was also checked byte-for-value against
                    # the original calibration by CalibrationShards.append.
                    self.assertEqual((writer.history_min, writer.history_max), (48, 53))


if __name__ == "__main__":
    unittest.main()
