"""Bulk assignment + tiny actual immutable Java checkpoint contracts only."""

from collections import Counter
from dataclasses import asdict
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-hybrid-bulk-pilot.py"
SPEC = importlib.util.spec_from_file_location("bulk_training_preparation", PATH)
PREPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREPARE
SPEC.loader.exec_module(PREPARE)


class BulkPreparationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.producer = PREPARE.producer_module()
        cls.generator = cls.producer.load_generator()

    def test_exact81500_assignment_and_each_family_cohort_without_events(self):
        counts, families, normal_actor_count = Counter(), Counter(), 0
        for role, _, namespace, part, batch in PREPARE.jobs(self.producer, 128):
            self.assertLessEqual(len(batch), 128)
            self.assertEqual((part.day, part.days), (15, 1))
            for _, evaluations in batch:
                self.assertEqual(len(evaluations), 1)
                ordinal, positive = evaluations[0]
                self.assertEqual(ordinal, 0)
                counts[(part.cohort, positive is not None)] += 1
                if role == "NORMAL_COMPONENT":
                    self.assertIsNone(positive)
                    self.assertEqual(namespace, PREPARE.NORMAL_NAMESPACE)
                    normal_actor_count += 1
                else:
                    self.assertEqual(namespace, PREPARE.SUPPLEMENT_NAMESPACE)
                if positive is not None:
                    families[(part.cohort, self.producer.FAMILIES[positive])] += 1
        self.assertEqual(normal_actor_count, 50000)
        self.assertEqual(sum(counts.values()), 81500)
        self.assertEqual(counts, Counter({("READY", False): 50050, ("UNSEEN_READY", False): 14300,
            ("COLD", False): 7150, ("READY", True): 7000, ("UNSEEN_READY", True): 2000, ("COLD", True): 1000}))
        for cohort, count in (("READY", 1400), ("UNSEEN_READY", 400), ("COLD", 200)):
            self.assertTrue(all(families[(cohort, family)] == count for family in self.producer.FAMILIES))

    def test_actual_java_normal_prefix_supplement_and_committed_resume_receipt(self):
        _, _, proof = PREPARE.source_data()
        classpath, _ = self.producer.workspace_identity(self.producer.DEFAULT_WORKSPACE, self.producer.DEFAULT_WORKSPACE_SHA256)
        identity = PREPARE.value_sha({"scope": "CONTRACT_FIXTURE_NOT_BULK_POPULATION_OR_QUALITY"})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            PREPARE.write_new(output / "fixture-predeclared.private.json", {"scope": "TINY_ACTUAL_JAVA_CONTRACT",
                "normal_namespace": PREPARE.NORMAL_NAMESPACE, "supplement_namespace": PREPARE.SUPPLEMENT_NAMESPACE,
                "generator_sha256": PREPARE.GENERATOR_SHA, "new_frames_generated_before_declaration": 0, "fit_or_score_calls": 0})
            part = self.producer.Part("fold1-fit", "READY", 15, 1, 2)
            batch = next(self.producer.actor_batches(part, ready_pool=50000, batch_accounts=128))
            writer = self.producer.BatchShards(output, "bulk-normal-ready", "normal-b000000")
            audit = PREPARE.AuditedWriter(writer, proof, True)
            state = self.producer.export_batch(self.generator, PREPARE.NORMAL_NAMESPACE, part, batch, 0, classpath, output, audit, timeout=60)
            self.assertEqual((state["evaluated_rows"], state["raw_frames"]), (2, 98))
            receipt = {"job_id": "normal-b000000", "role": "NORMAL_COMPONENT", "assignment_sha256": PREPARE.value_sha([asdict(part), batch]),
                "source_identity_sha256": identity, "shards": writer.descriptors, **state}
            PREPARE.write_new(output / "receipt.private.json", receipt)
            verified = PREPARE.check_committed(self.producer, output, "normal-b000000", "NORMAL_COMPONENT", part, batch, identity, proof)
            self.assertEqual(verified, receipt)
            with self.assertRaises(ValueError):
                PREPARE.check_committed(self.producer, output, "normal-b000001", "NORMAL_COMPONENT", part, batch, identity, proof)
            for cohort, job in (("READY", "ready-b000000"), ("UNSEEN_READY", "unseen-b000000"), ("COLD", "cold-b000000")):
                part = self.producer.Part("incident-training", cohort, 15, 1, 1, 5)
                batch = [(actor, [(0, None if actor == 0 else actor - 1)]) for actor in range(6)]
                writer = self.producer.BatchShards(output, "bulk-supplement", job)
                audit = PREPARE.AuditedWriter(writer, proof, False)
                state = self.producer.export_batch(self.generator, PREPARE.SUPPLEMENT_NAMESPACE, part, batch, 0, classpath, output, audit, timeout=60)
                self.assertEqual(state["evaluated_rows"], 6)
                self.assertEqual(state["raw_frames"], 24 if cohort == "COLD" else 294)
                self.assertEqual(writer.descriptors[0]["normal"], 1)
                self.assertEqual(writer.descriptors[0]["positive"], 5)


if __name__ == "__main__":
    unittest.main()
