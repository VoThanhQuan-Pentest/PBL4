"""Actual small scored-row journals verify proof integrity, never high-accuracy gates."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from app.metric_journal import MetricJournal
from app.policy import ScorePolicy, canonical
from app.quality_proof import audit_actual_rows, cluster_binding, math_binding, verify_confidence, verify_quality
from app.strict_metrics import confidence_for
from test_metric_journal import rows, checksum


class QualityProofTest(unittest.TestCase):
    def journal(self, root):
        return MetricJournal(root / "actual_scoring_model.metrics.sqlite", policy=ScorePolicy.strict(),
                             model_sha256="a" * 64, calibration_sha256="b" * 64, dataset_sha256="c" * 64)

    def test_aggregate_and_cluster_counts_are_derived_from_actual_episode_predictions(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(Path(directory))
            try:
                journal.ingest("scored-shard-0001", rows(), checksum(rows()), source_sha256="d" * 64)
                self.assertEqual(audit_actual_rows(journal.db), 2)
                self.assertTrue(journal.completed_source_shard("scored-shard-0001", "d" * 64, 2))
                with self.assertRaises(ValueError): journal.completed_source_shard("scored-shard-0001", "e" * 64, 2)
                journal.db.execute("UPDATE counts SET tp=tp+1 WHERE scope='MODEL_ONLY' AND kind='global'"); journal.db.commit()
                with self.assertRaisesRegex(ValueError, "actual scored episodes"): audit_actual_rows(journal.db)
            finally: journal.close()

    def test_changed_cached_cluster_is_not_a_valid_confidence_source(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(Path(directory))
            try:
                journal.ingest("scored-shard-0001", rows(), checksum(rows()))
                journal.db.execute("UPDATE counts SET fp=1 WHERE scope='MODEL_ONLY' AND kind='cluster'"); journal.db.commit()
                with self.assertRaisesRegex(ValueError, "cluster counters"): audit_actual_rows(journal.db)
            finally: journal.close()

    def test_exact_and_conservative_intervals_cannot_be_replaced_by_a_pass_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(Path(directory))
            try:
                journal.ingest("scored-shard-0001", rows(), checksum(rows()))
                counts = journal.counter("MODEL_ONLY"); groups = list(journal.groups("MODEL_ONLY", "cluster"))
                confidence = confidence_for(counts, journal.policy, [[row.tp, row.fn, row.fp, row.tn] for _, row in groups])
                cluster = cluster_binding(journal.db, "MODEL_ONLY")
                confidence["cluster_counter_sha256"] = cluster["cluster_counter_sha256"]
                verify_confidence(counts, journal.policy, confidence, cluster)
                confidence["conservative"]["precision"]["lower"] = 1
                with self.assertRaisesRegex(ValueError, "altered"): verify_confidence(counts, journal.policy, confidence, cluster)
            finally: journal.close()

    def test_forged_pass_file_has_no_authority_without_complete_code_and_scored_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); journal = self.journal(root)
            journal.ingest("scored-shard-0001", rows(), checksum(rows())); journal.close()
            binding = {"model_version": "actual_scoring_model", "model_sha256": "a" * 64, "calibration_sha256": "b" * 64,
                       "dataset_sha256": "c" * 64, "feature_schema_version": 2, "policy_sha256": ScorePolicy.strict().sha256}
            evidence = {**binding, "status": "SUCCEEDED", "quality_gate": "PASS", "data_provenance": "DEMO_ONLY",
                        "evaluation_scope": "FROZEN_HOLDOUT", "quality_math_binding": math_binding(),
                        "scored_journal_file": "actual_scoring_model.metrics.sqlite",
                        "scored_journal_sha256": hashlib.sha256((root / "actual_scoring_model.metrics.sqlite").read_bytes()).hexdigest(),
                        "scopes": {scope: {"quality_gate": "PASS", "confidence": {}} for scope in ("MODEL_ONLY", "SIEM_FINAL")}}
            (root / "actual_scoring_model.evaluation.json").write_text(canonical(evidence))
            with self.assertRaisesRegex(ValueError, "actual account/day clusters"):
                verify_quality(root, "actual_scoring_model", ScorePolicy.strict(), binding)


if __name__ == "__main__": unittest.main()
