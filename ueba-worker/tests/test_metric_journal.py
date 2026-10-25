"""Small scored-row fixtures test bounded ingestion/dedup, not a large performance benchmark."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.metric_journal import MetricJournal
from app.policy import ScorePolicy, canonical


def rows():
    return [{"frame_id": "episode-frame-0001", "account_id": "account-owned-0001", "window_start": "2026-10-01T00:00:00Z",
             "label": 0, "family": "normal", "cohort": "COLD", "predictions": {"MODEL_ONLY": False, "SIEM_FINAL": False}},
            {"frame_id": "episode-frame-0002", "account_id": "account-owned-0002", "window_start": "2026-10-01T00:00:00Z",
             "label": 1, "family": "endpoint_scan", "cohort": "READY", "predictions": {"MODEL_ONLY": True, "SIEM_FINAL": False}}]


def checksum(values): return hashlib.sha256(canonical(values).encode()).hexdigest()


class MetricJournalTest(unittest.TestCase):
    def test_storage_guard_refuses_batch_before_any_episode_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = MetricJournal(Path(directory) / 'guarded.sqlite', policy=ScorePolicy.strict(),
                                    model_sha256='a' * 64, calibration_sha256='b' * 64,
                                    dataset_sha256='c' * 64, storage_guard=True)
            try:
                values = rows()
                with patch('app.storage_budget.require_headroom', side_effect=ValueError('reserve fixture')):
                    with self.assertRaisesRegex(ValueError, 'reserve fixture'):
                        journal.ingest('guarded-shard-000001', values, checksum(values))
                self.assertEqual(journal.progress()['episodes'], 0)
                self.assertEqual(journal.db.execute('SELECT count(*) FROM shards').fetchone()[0], 0)
            finally:
                journal.close()

    def journal(self, path, dataset="c" * 64):
        return MetricJournal(path, policy=ScorePolicy.strict(), model_sha256="a" * 64,
                             calibration_sha256="b" * 64, dataset_sha256=dataset)

    def test_model_and_final_alerts_are_separate_and_retry_does_not_inflate_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(Path(directory) / "metrics.sqlite")
            try:
                first = journal.ingest("shard-test-0001", rows(), checksum(rows()))
                self.assertFalse(first["replayed"])
                self.assertTrue(journal.ingest("shard-test-0001", rows(), checksum(rows()))["replayed"])
                self.assertEqual(journal.progress()["episodes"], 2)
                self.assertEqual(journal.counter("MODEL_ONLY").tp, 1)
                self.assertEqual(journal.counter("SIEM_FINAL").fn, 1)
                self.assertEqual(len(list(journal.groups("MODEL_ONLY", "cluster"))), 2)
            finally: journal.close()

    def test_duplicate_hour_unknown_body_and_mutated_shard_are_rejected_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = self.journal(Path(directory) / "metrics.sqlite")
            try:
                journal.ingest("shard-test-0001", rows(), checksum(rows()))
                collision = rows()
                collision[0]["frame_id"] = "another-frame-0001"
                collision[0]["window_start"] = "2026-10-01T00:15:00Z"
                with self.assertRaisesRegex(ValueError, "duplicate account/hour"):
                    journal.ingest("shard-test-0002", collision, checksum(collision))
                self.assertEqual(journal.progress()["episodes"], 2)
                poisoned = rows(); poisoned[0]["raw_body"] = "never-store-this"
                with self.assertRaises(ValueError): journal.ingest("shard-test-0003", poisoned, checksum(poisoned))
                changed = rows(); changed[0]["predictions"]["SIEM_FINAL"] = True
                with self.assertRaises(ValueError): journal.ingest("shard-test-0001", changed, checksum(changed))
                self.assertEqual(journal.progress()["episodes"], 2)
            finally: journal.close()

    def test_resuming_requires_same_immutable_identity_and_preserves_the_previous_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.sqlite"
            journal = self.journal(path)
            journal.ingest("shard-test-0001", rows(), checksum(rows()))
            journal.close()
            with self.assertRaises(ValueError): self.journal(path, "d" * 64)
            resumed = self.journal(path)
            try: self.assertEqual(resumed.progress()["episodes"], 2)
            finally: resumed.close()


if __name__ == "__main__": unittest.main()
