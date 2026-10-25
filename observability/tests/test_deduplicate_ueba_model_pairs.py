"""Isolated transaction tests for the fixed r2 model-pair storage helper."""
from __future__ import annotations

from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/deduplicate-ueba-model-pairs.py"
SPEC = importlib.util.spec_from_file_location("deduplicate_ueba_model_pairs_tested", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class ModelPairTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ueba-model-pair-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.models = self.root / "models"
        self.models.mkdir(mode=0o700)
        os.chmod(self.models, 0o700)
        self.session = self.root / "session"
        self.session.mkdir(mode=0o700)
        os.chmod(self.session, 0o700)
        self.cal_name = "hybrid_cal_aaaaaaaaaaaaaaaaaaaaaaaa.joblib"
        self.top_name = "hybrid_top_bbbbbbbbbbbbbbbbbbbbbbbb.joblib"
        self.payload = (b"same fitted model bytes\x00" * 1000)
        self.expected_sha = hashlib.sha256(self.payload).hexdigest()
        (self.models / self.cal_name).write_bytes(self.payload)
        (self.models / self.top_name).write_bytes(self.payload)
        os.chmod(self.models / self.cal_name, 0o600)
        os.chmod(self.models / self.top_name, 0o600)
        self.pair_id = "c" * 24
        self.pair = self._pair()
        self.identity = TOOL._record_identity("a" * 64, "b" * 64, self.pair)
        self.patchers = [
            patch.object(TOOL, "MODELS", self.models),
            patch.object(TOOL, "_verify_pair_frozen_inputs"),
            patch.object(TOOL, "_authority_snapshot", return_value={"dataset_sha256": "d" * 64}),
            patch.object(
                TOOL.shutil, "disk_usage",
                return_value=shutil._ntuple_diskusage(100_000_000_000, 10_000_000_000, 90_000_000_000),
            ),
        ]
        for item in self.patchers:
            item.start()
            self.addCleanup(item.stop)

    def _pair(self, target_payload=None):
        cal = self.models / self.cal_name
        top = self.models / self.top_name
        digest = hashlib.sha256(self.payload if target_payload is None else target_payload).hexdigest()
        return {
            "pair_id": self.pair_id,
            "run_id": "hybrid-v1-iterations-100-leaves-31-l2-0-seed-23-fold-1",
            "sha256": self.expected_sha,
            "bytes": len(self.payload),
            "cal_path": self.cal_name,
            "top_path": self.top_name,
            "cal_signature": TOOL._file_signature(cal.stat()),
            "top_signature": TOOL._file_signature(top.stat()),
            "temporary_name": ".storage-dedup-" + self.pair_id + ".pending",
            "allocated_bytes_reclaimable": top.stat().st_blocks * 512,
        }

    def test_apply_keeps_both_names_and_exact_bytes(self):
        result = TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        cal = self.models / self.cal_name
        top = self.models / self.top_name
        self.assertEqual(result["state"], "VERIFIED_DONE")
        self.assertEqual(cal.read_bytes(), self.payload)
        self.assertEqual(top.read_bytes(), self.payload)
        self.assertEqual((cal.stat().st_dev, cal.stat().st_ino), (top.stat().st_dev, top.stat().st_ino))
        self.assertEqual(cal.stat().st_nlink, 2)
        self.assertTrue((self.session / "journal" / (self.pair_id + ".done.private.json")).exists())

    def test_resume_after_link_creation_before_journal_update(self):
        intent_path, _, _, _ = TOOL._pair_records(self.session, self.pair_id)
        TOOL._write_journal(intent_path, self.identity, "INTENT_DURABLE", {
            "temporary_name": self.pair["temporary_name"],
            "canonical_signature": self.pair["cal_signature"],
            "target_signature": self.pair["top_signature"],
        })
        os.link(self.models / self.cal_name, self.models / self.pair["temporary_name"])
        result = TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertEqual(result["state"], "VERIFIED_DONE")
        self.assertEqual((self.models / self.cal_name).stat().st_ino, (self.models / self.top_name).stat().st_ino)
        self.assertFalse((self.models / self.pair["temporary_name"]).exists())

    def test_resume_after_durable_intent_before_link_creation(self):
        intent_path, _, _, _ = TOOL._pair_records(self.session, self.pair_id)
        TOOL._write_journal(intent_path, self.identity, "INTENT_DURABLE", {
            "temporary_name": self.pair["temporary_name"],
            "canonical_signature": self.pair["cal_signature"],
            "target_signature": self.pair["top_signature"],
        })
        result = TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertEqual(result["state"], "VERIFIED_DONE")
        self.assertEqual((self.models / self.cal_name).stat().st_ino,
                         (self.models / self.top_name).stat().st_ino)

    def test_resume_after_replace_before_done_journal(self):
        intent_path, _, _, _ = TOOL._pair_records(self.session, self.pair_id)
        TOOL._write_journal(intent_path, self.identity, "INTENT_DURABLE", {
            "temporary_name": self.pair["temporary_name"],
            "canonical_signature": self.pair["cal_signature"],
            "target_signature": self.pair["top_signature"],
        })
        os.link(self.models / self.cal_name, self.models / self.pair["temporary_name"])
        os.replace(self.models / self.pair["temporary_name"], self.models / self.top_name)
        result = TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertEqual(result["state"], "VERIFIED_DONE")
        self.assertEqual((self.models / self.cal_name).stat().st_ino, (self.models / self.top_name).stat().st_ino)

    def test_mismatched_binary_is_refused_before_any_name_changes(self):
        top = self.models / self.top_name
        top.write_bytes(b"different payload")
        os.chmod(top, 0o600)
        before = (self.models / self.cal_name).stat().st_ino, top.stat().st_ino
        with self.assertRaises(TOOL.ReclaimError):
            TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertEqual(before, ((self.models / self.cal_name).stat().st_ino, top.stat().st_ino))
        self.assertEqual(top.read_bytes(), b"different payload")
        self.assertFalse((self.session / "journal" / (self.pair_id + ".done.private.json")).exists())

    def test_extra_link_is_refused(self):
        extra = self.models / "hybrid_fit_cccccccccccccccccccccccc.joblib"
        os.link(self.models / self.cal_name, extra)
        with self.assertRaises(TOOL.ReclaimError):
            TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertNotEqual((self.models / self.cal_name).stat().st_ino,
                            (self.models / self.top_name).stat().st_ino)

    def test_symlink_target_is_refused(self):
        outside = self.root / "outside-model.joblib"
        outside.write_bytes(b"do not touch")
        os.chmod(outside, 0o600)
        top = self.models / self.top_name
        top.unlink()
        top.symlink_to(outside)
        before = (self.models / self.cal_name).stat().st_ino
        with self.assertRaises(OSError):
            TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        self.assertEqual((self.models / self.cal_name).stat().st_ino, before)
        self.assertEqual(outside.read_bytes(), b"do not touch")

    def test_unapproved_basename_is_refused(self):
        directory_fd = os.open(self.models, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(TOOL.ReclaimError):
                TOOL._model_fd(directory_fd, "../outside-model.joblib")
        finally:
            os.close(directory_fd)

    def test_busy_coordinator_lock_is_refused(self):
        lock = self.root / "campaign.lock"
        lock.touch(mode=0o600)
        os.chmod(lock, 0o600)
        held_fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(held_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with ExitStack() as stack:
                with self.assertRaises(TOOL.ReclaimError):
                    stack.enter_context(TOOL._held_lock(stack, lock))
        finally:
            os.close(held_fd)

    def test_apply_then_rollback_restores_an_independent_copy(self):
        TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        result = TOOL._rollback_one(self.pair, self.session, "a" * 64, "b" * 64, "d" * 64)
        cal = self.models / self.cal_name
        top = self.models / self.top_name
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(cal.read_bytes(), self.payload)
        self.assertEqual(top.read_bytes(), self.payload)
        self.assertNotEqual((cal.stat().st_dev, cal.stat().st_ino), (top.stat().st_dev, top.stat().st_ino))
        self.assertEqual(cal.stat().st_nlink, 1)
        self.assertEqual(top.stat().st_nlink, 1)

    def test_rollback_stops_before_copy_when_reserve_would_be_breached(self):
        TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        low_disk = shutil._ntuple_diskusage(20_000_000_000, 14_900_000_000, 5_100_000_000)
        with patch.object(TOOL.shutil, "disk_usage", return_value=low_disk):
            with self.assertRaises(TOOL.ReclaimError):
                TOOL._rollback_one(self.pair, self.session, "a" * 64, "b" * 64, "d" * 64)
        self.assertEqual((self.models / self.cal_name).stat().st_ino,
                         (self.models / self.top_name).stat().st_ino)
        self.assertFalse((self.session / "journal" /
                          (self.pair_id + ".rollback-intent.private.json")).exists())

    def test_resume_rollback_after_atomic_replace_before_terminal_journal(self):
        TOOL._deduplicate_one(self.pair, self.session, "a" * 64, "b" * 64)
        _, done_path, rollback_path, _ = TOOL._pair_records(self.session, self.pair_id)
        TOOL._verify_pair_completed(self.pair, done_path, self.identity)
        temp_name = ".storage-rollback-" + self.pair_id + ".pending"
        TOOL._write_journal(rollback_path, self.identity, "ROLLBACK_INTENT_DURABLE", {
            "temporary_name": temp_name,
            "target_shared_signature": TOOL._file_signature((self.models / self.top_name).stat()),
        })
        temp = self.models / temp_name
        temp.write_bytes((self.models / self.cal_name).read_bytes())
        os.chmod(temp, 0o600)
        TOOL._write_journal(rollback_path, self.identity, "ROLLBACK_TEMP_VERIFIED", {
            "temporary_name": temp_name,
            "temporary_signature": TOOL._file_signature(temp.stat()),
            "target_shared_signature": TOOL._file_signature((self.models / self.top_name).stat()),
        })
        os.replace(temp, self.models / self.top_name)
        result = TOOL._rollback_one(self.pair, self.session, "a" * 64, "b" * 64, "d" * 64)
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual((self.models / self.cal_name).read_bytes(), self.payload)
        self.assertEqual((self.models / self.top_name).read_bytes(), self.payload)
        self.assertNotEqual((self.models / self.cal_name).stat().st_ino,
                            (self.models / self.top_name).stat().st_ino)


if __name__ == "__main__":
    unittest.main()
