"""Actual small inference/replay/journal fixtures; never a frozen high-accuracy benchmark."""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from app.catalog import ShardedDataset, validate_rows
from app.catalog_evaluation import evaluate_recipe
from app.frozen_evaluation import evaluate, evaluate_bound, score_shards
from app.metric_journal import MetricJournal
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from app.quality_proof import audit_actual_rows
from app.risk_replay import JavaRiskReplay
from app.strict_campaign import fit_one
from test_calibration import fixture
from test_catalog import row

ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", Path(__file__).resolve().parents[2]))


class FrozenGuardTest(unittest.TestCase):
    def test_pilot_is_rejected_before_looking_for_selection_or_opening_holdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            with self.assertRaisesRegex(ValueError, "pilot"):
                evaluate(root, ROOT)
            self.assertFalse((root / "strict-models").exists())

    def test_source_worker_and_internal_transport_refuse_markers_before_consumer_io(self):
        for location in ("dataset", "parent"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory); parent.chmod(0o700)
                root = parent / "standard"; root.mkdir(mode=0o700)
                marker = (root if location == "dataset" else parent) / "holdout-access-audit.private.json"
                marker.write_text(canonical({"audit_schema_version": 1, "status": "BLOCKED", "dataset_id": "future-audit-fixture",
                    "affected_split": "holdout", "reason": "INDETERMINATE_HOLDOUT_EXPOSURE", "acceptance_allowed": False,
                    "audit_id": "future-audit-only", "recorded_at_utc": "2026-10-05T00:00:00Z"})); marker.chmod(0o600)
                # No selection/model/row fixtures exist; the specific provenance
                # error proves refusal happens before those consumer boundaries.
                dataset = SimpleNamespace(root=root, manifest={"stage": "STRICT"}, iter_shards=Mock())
                store = Mock(); recipe = SimpleNamespace(mode="STRICT", dataset=dataset)
                with patch("app.frozen_evaluation.ShardedDataset", return_value=dataset), \
                        patch("app.frozen_evaluation.ModelStore") as models, \
                        patch("app.frozen_evaluation.evaluate_bound") as transport:
                    with self.assertRaisesRegex(ValueError, "BLOCKED"): evaluate(root, parent)
                    models.assert_not_called(); transport.assert_not_called()
                with self.assertRaisesRegex(ValueError, "BLOCKED"): evaluate_recipe(store, recipe, "fixture-version", parent)
                store.load_candidate.assert_not_called()
                with self.assertRaisesRegex(ValueError, "BLOCKED"):
                    evaluate_bound(dataset, store, None, None, None, None, parent)
                with self.assertRaisesRegex(ValueError, "BLOCKED"):
                    score_shards(dataset, "holdout", None, None, None, None)
                dataset.iter_shards.assert_not_called()

    def test_pre_holdout_transport_does_not_consume_or_reject_a_holdout_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "holdout-access-audit.private.json"; marker.write_bytes(b"{}"); marker.chmod(0o600)
            dataset = SimpleNamespace(root=root, iter_shards=Mock(return_value=iter(())))
            score_shards(dataset, "fold1-validation", None, None, None, None)
            dataset.iter_shards.assert_called_once_with("fold1-validation")

    def test_worker_known_blocked_pin_refuses_even_when_packaged_marker_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset = SimpleNamespace(root=root, manifest={"stage": "STRICT"})
            store = Mock()
            # No marker, selection, model or numeric resources exist. Both a
            # registered BLOCKED pin and an invalid pin must fail at provenance.
            for pin in ("a" * 64, "bad", "", True):
                with self.subTest(pin=pin), patch("app.catalog_evaluation.evaluate_bound") as transport:
                    recipe = SimpleNamespace(mode="STRICT", dataset=dataset, holdout_access_audit_sha256=pin)
                    with self.assertRaisesRegex(ValueError, "holdout"):
                        evaluate_recipe(store, recipe, "fixture-version", root)
                    store.load_candidate.assert_not_called(); transport.assert_not_called()


@unittest.skipUnless(shutil.which("java") and (ROOT / "backend/target/ueba-experiment.classpath").is_file(), "production Java workspace required")
class ActualScoringJournalTest(unittest.TestCase):
    def test_actual_scores_are_journalled_and_committed_sources_resume_without_scoring_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root / "data"; data.mkdir(); dataset = fixture(data)
            records = [row(1), row(2, True)]
            records[1]["label"] = 1; records[1]["family"] = "auth_failure_burst"
            records[1]["features"] = [150, 30, 5, 15, 0, 2, 7, 1, 0, 0, 0, 0, 0, 0.2, 1]
            path = data / "shards/fold1-validation-000000.json"; path.write_text(canonical(records))
            descriptor = {"id": "fold1-validation-000000", "path": "shards/" + path.name,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **validate_rows(records)}
            split = {**validate_rows(records), "shards": [descriptor]}; split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest()
            dataset.manifest["splits"]["fold1-validation"] = split
            (data / "manifest.json").write_text(canonical(dataset.manifest)); dataset = ShardedDataset(data)
            actual_fit = fit_one(data, "trees-200-samples-128-features-100-seed-42-fold-1")
            store = ModelStore(data / "strict-models"); metadata, payload = store.load_candidate(actual_fit["model_version"])
            policy = ScorePolicy.from_wire(metadata["score_policy"])
            journal = MetricJournal(root / "actual.sqlite", policy=policy, model_sha256=metadata["sha256"],
                                    calibration_sha256=metadata["calibration_sha256"], dataset_sha256=dataset.sha256)
            try:
                with JavaRiskReplay(ROOT, policy) as replay:
                    score_shards(dataset, "fold1-validation", payload, policy, replay, journal)
                    self.assertEqual(audit_actual_rows(journal.db), 2)
                    self.assertEqual(journal.counter("SIEM_FINAL").tp, 1)
                    first = journal.progress()
                    # Resume must not run inference/replay for already committed
                    # source bytes; a missing transport is safe in this case.
                    score_shards(dataset, "fold1-validation", payload, policy, None, journal)
                    self.assertEqual(journal.progress(), first)
            finally: journal.close()


if __name__ == "__main__": unittest.main()
