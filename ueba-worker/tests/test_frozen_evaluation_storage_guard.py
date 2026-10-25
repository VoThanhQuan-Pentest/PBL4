"""Mocked journal/transport guard wiring only; no numeric rows or quality proof."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from app.contract import IF_MODEL_KIND
from app.frozen_evaluation import evaluate_bound
from app.strict_metrics import SCOPES


class EvaluationStorageGuardTest(unittest.TestCase):
    def exercise(self, *, archive=False, explicit=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); model_root = root / "models"; model_root.mkdir(mode=0o700)
            holdout = {"normal": 10000000, "positive": 10000, "records": 10010000, "shards": [{"id": "mocked-only"}]}
            dataset = SimpleNamespace(root=root, sha256="a" * 64, manifest={"stage": "STRICT", "feature_schema_version": 4},
                split=Mock(return_value=holdout), iter_shards=Mock(side_effect=AssertionError("no numeric rows")))
            if archive: dataset.archive_sha256 = "e" * 64
            policy = SimpleNamespace(strict_gate=True, document={"feature_schema_version": 4})
            metadata = {"model_version": "guard_wiring_fixture", "sha256": "b" * 64, "calibration_sha256": "c" * 64,
                        "calibration_scope": "STRICT", "dataset_manifest_sha256": dataset.sha256}
            binding = {"feature_schema_version": 4}; identity = {**binding, "production_classes": {}, "quality_math_binding": {}}
            journal = Mock(); journal.progress.return_value = {"episodes": holdout["records"]}
            journal.db.execute.return_value.fetchone.return_value = (len(holdout["shards"]),)
            def open_journal(*args, **kwargs):
                journal.storage_guard = kwargs["storage_guard"]
                return journal
            def compute_scope(actual, *args):
                self.assertIs(actual, journal)
                self.assertIs(actual.storage_guard, archive or explicit is True)
                return {"quality_gate": "FAIL"}
            with patch("app.frozen_evaluation.model_binding", return_value=binding), \
                    patch("app.frozen_evaluation.model_recipe_binding", return_value={"model_kind": IF_MODEL_KIND}), \
                    patch("app.frozen_evaluation.MetricJournal", side_effect=open_journal) as constructor, \
                    patch("app.frozen_evaluation.JavaRiskReplay"), \
                    patch("app.frozen_evaluation.score_shards") as scoring, \
                    patch("app.frozen_evaluation.audit_actual_rows", return_value=holdout["records"]), \
                    patch("app.frozen_evaluation.compute_scope", side_effect=compute_scope) as scopes, \
                    patch("app.frozen_evaluation.sha_file", return_value="d" * 64), \
                    patch("app.frozen_evaluation.write"):
                options = {} if explicit is None else {"require_storage_guard": explicit}
                result = evaluate_bound(dataset, SimpleNamespace(directory=model_root), metadata, object(), policy, identity, root, **options)
                self.assertEqual(result["quality_gate"], "FAIL")  # Synthetic wiring is never qualification evidence.
                dataset.iter_shards.assert_not_called(); scoring.assert_called_once()
                self.assertEqual(scopes.call_count, len(SCOPES)); journal.close.assert_called_once()
                return constructor.call_args.kwargs["storage_guard"]

    def test_explicit_true_enables_guard_without_an_archive_identity(self):
        self.assertIs(self.exercise(explicit=True), True)

    def test_archive_default_is_guarded_and_explicit_false_cannot_disable_it(self):
        self.assertIs(self.exercise(archive=True), True)
        self.assertIs(self.exercise(archive=True, explicit=False), True)

    def test_legacy_default_and_explicit_false_remain_unguarded(self):
        self.assertIs(self.exercise(), False)
        self.assertIs(self.exercise(explicit=False), False)

    def test_nonboolean_guard_is_refused_before_provenance_or_consumer_io(self):
        for value in (0, 1, None, "true", [], object()):
            with self.subTest(value=type(value).__name__), \
                    patch("app.frozen_evaluation.require_unblocked_holdout") as provenance, \
                    patch("app.frozen_evaluation.MetricJournal") as journal, \
                    patch("app.frozen_evaluation.score_shards") as scoring, \
                    self.assertRaisesRegex(ValueError, "explicit evaluation storage guard"):
                evaluate_bound(None, None, None, None, None, None, None, require_storage_guard=value)
            provenance.assert_not_called(); journal.assert_not_called(); scoring.assert_not_called()


if __name__ == "__main__": unittest.main()
