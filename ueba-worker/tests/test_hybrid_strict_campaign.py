"""Strict adapter boundary/counter fixtures only; never strict campaign runs."""
from dataclasses import asdict
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.contract import HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, campaign_runs
from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig
from app.strict_campaign import HybridFitCounter, campaign_prefix, fingerprint, hybrid_fold_training, run_identity, validate_fit_recipe
from test_hybrid_incident import labeled_fixture
from test_normal_support import normal


class HybridStrictCampaignTest(unittest.TestCase):
    def test_prefix_fingerprint_and_grid_keep_legacy_paths(self):
        self.assertEqual(campaign_prefix(IF_MODEL_KIND), 'strict')
        self.assertEqual(campaign_prefix(SUPPORT_MODEL_KIND), 'support')
        self.assertEqual(campaign_prefix(HYBRID_MODEL_KIND), 'hybrid')
        self.assertEqual(len(campaign_runs(HYBRID_MODEL_KIND)), 360)
        sources = fingerprint(HYBRID_MODEL_KIND)['sources']
        for name in ('hybrid_semantic.py', 'model_state_dispatch.py', 'hybrid_strict_dataset.py'):
            self.assertIn(name, sources)

    def test_identity_binds_matching_fold_label_hash_and_normal_fit(self):
        config = HybridResearchConfig(100, 15, 1, 42)
        dataset = SimpleNamespace(sha256='a' * 64, split=lambda name: {'sha256': 'b' * 64})
        label = {'sections': {'normal': {'shards': []}, 'supplement': {'shards': []}}}
        run = {'run_id': 'counter-only-not-campaign', 'fold': 2, 'config': config}
        with patch('app.strict_campaign.hybrid_fold_training', return_value=([], [], label, 'c' * 64)):
            identity = run_identity(dataset, run)
        self.assertEqual(identity['config'], asdict(config))
        self.assertEqual(identity['labeled_training_manifest_sha256'], 'c' * 64)
        self.assertEqual(identity['normal_fit_split_sha256'], 'b' * 64)
        self.assertEqual(identity['labeled_training_artifact_id'], 'labels-fold2')
        self.assertEqual(identity['labeled_training_windows'], 81500)

    def test_pilot_scoped_source_or_wrong_fold_cannot_become_strict_fit(self):
        dataset = SimpleNamespace(manifest={'stage': 'PILOT', 'feature_schema_version': 4})
        with patch('app.hybrid_strict_dataset.load_hybrid_strict_fit') as loader:
            with self.assertRaises(ValueError): hybrid_fold_training(dataset, 1)
        loader.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); normal_root = root / 'standard'; normal_root.mkdir()
            label_root = root / 'labels-fold1'; label_root.mkdir()
            manifest = label_root / 'manifest.private.json'; manifest.write_text('{}'); manifest.chmod(0o600)
            dataset = SimpleNamespace(root=normal_root, sha256='a' * 64,
                manifest={'stage': 'STRICT', 'feature_schema_version': 4}, split=lambda name: {})
            with patch('app.hybrid_strict_dataset.load_hybrid_strict_fit', return_value=([], [], {
                    'scope': 'SCOPED_TEST', 'fold': 1, 'standard_manifest_sha256': 'a' * 64, 'standard_fit': {}})):
                with self.assertRaises(ValueError): hybrid_fold_training(dataset, 1)

    def test_original_million_calibration_minimum_and_gap_not_relaxed(self):
        fit = {'records': 50000, 'positive': 0, 'cohorts': {'READY': 50000}, 'to': '2026-04-15T12:00:00Z'}
        dataset = SimpleNamespace(manifest={'stage': 'STRICT'}, split=lambda name: fit)
        with patch('app.strict_campaign.cohort_split', return_value={'records': 60000, 'from': '2026-05-03T00:00:00Z'}):
            with self.assertRaisesRegex(ValueError, 'million'): validate_fit_recipe(dataset, 1)
        with patch('app.strict_campaign.cohort_split', return_value={'records': 1000000, 'from': '2026-04-20T00:00:00Z'}):
            with self.assertRaisesRegex(ValueError, 'history gap'): validate_fit_recipe(dataset, 1)

    def test_two_actual_tiny_component_fits_observed_without_campaign_or_holdout(self):
        rows, labels = labeled_fixture()
        with HybridFitCounter() as counter:
            HybridIncidentScorer(HybridResearchConfig(100, 15, 1, 42)).fit([normal(i) for i in range(256)], rows, labels)
        self.assertEqual(counter.counts, {'normal_component_fit_calls': 1, 'labeled_component_fit_calls': 1})


if __name__ == '__main__': unittest.main()
