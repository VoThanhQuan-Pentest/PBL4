"""Tiny actual worker fixtures, never campaign or serving qualification evidence."""
from dataclasses import asdict
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from app.contract import (HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, SupportTrainingConfig,
                          TrainingConfig, campaign_runs, model_recipe_binding, parse_training_config, recipe_binding)
from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig
from app.hybrid_semantic import FORMAT as INNER_FORMAT, state_sha256 as predictive_sha
from app.model import ModelStore
from app.model_state_dispatch import HYBRID_FORMAT, state_format, state_sha256, verifier_sha256
from app import semantic_model as legacy
from app.normal_support import NormalSupportScorer
from app.policy import ScorePolicy, canonical
from test_hybrid_incident import labeled_fixture
from test_normal_support import normal
from test_model import normal as legacy_normal

CONFIG = HybridResearchConfig(100, 15, 1, 42)


def train(store, version='hybrid_owned_fixture'):
    rows, labels = labeled_fixture()
    return store.train(version, [normal(i) for i in range(600)], [normal(i) for i in range(600, 900)],
                       schema_version=4, config=CONFIG, policy=ScorePolicy.strict(schema=4),
                       labeled_samples=rows, labeled_targets=labels)


class HybridModelStoreTest(unittest.TestCase):
    def test_low_disk_refuses_new_hybrid_before_fit_or_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            with patch('app.storage_budget.require_headroom', side_effect=ValueError('reserve fixture')), \
                    patch.object(HybridIncidentScorer, 'fit', side_effect=AssertionError('must not fit')) as fit:
                with self.assertRaisesRegex(ValueError, 'reserve fixture'):
                    train(store)
            fit.assert_not_called()
            self.assertFalse(list(store.directory.glob('*.joblib')))
            self.assertFalse(list(store.directory.glob('.pending-*')))

    def test_new_hybrid_publication_is_compressed_and_exact_readback_failure_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            original_dump = joblib.dump
            with patch('app.model.joblib.dump', wraps=original_dump) as save:
                metadata = train(store)
            self.assertEqual(save.call_args.kwargs, {'compress': ('lzma', 3)})
            self.assertEqual(metadata['artifact_compression'], {'codec': 'lzma', 'level': 3})
            plain = joblib.load(store.directory / 'hybrid_owned_fixture.joblib')
            self.assertEqual(state_sha256(plain), metadata['model_state_sha256'])
            self.assertEqual(store.calibration_hash(plain), metadata['calibration_sha256'])
            with patch.object(NormalSupportScorer, 'fit', side_effect=AssertionError('no restore fit')), \
                    patch.object(HistGradientBoostingClassifier, 'fit', side_effect=AssertionError('no restore fit')):
                self.assertEqual(store.load_candidate('hybrid_owned_fixture')[0]['sha256'], metadata['sha256'])
            meta_path = store.directory / 'hybrid_owned_fixture.json'
            for compression in ({'codec': 'caller', 'level': 3}, {'codec': 'lzma', 'level': True},
                                {'codec': 'lzma', 'level': 3, 'extra': 1}):
                meta_path.write_text(canonical(metadata | {'artifact_compression': compression}))
                with self.assertRaisesRegex(ValueError, 'compression descriptor'):
                    store.load_candidate('hybrid_owned_fixture')
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            with patch('app.model.joblib.load', return_value={'model': {}}), self.assertRaises(ValueError):
                train(store)
            self.assertFalse((store.directory / 'hybrid_owned_fixture.joblib').exists())
            self.assertFalse((store.directory / 'hybrid_owned_fixture.json').exists())
            self.assertTrue((store.directory / '.pending-hybrid_owned_fixture').is_dir())

    def test_legacy_publication_keeps_default_uncompressed_joblib_codec(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            original_dump = joblib.dump
            with patch('app.model.joblib.dump', wraps=original_dump) as save:
                metadata = store.train('legacy_compression_fixture', [legacy_normal(i) for i in range(600)],
                                       [legacy_normal(i) for i in range(600, 720)])
            self.assertEqual(save.call_args.kwargs, {})
            self.assertNotIn('artifact_compression', metadata)
            store.activate('legacy_compression_fixture')
            self.assertTrue(ModelStore(store.directory).score([legacy_normal(1)])['available'])

    def test_typed_grid_has120_recipes360_runs_and_legacy_identities_exact(self):
        runs = campaign_runs(HYBRID_MODEL_KIND)
        self.assertEqual(len(runs), 360)
        self.assertEqual(len({row['run_id'] for row in runs}), 360)
        self.assertEqual(len({recipe_binding(row['config'])['recipe_sha256'] for row in runs}), 120)
        self.assertEqual(parse_training_config(HYBRID_MODEL_KIND, asdict(CONFIG)), CONFIG)
        expected = {'model_kind': HYBRID_MODEL_KIND, 'recipe_version': 1, 'config': asdict(CONFIG)}
        self.assertEqual(recipe_binding(CONFIG)['recipe_sha256'], hashlib.sha256(canonical(expected).encode()).hexdigest())
        for config, kind in ((TrainingConfig(), IF_MODEL_KIND), (SupportTrainingConfig(), SUPPORT_MODEL_KIND)):
            old = {'model_kind': kind, 'recipe_version': 1, 'config': config.parameters()}
            self.assertEqual(recipe_binding(config)['recipe_sha256'], hashlib.sha256(canonical(old).encode()).hexdigest())
        for value in ({}, asdict(CONFIG) | {'max_iter': True}, asdict(CONFIG) | {'custom_pipeline': 'caller'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_training_config(HYBRID_MODEL_KIND, value)
        with self.assertRaises(ValueError): model_recipe_binding(recipe_binding(CONFIG) | {'model_kind': 'caller_model'})

    def test_actual_train_persists_primitives_loads_scores_exact_and_keeps_legacy_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store = ModelStore(root)
            store.train('legacy_active_fixture', [legacy_normal(i) for i in range(600)], [legacy_normal(i) for i in range(120)])
            store.activate('legacy_active_fixture')
            metadata = train(store)
            self.assertEqual(metadata['training_windows'], 600)
            self.assertEqual(metadata['labeled_training_windows'], 180)
            self.assertEqual(metadata['labeled_class_windows'], {'0': 60, '1': 60, '2': 60})
            self.assertEqual(metadata['model_state_format'], HYBRID_FORMAT)
            stored = joblib.load(root / 'hybrid_owned_fixture.joblib')
            self.assertIs(type(stored['model']), dict)
            self.assertEqual(stored['model']['state_format'], INNER_FORMAT)
            def plain(value):
                if type(value) is dict:
                    for item in value.values(): plain(item)
                elif type(value) is list:
                    for item in value: plain(item)
                else: self.assertIn(type(value), (str, int, float, bool, type(None)))
            plain(stored['model'])
            expected = store.score_candidate('hybrid_owned_fixture', [normal(), normal(13)], 4)
            with patch.object(HistGradientBoostingClassifier, 'fit', side_effect=AssertionError('no restore fit')), \
                    patch.object(NormalSupportScorer, 'fit', side_effect=AssertionError('no restore fit')):
                restored = ModelStore(root)
                loaded, payload = restored.load_candidate('hybrid_owned_fixture')
                self.assertIs(type(payload['model']), HybridIncidentScorer)
                self.assertEqual(restored.score_candidate('hybrid_owned_fixture', [normal(), normal(13)], 4), expected)
                self.assertEqual(state_sha256(payload), loaded['model_state_sha256'])
            self.assertEqual(set(expected['results'][0]), {'raw_anomaly_score', 'normal_percentile', 'level', 'scoring_cohort', 'model_scope'})
            self.assertEqual(restored.active_version, 'legacy_active_fixture')
            self.assertEqual((root / 'hybrid_owned_fixture.joblib').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, 'immutable dataset'):
                store.activate('hybrid_owned_fixture')

    def test_separate_labels_schema_policy_and_primitive_inputs_fail_before_fits(self):
        rows, labels = labeled_fixture()
        common = {'schema_version': 4, 'config': CONFIG, 'policy': ScorePolicy.strict(schema=4),
                  'labeled_samples': rows, 'labeled_targets': labels}
        variants = [common | {'labeled_samples': None}, common | {'labeled_targets': None},
                    common | {'schema_version': 3}, common | {'policy': ScorePolicy.legacy(2)},
                    common | {'labeled_targets': [0] * 180}, common | {'labeled_targets': [True, *labels[1:]]}]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(HybridIncidentScorer, 'fit', side_effect=AssertionError('invalid request cannot fit')):
            store = ModelStore(Path(directory))
            for variant in variants:
                with self.subTest(variant=list(variant)), self.assertRaises(ValueError):
                    store.train('invalid_hybrid_fixture', [normal(i) for i in range(600)], [normal(i) for i in range(300)], **variant)
            for value in (True, '40', complex(40, 1), np.complex128(40), float('nan')):
                bad = normal(); bad[0] = value
                with self.subTest(value=value), self.assertRaises(ValueError):
                    store.train('invalid_numeric_fixture', [bad] * 600, [normal()] * 300, **common)
            with self.assertRaisesRegex(ValueError, 'only accepted'):
                store.train('invalid_legacy_fixture', [legacy_normal(i) for i in range(600)], [legacy_normal(i) for i in range(120)],
                            labeled_samples=rows, labeled_targets=labels)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_zero_fit_recalibration_rebinds_all_buckets_but_pilot_activation_still_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory)); source = train(store)
            _, original = store.load_candidate('hybrid_owned_fixture')
            original_model_sha = predictive_sha(original['model'])
            ready = np.sort(-original['model'].score_samples([normal(i) for i in range(300)]))
            cold_rows = [normal(i) for i in range(300)]
            for row in cold_rows: row[35] = 3
            cold = np.sort(-original['model'].score_samples(cold_rows))
            with patch.object(HistGradientBoostingClassifier, 'fit', side_effect=AssertionError('no recal fit')), \
                    patch.object(NormalSupportScorer, 'fit', side_effect=AssertionError('no recal fit')):
                recal = store.recalibrated_candidate('hybrid_owned_fixture', 'hybrid_recal_fixture', {'READY': ready, 'COLD': cold},
                    ScorePolicy.strict(schema=4), expected_source_sha256=source['sha256'], dataset_sha256='a' * 64,
                    split_sha256={'READY': 'b' * 64, 'COLD': 'c' * 64}, calibration_scope='PILOT_ONLY')
                metadata, payload = store.load_candidate('hybrid_recal_fixture')
                self.assertEqual(predictive_sha(payload['model']), original_model_sha)
                self.assertEqual(metadata['additional_fit_calls'], 0)
                self.assertEqual(metadata['model_state_sha256'], state_sha256(payload))
                self.assertNotEqual(metadata['model_state_sha256'], source['model_state_sha256'])
                self.assertEqual(recal['calibration_cohort_windows'], {'READY': 300, 'COLD': 300})
                scores = store.score_candidate('hybrid_recal_fixture', [normal(), cold_rows[0]], 4, ['READY', 'COLD'])
                self.assertEqual([r['scoring_cohort'] for r in scores['results']], ['READY', 'COLD'])
                with self.assertRaisesRegex(ValueError, 'independent cohort calibration'):
                    store.activate('hybrid_recal_fixture')
            self.assertIsNone(store.active_version)
            self.assertFalse((store.directory / 'active.json').exists())

    def test_metadata_binary_state_recipe_and_implementation_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store = ModelStore(root); metadata = train(store)
            path = root / 'hybrid_owned_fixture.json'
            changes = ({'model_state_sha256': '0' * 64}, {'model_state_verifier_sha256': '0' * 64},
                       {'model_state_format': INNER_FORMAT}, {'recipe_sha256': '0' * 64}, {'model_kind': 'caller_model'},
                       {'scoring_implementation': {}}, {'labeled_training_windows': 181},
                       {'labeled_class_windows': {'0': 60, '1': 60, '2': True}}, {'calibration_sha256': '0' * 64})
            for change in changes:
                path.write_text(canonical(metadata | change))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    store.load_candidate('hybrid_owned_fixture')
            path.write_text(canonical(metadata))
            binary = root / 'hybrid_owned_fixture.joblib'
            with binary.open('ab') as stream: stream.write(b'tamper')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                store.load_candidate('hybrid_owned_fixture')

    def test_calibrated_dispatch_binds_all_arrays_and_legacy_dispatch_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory)); train(store)
            _, payload = store.load_candidate('hybrid_owned_fixture')
            identity = state_sha256(payload)
            changed = {**payload, 'calibration_scores': payload['calibration_scores'] + 0.01}
            self.assertNotEqual(state_sha256(changed), identity)
            for bad in (np.asarray([True] * 100), [True] * 100, np.asarray(['1'] * 100), np.full(100, np.nan)):
                with self.subTest(dtype=type(bad)), self.assertRaises(ValueError):
                    state_sha256({**payload, 'calibration_scores': bad})
            with self.assertRaisesRegex(ValueError, 'cohort buckets'):
                state_sha256({**payload, 'calibration_by_cohort': None})
            with patch('app.model_state_dispatch.MAX_CALIBRATION_ROWS', 100), self.assertRaises(ValueError):
                state_sha256(payload)
            with patch('app.model_state_dispatch.MAX_TOTAL_NUMERIC_BYTES', 100), self.assertRaisesRegex(ValueError, 'budget'):
                state_sha256(payload)
            for kind in (IF_MODEL_KIND, SUPPORT_MODEL_KIND):
                self.assertEqual(state_format(kind), legacy.state_format(kind))
                self.assertEqual(verifier_sha256(kind), legacy.verifier_sha256(kind))
            support = NormalSupportScorer(4, 128, 'euclidean', 42).fit([normal(i) for i in range(600)])
            old = {'model': support, 'calibration_scores': np.sort(-support.score_samples([normal(i) for i in range(120)]))}
            self.assertEqual(state_sha256(old), legacy.state_sha256(old))
            forest = IsolationForest(n_estimators=200, max_samples=128, random_state=42).fit([legacy_normal(i) for i in range(600)])
            old = {'model': forest, 'calibration_scores': np.sort(-forest.score_samples([legacy_normal(i) for i in range(120)]))}
            self.assertEqual(state_sha256(old), legacy.state_sha256(old))
            self.assertEqual(hashlib.sha256(Path(legacy.__file__).read_bytes()).hexdigest(),
                             '7570e04d44333acfb9851cd66f21109e6edf5ff7b14c56a14d39593d230804fa')

    def test_historical_support_implementation_mismatch_is_not_silently_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ModelStore(Path(directory))
            metadata = store.train('support_history_fixture', [normal(i) for i in range(600)], [normal(i) for i in range(120)],
                schema_version=4, config=SupportTrainingConfig(), policy=ScorePolicy.strict(schema=4))
            historical = copy.deepcopy(metadata)
            historical['scoring_implementation']['sources']['contract.py'] = '09fd427f2f1d0c11f3b422f31a689af334a80fdf0668f5b67fb454c879b49103'
            (store.directory / 'support_history_fixture.json').write_text(canonical(historical))
            with self.assertRaisesRegex(ValueError, 'implementation mismatch'):
                store.load_candidate('support_history_fixture')


if __name__ == '__main__':
    unittest.main()
