"""ID/reference boundary fixtures only: no fitting or measured qualification."""
from dataclasses import asdict
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from app.contract import HYBRID_MODEL_KIND, recipe_binding
from app.hybrid_incident import HybridResearchConfig
from app.model_state_dispatch import HYBRID_FORMAT
from app.operator_catalog import OperatorCatalog, Recipe, hybrid_training, train_recipe, verify_registered_hybrid
from app.policy import ScorePolicy
from app.strict_campaign import write
from app.quality_proof import sha_file

ARTIFACT = 'hybrid-owned-label-fixture'
DATASET = 'hybrid-owned-normal-fixture'
SHA = 'a' * 64


def fixture(root):
    root.chmod(0o700)
    for name in (DATASET, ARTIFACT): (root / name).mkdir(mode=0o700)
    write(root / DATASET / 'manifest.json', {'fixture': 'boundary-only'})
    write(root / ARTIFACT / 'manifest.private.json', {'fixture': 'boundary-only'})
    fit = {'records': 50000, 'normal': 50000, 'positive': 0, 'cohorts': {'READY': 50000}, 'sha256': 'b' * 64}
    # Controlled loader mocks test only binding; duplicates are NOT accepted by
    # the actual BULK loader and these records never reach a real model fit.
    normal = [{'features': [0] * 37}] * 50000
    supervised = [*normal, *([{'features': [0] * 37}] * 31500)]
    dataset = SimpleNamespace(root=root / DATASET, manifest={'stage': 'PILOT', 'feature_schema_version': 4},
                              split=lambda name: fit, iter_shards=lambda name: [('fixture', normal)])
    entry = {'recipe_id': 'hybrid-owned-recipe-fixture', 'dataset_id': DATASET, 'manifest_sha256': SHA,
             'mode': 'PILOT', 'fold': 1, 'config': asdict(HybridResearchConfig()),
             'score_policy': ScorePolicy.strict(schema=4).wire(), **recipe_binding(HybridResearchConfig()),
             'model_state_format': HYBRID_FORMAT, 'labeled_training_artifact_id': ARTIFACT,
             'labeled_training_manifest_sha256': SHA}
    write(root / 'catalog.json', {'strict_entries': [entry]})
    bulk = {'artifact_id': ARTIFACT, 'training_sections': {'NORMAL_COMPONENT': copy.deepcopy(fit)}}
    return dataset, entry, (normal, supervised, bulk)


class HybridOperatorCatalogTest(unittest.TestCase):
    def test_missing_pathlike_or_wrong_hash_refs_fail_before_loader(self):
        dataset = SimpleNamespace(manifest={'stage': 'PILOT', 'feature_schema_version': 4})
        with patch('app.hybrid_bulk_dataset.load_hybrid_bulk_fit') as loader:
            for identifier, checksum in ((None, SHA), ('../private', SHA), (ARTIFACT, None), (ARTIFACT, 'bad')):
                with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                    hybrid_training(dataset, 1, identifier, checksum)
        loader.assert_not_called()

    def test_hybrid_strict_registration_fails_before_labeled_io(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset, entry, _ = fixture(root)
            entry['mode'] = 'STRICT'; dataset.manifest['stage'] = 'STRICT'
            write(root / 'catalog.json', {'strict_entries': [entry]})
            with patch('app.operator_catalog.ShardedDataset', return_value=dataset), \
                    patch('app.hybrid_bulk_dataset.load_hybrid_bulk_fit') as loader:
                with self.assertRaisesRegex(ValueError, 'STRICT proof pin'):
                    OperatorCatalog(root).recipe(entry['recipe_id'])
            loader.assert_not_called()

    def test_public_or_symlinked_labeled_storage_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset, _, data = fixture(root)
            (root / ARTIFACT / 'manifest.private.json').chmod(0o644)
            with patch('app.hybrid_bulk_dataset.load_hybrid_bulk_fit', return_value=data) as loader:
                with self.assertRaisesRegex(ValueError, 'private owner-controlled'):
                    hybrid_training(dataset, 1, ARTIFACT, SHA)
            loader.assert_not_called()
            (root / ARTIFACT / 'manifest.private.json').chmod(0o600)
            link = root / 'symlink-label-fixture'; link.symlink_to(root / ARTIFACT, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                hybrid_training(dataset, 1, link.name, SHA)

    def test_actual_normal_section_binding_cannot_inflate_old2000_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset, _, data = fixture(root)
            old_fit = data[2]['training_sections']['NORMAL_COMPONENT'] | {'records': 2000, 'normal': 2000}
            dataset.split = lambda name: old_fit
            with patch('app.hybrid_bulk_dataset.load_hybrid_bulk_fit', return_value=data):
                with self.assertRaisesRegex(ValueError, 'actual complete registered normal FIT'):
                    hybrid_training(dataset, 1, ARTIFACT, SHA)

    def test_id_only_pilot_recipe_keeps_exact_protected_refs_and_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dataset, entry, data = fixture(root)
            with patch('app.operator_catalog.ShardedDataset', return_value=dataset), \
                    patch('app.hybrid_bulk_dataset.load_hybrid_bulk_fit', return_value=data) as loader:
                recipe = OperatorCatalog(root).recipe(entry['recipe_id'])
            self.assertEqual(recipe.model_kind, HYBRID_MODEL_KIND)
            self.assertEqual(recipe.model_state_format, HYBRID_FORMAT)
            self.assertEqual(recipe.labeled_training_artifact_id, ARTIFACT)
            self.assertEqual(recipe.labeled_training_manifest_sha256, SHA)
            loader.assert_called_once_with(root / ARTIFACT, SHA)

    def test_strict_queue_headers_pin_private_proof_and_deep_failure_prevents_fit(self):
        from test_hybrid_frozen_evaluation import Fixture
        from app.frozen_evaluation import _hybrid_read
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = Fixture(root)
            write(source.root / 'manifest.json', {'mocked_boundary': True})
            write(source.root / 'hybrid-selection.json', source.selected)
            source.files['hybrid-selection.json'] = source.proof['selection_sha256'] = sha_file(source.root / 'hybrid-selection.json')
            for fold in (1, 2, 3):
                labeled = root / f'labels-fold{fold}'; labeled.mkdir(mode=0o700)
                write(labeled / 'manifest.private.json', {'mocked_boundary': True})
                source.fold_manifests[fold].update(format='HYBRID_STRICT_LABELED_SOURCE_V1', stage='STRICT_SOURCE',
                    standard_manifest_sha256=source.sha, standard_fit=source.split(f'fold{fold}-fit'),
                    quality_gate='NOT_EVALUATED', fit_or_score_calls=0, holdout_numeric_records_read=0)
            entry = {'recipe_id': 'hybrid-strict-fixture', 'dataset_id': source.root.name,
                     'manifest_sha256': source.sha, 'mode': 'STRICT', 'fold': 3,
                     'config': asdict(source.config), 'score_policy': source.policy.wire(),
                     'selection_sha256': sha_file(source.root / 'hybrid-selection.json'),
                     'expected_model_sha256': source.model_sha, 'expected_calibration_sha256': source.cal_sha,
                     'expected_model_state_sha256': source.state_sha, 'model_state_format': HYBRID_FORMAT,
                     'model_state_verifier_sha256': 'e' * 64, 'strict_proof_sha256': '5' * 64,
                     **source.label_binding(3), **recipe_binding(source.config)}
            write(root / 'catalog.json', {'strict_entries': [entry]})
            def read(path, maximum, **kwargs):
                if path == root / 'catalog.json': return _hybrid_read(path, maximum, **kwargs)
                if path == source.root / 'manifest.json': return source.sha, source.dataset.manifest
                if path.parent.name.startswith('labels-fold'):
                    fold = int(path.parent.name[-1]); return str(fold) * 64, source.fold_manifests[fold]
                return source.read(path, maximum, **kwargs)
            store = MagicMock(); store.scoring_identity.return_value = source.implementation
            store.return_value.load_candidate.return_value = (source.metadata, source.payload)
            with patch('app.operator_catalog.ShardedDataset', return_value=source.dataset), \
                    patch('app.operator_catalog.ModelStore', store), \
                    patch('app.operator_catalog.fingerprint', return_value=source.code), \
                    patch('app.operator_catalog.verifier_sha256', return_value='e' * 64), \
                    patch('app.frozen_evaluation._hybrid_read', side_effect=read), \
                    patch('app.frozen_evaluation.fingerprint', return_value=source.code), \
                    patch('app.frozen_evaluation.hybrid_fold_training', side_effect=lambda dataset, fold:
                          ([], [], source.fold_manifests[fold], str(fold) * 64)) as labels, \
                    patch('app.frozen_evaluation.ModelStore', source.store()), \
                    patch('app.frozen_evaluation.state_sha256', return_value=source.state_sha), \
                    patch('app.frozen_evaluation.verifier_sha256', return_value='e' * 64):
                recipe = OperatorCatalog(root).recipe(entry['recipe_id'])
                self.assertEqual(recipe.strict_proof_sha256, '5' * 64)
                self.assertIsNone(recipe.holdout_access_audit_sha256)
                entry['holdout_access_audit_sha256'] = SHA
                write(root / 'catalog.json', {'strict_entries': [entry]})
                pinned_recipe = OperatorCatalog(root).recipe(entry['recipe_id'])
                self.assertEqual(pinned_recipe.holdout_access_audit_sha256, SHA)
                entry.pop('holdout_access_audit_sha256')
                write(root / 'catalog.json', {'strict_entries': [entry]})
                labels.assert_not_called(); store.return_value.load_candidate.assert_not_called()
                first_validation = source.records['hybrid-validations/' + source.runs[0]['run_id'] + '.json']
                policies = first_validation['policies']; first_validation['policies'] = []
                queued_recipe = OperatorCatalog(root).recipe(entry['recipe_id'])
                with self.assertRaisesRegex(ValueError, 'original192 policies'):
                    train_recipe(store.return_value, queued_recipe, 'strict_failure_fixture', source.root / 'cache')
                store.return_value.train.assert_not_called(); first_validation['policies'] = policies
                verified = verify_registered_hybrid(recipe)
                self.assertEqual(verified['actual_composite_trials'], 360)
                entry['strict_proof_sha256'] = '6' * 64; write(root / 'catalog.json', {'strict_entries': [entry]})
                with self.assertRaisesRegex(ValueError, 'proof/labeled source checksum'):
                    OperatorCatalog(root).recipe(entry['recipe_id'])
                entry['strict_proof_sha256'] = '5' * 64; write(root / 'catalog.json', {'strict_entries': [entry]})
                source.records['hybrid-campaign.progress.json']['actual_component_fit_calls'] = 719
                with self.assertRaisesRegex(ValueError, '360/720'):
                    OperatorCatalog(root).recipe(entry['recipe_id'])
                source.records['hybrid-campaign.progress.json']['actual_component_fit_calls'] = 720
                source.metadata['actual_component_fit_counts']['normal_component_fit_calls'] = True
                with self.assertRaisesRegex(ValueError, 'metadata header'): OperatorCatalog(root).recipe(entry['recipe_id'])
                source.metadata['actual_component_fit_counts']['normal_component_fit_calls'] = 1
                (root / 'catalog.json').chmod(0o644)
                with self.assertRaisesRegex(ValueError, 'protected'): OperatorCatalog(root).recipe(entry['recipe_id'])

    def test_strict_refit_uses_matching_fold_source_fingerprint_and_measured_components(self):
        from test_hybrid_frozen_evaluation import Fixture
        with tempfile.TemporaryDirectory() as directory:
            source = Fixture(Path(directory)); source.root.joinpath('worker-models').mkdir()
            recipe = Recipe('hybrid-strict-fixture', source.dataset, source.config, source.policy, 3, 'STRICT',
                            source.model_sha, source.cal_sha, source.state_sha, 'e' * 64,
                            HYBRID_MODEL_KIND, 1, recipe_binding(source.config)['recipe_sha256'], HYBRID_FORMAT,
                            'labels-fold3', '3' * 64, '5' * 64)
            rows = [{'features': [0] * 37}] * 50000; supervised = [*rows, *rows[:31500]]
            fit = {'records': 50000, 'positive': 0, 'cohorts': {'READY': 50000}, 'sha256': '7' * 64}
            source.dataset.split = lambda name: fit
            source.dataset.iter_shards = lambda name: [('fixture', rows if name.endswith('-fit') else rows[:5000])]
            store = MagicMock(); store.directory = source.root / 'worker-models'
            trained = copy.deepcopy(source.metadata); store.train.return_value = trained
            store.load_candidate.return_value = (trained, source.payload)
            proof = {'format': 'HYBRID_STRICT_PROOF_V1', 'proof_sha256': '5' * 64}
            counter = SimpleNamespace(counts={'normal_component_fit_calls': 1, 'labeled_component_fit_calls': 1})
            with patch('app.operator_catalog.verify_registered_hybrid', return_value=proof) as guard, \
                    patch('app.operator_catalog.hybrid_fold_training', return_value=(rows, supervised, source.fold_manifests[3], '3' * 64)) as labels, \
                    patch('app.operator_catalog.fingerprint', return_value=source.code), \
                    patch('app.operator_catalog.hybrid_fingerprint', side_effect=AssertionError('PILOT fingerprint forbidden')), \
                    patch('app.operator_catalog.HybridFitCounter') as measured, \
                    patch('app.hybrid_dataset.training_targets', return_value=[0] * 71500 + [1] * 8000 + [2] * 2000), \
                    patch('app.operator_catalog.recalibrate', return_value={'metadata': trained}), \
                    patch('app.operator_catalog.state_sha256', return_value=source.state_sha), \
                    patch('app.operator_catalog.state_format', return_value=HYBRID_FORMAT), \
                    patch('app.operator_catalog.verifier_sha256', return_value='e' * 64):
                measured.return_value.__enter__.return_value = counter
                result = train_recipe(store, recipe, 'strict_worker_fixture', source.root / 'cache')
                labels.assert_called_once_with(source.dataset, 3); self.assertEqual(guard.call_count, 2)
                self.assertEqual(result['code_fingerprint'], source.code)
                self.assertEqual(result['strict_proof_sha256'], recipe.strict_proof_sha256)
                self.assertEqual(result['scope'], 'FULL_STRICT_SOURCE')
                self.assertEqual(result['normal_fit_split_sha256'], fit['sha256'])
                self.assertEqual(result['actual_component_fit_counts'], counter.counts)
                self.assertEqual(len(store.train.call_args.kwargs['labeled_samples']), 81500)
                counter.counts = {'normal_component_fit_calls': 1, 'labeled_component_fit_calls': 0}
                with self.assertRaisesRegex(ValueError, 'both genuine component'):
                    train_recipe(store, recipe, 'strict_second_fixture', source.root / 'cache')


if __name__ == '__main__': unittest.main()
