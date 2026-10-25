"""Protocol/count controls only; never read holdout records or fit any model."""
import copy
import unittest

from app.hybrid_strict_protocol import (FORMAT, disk_plan, protocol_sha256, require_space,
                                      source_protocol, validate_manifest)


class HybridStrictProtocolTest(unittest.TestCase):
    def test_full_populations_three_folds_and_360_two_component_trials(self):
        protocol = source_protocol('hybrid-strict-20261004-a01')
        self.assertEqual(protocol['standard_numeric_rows'], 19163000)
        self.assertEqual(protocol['additional_labeled_rows'], 94500)
        self.assertEqual([item['fit_day'] for item in protocol['folds']], [15, 22, 29])
        self.assertEqual([item['validation']['start_day'] for item in protocol['folds']], [51, 58, 65])
        self.assertEqual(len(protocol['campaign']), 360)
        self.assertEqual(protocol['required_component_fit_calls'], 720)
        self.assertEqual(len({item['labeled_training']['namespace'] for item in protocol['folds']}), 3)
        for fold in protocol['folds']:
            self.assertEqual(fold['normal_fit']['records'], 50000)
            self.assertEqual(fold['labeled_training']['records'], 81500)
            self.assertEqual(fold['calibration']['READY'], 1000000)
            self.assertEqual(fold['calibration']['COLD'], 1000000)
            self.assertGreater(fold['training_to_calibration_gap_days_min'], 14)
            self.assertGreater(fold['calibration_to_validation_gap_days_min'], 14)
        self.assertEqual(protocol['holdout']['normal'], 10000000)
        self.assertEqual(protocol['holdout']['positive'], 10000)
        self.assertFalse(protocol['holdout']['numeric_read_permitted_before_selection'])

    def test_fresh_namespace_and_pilot_laundering_refused(self):
        for identifier in ('schema4-pilot-20261003-a01', 'hybrid-bulk-pilot-20261004-a01', '../private', True):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError): source_protocol(identifier)
        self.assertNotEqual(protocol_sha256(source_protocol('hybrid-strict-new-a01')),
                            protocol_sha256(source_protocol('hybrid-strict-new-a02')))

    def test_strict_manifest_exact_integers_and_matching_fold_checksums(self):
        protocol = source_protocol('hybrid-strict-new-a01')
        manifest = {'format': FORMAT, 'dataset_id': protocol['dataset_id'], 'stage': 'STRICT_SOURCE',
            'quality_gate': 'NOT_EVALUATED', 'protocol_sha256': protocol_sha256(protocol),
            'source_identity_before': {'fixture': 'CONTROL_ONLY_NOT_SOURCE_PROOF'},
            'source_identity_after': {'fixture': 'CONTROL_ONLY_NOT_SOURCE_PROOF'},
            'fit_or_score_calls': 0, 'holdout_numeric_records_read': 0,
            'fold_training_sections': {str(fold): {'fold': fold, 'normal_records': 50000, 'labeled_records': 81500,
                'class_counts': {'0': 71500, '1': 8000, '2': 2000}, 'normal_fit_sha256': 'a' * 64,
                'standard_fit_sha256': 'a' * 64, 'labeled_split_sha256': 'b' * 64} for fold in (1, 2, 3)}}
        self.assertIs(validate_manifest(manifest, protocol), manifest)
        for field in ('fit_or_score_calls', 'holdout_numeric_records_read'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_manifest(manifest | {field: False}, protocol)
        for change in ({'normal_records': True}, {'fold': True}, {'standard_fit_sha256': 'c' * 64}):
            changed = copy.deepcopy(manifest); changed['fold_training_sections']['1'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): validate_manifest(changed, protocol)
        changed = copy.deepcopy(manifest); changed['fold_training_sections']['1'] = None
        with self.assertRaises(ValueError): validate_manifest(changed, protocol)
        with self.assertRaises(ValueError): validate_manifest(manifest | {'stage': 'BULK_PILOT'}, protocol)

    def test_disk_preflight_does_not_assume_one_pilot_compression_ratio(self):
        safe = disk_plan()
        self.assertFalse(safe['compression_upper_verified'])
        self.assertGreater(safe['required_free_bytes'], 42 * 1024**3)
        require_space(42 * 1024**3, safe, generation_only=True)
        with self.assertRaises(ValueError): require_space(42 * 1024**3, safe)
        with self.assertRaises(ValueError): require_space(False, safe)
        for value in (0, True, -1):
            with self.assertRaises(ValueError): disk_plan(verified_compressed_artifact_upper_bytes=value)
        measured = disk_plan(verified_compressed_artifact_upper_bytes=8 * 1024**2)
        self.assertTrue(measured['compression_upper_verified'])
        self.assertEqual(measured['components_bytes']['765_retained_model_artifacts'], 765 * 8 * 1024**2)


if __name__ == '__main__': unittest.main()
