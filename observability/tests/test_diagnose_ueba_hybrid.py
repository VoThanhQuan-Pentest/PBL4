"""Bounded runner-control fixtures only, never scored pilot accuracy evidence."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/diagnose-ueba-hybrid.py'
SPEC = importlib.util.spec_from_file_location('isolated_hybrid_diagnostic', PATH)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def populations():
    def row(number, family='normal', prefix='fit', when='2026-04-15T12:00:00Z', cohort='READY'):
        return {'frame_id': prefix + '-frame-' + str(number), 'account_id': prefix + '-account-' + str(number),
                'window_start': when, 'label': int(family != 'normal'), 'family': family,
                'cohort': cohort, 'baseline_established': cohort != 'COLD', 'features': [0] * 37}
    normal = [row(i) for i in range(2000)]
    fresh = [row(i, 'normal' if i < 1000 else 'request_burst' if i < 1800 else 'http_error_burst', 'new')
             for i in range(2000)]
    old = {'fold1-fit': normal,
           'fold1-calibration-ready': [row(1, prefix='cal-ready', when='2026-05-03T00:00:00Z')],
           'fold1-calibration-cold': [row(1, prefix='cal-cold', when='2026-05-03T00:00:00Z', cohort='COLD')],
           'fold1-validation': [row(1, prefix='val', when='2026-05-21T00:00:00Z', cohort='UNSEEN_READY')]}
    return [*normal, *fresh], old


class HybridDiagnosticTest(unittest.TestCase):
    def test_predeclared_default_and_all24_are_fixed(self):
        self.assertEqual(runner.DEFAULT, (200, 31, 1))
        self.assertEqual(len(runner.CONFIGURATIONS), 24)
        self.assertEqual(len(set(runner.CONFIGURATIONS)), 24)
        self.assertIn(runner.DEFAULT, runner.CONFIGURATIONS)
        self.assertEqual(runner.STAGE, 'PILOT_DEMO_ONLY')

    def test_complete_training_reuses_only_exact_normal_fit(self):
        training, old = populations()
        checks = runner.separation_checks(training, old)
        self.assertEqual(checks['class_counts'], {'0': 3000, '1': 800, '2': 200})
        self.assertGreater(checks['training_to_calibration_gap_seconds'], 14 * 86400)
        self.assertTrue(checks['unseen_validation_accounts_excluded'])
        altered = [dict(training[0], features=[1] * 37), *training[1:]]
        with self.assertRaisesRegex(ValueError, 'shared unchanged'):
            runner.separation_checks(altered, old)

    def test_training_score_only_episode_and_unseen_account_overlap_rejected(self):
        for key in ('frame_id', 'account_id'):
            training, old = populations()
            training[2000] = dict(training[2000], **{key: old['fold1-validation'][0][key]})
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.separation_checks(training, old)
        training, old = populations()
        training[2000] = dict(training[2000], account_id=old['fold1-calibration-ready'][0]['account_id'],
                              window_start='2026-05-03T00:30:00Z')
        with self.assertRaisesRegex(ValueError, 'account-hour leakage'):
            runner.separation_checks(training, old)

    def test_fourteen_day_gap_is_strict_and_uses_latest_any_training(self):
        training, old = populations()
        training[-1] = dict(training[-1], window_start='2026-04-19T00:00:00Z')
        with self.assertRaisesRegex(ValueError, 'more than14'):
            runner.separation_checks(training, old)

    def test_context_class_diagnostic_is_descriptive_and_separate(self):
        records = [{'context_target': 0, 'predicted_context': 0, 'family': 'normal', 'cohort': 'READY'},
                   {'context_target': 1, 'predicted_context': 2, 'family': 'request_burst', 'cohort': 'UNSEEN_READY'},
                   {'context_target': 2, 'predicted_context': 2, 'family': 'http_error_burst', 'cohort': 'COLD'}]
        metrics = runner.context_metrics(records)
        self.assertEqual(metrics['complete_validation']['true_by_predicted_context'], [[1, 0, 0], [0, 0, 1], [0, 0, 1]])
        self.assertEqual(metrics['complete_validation']['one_vs_rest']['2']['fp'], 1)
        self.assertFalse(metrics['probabilities_calibrated'])
        self.assertEqual(metrics['quality_gate'], 'NOT_APPLICABLE')

    def test_fit_profiler_distinguishes_composite_and_component_frames_without_fitting(self):
        counter = runner.FitCounter()
        for code in counter.codes:
            counter.profile(SimpleNamespace(f_code=code), 'call', None)
        self.assertEqual(counter.counts, {'composite_fit_trials': 1, 'normal_component_fit_calls': 1,
                                         'supervised_component_fit_calls': 1})

    def test_refuses_host_before_any_training_or_pilot_access(self):
        with patch.dict(os.environ, {'UEBA_DIAGNOSTIC_IMAGE_ID': ''}), \
                patch.object(runner.fixed, 'load_pilot') as pilot, patch.object(runner, 'load_hybrid_fit') as training:
            with self.assertRaisesRegex(ValueError, 'Pinned Docker'):
                runner.run(None, Path('/private/training'), '0' * 64)
        pilot.assert_not_called(); training.assert_not_called()

    def test_new_private_output_and_complete_default_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            output = runner.protected_directory(root / 'new')
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            runner.fixed.write_private(output / 'receipt.json', {'plumbing_fixture': True})
            self.assertEqual((output / 'receipt.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                runner.protected_directory(output)
            with self.assertRaises(ValueError):
                runner.verify_default(None, {}, runner.fixed.ScorePolicy.strict(schema=4))


if __name__ == '__main__':
    unittest.main()
