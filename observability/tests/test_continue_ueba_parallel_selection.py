import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'observability/scripts/continue-ueba-parallel-selection.py'
SPEC = importlib.util.spec_from_file_location('continue_ueba_parallel_selection', SCRIPT)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class ContinueParallelSelectionTest(unittest.TestCase):
    def test_selection_requires_all_fits_and_validations_without_holdout_or_aws_change(self):
        complete = {'status': 'PARALLEL_FIT_VALIDATION_COMPLETE',
                    'completed_fits': 360, 'required_fits': 360,
                    'completed_validations': 360, 'required_validations': 360,
                    'quality_gate': 'NOT_RUN', 'holdout_scored': False, 'aws_changed': False}
        module.validate_selection_readiness(complete)
        for mutation in (
            {'completed_fits': 359},
            {'completed_validations': 359},
            {'status': 'RUNNING'},
            {'quality_gate': 'PASS'},
            {'holdout_scored': True},
            {'aws_changed': True},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.validate_selection_readiness({**complete, **mutation})

    def test_incomplete_campaign_is_rejected_before_full_identity_recheck(self):
        incomplete = {'status': 'RUNNING', 'completed_fits': 214, 'required_fits': 360,
                      'completed_validations': 153, 'required_validations': 360,
                      'quality_gate': 'NOT_RUN', 'holdout_scored': False, 'aws_changed': False}
        class FakeController:
            def private_dir(self, path):
                return path
            def read_private(self, path):
                return incomplete
        with self.assertRaisesRegex(ValueError, 'all 360 fit and validation receipts'):
            module.selection_preflight(FakeController(), Path('/private/campaign'))

    def test_selection_container_is_bounded_offline_and_uses_exact_hybrid_pins(self):
        plan = SimpleNamespace(
            code=Path('/private/code'), dataset=Path('/private/source/standard'),
            workspace=Path('/private/workspace'), image='sha256:' + 'a' * 64,
            identity={'model_kind': 'normal_plus_incident_research',
                      'dataset_sha256': 'b' * 64, 'archive_sha256': 'c' * 64})
        identity = {'campaign_id': '67aa86961dc1ce37453439c0'}
        command = module.selection_command(plan, identity, 'flare-ph-67aa8696-selection-a1b2c3d4', 5)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('--read-only', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--security-opt=no-new-privileges', command)
        self.assertNotIn('-p', command)
        self.assertNotIn('--publish', command)
        self.assertIn('app.selection', command)
        self.assertIn('choose', command)
        self.assertIn('--coordinated', command)
        self.assertIn('--max-new-recalibrations', command)
        self.assertEqual(command[-1], '5')
        self.assertIn('--dataset-sha256', command)
        self.assertIn('b' * 64, command)
        self.assertIn('--archive-sha256', command)
        self.assertIn('c' * 64, command)
        self.assertIn('--model-kind', command)
        self.assertIn('normal_plus_incident_research', command)
        with self.assertRaises(ValueError):
            module.selection_command(plan, identity, 'fixture', 0)
        with self.assertRaises(ValueError):
            module.selection_command(plan, identity, 'fixture', 46)
        with self.assertRaises(ValueError):
            module.selection_command(plan, identity, 'fixture', 5)

    def test_supervisor_timeout_covers_a_full_maximum_recalibration_batch(self):
        self.assertGreaterEqual(module.SELECTION_TIMEOUT_SECONDS, 45 * 8 * 60)


if __name__ == '__main__':
    unittest.main()
