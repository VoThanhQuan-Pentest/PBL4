from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from postlogin_campaign_plan import build_plan


class CampaignPlanTest(unittest.TestCase):
    def test_all360_trials_keep_the_matching_fold_calendar(self):
        plan = build_plan('postlogin-lab-strict-v2-20261021')
        self.assertEqual(len({r['run_id'] for r in plan['trials']}), 360)
        for fold in plan['source_folds']:
            trials = [r for r in plan['trials'] if r['fold'] == fold['fold']]
            self.assertEqual(len(trials), 120)
            for trial in trials:
                self.assertEqual(trial['relative_protocol_days']['fit'], fold['fit_day'])
                self.assertEqual(trial['relative_protocol_days']['validation'],
                                 fold['validation']['start_day'])
        self.assertEqual(plan['required_component_fits'], 720)

    def test_plan_cannot_authorize_training_or_early_holdout(self):
        plan = build_plan('postlogin-lab-strict-v2-20261021')
        self.assertFalse(plan['training_admitted'])
        self.assertEqual(plan['new_fits'], 0)
        self.assertFalse(plan['holdout']['numeric_read_permitted_before_selection'])
        self.assertEqual(plan['failure_routes']['strict_gate_failed'],
                         'REPORT_NOT_QUALIFIED_WITHOUT_OPENING_HOLDOUT')
        phases = plan['phase_order']
        self.assertLess(phases.index('LOCK_SELECTION_BEFORE_HOLDOUT'),
                        phases.index('EVALUATE_SEALED_HOLDOUT'))

    def test_schedule_is_deterministic_and_rejects_pilot_aliases(self):
        self.assertEqual(build_plan('postlogin-lab-strict-v2-20261021'),
                         build_plan('postlogin-lab-strict-v2-20261021'))
        with self.assertRaises(ValueError):
            build_plan('postlogin-pilot-alias')


if __name__ == '__main__':
    unittest.main()
