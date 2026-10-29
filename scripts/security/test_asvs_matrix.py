import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('asvs_matrix', Path(__file__).with_name('asvs_matrix.py'))
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class EvidenceMatrixTest(unittest.TestCase):
    def setUp(self):
        self.matrix = MATRIX.seed('a' * 40)

    def evidence(self, kind='source_review', **fields):
        return {'kind': kind, 'source_sha': 'a' * 40, 'reference': 'source.java:15',
                'summary': 'Reviewed the enforcing control', **fields}

    def test_complete_catalog_is_seeded_without_a_compliance_claim(self):
        result = MATRIX.validate(self.matrix)
        self.assertEqual(253, result['counts']['NOT_VERIFIED'])
        self.assertFalse(result['asvs_l2_established_in_declared_environment'])
        with self.assertRaisesRegex(ValueError, 'not established'):
            MATRIX.validate(self.matrix, strict=True)

    def test_omitting_duplicating_or_rewriting_requirements_is_rejected(self):
        for change in ['omit', 'duplicate', 'rewrite']:
            m = copy.deepcopy(self.matrix)
            if change == 'omit': m['requirements'].pop()
            if change == 'duplicate': m['requirements'][1] = m['requirements'][0]
            if change == 'rewrite': m['requirements'][0]['description'] = 'weaker requirement'
            with self.subTest(change=change), self.assertRaises(ValueError):
                MATRIX.validate(m)

    def test_pass_requires_same_commit_evidence_and_actual_passing_tests(self):
        row = self.matrix['requirements'][0]
        row.update(status='PASS', rationale='Control and negative test checked')
        for evidence in [[], [self.evidence(source_sha='b' * 40)],
                         [self.evidence('automated_test', result='skipped')],
                         [self.evidence('automated_test', result='failed')],
                         [self.evidence('automated_test', result='not_run')]]:
            row['evidence'] = evidence
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                MATRIX.validate(self.matrix)
        row['evidence'] = [self.evidence('automated_test', result='passed')]
        self.assertEqual(1, MATRIX.validate(self.matrix)['counts']['PASS'])

    def test_nonapplicability_requires_a_source_based_explanation(self):
        row = self.matrix['requirements'][0]
        row.update(status='NOT_APPLICABLE', rationale='', evidence=[self.evidence()])
        with self.assertRaises(ValueError): MATRIX.validate(self.matrix)
        row.update(rationale='Feature absent in inspected route inventory',
                   evidence=[self.evidence('automated_test', result='passed')])
        with self.assertRaises(ValueError): MATRIX.validate(self.matrix)
        row['evidence'] = [self.evidence()]
        self.assertEqual(1, MATRIX.validate(self.matrix)['counts']['NOT_APPLICABLE'])

    def test_any_unresolved_or_failed_requirement_blocks_assurance(self):
        for row in self.matrix['requirements']:
            row.update(status='PASS', rationale='Reviewed fixture', evidence=[self.evidence()])
        self.assertTrue(MATRIX.validate(self.matrix, strict=True)['asvs_l2_established_in_declared_environment'])
        self.matrix['requirements'][-1].update(status='FAIL', rationale='Counterexample reproduced')
        with self.assertRaises(ValueError): MATRIX.validate(self.matrix, strict=True)


class ProgressReportTest(unittest.TestCase):
    def setUp(self):
        self.matrix = MATRIX.seed('a' * 40)
        states = ['PASS'] * 54 + ['FAIL'] * 22 + ['NOT_APPLICABLE'] * 62 + ['NOT_VERIFIED'] * 115
        for row, state in zip(self.matrix['requirements'], states):
            row['status'] = state
            if state != 'NOT_VERIFIED':
                row.update(rationale='Synthetic evidence fixture', evidence=[{
                    'kind': 'source_review', 'source_sha': 'a' * 40,
                    'reference': 'fixture.java:1', 'summary': 'Synthetic control review',
                }])
        self.checkpoint = {'pushed_sha': 'b' * 40, 'verified': {'assessment_progress': {
            'source_sha': 'a' * 40,
            'counts': {'PASS': 54, 'FAIL': 22, 'NOT_APPLICABLE': 62, 'NOT_VERIFIED': 115},
        }}}

    def test_reproduced_old_validator_acceptance_cannot_be_reported_as_current(self):
        # Validation of an old, internally consistent matrix was never a freshness check.
        self.assertEqual(54, MATRIX.validate(self.matrix)['counts']['PASS'])
        result = MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)
        self.assertEqual('HISTORICAL', result['snapshot_status'])
        self.assertIsNone(result['current_assessment']['completion_percent'])
        self.assertIsNone(result['current_assessment']['pass_percent'])
        self.assertEqual(39.8, result['assessment_snapshot']['completion_percent'])
        self.assertFalse(result['current_assessment']['asvs_l2_established'])
        with self.assertRaisesRegex(ValueError, 'historical'):
            MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40, require_current=True)

    def test_current_report_derives_counts_and_excludes_nonapplicable_requirements(self):
        self.checkpoint['pushed_sha'] = 'a' * 40
        result = MATRIX.progress(self.matrix, self.checkpoint, 'a' * 40, require_current=True)
        self.assertEqual('CURRENT', result['snapshot_status'])
        self.assertEqual(191, result['assessment_snapshot']['applicable'])
        self.assertEqual(76, result['assessment_snapshot']['concluded'])
        self.assertEqual({'completion_percent': 39.8, 'pass_percent': 28.3, 'asvs_l2_established': False},
                         result['current_assessment'])
        self.assertIsNone(result['overall_project_completion_percent'])

    def test_changed_cached_count_is_rejected_instead_of_silently_reused(self):
        self.checkpoint['verified']['assessment_progress']['counts']['PASS'] = 55
        with self.assertRaisesRegex(ValueError, 'cache disagrees'):
            MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)

    def test_changed_cached_source_is_rejected(self):
        self.checkpoint['verified']['assessment_progress']['source_sha'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'cache disagrees'):
            MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)

    def test_stale_candidate_checkpoint_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'candidate SHA disagrees'):
            MATRIX.progress(self.matrix, self.checkpoint, 'c' * 40)

    def test_green_ci_and_scoped_fix_do_not_promote_a_requirement_or_percentage(self):
        self.checkpoint['verified']['current_complete_ci'] = {'conclusion': 'success', 'sha': 'b' * 40}
        self.checkpoint['verified']['scoped_candidate'] = {'status': 'SCOPED_FIXED', 'sha': 'b' * 40}
        result = MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)
        self.assertEqual(115, result['assessment_snapshot']['counts']['NOT_VERIFIED'])
        self.assertIsNone(result['current_assessment']['completion_percent'])
        self.assertTrue(result['reassessment_required'])

    def test_missing_cache_and_invalid_current_sha_are_rejected(self):
        for checkpoint, sha in [({}, 'b' * 40), (self.checkpoint, 'short')]:
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                MATRIX.progress(self.matrix, checkpoint, sha)

    def test_malformed_checkpoint_documents_and_boolean_counts_are_rejected(self):
        malformed = [[], {'verified': []}, {'verified': {'assessment_progress': []}},
                     {'verified': {'assessment_progress': {'counts': []}}}]
        for checkpoint in malformed:
            with self.subTest(checkpoint=checkpoint), self.assertRaises(ValueError):
                MATRIX.progress(self.matrix, checkpoint, 'b' * 40)
        self.checkpoint['verified']['assessment_progress']['counts']['PASS'] = True
        with self.assertRaisesRegex(ValueError, 'cache disagrees'):
            MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)

    def test_zero_applicable_denominator_is_not_a_crash_or_a_completion_percentage(self):
        for row in self.matrix['requirements']:
            row.update(status='NOT_APPLICABLE', rationale='Synthetic absence', evidence=[{
                'kind': 'source_review', 'source_sha': 'a' * 40,
                'reference': 'fixture.java:1', 'summary': 'Synthetic absence review',
            }])
        self.checkpoint['verified']['assessment_progress']['counts'] = {'NOT_APPLICABLE': 253}
        result = MATRIX.progress(self.matrix, self.checkpoint, 'b' * 40)
        self.assertEqual(0, result['assessment_snapshot']['applicable'])
        self.assertIsNone(result['assessment_snapshot']['completion_percent'])


if __name__ == '__main__': unittest.main()
