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


if __name__ == '__main__': unittest.main()
