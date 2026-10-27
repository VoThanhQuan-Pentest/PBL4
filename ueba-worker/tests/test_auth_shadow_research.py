import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from app import auth_shadow_research as research


class OfflineSelectionTest(unittest.TestCase):
    def test_calibration_budget_does_not_exceed_a42_with_tied_scores(self):
        raw = np.array([4., 4., 3., 2., 10.])
        contexts = np.array([1, 1, 1, 0, 1])
        labels = np.array([0, 0, 0, 0, 1])
        reference = np.array([True, False, False, False, False])
        threshold = research.threshold_for(raw, contexts, labels, reference)
        self.assertLessEqual(int(((raw >= threshold) & (contexts == 1) & (labels == 0)).sum()), 1)

    def test_metrics_and_nonregression_require_each_family_and_each_legitimate_group(self):
        metadata = [{'family': family, 'recipe': recipe, 'account_group': account}
                    for family, recipe, account in [('routine', 'a', 'n1'), ('routine', 'b', 'n2'),
                        ('case3', 'case3', 'r1'), ('case4', 'case4', 'r2'), ('case5', 'case5', 'r3'),
                        ('operational', 'operational', 'o1')]]
        labels = np.array([0, 0, 1, 1, 1, 2]); contexts = np.array([0, 0, 1, 1, 1, 2])
        reference = research.metrics(np.array([True, False, True, True, True, False]), contexts, labels, metadata)
        candidate = research.metrics(np.array([False, True, True, True, True, False]), contexts, labels, metadata)
        self.assertFalse(research.nonregression(candidate, reference, evaluation=True))
        candidate = research.metrics(np.array([False, False, True, True, False, False]), contexts, labels, metadata)
        self.assertFalse(research.nonregression(candidate, reference, evaluation=True))
        candidate = research.metrics(np.array([False, False, True, True, True, False]), contexts, labels, metadata)
        self.assertTrue(research.nonregression(candidate, reference, evaluation=True))
        self.assertEqual(candidate['accounts']['review']['groups_with_review'], 3)

    def test_paired_bootstrap_compares_the_same_account_groups(self):
        labels = np.array([0, 0, 1, 1])
        metadata = [{'account_group': value} for value in ('a', 'b', 'a', 'b')]
        flags = np.array([False, True, True, False])
        result = research.paired_account_bootstrap(flags, flags, labels, metadata)
        self.assertEqual(result['groups'], 2)
        self.assertEqual(result['false_review_rate_difference_ci95'], [0.0, 0.0])
        self.assertEqual(result['recall_difference_ci95'], [0.0, 0.0])

    def test_admit_selection_never_opens_held_out_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            research.write_new(root / 'protocol.json', {'format': 'AUTH_CONTEXT_RESEARCH_V2', 'seed': 20261027,
                'schema': 7, 'features': 81, 'recipes': list(research.RECIPES), 'seeds': list(research.SEEDS),
                'expected_worker_image': 'sha256:4a37528fba90444305c2bf7eb685e1fad6750cc146435c582ee024dcf82acd2b',
                'expected_producer_image': 'sha256:02495bec4b4ec7024f86829b10464c7a283d1a2ecc398858b4eada2f2ae7e628',
                'normal_recipes': list(research.NORMAL_RECIPES),
                'quotas': {k: list(v) for k, v in research.CLASS_QUOTAS.items()} | {'controls': [5000, 5000, 0]}})
            manifest = {'format': 'AUTH_CONTEXT_LAB_SOURCE_V1', 'status': 'SOURCE_CAPTURE_COMPLETE', 'records': 100000,
                        'data_provenance': 'CONTROLLED_CLOCK_LAB', 'feature_schema_version': 7,
                        'protocol_sha256': research.digest(root / 'protocol.json'), 'splits': {}}
            for split, count in research.QUOTAS.items():
                name = split + '.jsonl.gz'; groups = [f'{split}-{i}' for i in range(200)]
                entry = {'records': count, 'file': name, 'raw_file': split + '-raw.jsonl.gz',
                         'sha256': hashlib.sha256(split.encode()).hexdigest(), 'account_groups': groups}
                manifest['splits'][split] = entry
                if split in ('train', 'calibration', 'development'):
                    (root / name).write_bytes(split.encode())
            research.write_new(root / 'manifest.json', manifest)
            research.write_new(root / 'producer-parity.json', {'status': 'HARNESS_REEXPORT_PARITY_PASS',
                'records': 100000, 'feature_count': 81, 'manifest_sha256': research.digest(root / 'manifest.json'),
                'protocol_sha256': research.digest(root / 'protocol.json')})
            research.admit(root, ('train', 'calibration', 'development'))
            with self.assertRaises(FileNotFoundError):
                research.admit(root, ('evaluation',))

    def test_evaluation_cannot_start_before_selection_and_receipts_are_immutable(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            research.write_new(root / 'selection.json', {'status': 'STOP_NO_IMPROVEMENT'})
            with self.assertRaises(FileExistsError):
                research.write_new(root / 'selection.json', {'status': 'SELECTED'})
            with patch.object(research, 'ResourceGuard'):
                with self.assertRaisesRegex(RuntimeError, 'frozen successful selection'):
                    research.evaluate(root, root)
            self.assertFalse((root / 'evaluation-started.json').exists())

    def test_benchmark_requires_successful_research_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            research.write_new(root / 'selection.json', {'status': 'SELECTED'})
            research.write_new(root / 'research-receipt.json', {'status': 'STOP_NO_IMPROVEMENT'})
            with patch.object(research, 'ResourceGuard'):
                with self.assertRaisesRegex(RuntimeError, 'successful frozen research receipt'):
                    research.benchmark(root, root)
            self.assertFalse((root / 'benchmark-started.json').exists())

    def test_four_reserved_fits_freeze_one_selection_before_single_evaluation(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder); data = root / 'data'; out = root / 'result'
            data.mkdir(); out.mkdir()
            labels = np.array([0, 0, 1, 1, 1, 2], dtype=np.uint8)
            values = np.zeros((len(labels), 81))
            metadata = [{'family': family, 'recipe': recipe, 'account_group': account,
                         'episode_id': account, 'session_group': account, 'as_of': '2026-01-01T00:00:00Z', 'trusted': 30}
                        for family, recipe, account in [('routine', 'a', 'group-a'), ('routine', 'b', 'group-b'),
                            ('case3', 'case3', 'group-a'), ('case4', 'case4', 'group-b'), ('case5', 'case5', 'group-a'),
                            ('operational', 'operational', 'group-b')]]
            baseline = SimpleNamespace(directory=root / 'baseline', verify_identity=lambda: None)
            shadow = SimpleNamespace(directory=root / 'shadow', baseline=baseline, state={'id': 'a42'},
                                     manifest={'threshold': 0.5})
            raw = np.array([0., 0., 1., 1., 1., 0.])
            contexts = np.array([0, 0, 1, 1, 1, 2])
            def comparator(state, threshold, rows, model, guard):
                flags = np.array([state.get('id') == 'a42', False, True, True, True, False])
                return flags, contexts
            class FakeClassifier:
                def _raw_predict(self, rows): return np.zeros((len(rows), 3))
            fit = stack.enter_context(patch.object(research, 'fit_classifier', side_effect=lambda *a: FakeClassifier()))
            replacements = {
                'ResourceGuard': lambda *a: SimpleNamespace(check=lambda **kw: None),
                'admit': lambda *a: ({}, {}, {'source': 'same'}),
                'models': lambda: (shadow, baseline), 'model_identity': lambda *_: {'model': 'same'},
                'check_output': lambda *a, **k: None,
                'rows_for': lambda *a: (values, labels, metadata),
                'comparator': comparator, 'candidate_scores': lambda *a: (raw, contexts),
                'export_classifier': lambda *a: {'id': 'candidate'},
                'logits': lambda state, rows: np.zeros((len(rows), 3)),
                'validate_state': lambda value: value,
                'check_controls': lambda *a: {'cold': 5000, 'missing': 5000},
                'baseline_scores': lambda *a: (np.array([False, False, True, True, True, False]), contexts),
            }
            for name, value in replacements.items():
                stack.enter_context(patch.object(research, name, value))
            research.select(data, out)
            self.assertEqual(fit.call_count, 4)
            selected = research.load_json(out / 'selection.json')
            self.assertEqual(selected['candidate']['id'], 'A-42')
            self.assertFalse(selected['evaluation_opened'])
            self.assertFalse((out / 'evaluation-started.json').exists())
            research.evaluate(data, out)
            receipt = research.load_json(out / 'research-receipt.json')
            self.assertEqual(receipt['status'], 'RESEARCH_PASS')
            self.assertEqual(receipt['classifier_fits'], 4)
            self.assertEqual(receipt['normal_fits'], 0)
            with self.assertRaises(FileExistsError):
                research.evaluate(data, out)
            self.assertEqual(fit.call_count, 4)


if __name__ == '__main__':
    unittest.main()
