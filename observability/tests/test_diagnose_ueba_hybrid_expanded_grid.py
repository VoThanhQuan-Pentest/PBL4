"""Control fixtures only; never scored expanded-grid qualification evidence."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/diagnose-ueba-hybrid-expanded-grid.py'
SPEC = importlib.util.spec_from_file_location('isolated_expanded_hybrid_grid', PATH)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class ExpandedHybridGridTest(unittest.TestCase):
    def test_exact24_grid_and_frozen_reference_receipts(self):
        self.assertEqual(len(runner.hybrid.CONFIGURATIONS), 24)
        self.assertEqual(len(set(runner.hybrid.CONFIGURATIONS)), 24)
        self.assertEqual(runner.EXPANDED_SHA, '05253075440b741a010ceae9b497d62acfa2c007952f11a13b91b5ae7443432d')
        self.assertEqual(runner.EXPANDED_DEFAULT_SHA, runner.fixed.checksum(runner.EXPANDED_DEFAULT))
        self.assertEqual(runner.ORIGINAL_GRID_SHA, runner.fixed.checksum(runner.ORIGINAL_GRID))

    def test_host_rejected_before_any_data_or_fit(self):
        with patch.dict(os.environ, {'UEBA_DIAGNOSTIC_IMAGE_ID': ''}), patch.object(runner.fixed, 'load_pilot') as load:
            with self.assertRaisesRegex(ValueError, 'Pinned Docker'):
                runner.run(None)
        load.assert_not_called()

    def test_matching_original_raw_hash_is_required(self):
        values = runner.np.arange(21000, dtype=float)
        reference = {'raw_score_sha256': runner.fixed.array_sha(values)}
        runner.assert_raw_reproduction(values, reference)
        altered = values.copy(); altered[-1] += 1
        with self.assertRaisesRegex(ValueError, 'ORIGINAL recipe'):
            runner.assert_raw_reproduction(altered, reference)
        with self.assertRaises(ValueError):
            runner.assert_raw_reproduction(values[:-1], reference)

    def test_validation_batch_boundaries_match_original1000(self):
        class BoundaryFixture:
            def __init__(self): self.sizes = []
            def anomaly_scores(self, features):
                self.sizes.append(len(features))
                return runner.np.asarray([row[0] for row in features], dtype=float)
        fixture = BoundaryFixture()
        rows = [{'features': [number]} for number in range(21000)]
        scores = runner.validation_raw_scores(fixture, rows)
        self.assertEqual(fixture.sizes, [1000] * 21)
        runner.np.testing.assert_array_equal(scores, runner.np.arange(21000))

    def test_incomplete_or_wrong_hash_reference_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            receipt = root / 'result.json'
            runner.fixed.write_private(receipt, {'status': 'PLUMBING_FIXTURE'})
            with self.assertRaisesRegex(ValueError, 'Exact complete'):
                runner.protected_receipt(receipt, '0' * 64)


if __name__ == '__main__':
    unittest.main()
