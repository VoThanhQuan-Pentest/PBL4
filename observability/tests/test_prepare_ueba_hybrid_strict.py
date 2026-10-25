"""Preparation boundary tests: no numeric source, holdout or model is opened."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/prepare-ueba-hybrid-strict.py'
SPEC = importlib.util.spec_from_file_location('isolated_hybrid_strict_preparation', PATH)
runner = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = runner; SPEC.loader.exec_module(runner)


class HybridStrictPreparationTest(unittest.TestCase):
    def test_host_refused_before_producer_or_numeric_io(self):
        with patch.dict(os.environ, {'UEBA_DIAGNOSTIC_IMAGE_ID': ''}), patch.object(runner, 'frozen_producer') as producer:
            with self.assertRaisesRegex(ValueError, 'pinned Docker'):
                runner.prepare('hybrid-strict-new-a01')
        producer.assert_not_called()


if __name__ == '__main__': unittest.main()
