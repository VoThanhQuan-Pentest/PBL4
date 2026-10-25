"""No-fit plumbing contracts; not accuracy or strict calibration evidence."""

import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np

PATH = Path(__file__).resolve().parents[1] / "scripts/diagnose-ueba-hybrid-expanded-calibration.py"
SPEC = importlib.util.spec_from_file_location("test_hybrid_expanded", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ExpandedHybridDiagnosticTest(unittest.TestCase):
    def test_host_refused_before_any_data_access(self):
        with patch.dict(os.environ, {"UEBA_DIAGNOSTIC_IMAGE_ID": ""}), patch.object(MODULE.fixed, "load_pilot") as read:
            with self.assertRaisesRegex(ValueError, "pinned Docker"):
                MODULE.run(None, "0" * 64, None)
            read.assert_not_called()

    def test_chunk_scores_respects_model_bound_and_preserves_order(self):
        class FakeScoreOnly:
            def __init__(self): self.sizes = []
            def anomaly_scores(self, values):
                self.sizes.append(len(values))
                return np.array([row[0] for row in values], dtype=np.float64)
        scorer = FakeScoreOnly()
        rows = [{"features": [index]} for index in range(12001)]
        values = MODULE.chunk_scores(scorer, rows)
        self.assertEqual(scorer.sizes, [5000, 5000, 2001])
        np.testing.assert_array_equal(values, np.arange(12001))

    def test_nonfinite_chunk_result_rejected(self):
        class BadScoreOnly:
            def anomaly_scores(self, _rows): return np.array([np.nan])
        with self.assertRaises(ValueError):
            MODULE.chunk_scores(BadScoreOnly(), [{"features": [0]}])

    def test_original_recipe_and_policy_unchanged(self):
        self.assertEqual(MODULE.hybrid.DEFAULT, (200, 31, 1))
        self.assertEqual(MODULE.fixed.ScorePolicy.strict(schema=4).sha256,
                         "0ff8c6ba2ef950e6401b5d605bbd79e940060f00764a2f833054f17fa3ace759")
        self.assertEqual(MODULE.DEFAULT_SHA,
                         "925d00e73c8e89d4497d91b7fd1ec78ea70b25e0194138e70550e0e43d6af3f3")
