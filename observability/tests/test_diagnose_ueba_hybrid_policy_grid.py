"""Policy-grid plumbing fixtures, not model-performance proof."""

import importlib.util
from pathlib import Path
import sys
import unittest

import numpy as np

PATH = Path(__file__).resolve().parents[1] / "scripts/diagnose-ueba-hybrid-policy-grid.py"
SPEC = importlib.util.spec_from_file_location("test_fixed_hybrid_policy_grid", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ExistingPolicyGridTest(unittest.TestCase):
    def test_existing_sweep_has192_policies_and_real_qualification_key(self):
        values = MODULE.sweep(np.array([0., 100., 0.]), np.array([0, 1, 0], dtype="u1"),
            np.array([0, 1, 0], dtype="u1"), np.array([0, 1, 2], dtype="u1"), np.zeros((3, 3), dtype=bool), schema=4)
        self.assertEqual(len(values), 192)
        self.assertTrue(all("point_qualified_for_selection" in value for value in values))
        self.assertTrue(all(value["quality_gate"] == "NOT_APPLICABLE" for value in values))
        self.assertEqual(sum(value["point_qualified_for_selection"] for value in values), 0)

    def test_bad_output_refused_before_model_io(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError): MODULE.run(Path(folder))
