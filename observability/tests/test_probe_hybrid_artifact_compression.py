"""No migration tests: trusted tiny fixture and unchanged originals."""
import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

PATH = Path(__file__).resolve().parents[1] / "scripts/probe-hybrid-artifact-compression.py"
SPEC = importlib.util.spec_from_file_location("test_hybrid_compression", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CompressionCopyTest(unittest.TestCase):
    def test_bad_source_hash_or_existing_output_never_loads_pickle(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE.joblib, "load") as load:
            root = Path(folder); source = root / "source"; source.write_bytes(b"not_pickle"); source.chmod(0o600)
            with self.assertRaises(ValueError): MODULE.probe(source, "0" * 64, root / "new")
            with self.assertRaises(ValueError): MODULE.probe(source, MODULE.checksum(source), root)
            load.assert_not_called()

    def test_exact_semantic_roundtrip_does_not_refit_or_change_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            # Existing tiny native forest fixture is only an identity test.
            model = IsolationForest(n_estimators=2, max_samples=8, random_state=42).fit(np.arange(16).reshape(8, 2))
            source = root / "trusted.joblib"
            joblib.dump({"model": model, "calibration_scores": np.arange(100, dtype=float)}, source); source.chmod(0o600)
            original = MODULE.checksum(source)
            with patch.object(IsolationForest, "fit", side_effect=AssertionError("no probe fit")):
                result = MODULE.probe(source, original, root / "copies")
            self.assertEqual(MODULE.checksum(source), original)
            self.assertEqual(result["fit_or_activation_calls"], 0)
            self.assertTrue(all(case["semantic_state_identical"] for case in result["compressed_copies"]))
