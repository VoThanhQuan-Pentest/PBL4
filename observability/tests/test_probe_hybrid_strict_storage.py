"""Storage-only safety/unit tests; no genuine component fits or quality claims."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/probe-hybrid-strict-storage.py"
SPEC = importlib.util.spec_from_file_location("test_strict_storage_probe", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
from app.contract import FEATURE_NAMES_V4
from app.hybrid_incident import HybridResearchConfig
from app.hybrid_semantic import NODE_FIELDS, verifier_sha256


def numeric_fixture():
    config = HybridResearchConfig(100, 15, 0, 42)
    normal = MODULE.NormalSupportScorer(8, 256, "euclidean", 42)
    normal_state = {"state_version": 1, "parameters": normal.parameters(),
        "feature_names": list(FEATURE_NAMES_V4), "training_scope": "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED",
        "applicability": "UNQUALIFIED_RESEARCH_ONLY", "reference_count": 256, "fit_count": 256,
        "fit_rows": [[0.0] * 37 for _ in range(256)], "reference_indices": list(range(256)),
        "center": [0.0] * 37, "scale": [1.0] * 37}
    node = {name: [0.0 if code == "<f8" else 0] for name, code in NODE_FIELDS}
    node["count"], node["is_leaf"] = [60], [1]
    return {"state_format": MODULE.FORMAT, "state_version": 1, "verifier_sha256": verifier_sha256(),
        "parameters": MODULE.HybridIncidentScorer(config).parameters(), "normal_fit_count": 256,
        "labeled_fit_count": 60, "normal_state": normal_state,
        "classifier_state": {"classes": [0, 1, 2], "n_features": 37, "baseline": [[0.0] * 3],
            "bin_thresholds": [[] for _ in range(37)],
            "predictors": [[copy.deepcopy(node) for _ in range(3)] for _ in range(100)]}}


class StrictStorageProbeTest(unittest.TestCase):
    def test_source_hash_mismatch_rejects_before_any_pickle_load(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE.joblib, "load") as load:
            path = Path(folder) / "metadata.json"; path.write_text("{}"); path.chmod(0o600)
            with self.assertRaises(ValueError):
                MODULE.read_json(path, "0" * 64)
            load.assert_not_called()

    def test_private_regular_path_and_symlink_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / "public"; path.write_text("{}"); path.chmod(0o644)
            with self.assertRaises(ValueError): MODULE.private_path(path)
            path.chmod(0o600); link = root / "link"; link.symlink_to(path)
            with self.assertRaises(ValueError): MODULE.private_path(link)

    def test_storage_arrays_are_sorted_high_entropy_float64_and_reproducible(self):
        first = MODULE.synthetic_arrays(0, 1000); second = MODULE.synthetic_arrays(0, 1000)
        self.assertEqual(MODULE.array_receipts(first), MODULE.array_receipts(second))
        self.assertNotEqual(MODULE.array_receipts(first)["READY"]["sha256"], MODULE.array_receipts(first)["COLD"]["sha256"])
        for values in first.values():
            self.assertEqual(values.dtype.str, "<f8")
            self.assertEqual(len(MODULE.np.unique(values)), 1000)
            self.assertTrue(MODULE.np.all(values[1:] >= values[:-1]))
        for args in ((True, 100), (24, 100), (0, 99), (0, 1_000_001)):
            with self.assertRaises(ValueError): MODULE.synthetic_arrays(*args)

    def test_actual_plain_numeric_codec_roundtrip_without_any_fit(self):
        with tempfile.TemporaryDirectory() as folder:
            arrays = MODULE.synthetic_arrays(1, 100)
            with MODULE.ExitStack() as stack:
                for cls in (MODULE.HybridIncidentScorer, MODULE.NormalSupportScorer, MODULE.HistGradientBoostingClassifier):
                    stack.enter_context(patch.object(cls, "fit", side_effect=AssertionError("no test fits")))
                payload = {"model": numeric_fixture(), "calibration_scores": arrays["READY"], "calibration_by_cohort": arrays}
                identity = MODULE.state_sha256(payload)
                result = MODULE.compressed_copy(payload, Path(folder) / "copy.joblib", identity)
            self.assertTrue(result["exact_state_identical"])
            self.assertEqual(result["exact_state_sha256"], identity)
            self.assertEqual((Path(folder) / "copy.joblib").stat().st_mode & 0o777, 0o600)

    def test_existing_copy_cannot_be_overwritten_or_loaded(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE.joblib, "load") as load:
            path = Path(folder) / "copy"; path.write_bytes(b"keep")
            with self.assertRaises(ValueError): MODULE.compressed_copy({}, path, "0" * 64)
            self.assertEqual(path.read_bytes(), b"keep"); load.assert_not_called()

    def test_exact_original_binary_archive_preserves_bytes_and_never_loads_pickle(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE.joblib, "load") as load:
            root = Path(folder); source = root / "source"; source.write_bytes(b"known nonpickle bytes" * 100)
            source.chmod(0o600); original = MODULE.checksum(source)
            archive = root / "source.xz"
            result = MODULE.exact_byte_archive(source, original, archive)
            self.assertTrue(result["byte_for_byte_identical"])
            self.assertEqual(result["restored_original_sha256"], original)
            self.assertEqual(MODULE.checksum(source), original); load.assert_not_called()
            with self.assertRaises(ValueError): MODULE.exact_byte_archive(source, original, archive)
            with self.assertRaises(ValueError): MODULE.exact_byte_archive(source, "0" * 64, root / "bad.xz")
            self.assertFalse((root / "bad.xz").exists())

    def test_host_context_refused_before_source_load(self):
        with patch.dict(MODULE.os.environ, {}, clear=True), patch.object(MODULE, "verify_owned_grid") as verify:
            with self.assertRaises(ValueError): MODULE.run(Path("/unused/storage"))
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
