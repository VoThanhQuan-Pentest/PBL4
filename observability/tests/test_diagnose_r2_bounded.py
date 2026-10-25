from collections import defaultdict, Counter
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("r2_diagnostic", SCRIPTS / "diagnose-ueba-r2-bounded.py")
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class BoundedR2DiagnosticTest(unittest.TestCase):
    def test_hash_sample_is_order_independent_with_fp_fn_and_control_caps(self):
        def sample(reverse):
            heaps = defaultdict(list)
            for i in (reversed(range(3000)) if reverse else range(3000)):
                row = {"frame_id": f"owned-frame-{i}", "cohort": ("READY", "UNSEEN_READY", "COLD")[i % 3],
                       "family": "normal"}
                for category in ("FP", "FN", "TN"):
                    diagnostic.keep_sample(heaps, row, category, {}, 0.0, 0.0, i)
            return sorted((key, tuple(sorted(item[1] for item in heap))) for key, heap in heaps.items())
        forward, backward = sample(False), sample(True)
        self.assertEqual(forward, backward)
        totals = Counter()
        for key, ids in forward:
            totals[key[0]] += len(ids)
        self.assertEqual(totals, {"FP": 200, "FN": 200, "TN": 200})

    def test_holdout_and_path_traversal_are_refused_before_file_access(self):
        for path in ("shards/holdout-owned.json", "../shards/fold1-validation-owned.json",
                     "/shards/fold1-validation-owned.json", "shards/fold2-validation-owned.json"):
            with self.assertRaisesRegex(ValueError, "validation shard paths"):
                diagnostic.read_validation_shard(Path("/nonexistent"), {"path": path}, {}, {})

    def test_source_archive_and_order_binding_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "shards").mkdir()
            original = json.dumps([{"label": 0}]).encode()
            archive = lzma.compress(original)
            relative = "shards/fold1-validation-owned.json"
            path = root / (relative + ".xz")
            path.write_bytes(archive)
            checksum = hashlib.sha256(original).hexdigest()
            descriptor = {"path": relative, "sha256": checksum, "records": 1}
            mapping = {relative: {"original_sha256": checksum, "original_bytes": len(original),
                                  "archive_path": relative + ".xz", "archive_bytes": len(archive),
                                  "archive_sha256": hashlib.sha256(archive).hexdigest()}}
            budget = {"compressed_bytes": 0, "decoded_bytes": 0}
            self.assertEqual(diagnostic.read_validation_shard(root, descriptor, mapping, budget), [{"label": 0}])
            path.write_bytes(b"x" * len(archive))
            with self.assertRaisesRegex(ValueError, "checksum"):
                diagnostic.read_validation_shard(root, descriptor, mapping, budget)

    def test_cache_names_bind_the_complete_identity(self):
        first = diagnostic.cache_path(Path("/fixture"), "scores", {"split": "validation", "model": "a"})
        self.assertNotEqual(first, diagnostic.cache_path(Path("/fixture"), "scores", {"split": "validation", "model": "b"}))
        self.assertNotEqual(first, diagnostic.cache_path(Path("/fixture"), "scores", {"split": "holdout", "model": "a"}))


if __name__ == "__main__":
    unittest.main()
