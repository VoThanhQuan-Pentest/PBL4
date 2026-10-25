"""Recovery boundary fixtures; not a model benchmark or raw-digest reconstruction."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

from test_prepare_ueba_strict import GENERATOR

PATH = Path(__file__).resolve().parents[1] / "scripts/resume-ueba-strict.py"
SPEC = importlib.util.spec_from_file_location("resume_strict_generator", PATH)
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


class RecoveryTest(unittest.TestCase):
    def test_partial_batch_prefix_is_not_appended_or_counted_twice(self):
        class Collector:
            def __init__(self): self.values = []
            def append(self, value): self.values.append(value)
        writer = Collector(); recovered = MODULE.PrefixWriter(writer, 3)
        for value in range(10): recovered.append(value)
        self.assertEqual(writer.values, list(range(3, 10)))
        self.assertEqual(recovered.appended, 7)
        self.assertEqual(recovered.skip, 0)

    def test_restoration_validates_numeric_shards_and_preserves_their_hashes(self):
        from app.policy import canonical
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "shards").mkdir()
            value = {"frame_id": "resume-owned-frame-0001", "account_id": "resume-owned-account-0001",
                     "window_start": "2026-06-01T00:00:00Z", "label": 0, "family": "normal", "cohort": "COLD",
                     "baseline_established": False, "trusted_window_count": 3,
                     "features": [2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]}
            path = root / "shards/fold1-validation-000000.json"; path.write_text(canonical([value]))
            writer, populations = MODULE.restored_writer(GENERATOR, root, "fold1-validation")
            self.assertEqual(populations["COLD"], 1)
            self.assertEqual(writer.shards[0]["sha256"], MODULE.digest(path))
            value["raw_body"] = "never-adopt-this"
            path.write_text(canonical([value]))
            with self.assertRaises(ValueError): MODULE.restored_writer(GENERATOR, root, "fold1-validation")


if __name__ == "__main__": unittest.main()
