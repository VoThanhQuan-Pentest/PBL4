"""Private bulk boundary fixtures, never model-quality measurements."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from app.hybrid_bulk_dataset import load_hybrid_bulk_fit, private_read, training_targets
from app.policy import canonical


class HybridBulkDatasetTest(unittest.TestCase):
    def test_immutable_manifest_hash_required_before_io(self):
        for value in (None, True, "invalid", "0" * 63):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "immutable"):
                load_hybrid_bulk_fit("/nonexistent-bulk-fixture", value)

    def test_only_local_bulk_training_paths_allowed(self):
        for path in ("holdout.json", "shards/fold1-validation.json", "../manifest.private.json", "shards/expanded-calibration-cold-000000.json"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "training artifacts"):
                private_read(Path("/nonexistent-bulk-fixture"), path, 1)

    def test_fifo_symlink_and_oversized_files_refused(self):
        for kind in ("fifo", "symlink", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, path = Path(directory), Path(directory) / "manifest.private.json"
                if kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind == "symlink":
                    path.symlink_to(root / "absent.json")
                else:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        stream.write("too-large-fixture")
                with self.assertRaises(ValueError):
                    private_read(root, "manifest.private.json", 1)

    def test_malformed_or_boolean_schema_refused(self):
        for value in ([], {"hybrid_bulk_training_schema_version": True}, {"hybrid_bulk_training_schema_version": 1, "fit_or_score_calls": False}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root, data = Path(directory), canonical(value).encode()
                descriptor = os.open(root / "manifest.private.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                with self.assertRaises(ValueError):
                    load_hybrid_bulk_fit(root, hashlib.sha256(data).hexdigest())

    def test_context_targets_remain_explicit_and_not_attack_confirmations(self):
        rows = [{"label": 0, "family": "normal", "features": []},
                {"label": 1, "family": "request_burst", "features": []},
                {"label": 1, "family": "http_error_burst", "features": []}]
        self.assertEqual(training_targets(rows), [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
