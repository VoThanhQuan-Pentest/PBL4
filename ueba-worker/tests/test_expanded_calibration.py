"""Expanded-calibration boundary fixtures; no model fitting/scoring."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from app.expanded_calibration import load_expanded_calibration, private_read
from app.policy import canonical


class ExpandedCalibrationTest(unittest.TestCase):
    def test_hash_binding_required_before_input_io(self):
        for value in (None, True, "invalid", "0" * 63):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "immutable"):
                load_expanded_calibration("/nonexistent-contract-fixture", value)

    def test_other_splits_and_path_escapes_refused_before_io(self):
        for value in ("holdout.json", "shards/fold1-validation.json", "shards/incident-training-shared-000000.json", "../manifest.private.json"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "calibration-only"):
                private_read(Path("/nonexistent-contract-fixture"), value, 1)

    def test_fifo_symlink_and_oversize_refused(self):
        for kind in ("fifo", "symlink", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, path = Path(directory), Path(directory) / "manifest.private.json"
                if kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind == "symlink":
                    path.symlink_to(root / "nonexistent.json")
                else:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        stream.write("bounded-fixture")
                with self.assertRaises(ValueError):
                    private_read(root, "manifest.private.json", 1)

    def test_malformed_object_and_boolean_count_refused(self):
        for value in ([], {"expanded_calibration_schema_version": True}, {"expanded_calibration_schema_version": 1, "fit_or_score_calls": False}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = canonical(value).encode()
                descriptor = os.open(root / "manifest.private.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
                with self.assertRaises(ValueError):
                    load_expanded_calibration(root, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
