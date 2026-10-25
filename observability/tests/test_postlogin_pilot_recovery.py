import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from postlogin_pilot_artifacts import publish_bundle, read_bundle, writer


class PilotRecoveryTest(unittest.TestCase):
    def kill_at(self, directory, point):
        script = """
import os,sys,signal
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from postlogin_pilot_artifacts import writer,publish_bundle
def fault(point):
    if point==sys.argv[3]:os.kill(os.getpid(),signal.SIGKILL)
with writer(Path(sys.argv[2])):
    publish_bundle(Path(sys.argv[2]),'fixture-unit',{'fixture':'NO_ESTIMATOR_NO_FITS'},{'model.bin':b'own-fixture'},fault=fault)
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(SCRIPTS), str(directory), point], timeout=10)
        self.assertEqual(result.returncode, -9)

    def test_sigkill_before_publish_leaves_only_pending_and_does_not_destroy_committed_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with writer(directory): publish_bundle(directory, "previous-unit", {"v": 1}, {"model.bin": b"committed"})
            before = (directory / "previous-unit.bundle.zip").read_bytes()
            self.kill_at(directory, "FILE_SYNCED")
            self.assertIsNone(read_bundle(directory, "fixture-unit", {"fixture": "NO_ESTIMATOR_NO_FITS"}))
            self.assertTrue(list(directory.glob(".pending-*")))
            self.assertEqual((directory / "previous-unit.bundle.zip").read_bytes(), before)
            with writer(directory):
                result = publish_bundle(directory, "fixture-unit", {"fixture": "NO_ESTIMATOR_NO_FITS"}, {"model.bin": b"own-fixture"})
            self.assertFalse(result["recovered"])

    def test_sigkill_after_published_bundle_recovers_without_replacing_model_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.kill_at(directory, "BUNDLE_PUBLISHED")
            before = (directory / "fixture-unit.bundle.zip").read_bytes()
            with writer(directory):
                result = publish_bundle(directory, "fixture-unit", {"fixture": "NO_ESTIMATOR_NO_FITS"}, {})
            self.assertTrue(result["recovered"])
            self.assertEqual(read_bundle(directory, "fixture-unit", {"fixture": "NO_ESTIMATOR_NO_FITS"}), {"model.bin": b"own-fixture"})
            self.assertEqual((directory / "fixture-unit.bundle.zip").read_bytes(), before)

    def test_sigkill_after_commit_reuses_verified_unit_without_a_second_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.kill_at(directory, "MARKER_COMMITTED")
            with writer(directory):
                result = publish_bundle(directory, "fixture-unit", {"fixture": "NO_ESTIMATOR_NO_FITS"}, {})
                self.assertTrue(result["reused"])
                with self.assertRaises(BlockingIOError):
                    with writer(directory): pass

    def test_committed_corruption_or_binding_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with writer(directory): publish_bundle(directory, "fixture-unit", {"v": 1}, {"model.bin": b"committed"})
            with self.assertRaises(ValueError): read_bundle(directory, "fixture-unit", {"v": 2})
            path = directory / "fixture-unit.bundle.zip"; value = bytearray(path.read_bytes()); value[50] ^= 1; path.write_bytes(value)
            with self.assertRaises(ValueError): read_bundle(directory, "fixture-unit", {"v": 1})


if __name__ == "__main__":
    unittest.main()
