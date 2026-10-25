"""Small structural checks; no 50k catalogue or model quality claim."""

import importlib.util
from pathlib import Path
import sys
import unittest
import tempfile
import errno
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/assemble-ueba-hybrid-pilot-catalog.py"
SPEC = importlib.util.spec_from_file_location("test_hybrid_catalog_assembly", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def row(identity, account, date, cohort):
    return {"frame_id": identity, "account_id": account, "window_start": date, "cohort": cohort}


class HybridCatalogueAssemblyTest(unittest.TestCase):
    def data(self):
        normal = [row("train-frame", "known-account", "2026-04-15T00:00:00Z", "READY")]
        calibration = {"READY": [row("ready-frame", "known-account", "2026-05-03T00:00:00Z", "READY")],
                       "COLD": [row("cold-frame", "cold-account", "2026-05-03T00:00:00Z", "COLD")]}
        validation = [row("val-frame", "unseen-account", "2026-05-21T00:00:00Z", "UNSEEN_READY")]
        return normal, calibration, validation

    def test_real_history_gap_and_ready_unseen_rules(self):
        MODULE.verify_chronology(*self.data())
        normal, calibration, validation = self.data()
        calibration["READY"][0]["account_id"] = "unknown-account"
        with self.assertRaises(ValueError): MODULE.verify_chronology(normal, calibration, validation)

    def test_frame_hour_overlap_and_unseen_alias_rejected(self):
        for key, value in (("frame_id", "train-frame"), ("account_id", "known-account")):
            normal, calibration, validation = self.data()
            validation[0][key] = value
            with self.assertRaises(ValueError): MODULE.verify_chronology(normal, calibration, validation)

    def test_exact_fourteen_days_is_insufficient(self):
        normal, calibration, validation = self.data()
        calibration["READY"][0]["window_start"] = "2026-04-29T00:00:00Z"
        with self.assertRaises(ValueError): MODULE.verify_chronology(normal, calibration, validation)

    def test_bad_identity_refused_before_bulk_io(self):
        with self.assertRaises(ValueError): MODULE.assemble(None, None, None, "../escape")

    def test_cross_mount_copy_is_exact_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source", Path(directory) / "target"
            MODULE.write_new(source, {"fixture": "NO_REAL_CORPUS"})
            with patch.object(MODULE.os, "link", side_effect=OSError(errno.EXDEV, "cross mount")):
                self.assertEqual(MODULE.link_or_copy(source, target), "BYTE_VERIFIED_COPY")
                self.assertEqual(MODULE.sha(source), MODULE.sha(target))
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): MODULE.link_or_copy(source, target)
