"""Byte-copy and package boundary tests; not candidate quality evidence."""

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/install-qualified-ueba-candidate.py"
SPEC = importlib.util.spec_from_file_location("qualified_candidate_installer_under_test", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class QualifiedCandidateInstallerTest(unittest.TestCase):
    def test_fresh_holdout_manifest_requires_the_pinned_demo_populations(self):
        manifest = {
            "dataset_id": "fresh-demo-holdout-v1",
            "data_provenance": "DEMO_ONLY",
            "splits": {"holdout": {"normal": 10_000_000, "positive": 10_000, "sha256": "a" * 64}},
        }
        self.assertEqual(manifest["splits"]["holdout"],
                         INSTALLER.validate_fresh_holdout_manifest("b" * 64, manifest))

    def test_fresh_holdout_manifest_rejects_invalid_digest_or_wrong_population(self):
        manifest = {
            "dataset_id": "fresh-demo-holdout-v1",
            "data_provenance": "DEMO_ONLY",
            "splits": {"holdout": {"normal": 10_000_000, "positive": 10_000, "sha256": "a" * 64}},
        }
        with self.assertRaises(ValueError):
            INSTALLER.validate_fresh_holdout_manifest("not-a-sha", manifest)
        manifest["splits"]["holdout"]["normal"] -= 1
        with self.assertRaises(ValueError):
            INSTALLER.validate_fresh_holdout_manifest("b" * 64, manifest)

    def test_verified_quality_result_requires_both_scopes_and_accuracy_above_98_percent(self):
        scope = {"tp": 9_990, "fn": 10, "fp": 10, "tn": 10_000_000 - 10,
                 "quality_gate": "PASS"}
        evaluation = {"status": "SUCCEEDED", "quality_gate": "PASS",
            "evaluation_scope": "FROZEN_HOLDOUT", "actual_scored_episodes": 10_010_000,
            "scopes": {"MODEL_ONLY": dict(scope), "SIEM_FINAL": dict(scope)}}
        self.assertEqual(10_010_000, INSTALLER.require_verified_holdout_quality(evaluation))

        evaluation["scopes"]["SIEM_FINAL"]["tn"] = 9_799_800
        evaluation["scopes"]["SIEM_FINAL"].update(tp=10_000, fn=0, fp=200_200)
        with self.assertRaises(ValueError):
            INSTALLER.require_verified_holdout_quality(evaluation)

    def test_verified_quality_result_rejects_population_count_instead_of_document(self):
        with self.assertRaises(ValueError):
            INSTALLER.require_verified_holdout_quality(10_010_000)

    def test_package_reader_requires_exact_owner_group_mode_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "proof.json"
            path.write_bytes(b"metadata only")
            path.chmod(0o640)
            os.chown(path, os.geteuid(), 1000)
            self.assertEqual(path, INSTALLER.package_file(path, 1024))
            link = directory / "linked.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                INSTALLER.package_file(link, 1024)
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                INSTALLER.package_file(path, 1024)
            link.unlink()
            original = path.lstat()
            invalid_owner = os.stat_result(tuple(original)[:4] + (1001,) + tuple(original)[5:])
            with patch.object(Path, "lstat", return_value=invalid_owner):
                with self.assertRaises(ValueError):
                    INSTALLER.package_file(path, 1024)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                INSTALLER.package_file(path, 1024)

    def test_private_package_copy_preserves_exact_bytes_and_pins_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source.bin"
            destination = directory / "copy.bin"
            raw = bytes(range(256)) * 100
            source.write_bytes(raw)
            source.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            size = INSTALLER.copy_exact(source, destination, digest, maximum=1024 * 1024)
            self.assertEqual(len(raw), size)
            self.assertEqual(raw, destination.read_bytes())
            self.assertEqual(0o640, destination.stat().st_mode & 0o777)
            self.assertEqual(1000, destination.stat().st_gid)

    def test_package_copy_rejects_changed_source_digest_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source.bin"
            destination = directory / "copy.bin"
            source.write_bytes(b"candidate bytes")
            source.chmod(0o600)
            with self.assertRaises(ValueError):
                INSTALLER.copy_exact(source, destination, "0" * 64, maximum=1024)
            self.assertTrue(destination.exists())  # The failed attempt remains inspectable.
            self.assertEqual(b"candidate bytes", destination.read_bytes())
            self.assertEqual(0o640, destination.stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
