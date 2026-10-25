"""Bytewise archival boundaries; no fit, scoring, or qualification fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/probe-hybrid-source-archives.py"
SPEC = importlib.util.spec_from_file_location("test_source_archive_probe", PATH)
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


class SourceArchiveProbeTest(unittest.TestCase):
    def test_exact_archive_and_bounded_json_restore_keep_original_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "source.json"
            source.write_text(json.dumps([{"features": [1.0] * 37}]), encoding="utf-8"); source.chmod(0o600)
            digest = MODULE.checksum(source)
            receipt = MODULE.archive_bytes(source, digest, root / "source.xz")
            self.assertEqual(MODULE.read_verified_archive(receipt), source.read_bytes())
            self.assertEqual(MODULE.checksum(source), digest)
            self.assertTrue(receipt["byte_for_byte_identical"])
            self.assertEqual((root / "source.xz").stat().st_mode & 0o777, 0o600)

    def test_bad_source_hash_existing_archive_or_public_source_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "source"; source.write_bytes(b"same" * 100); source.chmod(0o600)
            with self.assertRaises(ValueError): MODULE.archive_bytes(source, "0" * 64, root / "bad")
            self.assertFalse((root / "bad").exists())
            digest = MODULE.checksum(source); archive = root / "archive"
            MODULE.archive_bytes(source, digest, archive)
            with self.assertRaises(ValueError): MODULE.archive_bytes(source, digest, archive)
            source.chmod(0o644)
            with self.assertRaises(ValueError): MODULE.archive_bytes(source, digest, root / "public")

    def test_restore_rejects_wrong_archive_hash_blob_hash_and_size_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "source"; source.write_bytes(b"bounded" * 100); source.chmod(0o600)
            receipt = MODULE.archive_bytes(source, MODULE.checksum(source), root / "archive")
            for changed in ({**receipt, "archive_sha256": "0" * 64}, {**receipt, "original_sha256": "0" * 64},
                            {**receipt, "original_bytes": MODULE.MAX_JSON_BYTES + 1}):
                with self.assertRaises(ValueError): MODULE.read_verified_archive(changed)
            with self.assertRaises(ValueError): MODULE.read_verified_archive(receipt, maximum=100)
            with self.assertRaises(ValueError): MODULE.read_verified_archive(receipt, maximum=True)

    def test_inflated_archive_cannot_exceed_declared_restore_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "source"; source.write_bytes(b"b" * 1000); source.chmod(0o600)
            receipt = MODULE.archive_bytes(source, MODULE.checksum(source), root / "archive")
            receipt["original_bytes"] = 100
            with self.assertRaises(ValueError): MODULE.read_verified_archive(receipt, maximum=100)

    def test_catalog_path_escape_and_symlink_refused(self):
        with self.assertRaises(ValueError): MODULE.source_path("../outside")
        with self.assertRaises(ValueError): MODULE.source_path("/etc/passwd")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "source"; source.write_bytes(b"keep"); source.chmod(0o600)
            link = root / "link"; link.symlink_to(source)
            with self.assertRaises(ValueError): MODULE.trusted_source(link, MODULE.checksum(source))

    def test_host_refused_before_any_source_inspection(self):
        with patch.dict(MODULE.os.environ, {}, clear=True), patch.object(MODULE, "collect_sources") as collect:
            with self.assertRaises(ValueError): MODULE.run(Path("/unused"))
            collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
