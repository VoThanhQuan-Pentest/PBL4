"""Private backup boundaries and actual small legacy serving, not ML quality."""
from contextlib import nullcontext
import gzip
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from app.model import ModelStore
from app import restore_check
from app.restore_check import unpack_owned_backup, verify


class ModelRestoreCheckTest(unittest.TestCase):
    @staticmethod
    def raw_member(name="owned.txt", data=b"owned", kind=tarfile.REGTYPE, declared_size=None):
        member = tarfile.TarInfo(name); member.type = kind
        member.size = len(data) if declared_size is None else declared_size
        return member.tobuf(format=tarfile.GNU_FORMAT) + data + bytes(-len(data) % 512)

    @staticmethod
    def pax_record(key, value):
        payload = f" {key}={value}\n".encode(); size = len(payload) + 1
        while len(str(size)) + len(payload) != size: size = len(str(size)) + len(payload)
        return str(size).encode() + payload

    def assert_raw_refused_before_tarfile(self, raw, message, **limits):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / "owned.tar.gz"; target = root / "restore"; target.mkdir()
            archive.write_bytes(gzip.compress(raw)); checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            bounds = patch.multiple(restore_check, **limits) if limits else nullcontext()
            with bounds, patch.object(restore_check.tarfile, "open") as parse:
                with self.assertRaisesRegex(ValueError, message): unpack_owned_backup(archive, target, checksum)
                parse.assert_not_called()
            self.assertEqual(list(target.iterdir()), [])

    def test_path_traversal_symlinks_and_wrong_archive_checksum_are_refused(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE), ("linked", tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); archive = root / "owned.tar.gz"; target = root / "restore"; target.mkdir()
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo(name); member.type = kind
                    if kind == tarfile.REGTYPE: member.size = 1; stream.addfile(member, io.BytesIO(b"x"))
                    else: member.linkname = "../private"; stream.addfile(member)
                checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaises(ValueError): unpack_owned_backup(archive, target, checksum)
                with self.assertRaisesRegex(ValueError, "checksum"): unpack_owned_backup(archive, target, "0" * 64)

    def test_extension_body_budgets_are_checked_before_tarfile_allocates(self):
        for kind in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
            with self.subTest(kind=kind):
                raw = self.raw_member("extension", b"x" * 1025, kind) + self.raw_member() + bytes(1024)
                self.assert_raw_refused_before_tarfile(raw, "extension metadata", _MAX_EXTENSION_BYTES=1024)
                # Declared multi-gigabyte bodies must fail without even reading the body.
                raw = self.raw_member("extension", b"", kind, 8 * 1024 ** 3) + bytes(1024)
                self.assert_raw_refused_before_tarfile(raw, "extension metadata")

    def test_header_and_recursive_extension_counts_are_checked_before_tarfile(self):
        ordinary = b"".join(self.raw_member(f"owned-{index}", b"") for index in range(4)) + bytes(1024)
        self.assert_raw_refused_before_tarfile(ordinary, "too many", _MAX_HEADERS=3)
        extensions = b"".join(self.raw_member("extension", b"name\0", tarfile.GNUTYPE_LONGNAME)
                              for _ in range(4)) + self.raw_member() + bytes(1024)
        self.assert_raw_refused_before_tarfile(extensions, "too many", _MAX_HEADERS=3)
        self.assert_raw_refused_before_tarfile(extensions, "extension metadata", _MAX_EXTENSION_CHAIN=3)
        # Interleaving files cannot evade the cumulative metadata budget.
        separate = b"".join(self.raw_member("extension", f"owned-{index}\0".encode(), tarfile.GNUTYPE_LONGNAME)
                            + self.raw_member(f"owned-{index}") for index in range(4)) + bytes(1024)
        self.assert_raw_refused_before_tarfile(separate, "extension metadata", _MAX_TOTAL_EXTENSION_BYTES=24)

    def test_pax_layout_overrides_and_sparse_archives_are_refused_before_tarfile(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
            for key, value in (("size", "1"), ("GNU.sparse.size", "1"), ("GNU.sparse.map", "0,1"),
                               ("GNU.sparse.major", "1"), ("GNU.sparse.realsize", "8589934592")):
                with self.subTest(kind=kind, key=key):
                    raw = self.raw_member("pax", self.pax_record(key, value), kind) + self.raw_member() + bytes(1024)
                    self.assert_raw_refused_before_tarfile(raw, "PAX layout overrides")
        self.assert_raw_refused_before_tarfile(self.raw_member(kind=tarfile.GNUTYPE_SPARSE) + bytes(1024), "unsafe")
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
            with self.subTest(padding_kind=kind):
                body = self.pax_record("mtime", "1.25"); hidden = self.pax_record("size", "8589934592")
                padded = bytearray(self.raw_member("pax", body, kind))
                padded[512 + len(body):512 + len(body) + len(hidden)] = hidden
                self.assert_raw_refused_before_tarfile(bytes(padded) + self.raw_member() + bytes(1024), "PAX metadata padding")

    def test_member_bounds_and_malformed_body_positions_are_preflighted(self):
        raw = self.raw_member(declared_size=restore_check._MAX_MEMBER_BYTES + 1) + bytes(1024)
        self.assert_raw_refused_before_tarfile(raw, "unsafe or unbounded")
        self.assert_raw_refused_before_tarfile(self.raw_member(declared_size=8192) + bytes(1024), "incomplete")
        self.assert_raw_refused_before_tarfile(self.raw_member(kind=tarfile.DIRTYPE) + bytes(1024), "unsafe")
        self.assert_raw_refused_before_tarfile(self.raw_member("v7-directory/", kind=tarfile.AREGTYPE) + bytes(1024), "unsafe")
        self.assert_raw_refused_before_tarfile(self.raw_member() + bytes(512), "end marker")
        self.assert_raw_refused_before_tarfile(self.raw_member() + bytes(1024) + b"hidden" + bytes(506), "hidden data")
        header = bytearray(self.raw_member()); header[0] ^= 1
        self.assert_raw_refused_before_tarfile(bytes(header) + bytes(1024), "checksum")
        for body in (b"999 path=owned\n", b"0 path=owned\n", b"not-a-record", b"13 size=1\n\0\0\0"):
            with self.subTest(body=body):
                raw = self.raw_member("pax", body, tarfile.XHDTYPE) + self.raw_member() + bytes(1024)
                self.assert_raw_refused_before_tarfile(raw, "PAX")

    def test_all_expanded_gzip_bytes_including_hidden_padding_are_bounded(self):
        ordinary = self.raw_member() + bytes(1024)
        for raw in (ordinary + bytes(8192), ordinary + b"hidden" * 2048):
            with self.subTest(size=len(raw)):
                self.assert_raw_refused_before_tarfile(raw, "expanded.*budget", _MAX_EXPANDED_BYTES=4096)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / "restore"; target.mkdir(); archive = root / "owned.tar.gz"
            # A second gzip member is otherwise invisible to tarfile after tar EOF.
            archive.write_bytes(gzip.compress(ordinary) + gzip.compress(bytes(8192)))
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(restore_check, "_MAX_EXPANDED_BYTES", 4096), patch.object(restore_check.tarfile, "open") as parse:
                with self.assertRaisesRegex(ValueError, "expanded.*budget"): unpack_owned_backup(archive, target, checksum)
                parse.assert_not_called()
            self.assertEqual(list(target.iterdir()), [])

    def test_compressed_budget_corrupt_gzip_and_truncated_trailer_are_refused(self):
        raw = self.raw_member() + bytes(1024); compressed = gzip.compress(raw)
        for body, limits, message in ((compressed, {"_MAX_COMPRESSED_BYTES": len(compressed) - 1}, "bounded regular"),
                                      (b"not gzip", {}, "invalid compressed"),
                                      (compressed[:-4], {}, "invalid compressed"),
                                      (compressed + b"hidden", {}, "invalid compressed")):
            with self.subTest(message=message, size=len(body)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); target = root / "restore"; target.mkdir(); archive = root / "owned.tar.gz"
                archive.write_bytes(body); checksum = hashlib.sha256(body).hexdigest()
                bounds = patch.multiple(restore_check, **limits) if limits else nullcontext()
                with bounds, patch.object(restore_check.tarfile, "open") as parse:
                    with self.assertRaisesRegex(ValueError, message): unpack_owned_backup(archive, target, checksum)
                    parse.assert_not_called()
                self.assertEqual(list(target.iterdir()), [])

    def test_verified_compressed_snapshot_is_read_and_hashed_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / "restore"; target.mkdir(); archive = root / "owned.tar.gz"
            archive.write_bytes(gzip.compress(self.raw_member() + bytes(1024)))
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest(); decode = restore_check._decode_bounded_gzip
            actual_open = os.open; source_opens = []
            def track_open(path, flags, *args, **kwargs):
                if path == archive: source_opens.append(path)
                return actual_open(path, flags, *args, **kwargs)
            def replace_original(snapshot, expanded):
                archive.write_bytes(gzip.compress(self.raw_member(data=b"changed") + bytes(1024)))
                return decode(snapshot, expanded)
            with patch.object(restore_check.os, "open", side_effect=track_open), \
                    patch.object(restore_check.hashlib, "sha256", wraps=hashlib.sha256) as digest, \
                    patch.object(restore_check, "_decode_bounded_gzip", side_effect=replace_original):
                unpack_owned_backup(archive, target, checksum)
                self.assertEqual(digest.call_count, 1)
            self.assertEqual(len(source_opens), 1); self.assertEqual((target / "owned.txt").read_bytes(), b"owned")

    def test_ordinary_gnu_and_python_pax_timestamps_and_longnames_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); models = root / "models"; models.mkdir()
            long_directory = "d" * 80; long_name = "m" * 120 + ".json"
            (models / long_directory).mkdir(); (models / long_directory / long_name).write_bytes(b"owned")
            for format in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
                with self.subTest(format=format):
                    archive = root / f"python-{format}.tar.gz"; target = root / f"restore-{format}"; target.mkdir()
                    with tarfile.open(archive, "w:gz", format=format) as stream: stream.add(models, arcname=".")
                    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                    unpack_owned_backup(archive, target, checksum)
                    self.assertEqual((target / long_directory / long_name).read_bytes(), b"owned")
            archive = root / "gnu-command.tar.gz"; target = root / "gnu-restore"; target.mkdir()
            subprocess.run(["tar", "-czf", str(archive), "-C", str(models), "."], check=True, capture_output=True)
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest(); unpack_owned_backup(archive, target, checksum)
            self.assertEqual((target / long_directory / long_name).read_bytes(), b"owned")

    def test_actual_legacy_fit_backup_load_and_serving_preserve_selection_without_quality_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store = ModelStore(root / "models")
            rows = [[4 + index % 20,0,0,0,1,0,1,1,0,0,0] for index in range(600)]
            store.train("owned_legacy_fixture", rows, rows[:120]); store.activate("owned_legacy_fixture")
            archive = root / "owned.tar.gz"
            with tarfile.open(archive, "w:gz") as stream: stream.add(store.directory, arcname=".")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            result = verify(archive, checksum, "owned_legacy_fixture")
            self.assertTrue(result["passed"]); self.assertEqual(result["actual_vectors_scored"], 3)
            self.assertEqual(result["quality_gate"], "NOT_APPLICABLE"); self.assertEqual(result["model_fit_calls"], 0)
            self.assertFalse(result["cloud_primary_changed"])
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), checksum)


if __name__ == "__main__": unittest.main()
