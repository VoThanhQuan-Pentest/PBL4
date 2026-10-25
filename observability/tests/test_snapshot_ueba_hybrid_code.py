"""Private inert code fixtures only; no models, source rows, or authority."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("hybrid_code_snapshot_test", Path(__file__).resolve().parents[1] / "scripts/snapshot-ueba-hybrid-code.py")
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class HybridCodeSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / "private-backups"; self.backups.mkdir(mode=0o700)
        self.app = self.root / "ueba-worker/app"; self.app.mkdir(mode=0o700, parents=True)
        for name in ("__init__.py", "strict_campaign.py", "selection.py", "frozen_evaluation.py", "storage_budget.py", "pipeline_lock.py"):
            self.file(self.app / name, b"" if name == "__init__.py" else b"# inert source fixture\n")
        (self.app / "__pycache__").mkdir(mode=0o700)
        self.file(self.app / "__pycache__/unread-and-preserved.pyc", b"CACHE_NOT_READ")
        self.originals = {name: (M.ROOT / name).read_bytes() for name in M.TOOLS}
        for name in M.TOOLS:
            path = self.root / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.file(path, self.originals[name] if name != "ueba-worker/app/pipeline_lock.py" else b"# inert source fixture\n")
        self.output = self.backups / "hybrid-execution-code-fixture-12345678"
        self.patches = [patch.object(M, "ROOT", self.root), patch.object(M, "BACKUPS", self.backups), patch.object(M, "APP", self.app)]
        for value in self.patches: value.start(); self.addCleanup(value.stop)
        self.addCleanup(setattr, M.sys, "dont_write_bytecode", True)

    def file(self, path, raw): path.write_bytes(raw); path.chmod(0o600)

    def test_snapshot_exact_private_readback_and_outside_app_technical_receipt(self):
        before = {path.name: path.read_bytes() for path in self.app.iterdir() if path.suffix == ".py"}
        result = M.snapshot(self.output)
        self.assertEqual(result["copied_python_files"], 6)
        self.assertEqual(result["original_code_inventory_sha256_before"], result["original_code_inventory_sha256_after"])
        self.assertEqual(result["canonical_code_inventory_sha256"], result["original_code_inventory_sha256_before"])
        self.assertEqual(result["excluded_known_source_members"], ["__pycache__"])
        self.assertTrue((self.output / M.RECEIPT).is_file()); self.assertFalse((self.output / "app" / M.RECEIPT).exists())
        self.assertFalse((self.output / "app/__pycache__").exists())
        self.assertEqual((self.app / "__pycache__/unread-and-preserved.pyc").read_bytes(), b"CACHE_NOT_READ")
        for name, raw in before.items():
            self.assertEqual((self.app / name).read_bytes(), raw)
            self.assertEqual((self.output / "app" / name).read_bytes(), raw)
            self.assertEqual((self.output / "app" / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.output / "app").stat().st_mode & 0o777, 0o700)
        self.assertFalse(result["execution_approved"]); self.assertFalse(result["retirement_approved"])
        self.assertEqual(result["models_copied"], 0); self.assertEqual(result["fit_or_score_calls"], 0)
        self.assertEqual(set(result["technical_tool_pins"]), set(M.TOOLS))

    def test_existing_destination_refuses_without_overwrite(self):
        self.output.mkdir(mode=0o700); sentinel = self.output / "keep.private"; self.file(sentinel, b"KEEP")
        with self.assertRaisesRegex(ValueError, "fresh exact"): M.snapshot(self.output)
        self.assertEqual(sentinel.read_bytes(), b"KEEP")

    def test_unknown_symlink_nonregular_empty_noninit_and_oversize_are_refused(self):
        cases = (("extra.json", lambda path: self.file(path, b"{}")),
                 ("linked.py", lambda path: path.symlink_to(self.app / "selection.py")),
                 ("nested.py", lambda path: path.mkdir()),
                 ("empty.py", lambda path: self.file(path, b"")),
                 ("oversized.py", lambda path: self.file(path, b"x" * (M.MAX_FILE + 1))))
        for name, create in cases:
            path = self.app / name; create(path)
            with self.subTest(name=name), self.assertRaises(ValueError): M.snapshot(self.output)
            if path.is_dir(): path.rmdir()
            else: path.unlink()  # Only this test's temporary invalid fixture.
            self.assertFalse(self.output.exists())

    def test_known_cache_symlink_is_not_an_exclusion(self):
        cache = self.app / "__pycache__"
        (cache / "unread-and-preserved.pyc").unlink(); cache.rmdir()  # Private fixture only.
        cache.symlink_to(self.backups, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"): M.snapshot(self.output)

    def test_source_change_during_copy_refuses_receipt_and_preserves_partial(self):
        original = M.write_new
        def write(path, raw):
            original(path, raw)
            if path.name == "selection.py" and path.parent.name == "app":
                self.file(self.app / "selection.py", b"# changed fixture source\n")
        with patch.object(M, "write_new", side_effect=write), self.assertRaisesRegex(ValueError, "original Python"):
            M.snapshot(self.output)
        self.assertTrue(self.output.is_dir()); self.assertFalse((self.output / M.RECEIPT).exists())
        self.assertEqual((self.app / "selection.py").read_bytes(), b"# changed fixture source\n")


if __name__ == "__main__": unittest.main()
