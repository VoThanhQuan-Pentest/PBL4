"""Small restoration fixtures; no original experiment or AWS data removed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/archive-completed-ueba-experiment.py'
SPEC = importlib.util.spec_from_file_location('completed_archive', SCRIPT)
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)


class CompletedArchiveTest(unittest.TestCase):
    def fixture(self, root):
        source = root / 'owned-small-experiment'
        source.mkdir(mode=0o700)
        (source / 'empty-directory').mkdir()
        (source / 'empty-file').touch()
        (source / 'binary').write_bytes(bytes(range(256)) * 100)
        (source / 'strict-selection.json').write_text(json.dumps({
            'status': 'NO_QUALIFIED_CONFIG', 'actual_fits_completed': 360,
            'validation_runs_completed': 360, 'holdout_scored': False}))
        return source

    def test_archive_restores_every_file_byte_and_keeps_source_without_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            result = archive.archive_completed(source, root / 'checkpoint')
            self.assertEqual(result['regular_files'], 3)
            self.assertEqual(result['directories'], 2)
            self.assertFalse(result['uncompressed_source_removed'])
            self.assertTrue(source.exists())
            self.assertEqual(archive.sha(Path(result['archive'])), result['archive_sha256'])

    def test_symlink_or_nonterminal_source_never_archives_or_removes_user_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            (source / 'link').symlink_to(source / 'binary')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                archive.archive_completed(source, root / 'checkpoint')
            self.assertTrue(source.exists())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            (source / 'strict-selection.json').write_text('{"status":"RUNNING"}')
            with self.assertRaisesRegex(ValueError, 'completed'):
                archive.archive_completed(source, root / 'checkpoint')
            self.assertTrue(source.exists())

    def test_retirement_is_rejected_for_any_other_exact_target_after_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            with patch.object(archive.shutil, 'rmtree') as deletion:
                with self.assertRaisesRegex(ValueError, 'approved source'):
                    archive.archive_completed(source, root / 'checkpoint', retire=True)
                self.assertTrue(all(str(call.args[0]) != str(source) for call in deletion.call_args_list))
            self.assertTrue(source.exists())


if __name__ == '__main__':
    unittest.main()
