"""A reproducible snapshot is not mislabeled as a live-source equality proof."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('owned_restore_verifier', SCRIPTS / 'verify-aws-backup-restore.py')
restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)


class BackupInventoryReferenceTest(unittest.TestCase):
    def test_same_snapshot_requires_exact_backup_hash_and_import_origin(self):
        expected = {'inventory_origin': 'DISPOSABLE_LOCAL_FULL_IMPORT', 'backup_sha256': 'a' * 64}
        restore.validate_reference(expected, 'SAME_IMMUTABLE_BACKUP', 'a' * 64)
        with self.assertRaises(ValueError): restore.validate_reference(expected, 'SAME_IMMUTABLE_BACKUP', 'b' * 64)
        with self.assertRaises(ValueError): restore.validate_reference({}, 'SAME_IMMUTABLE_BACKUP', 'a' * 64)
        with self.assertRaises(ValueError): restore.validate_reference(None, 'SAME_IMMUTABLE_BACKUP', 'a' * 64)

    def test_restored_reference_cannot_claim_equality_to_an_observed_live_source(self):
        restore.validate_reference(None, 'SOURCE_CHECKPOINT', 'a' * 64)
        restore.validate_reference({'inventory_origin': 'READ_ONLY_LIVE_CAPTURE'}, 'SOURCE_CHECKPOINT', 'a' * 64)
        with self.assertRaises(ValueError):
            restore.validate_reference({'inventory_origin': 'DISPOSABLE_LOCAL_FULL_IMPORT'}, 'SOURCE_CHECKPOINT', 'a' * 64)

    def test_legacy_format_is_rejected_before_import_without_mutating_evidence(self):
        original = {'format': 'MYSQL_ALL_TABLES_SHA256_V1'}
        with self.assertRaises(ValueError): restore.validate_current_format(original)
        self.assertEqual(original, {'format': 'MYSQL_ALL_TABLES_SHA256_V1'})
        restore.validate_current_format(None)
        restore.validate_current_format({'format': 'MYSQL_ALL_TABLES_SHA256_V2'})

    def test_private_inventory_output_parent_is_created_and_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'private' / 'restore' / 'inventory.json'
            prepared = restore.prepare_private_output(output)
            self.assertEqual(prepared, output)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            output.write_text('{}')
            with self.assertRaises(ValueError):
                restore.prepare_private_output(output)
            link = root / 'linked'
            link.symlink_to(output.parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                restore.prepare_private_output(link / 'other.json')


if __name__ == '__main__': unittest.main()
