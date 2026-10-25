"""No implicit archive discovery or relaxation of existing catalogue checks."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.owned_dataset import open_owned_dataset


class OwnedDatasetTest(unittest.TestCase):
    def test_actual_archive_factory_restores_identical_rows_without_fit_or_holdout(self):
        from test_archived_catalog import ARCHIVER, fixture
        from app.archived_catalog import ArchivedShardedDataset
        from app.catalog import ShardedDataset
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            checksum = fixture(source)
            target = root / "archive"
            result = ARCHIVER.archive_owned_catalog(source, checksum, target)
            archived = open_owned_dataset(target, expected_sha256=checksum,
                                          expected_archive_sha256=result["archive_sidecar_sha256"])
            ordinary = ShardedDataset(source, expected_sha256=checksum)
            self.assertIsInstance(archived, ArchivedShardedDataset)
            self.assertEqual(archived.sha256, ordinary.sha256)
            for name in ordinary.manifest["splits"]:
                self.assertEqual(list(archived.iter_shards(name)), list(ordinary.iter_shards(name)))
            self.assertEqual(result["fit_calls"], 0)
            self.assertEqual(result["holdout_rows_read"], 0)
            self.assertEqual(result["source_files_deleted_or_renamed"], 0)

    def test_plain_catalogue_keeps_existing_reader_and_optional_hash(self):
        root = Path("/operator/owned")
        with patch("app.owned_dataset.ShardedDataset") as plain, \
                patch("app.archived_catalog.ArchivedShardedDataset") as archived:
            self.assertIs(open_owned_dataset(root), plain.return_value)
            plain.assert_called_once_with(root, expected_sha256=None)
            archived.assert_not_called()
            plain.reset_mock()
            self.assertIs(open_owned_dataset(root, expected_sha256="a" * 64), plain.return_value)
            plain.assert_called_once_with(root, expected_sha256="a" * 64)
            archived.assert_not_called()

    def test_archive_needs_two_explicit_bindings_without_plain_fallback(self):
        root = Path("/operator/owned")
        with patch("app.owned_dataset.ShardedDataset") as plain, \
                patch("app.archived_catalog.ArchivedShardedDataset") as archived:
            with self.assertRaisesRegex(ValueError, "both explicitly trusted"):
                open_owned_dataset(root, expected_archive_sha256="b" * 64)
            plain.assert_not_called()
            archived.assert_not_called()
            self.assertIs(open_owned_dataset(root, expected_sha256="a" * 64,
                                            expected_archive_sha256="b" * 64), archived.return_value)
            archived.assert_called_once_with(root, expected_sha256="a" * 64,
                                             expected_archive_sha256="b" * 64)
            plain.assert_not_called()

    def test_invalid_archive_binding_never_falls_back_to_plain_reader(self):
        with patch("app.owned_dataset.ShardedDataset") as plain, \
                patch("app.archived_catalog.ArchivedShardedDataset", side_effect=ValueError("bad binding")):
            with self.assertRaisesRegex(ValueError, "bad binding"):
                open_owned_dataset(Path("/operator/owned"), expected_sha256="a" * 64,
                                   expected_archive_sha256="b" * 64)
            plain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
