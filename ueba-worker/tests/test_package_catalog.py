from pathlib import Path
import copy
import lzma
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.archived_catalog import ArchivedShardedDataset, FORMAT, SIDECAR
from app.catalog import ShardedDataset, parse_json, sha256, validate_rows
from app.operator_catalog import OperatorCatalog
from app.package_catalog import copy_checked, package_recipe, recipe_entry
from app.holdout_provenance import MARKER, require_unblocked_holdout
from app.policy import canonical
from app.strict_campaign import write
from test_calibration import fixture


class CataloguePackagingTest(unittest.TestCase):
    def audit_fixture(self, root):
        """Opaque no-shard fixture; not a campaign or qualification proof."""
        source = root / "source"; source.mkdir(mode=0o700)
        manifest = {"dataset_id": "future-audit-fixture", "splits": {}}
        write(source / "manifest.json", manifest); (source / "manifest.json").chmod(0o600)
        dataset = SimpleNamespace(root=source, manifest=manifest, sha256=sha256((source / "manifest.json").read_bytes()))
        entry = {"recipe_id": "future-audit-recipe", "dataset_id": manifest["dataset_id"], "mode": "PILOT"}
        audit = {"audit_schema_version": 1, "status": "BLOCKED", "dataset_id": manifest["dataset_id"],
                 "affected_split": "holdout", "reason": "INDETERMINATE_HOLDOUT_EXPOSURE", "acceptance_allowed": False,
                 "audit_id": "future-audit-only", "recorded_at_utc": "2026-10-05T00:00:00Z"}
        return source, dataset, entry, audit

    def test_protected_audit_survives_packaging_from_root_parent_or_both(self):
        for location in ("root", "parent", "both"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source, dataset, entry, audit = self.audit_fixture(root)
                raw = canonical(audit).encode()
                for parent in ((source,) if location == "root" else (root,) if location == "parent" else (source, root)):
                    (parent / MARKER).write_bytes(raw); (parent / MARKER).chmod(0o600)
                target = root / "catalog"
                with patch("app.package_catalog.ShardedDataset", return_value=dataset), \
                        patch("app.package_catalog.recipe_entry", side_effect=lambda *args, **kwargs: dict(entry)):
                    result = package_recipe(source, target, entry["recipe_id"], preview=True)
                    installed = target / entry["dataset_id"]; retained = installed / MARKER
                    self.assertEqual(retained.read_bytes(), raw); self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(result["holdout_access_audit_sha256"], sha256(raw))
                    with self.assertRaisesRegex(ValueError, "BLOCKED"): require_unblocked_holdout(installed)
                    self.assertEqual(package_recipe(source, target, entry["recipe_id"], preview=True), result)
                    retained.unlink()  # Only this test's temporary protected marker.
                    with self.assertRaisesRegex(ValueError, "audit changed or missing"):
                        package_recipe(source, target, entry["recipe_id"], preview=True)

    def test_conflicting_root_and_parent_audits_refuse_before_copying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, dataset, entry, audit = self.audit_fixture(root)
            for parent, value in ((source, audit), (root, audit | {"audit_id": "other-audit-only"})):
                (parent / MARKER).write_text(canonical(value)); (parent / MARKER).chmod(0o600)
            target = root / "catalog"
            with patch("app.package_catalog.ShardedDataset", return_value=dataset), \
                    patch("app.package_catalog.copy_checked") as copying:
                with self.assertRaisesRegex(ValueError, "conflicting protected holdout"):
                    package_recipe(source, target, entry["recipe_id"], preview=True)
                copying.assert_not_called()
            self.assertFalse(target.exists())

    def test_audit_added_during_copy_cannot_publish_an_unblocked_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, dataset, entry, audit = self.audit_fixture(root)
            target = root / "catalog"
            def copying(*args, **kwargs):
                copy_checked(*args, **kwargs)
                (source / MARKER).write_text(canonical(audit)); (source / MARKER).chmod(0o600)
            with patch("app.package_catalog.ShardedDataset", return_value=dataset), \
                    patch("app.package_catalog.recipe_entry", return_value=entry), \
                    patch("app.package_catalog.copy_checked", side_effect=copying):
                with self.assertRaisesRegex(ValueError, "audit changed during packaging"):
                    package_recipe(source, target, entry["recipe_id"], preview=True)
            self.assertFalse((target / entry["dataset_id"]).exists()); self.assertFalse((target / "catalog.json").exists())

    def archived_fixture(self, root):
        source = root / 'source'; source.mkdir(mode=0o700); dataset = fixture(source)
        rows = copy.deepcopy(dataset.load_shard('fold1-calibration-ready', 0)[1][:2])
        for index, row in enumerate(rows):
            row['frame_id'] = f'archive-package-holdout-frame-{index:06d}'
            row['account_id'] = f'archive-package-holdout-account-{index:06d}'
        identifier = 'archive-package-holdout-000001'; relative = 'shards/' + identifier + '.json'
        raw = canonical(rows).encode(); write(source / relative, rows)
        shard = {'id': identifier, 'path': relative, 'sha256': sha256(raw), **validate_rows(rows, 2)}
        split = {**validate_rows(rows, 2), 'shards': [shard]}; split['sha256'] = sha256(canonical(split).encode())
        manifest = copy.deepcopy(dataset.manifest); manifest['splits']['holdout'] = split
        write(source / 'manifest.json', manifest)
        for path in source.rglob('*'): path.chmod(0o700 if path.is_dir() else 0o600)
        dataset = ShardedDataset(source); archive = root / 'archived'
        archive.mkdir(mode=0o700); (archive / 'shards').mkdir(mode=0o700)
        copy_checked(source / 'manifest.json', archive / 'manifest.json', dataset.sha256, 8 * 1024 * 1024, private=True)
        archives = {}
        # Tiny storage fixtures only: no production retirement or archive authority.
        for part in dataset.manifest['splits'].values():
            for descriptor in part['shards']:
                plain = (source / descriptor['path']).read_bytes(); encoded = lzma.compress(plain, preset=0)
                archive_path = descriptor['path'] + '.xz'; path = archive / archive_path
                path.write_bytes(encoded); path.chmod(0o600)
                archives[descriptor['path']] = {'original_sha256': descriptor['sha256'], 'original_bytes': len(plain),
                    'archive_path': archive_path, 'archive_sha256': sha256(encoded), 'archive_bytes': len(encoded)}
        sidecar = {'archive_schema_version': 1, 'archive_format': FORMAT,
                   'dataset_manifest_sha256': dataset.sha256, 'shards': archives}
        write(archive / SIDECAR, sidecar); archive_sha = sha256(canonical(sidecar).encode())
        for descriptor in dataset.split('fold1-fit')['shards']:
            copy_checked(source / descriptor['path'], archive / descriptor['path'], descriptor['sha256'], 8 * 1024 * 1024, private=True)
        return source, dataset, archive, archive_sha, rows

    def test_preview_package_is_hash_bound_idempotent_and_never_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.mkdir(); dataset = fixture(source)
            target = root / "catalog"; entry = package_recipe(source, target, "owned-package-preview", preview=True)
            self.assertEqual(entry["mode"], "PILOT")
            actual = OperatorCatalog(target).recipe(entry["recipe_id"])
            self.assertEqual(actual.dataset.sha256, dataset.sha256); self.assertEqual(actual.mode, "PILOT")
            self.assertEqual(package_recipe(source, target, entry["recipe_id"], preview=True), entry)
            installed = ShardedDataset(target / dataset.manifest["dataset_id"])
            shard = installed.root / installed.split("fold1-fit")["shards"][0]["path"]
            self.assertEqual(shard.stat().st_mode & 0o777, 0o640)
            shard.write_text(shard.read_text() + "\n")
            with self.assertRaises(ValueError): package_recipe(source, target, entry["recipe_id"], preview=True)

    def test_preview_and_incomplete_selection_cannot_be_packaged_as_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.mkdir(); dataset = fixture(source)
            with self.assertRaises(ValueError): recipe_entry(dataset, "owned-strict-recipe")
            with self.assertRaises(ValueError): recipe_entry(dataset, "../private-file", preview=True)
            target = root / "catalog"; target.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError): package_recipe(source, target, "owned-package-preview", preview=True)

    def test_explicit_archive_package_copies_only_bound_bytes_and_later_reads_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, dataset, archive, archive_sha, rows = self.archived_fixture(root)
            target = root / 'catalog'
            with patch('app.archived_catalog.restore_xz', side_effect=AssertionError('packaging must not decode holdout')), \
                    patch.object(ArchivedShardedDataset, 'load_shard', side_effect=AssertionError('packaging must not parse any numeric rows')):
                entry = package_recipe(archive, target, 'owned-archive-preview', preview=True,
                                       expected_sha256=dataset.sha256, expected_archive_sha256=archive_sha)
                self.assertEqual(package_recipe(archive, target, entry['recipe_id'], preview=True,
                                               expected_sha256=dataset.sha256, expected_archive_sha256=archive_sha), entry)
            self.assertEqual(entry['archive_sha256'], archive_sha)
            installed = target / dataset.manifest['dataset_id']
            self.assertEqual((installed / 'manifest.json').read_bytes(), (source / 'manifest.json').read_bytes())
            self.assertEqual((installed / SIDECAR).read_bytes(), (archive / SIDECAR).read_bytes())
            for path in target.rglob('*'):
                self.assertFalse(path.is_symlink()); self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            recipe = OperatorCatalog(target).recipe(entry['recipe_id'])
            self.assertIsInstance(recipe.dataset, ArchivedShardedDataset)
            self.assertEqual(recipe.dataset.archive_sha256, archive_sha)
            self.assertEqual(recipe.dataset.manifest, dataset.manifest)
            self.assertEqual(recipe.dataset.load_shard('holdout', 0)[1], rows)
            fit_relative = dataset.split('fold1-fit')['shards'][0]['path']
            self.assertTrue((installed / fit_relative).is_file())
            holdout_relative = dataset.split('holdout')['shards'][0]['path']
            self.assertFalse((installed / holdout_relative).exists())
            (installed / (holdout_relative + '.xz')).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                package_recipe(archive, target, entry['recipe_id'], preview=True,
                               expected_sha256=dataset.sha256, expected_archive_sha256=archive_sha)

    def test_archive_opt_in_bad_pins_sidecar_and_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _, dataset, archive, archive_sha, _ = self.archived_fixture(root)
            for manifest_pin, archive_pin in ((None, archive_sha), (dataset.sha256, '0' * 64), ('0' * 64, archive_sha)):
                target = root / 'must-not-publish'
                with self.assertRaises(ValueError):
                    package_recipe(archive, target, 'owned-archive-preview', preview=True,
                                   expected_sha256=manifest_pin, expected_archive_sha256=archive_pin)
                self.assertFalse(target.exists())
            with self.assertRaises((ValueError, OSError)):
                package_recipe(archive, root / 'no-implicit-archive', 'owned-archive-preview', preview=True)
            sidecar = archive / SIDECAR; original = sidecar.read_bytes()
            document = parse_json(original); document['dataset_manifest_sha256'] = '0' * 64
            raw = canonical(document).encode(); sidecar.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'sidecar schema'):
                package_recipe(archive, root / 'bad-sidecar', 'owned-archive-preview', preview=True,
                               expected_sha256=dataset.sha256, expected_archive_sha256=sha256(raw))
            self.assertFalse((root / 'bad-sidecar').exists()); sidecar.write_bytes(original)
            relative = dataset.split('holdout')['shards'][0]['path'] + '.xz'
            (archive / relative).write_bytes((archive / relative).read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                package_recipe(archive, root / 'bad-blob', 'owned-archive-preview', preview=True,
                               expected_sha256=dataset.sha256, expected_archive_sha256=archive_sha)
            self.assertFalse((root / 'bad-blob').exists())

    def test_archived_operator_recipe_requires_protected_registry_and_both_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _, dataset, archive, archive_sha, _ = self.archived_fixture(root)
            target = root / 'catalog'; entry = package_recipe(archive, target, 'owned-archive-preview', preview=True,
                expected_sha256=dataset.sha256, expected_archive_sha256=archive_sha)
            registry = target / 'catalog.json'; original = parse_json(registry.read_bytes())
            for field, bad in (('archive_sha256', None), ('archive_sha256', '0' * 64), ('manifest_sha256', None)):
                changed = copy.deepcopy(original); changed['strict_entries'][0][field] = bad; write(registry, changed)
                with self.assertRaises(ValueError): OperatorCatalog(target).recipe(entry['recipe_id'])
            write(registry, original); registry.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'protected'): OperatorCatalog(target).recipe(entry['recipe_id'])
            registry.chmod(0o600); target.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'private'): OperatorCatalog(target).recipe(entry['recipe_id'])


if __name__ == "__main__": unittest.main()
