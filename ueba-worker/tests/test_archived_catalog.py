"""Private archive-view boundaries, never benchmark or holdout evidence."""
import importlib.util
import lzma
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import archived_catalog as module
from app.catalog import ShardedDataset, sha256, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.policy import canonical

SCRIPT = Path(__file__).resolve().parents[2] / "observability/scripts/archive-ueba-owned-catalog.py"
SPEC = importlib.util.spec_from_file_location("owned_archive_test_script", SCRIPT)
ARCHIVER = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ARCHIVER)


def fixture(root, stage="PILOT"):
    root.mkdir(mode=0o700); (root / "shards").mkdir(mode=0o700)
    splits = {}
    for index, name in enumerate(("fold1-fit", "fold1-calibration-ready", "fold1-calibration-cold", "fold1-validation")):
        cohorts = ["COLD"] if "cold" in name else (["READY", "UNSEEN_READY", "COLD"] if "validation" in name else ["READY"])
        rows = []
        for offset, cohort in enumerate(cohorts):
            features = [0] * 37; features[0] = features[6] = features[7] = features[15] = 1
            positive = name == "fold1-validation" and offset == 0
            rows.append({"frame_id": f"archive-test-frame-{index:04d}-{offset:04d}",
                "account_id": f"archive-test-account-{index:04d}-{offset:04d}", "window_start": "2026-10-01T00:00:00Z",
                "label": int(positive), "family": "request_burst" if positive else "normal", "cohort": cohort,
                "baseline_established": cohort != "COLD", "trusted_window_count": 3 if cohort == "COLD" else 48,
                "features": features})
        raw = canonical(rows).encode(); identifier = f"archive-shard-{index:06d}"; relative = "shards/" + identifier + ".json"
        ARCHIVER.write_new(root / relative, raw)
        shard = {"id": identifier, "path": relative, "sha256": sha256(raw), **validate_rows(rows, 4)}
        split = {key: value for key, value in shard.items() if key not in ("id", "path", "sha256")}
        split["shards"] = [shard]; split["sha256"] = sha256(canonical(split).encode()); splits[name] = split
    manifest = {"catalog_schema_version": 2, "dataset_id": "archive-test-schema4", "stage": stage,
        "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
        "data_provenance": "DEMO_ONLY", "splits": splits}
    raw = canonical(manifest).encode(); ARCHIVER.write_new(root / "manifest.json", raw)
    return sha256(raw)


class ArchivedCatalogTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root / "source"
        self.sha = fixture(self.source); self.output = self.root / "archived"
        self.receipt = ARCHIVER.archive_owned_catalog(self.source, self.sha, self.output)
        self.sidecar_sha = self.receipt["archive_sidecar_sha256"]

    def dataset(self, sidecar_sha=None):
        return module.ArchivedShardedDataset(self.output, expected_sha256=self.sha,
                                            expected_archive_sha256=sidecar_sha or self.sidecar_sha)

    def rewrite_sidecar(self, change):
        path = self.output / module.SIDECAR
        document = module.parse_json(path.read_bytes()); change(document)
        raw = canonical(document).encode(); path.write_bytes(raw)
        return sha256(raw)

    def entry(self):
        document = module.parse_json((self.output / module.SIDECAR).read_bytes())
        relative = next(iter(document["shards"])); return relative, document["shards"][relative]

    def test_archive_only_preserves_manifest_descriptor_rows_and_mixed_labels(self):
        ordinary = ShardedDataset(self.source, expected_sha256=self.sha); archived = self.dataset()
        self.assertIsInstance(archived, ShardedDataset)
        self.assertEqual(archived.manifest, ordinary.manifest); self.assertEqual(archived.sha256, self.sha)
        self.assertEqual((self.output / "manifest.json").read_bytes(), (self.source / "manifest.json").read_bytes())
        for name in ordinary.manifest["splits"]:
            self.assertEqual(ordinary.load_shard(name, 0), archived.load_shard(name, 0))
        self.assertEqual([row["label"] for row in archived.load_shard("fold1-validation", 0)[1]], [1, 0, 0])
        self.assertTrue(self.receipt["archive_only_view_has_no_plain_shards"])
        self.assertEqual(self.receipt["source_files_deleted_or_renamed"], 0)

    def test_present_original_delegates_and_corruption_never_silently_falls_back(self):
        relative, _ = self.entry(); plain = self.output / relative
        ARCHIVER.write_new(plain, (self.source / relative).read_bytes())
        with patch.object(module, "restore_xz", side_effect=AssertionError("plain must win")):
            self.assertEqual(self.dataset()._read(relative, module.MAX_SHARD_BYTES), plain.read_bytes())
        plain.write_bytes(b"[]")
        with self.assertRaises(ValueError): self.dataset().load_shard("fold1-fit", 0)

    def test_two_hashes_are_required_and_sidecar_cannot_rebind_manifest(self):
        for manifest_sha, archive_sha in (("bad", self.sidecar_sha), (self.sha, "bad"), ("0" * 64, self.sidecar_sha), (self.sha, "0" * 64)):
            with self.assertRaises(ValueError):
                module.ArchivedShardedDataset(self.output, expected_sha256=manifest_sha, expected_archive_sha256=archive_sha)
        changed = self.rewrite_sidecar(lambda value: value.update(dataset_manifest_sha256="0" * 64))
        with self.assertRaises(ValueError): self.dataset(changed)

    def test_unsupported_sidecar_fields_versions_types_and_paths_rejected(self):
        original = (self.output / module.SIDECAR).read_bytes()
        attacks = (lambda value: value.update(extra=1), lambda value: value.update(archive_schema_version=True),
            lambda value: value.update(archive_format="PICKLE"), lambda value: value["shards"].pop(next(iter(value["shards"]))),
            lambda value: next(iter(value["shards"].values())).update(original_bytes=True),
            lambda value: next(iter(value["shards"].values())).update(archive_path="../outside.json.xz"),
            lambda value: next(iter(value["shards"].values())).update(original_sha256="0" * 64),
            lambda value: next(iter(value["shards"].values())).update(archive_bytes=module.MAX_XZ_BYTES + 1))
        for attack in attacks:
            (self.output / module.SIDECAR).write_bytes(original)
            with self.subTest(attack=attack), self.assertRaises(ValueError): self.dataset(self.rewrite_sidecar(attack))

    def test_bad_archive_bytes_wrong_restored_sha_and_missing_blob_rejected(self):
        relative, entry = self.entry(); path = self.output / entry["archive_path"]
        original = path.read_bytes(); path.write_bytes(original + b"changed")
        with self.assertRaises(ValueError): self.dataset()._read(relative, module.MAX_SHARD_BYTES)
        path.write_bytes(original); altered = dict(entry, original_sha256="0" * 64)
        with self.assertRaises(ValueError): module.restore_xz(self.output, altered)
        path.unlink()
        with self.assertRaises(ValueError): self.dataset()._read(relative, module.MAX_SHARD_BYTES)

    def test_concatenation_trailing_data_truncation_zipbomb_and_wrong_format_rejected(self):
        relative, entry = self.entry(); path = self.output / entry["archive_path"]
        original = path.read_bytes()
        cases = (original + original, original + b"junk", original[:-4], lzma.compress(b"x" * (module.MAX_SHARD_BYTES + 1), preset=0),
                 lzma.compress(b"[]", format=lzma.FORMAT_ALONE))
        for encoded in cases:
            path.write_bytes(encoded)
            altered = dict(entry, archive_sha256=sha256(encoded), archive_bytes=len(encoded))
            with self.subTest(bytes=len(encoded)), self.assertRaises(ValueError): module.restore_xz(self.output, altered)

    def test_xz_dictionary_memory_budget_is_enforced(self):
        _, entry = self.entry()
        with patch.object(module, "XZ_MEMORY_LIMIT", 1024), self.assertRaises(ValueError):
            module.restore_xz(self.output, entry)

    def test_public_metadata_and_invalid_direct_resource_types_rejected(self):
        for name in ("manifest.json", module.SIDECAR):
            path = self.output / name; path.chmod(0o644)
            with self.subTest(name=name), self.assertRaises(ValueError): self.dataset()
            path.chmod(0o600)
        for value in (None, True, [], "shards/unapproved-test.json", "../secret"):
            with self.subTest(value=value), self.assertRaises(ValueError): self.dataset()._read(value, module.MAX_SHARD_BYTES)
        relative, _ = self.entry(); dataset = self.dataset(); self.output.chmod(0o755)
        with self.assertRaises(ValueError): dataset._read(relative, module.MAX_SHARD_BYTES)

    def test_private_owner_modes_symlinks_and_resource_traversal_rejected(self):
        relative, entry = self.entry(); path = self.output / entry["archive_path"]
        path.chmod(0o644)
        with self.assertRaises(ValueError): self.dataset()._read(relative, module.MAX_SHARD_BYTES)
        path.chmod(0o600)
        with patch.object(module.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(ValueError): self.dataset()
        original = path.read_bytes(); path.unlink(); outside = self.root / "outside.xz"; ARCHIVER.write_new(outside, original); path.symlink_to(outside)
        with self.assertRaises(ValueError): self.dataset()
        with self.assertRaises(ValueError): module.resource_path(self.output, "../outside.xz")

    def test_plain_broken_symlink_directory_and_public_root_rejected(self):
        relative, _ = self.entry(); plain = self.output / relative; plain.symlink_to(self.root / "missing")
        with self.assertRaises(ValueError): self.dataset()._read(relative, module.MAX_SHARD_BYTES)
        plain.unlink(); (self.output / "shards").chmod(0o755)
        with self.assertRaises(ValueError): self.dataset()
        (self.output / "shards").chmod(0o700); self.output.chmod(0o755)
        with self.assertRaises(ValueError): self.dataset()

    def test_duplicate_json_and_nonfinite_sidecar_rejected(self):
        for raw in (b'{"archive_schema_version":1,"archive_schema_version":1}', b'{"archive_schema_version":NaN}'):
            (self.output / module.SIDECAR).write_bytes(raw)
            with self.assertRaises(ValueError): self.dataset(sha256(raw))

    def test_strict_constructor_reads_only_metadata_archiver_refuses_strict_and_existing_output(self):
        strict = self.root / "strict"; strict_sha = fixture(strict, stage="STRICT")
        with patch.object(ShardedDataset, "load_shard", side_effect=AssertionError("no STRICT rows")), self.assertRaises(ValueError):
            ARCHIVER.archive_owned_catalog(strict, strict_sha, self.root / "new-strict-view")
        with self.assertRaises(ValueError): ARCHIVER.archive_owned_catalog(self.source, self.sha, self.output)
        # A STRICT metadata view is permitted, with no automatic numeric reads.
        manifest = module.parse_json((self.output / "manifest.json").read_bytes()); manifest["stage"] = "STRICT"
        raw = canonical(manifest).encode(); (self.output / "manifest.json").write_bytes(raw)
        changed = self.rewrite_sidecar(lambda value: value.update(dataset_manifest_sha256=sha256(raw)))
        with patch.object(module, "restore_xz", side_effect=AssertionError("constructor must not read rows")):
            module.ArchivedShardedDataset(self.output, expected_sha256=sha256(raw), expected_archive_sha256=changed)


if __name__ == "__main__": unittest.main()
