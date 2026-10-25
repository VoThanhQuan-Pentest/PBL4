"""Compact opaque-byte fixtures are storage tests, never strict source evidence.

Only the full-population validator is mocked for small successful fixtures.
Production still invokes that unchanged frozen validator. Shard bytes are not
even JSON, proving neither holdout nor other numeric JSON can be parsed here.
"""
import fcntl
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/archive-ueba-strict-source.py"
SPEC = importlib.util.spec_from_file_location("strict_source_archive_test", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class StrictSourceArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.runtime = patch.object(M, "RUNTIME", self.base); self.runtime.start(); self.addCleanup(self.runtime.stop)
        self.run = self.base / "hybrid-strict-source-fixture-12345678"; self.run.mkdir(mode=0o700)
        self.parent = self.run / "source"; self.parent.mkdir(mode=0o700)
        self.source = self.parent / "standard"; self.source.mkdir(mode=0o700)
        (self.source / "shards").mkdir(mode=0o700); (self.source / "batches").mkdir(mode=0o700)
        for path in (self.parent / "writer.lock", self.source / "generation.lock"): path.touch(mode=0o600)
        self.identity = {"fixture": "terminal-control-only-not-real-source"}
        self.dataset_id = "strict-archive-dummy-fixture"
        self.protocol = {"dataset_id": self.dataset_id, "stage": "STRICT_SOURCE", "quality_gate": "NOT_EVALUATED"}
        self.marker = {"scope": "FULL_STRICT_SOURCE", "source_identity": self.identity,
                       "protocol": self.protocol, "protocol_sha256": M.protocol_sha256(self.protocol),
                       "fit_or_score_calls": 0, "holdout_numeric_records_read": 0}
        self.terminal = {"status": "COMPLETE_UNQUALIFIED_SOURCE", "stage": "STRICT_SOURCE", "scope": "FULL_STRICT_SOURCE",
                         "quality_gate": "NOT_EVALUATED", "folds_completed": [1, 2, 3],
                         "source_identity_before": self.identity, "source_identity_after": self.identity,
                         "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "downstream_holdout_numeric_records_read": 0}
        self.binding = {"fixture-producer": "a" * 64}
        self.generation = {"dataset_id": self.dataset_id, "stage": "STRICT", "source_binding": self.binding,
                           "old_numeric_corpus_read": False, "authentic_capture": False, "fit_or_score_calls": 0}
        self.write_json(self.source / "generation.identity.json", self.generation)
        names = [name for fold in (1, 2, 3) for name in (f"fold{fold}-fit", f"fold{fold}-calibration-ready",
                 f"fold{fold}-calibration-cold", f"fold{fold}-validation")] + ["holdout"]
        self.originals = {}; splits = {}
        for index, name in enumerate(names):
            identifier = f"strict-dummy-shard-{index:06d}"; relative = "shards/" + identifier + ".json"
            raw = b"\xff\x00NOT-NUMERIC-JSON:" + name.encode()
            path = self.source / relative; M.write_new(path, raw); self.originals[relative] = raw
            cohort = "COLD" if "cold" in name else "READY"
            shard = {"id": identifier, "path": relative, "sha256": M.sha256(raw), "records": 1, "normal": 1, "positive": 0,
                     "families": {"normal": 1}, "cohorts": {cohort: 1}, "from": "2026-04-15T00:00:00Z", "to": "2026-04-15T00:00:00Z"}
            split = {key: value for key, value in shard.items() if key not in ("id", "path", "sha256")}
            split["shards"] = [shard]; split["sha256"] = M.sha256(M.canonical(split).encode()); splits[name] = split
        from app.contract import FEATURE_NAMES_V4
        self.manifest = {"catalog_schema_version": 2, "dataset_id": self.dataset_id, "stage": "STRICT",
                         "data_provenance": "DEMO_ONLY", "feature_schema_version": 4, "telemetry_contract_version": 3,
                         "feature_names": list(FEATURE_NAMES_V4), "splits": splits, "source_binding": self.binding,
                         "generation_identity_sha256": M.sha256((self.source / "generation.identity.json").read_bytes())}
        self.write_json(self.source / "manifest.json", self.manifest)
        self.manifest_sha = M.sha256((self.source / "manifest.json").read_bytes())
        self.progress = {"status": "COMPLETED", "stage": "STRICT", "dataset_id": self.dataset_id,
                         "manifest_sha256": self.manifest_sha, "fit_or_score_calls": 0}
        self.write_json(self.source / "generation.progress.json", self.progress)
        self.write_json(self.parent / "predeclared.private.json", self.marker)
        self.write_json(self.parent / "state.private.json", self.terminal)
        batch = self.source / "batches" / "part00-batch000000"; batch.mkdir(mode=0o700)
        first = self.source / next(iter(self.originals)); self.committed = batch / first.name
        os.link(first, self.committed)
        self.receipt = batch / "receipt.json"; self.write_json(self.receipt, {"fixture": "committed bytes must remain unchanged"})

    def write_json(self, path, value):
        path.write_text(M.canonical(value)); path.chmod(0o600)

    def pins(self):
        return (M.sha256((self.source / "manifest.json").read_bytes()),
                M.sha256((self.parent / "predeclared.private.json").read_bytes()),
                M.sha256((self.parent / "state.private.json").read_bytes()))

    def invoke(self, *, pins=None, compact=True):
        with patch.object(M.ShardedDataset, "load_shard", side_effect=AssertionError("numeric rows must not be loaded")), \
                patch.object(M.ShardedDataset, "iter_shards", side_effect=AssertionError("holdout/row iterator must not run")):
            if compact:
                with patch.object(M, "validate_standard_manifest") as full_population:
                    result = M.archive_strict_source(self.source, *(pins or self.pins()))
                    full_population.assert_called_once()
                    return result
            return M.archive_strict_source(self.source, *(pins or self.pins()))

    def unchanged(self):
        for relative, raw in self.originals.items(): self.assertEqual((self.source / relative).read_bytes(), raw)
        self.assertFalse((self.source / M.SIDECAR).exists()); self.assertFalse((self.source / M.RESULT).exists())

    def test_low_disk_refuses_before_writing_archive_and_keeps_original_bytes(self):
        with patch.object(M, 'require_headroom', side_effect=ValueError('reserve fixture')):
            with self.assertRaisesRegex(ValueError, 'reserve fixture'): self.invoke()
        self.assertFalse(list((self.source / 'shards').glob('*.xz')))
        self.assertFalse((self.source / M.SIDECAR).exists())
        for relative, raw in self.originals.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)

    def test_archive_only_restores_opaque_holdout_bytes_and_preserves_batch_hardlinks(self):
        before_manifest = (self.source / "manifest.json").read_bytes(); before_receipt = self.receipt.read_bytes()
        original_inode = self.committed.stat().st_ino; original_links = self.committed.stat().st_nlink
        result = self.invoke()
        self.assertEqual(result["dataset_manifest_sha256"], self.manifest_sha)
        self.assertEqual(result["numeric_rows_parsed"], 0); self.assertEqual(result["holdout_numeric_records_read"], 0)
        self.assertEqual(result["original_files_deleted_or_renamed"], 0); self.assertEqual(result["archived_shards"], 13)
        self.assertEqual((self.source / "manifest.json").read_bytes(), before_manifest); self.assertEqual(self.receipt.read_bytes(), before_receipt)
        self.assertEqual(self.committed.stat().st_ino, original_inode); self.assertEqual(self.committed.stat().st_nlink, original_links)
        sidecar_raw = (self.source / M.SIDECAR).read_bytes()
        self.assertEqual(M.sha256(sidecar_raw), result["archive_sidecar_sha256"])
        document = M.parse_json(sidecar_raw)
        for relative, entry in document["shards"].items():
            self.assertEqual(M.restore_xz(self.source, entry), self.originals[relative])
            self.assertEqual((self.source / relative).read_bytes(), self.originals[relative])
        view = M.ArchivedShardedDataset(self.source, expected_sha256=self.manifest_sha,
                                       expected_archive_sha256=result["archive_sidecar_sha256"])
        self.assertEqual(view.sha256, self.manifest_sha)
        with self.assertRaises(ValueError): M.ArchivedShardedDataset(self.source, expected_sha256=self.manifest_sha, expected_archive_sha256="0" * 64)

    def test_both_live_generator_locks_refuse_before_creating_archives(self):
        for path in (self.parent / "writer.lock", self.source / "generation.lock"):
            with path.open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(ValueError, "live source"): self.invoke()
            self.assertFalse(any((self.source / "shards").glob("*.xz"))); self.unchanged()

    def test_missing_or_public_lock_is_not_created_or_chmodded(self):
        path = self.source / "generation.lock"; path.chmod(0o644)
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        path.unlink()  # Temporary fixture only.
        with self.assertRaises(OSError): self.invoke()
        self.assertFalse(path.exists()); self.unchanged()

    def test_hardlinked_lock_refuses_without_rejecting_payload_hardlinks(self):
        path = self.source / "generation.lock"; alias = self.base / "fixture-lock-alias"
        os.link(path, alias)
        with self.assertRaisesRegex(ValueError, "single-link"): self.invoke()
        self.unchanged(); self.assertFalse(any((self.source / "shards").glob("*.xz")))
        alias.unlink()  # Temporary fixture only.
        payload_alias = self.base / "fixture-third-payload-alias"; os.link(self.committed, payload_alias)
        self.assertEqual(self.committed.stat().st_nlink, 3)
        self.assertEqual(self.invoke()["status"], "COMPLETED")
        self.assertEqual(self.committed.stat().st_nlink, 3)
        self.assertEqual(payload_alias.read_bytes(), self.committed.read_bytes())

    def test_lock_path_replacement_before_and_after_flock_is_refused(self):
        path = self.source / "generation.lock"; private_stream = M.private_stream; flock = M.fcntl.flock
        def replace_path():
            path.rename(self.base / "fixture-displaced-lock")
            path.touch(mode=0o600)
        def open_and_replace(*args, **kwargs):
            source = private_stream(*args, **kwargs)
            if Path(args[0]) == path: replace_path()
            return source
        with ExitStack() as stack, patch.object(M, "private_stream", side_effect=open_and_replace):
            with self.assertRaisesRegex(ValueError, "unchanged source lock"): M.lock_existing(stack, path)
        (self.base / "fixture-displaced-lock").unlink()  # Temporary fixture only.
        def flock_and_replace(source, operation):
            flock(source, operation); replace_path()
        with ExitStack() as stack, patch.object(M.fcntl, "flock", side_effect=flock_and_replace):
            with self.assertRaisesRegex(ValueError, "unchanged source lock"): M.lock_existing(stack, path)
        self.unchanged()

    def test_lock_path_replacement_during_lifetime_is_refused(self):
        path = self.source / "generation.lock"
        with self.assertRaisesRegex(ValueError, "unchanged source lock"):
            with ExitStack() as stack:
                M.lock_existing(stack, path)
                path.rename(self.base / "fixture-displaced-lock"); path.touch(mode=0o600)
        self.unchanged()

    def test_explicit_wrong_sha_nonterminal_scoped_or_pilot_stage_is_refused(self):
        pins = self.pins()
        for index in range(3):
            changed = list(pins); changed[index] = "0" * 64
            with self.subTest(index=index), self.assertRaises(ValueError): self.invoke(pins=changed)
        for field, value in (("status", "STANDARD_SOURCE_RUNNING"), ("scope", "SCOPED_TEST"),
                             ("fit_or_score_calls", True), ("downstream_holdout_numeric_records_read", 1)):
            changed = dict(self.terminal, **{field: value}); self.write_json(self.parent / "state.private.json", changed)
            with self.subTest(field=field), self.assertRaises(ValueError): self.invoke()
        self.write_json(self.parent / "state.private.json", self.terminal)
        self.manifest["stage"] = "PILOT"; self.write_json(self.source / "manifest.json", self.manifest)
        with self.assertRaisesRegex(ValueError, "STRICT"): self.invoke()
        self.unchanged()

    def test_production_full_population_validator_is_never_bypassed(self):
        with self.assertRaisesRegex(ValueError, "complete normal READY FIT"): self.invoke(compact=False)
        self.unchanged(); self.assertFalse(any((self.source / "shards").glob("*.xz")))

    def test_symlink_traversal_or_old_source_root_cannot_be_archived(self):
        pins = self.pins(); link = self.parent / "linked-standard"; link.symlink_to(self.source, target_is_directory=True)
        for path in (link, self.source / ".." / "standard", self.parent, self.base):
            with self.subTest(path=str(path)), self.assertRaises(ValueError): M.archive_strict_source(path, *pins)
        first = self.source / next(iter(self.originals)); first.rename(first.with_suffix(".saved")); first.symlink_to(first.with_suffix(".saved"))
        with self.assertRaises(ValueError): self.invoke()
        self.assertFalse(any((self.source / "shards").glob("*.xz")))

    def test_changed_original_or_corrupt_restore_never_publishes_sidecar(self):
        first = self.source / next(iter(self.originals)); original = first.read_bytes(); first.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "byte checksum"): self.invoke()
        first.write_bytes(original)
        with patch.object(M, "restore_xz", return_value=b"corrupt restored bytes"), self.assertRaisesRegex(ValueError, "exact original"):
            self.invoke()
        self.unchanged()

    def test_existing_derived_artifacts_are_never_adopted_or_overwritten(self):
        for path in (self.source / M.SIDECAR, self.source / M.RESULT, self.source / (next(iter(self.originals)) + ".xz")):
            path.write_bytes(b"fixture-existing-artifact"); path.chmod(0o600)
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "existing archive"): self.invoke()
            self.assertEqual(path.read_bytes(), b"fixture-existing-artifact"); path.unlink()  # Temporary fixture only.
        self.unchanged()

    def test_corrupt_archive_is_detected_and_completed_archive_cannot_implicitly_resume(self):
        result = self.invoke(); sidecar = M.parse_json((self.source / M.SIDECAR).read_bytes())
        entry = next(iter(sidecar["shards"].values())); path = self.source / entry["archive_path"]
        path.write_bytes(b"corrupt-xz")
        with self.assertRaisesRegex(ValueError, "archive byte checksum"): M.restore_xz(self.source, entry)
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(result["original_files_deleted_or_renamed"], 0)
        for relative, raw in self.originals.items(): self.assertEqual((self.source / relative).read_bytes(), raw)

    def test_6489_shard_archive_topology_stays_within_unchanged_metadata_bound(self):
        # Metadata topology only: these descriptors never establish source rows.
        root = self.run / "metadata-only-view"; root.mkdir(mode=0o700); (root / "shards").mkdir(mode=0o700)
        template = self.manifest["splits"]["holdout"]["shards"][0]
        shards, entries = [], {}
        for index in range(6489):
            identifier = f"metadata-only-shard-{index:06d}"; relative = "shards/" + identifier + ".json"
            descriptor = {**template, "id": identifier, "path": relative}; shards.append(descriptor)
            entries[relative] = {"original_sha256": descriptor["sha256"], "original_bytes": 1,
                                 "archive_path": relative + ".xz", "archive_sha256": "0" * 64, "archive_bytes": 20}
        split = {"records": 6489, "normal": 6489, "positive": 0, "families": {"normal": 6489}, "cohorts": {"READY": 6489},
                 "from": template["from"], "to": template["to"], "shards": shards}
        split["sha256"] = M.sha256(M.canonical(split).encode())
        manifest_raw = M.canonical({**self.manifest, "splits": {"holdout": split}}).encode(); manifest_sha = M.sha256(manifest_raw)
        sidecar_raw = M.canonical({"archive_schema_version": 1, "archive_format": M.FORMAT,
                                  "dataset_manifest_sha256": manifest_sha, "shards": entries}).encode()
        self.assertLess(len(manifest_raw), M.MAX_MANIFEST_BYTES); self.assertLess(len(sidecar_raw), M.MAX_MANIFEST_BYTES)
        M.write_new(root / "manifest.json", manifest_raw); M.write_new(root / M.SIDECAR, sidecar_raw)
        with patch.object(M.ShardedDataset, "load_shard", side_effect=AssertionError("no row transport")), \
                patch.object(M.ShardedDataset, "iter_shards", side_effect=AssertionError("no holdout row transport")):
            view = M.ArchivedShardedDataset(root, expected_sha256=manifest_sha, expected_archive_sha256=M.sha256(sidecar_raw))
        self.assertEqual(len(view.split("holdout")["shards"]), 6489)


if __name__ == "__main__": unittest.main()
