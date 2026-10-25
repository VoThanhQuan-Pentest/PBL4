"""Only private temporary fixtures are retired in these tests, never real data."""
import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import struct
import unittest
from unittest.mock import patch
import fcntl

PATH = Path(__file__).resolve().parents[1] / "scripts/archive-ueba-staged-cache.py"
SPEC = importlib.util.spec_from_file_location("test_staged_cache_archive", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class StagedCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.root = self.base / "hybrid-strict-new-cache-fixture"; self.root.mkdir(mode=0o700)
        self.patch = patch.object(M, "RUNTIME", self.base); self.patch.start(); self.addCleanup(self.patch.stop)
        (self.root / "cache").mkdir(mode=0o700)
        self.leaf = self.root / "cache" / ("scores-" + "a" * 24); self.leaf.mkdir(mode=0o700)
        self.source = self.leaf / "raw.f64"; self.source.write_bytes(b"exact-new-cache-bytes" * 100); self.source.chmod(0o600)
        for path in (self.root / "writer.lock", self.leaf / "writer.lock", *(self.root / name for name in M.CAMPAIGN_LOCKS)):
            path.touch(mode=0o600)
        M.write_new(self.root / "predeclared.private.json", {"scope": "FULL_STRICT_SOURCE", "protocol": {"dataset_id": "test-new-strict-campaign"}})
        M.write_new(self.root / "state.private.json", {"status": "COMPLETE_UNQUALIFIED_SOURCE", "stage": "STRICT_SOURCE",
            "scope": "FULL_STRICT_SOURCE", "folds_completed": [1, 2, 3], "fit_or_score_calls": 0,
            "source_identity_before": {}, "source_identity_after": {}})
        self.approval = {"approval_schema_version": 1, "scope": "NEW_STRICT_CAMPAIGN_CACHE_ONLY", "campaign_root": str(self.root),
            "source_marker_sha256": M.digest(self.root / "predeclared.private.json"), "source_terminal_sha256": M.digest(self.root / "state.private.json"),
            "cache_roots": ["cache"], "campaign_locks": sorted(M.CAMPAIGN_LOCKS),
            "targets": [{"path": str(self.source.relative_to(self.root)), "sha256": M.digest(self.source), "bytes": self.source.stat().st_size}],
            "retirement_approved": False, "user_approval_reference": "temporary fixture approval only"}
        self.approval_path = self.base / "approval.private.json"; self.output = self.base / "archives"

    def invoke(self, *, retire=False, resume=False, restore=False, closed_generation=0, **admission):
        self.approval_path.write_text(M.canonical(self.approval)); self.approval_path.chmod(0o600)
        return M.run(self.approval_path, M.digest(self.approval_path), self.output, retire=retire, resume=resume,
                     restore=restore, closed_generation=closed_generation, **admission)

    def production_layout(self):
        standard = self.root / 'standard'
        standard.mkdir(mode=0o700)
        (standard / 'generation.lock').touch(mode=0o600)

    def test_production_cache_requires_separate_source_checkpoint_before_any_unlink(self):
        self.production_layout(); self.approval['retirement_approved'] = True
        with self.assertRaisesRegex(ValueError, 'three explicit source/archive pins'):
            self.invoke(retire=True, production=True)
        self.assertTrue(self.source.exists())
        self.assertFalse((self.output / 'target-000000.xz').exists())

    def test_production_adapter_checks_five_source_locks_and_rechecks_before_unlink(self):
        self.production_layout(); self.approval['retirement_approved'] = True
        checked = []
        def admission(root, approval, approval_sha, checkpoint, checkpoint_sha, pins, locks):
            self.assertEqual(len(locks), 5)
            self.assertEqual(root, self.root)
            for lock in locks: lock()
            def verify():
                checked.append(True)
                for lock in locks: lock()
            verify()
            return verify
        with patch.object(M, 'admit_cache_retirement', side_effect=admission):
            result = self.invoke(retire=True, production=True, coordinator_checkpoint=self.base / 'checkpoint',
                                 coordinator_checkpoint_sha256='a' * 64,
                                 source_pins={'dataset_manifest_sha256':'b'*64, 'archive_sidecar_sha256':'c'*64,
                                              'archive_result_sha256':'d'*64})
        self.assertEqual(result['scope'], 'NEW_STRICT_CACHE_RETIRED')
        self.assertFalse(self.source.exists())
        self.assertGreaterEqual(len(checked), 3)

    def test_production_code_or_checkpoint_drift_aborts_before_unlink(self):
        self.production_layout(); self.approval['retirement_approved'] = True
        def admission(*args):
            def verify(): raise ValueError('checkpoint changed fixture')
            return verify
        with patch.object(M, 'admit_cache_retirement', side_effect=admission):
            with self.assertRaisesRegex(ValueError, 'checkpoint changed'):
                self.invoke(retire=True, production=True)
        self.assertTrue(self.source.exists())

    def test_production_resume_cannot_inherit_another_coordinator_checkpoint(self):
        self.production_layout(); self.approval['retirement_approved'] = True
        options = {'retire': True, 'production': True, 'coordinator_checkpoint': self.base / 'checkpoint',
                   'coordinator_checkpoint_sha256': 'a' * 64}
        with patch.object(M, 'admit_cache_retirement', return_value=lambda: None):
            self.invoke(**options)
            with self.assertRaisesRegex(ValueError, 'prior approved retirement intent'):
                self.invoke(**(options | {'resume': True, 'coordinator_checkpoint_sha256': 'b' * 64}))
        self.assertFalse(self.source.exists())
        self.assertTrue((self.output / 'target-000000.xz').exists())

    def test_production_requires_filesystem_restoration_before_unlink(self):
        self.production_layout(); self.approval['retirement_approved'] = True
        with patch.object(M, 'admit_cache_retirement', return_value=lambda: None), \
                patch.object(M, 'verify_filesystem_recovery', side_effect=ValueError('filesystem restore fixture')):
            with self.assertRaisesRegex(ValueError, 'filesystem restore fixture'):
                self.invoke(retire=True, production=True, coordinator_checkpoint_sha256='a' * 64)
        self.assertTrue(self.source.exists())
        self.assertFalse((self.output / 'target-000000.retirement-pending.private.json').exists())

    def test_actual_filesystem_recovery_readback_matches_and_only_own_scratch_removed(self):
        self.invoke()
        evidence = self.output / 'target-000000.verified.private.json'
        receipt = M.json_file(evidence, M.digest(evidence))['recovery']
        result = M.verify_filesystem_recovery(self.output / 'target-000000.xz', receipt)
        self.assertEqual(result['restored_sha256'], M.digest(self.source))
        self.assertTrue(result['filesystem_write_fsync_readback_verified'])
        self.assertFalse(list(self.output.glob('.cache-fs-recovery-*.pending')))

    def test_restore_use_and_explicit_new_generation_retire_reuses_exact_existing_archive(self):
        original = self.retire_fixture()
        archive = self.output / 'target-000000.xz'
        old_archive = archive.read_bytes()
        old_receipt = (self.output / 'target-000000.verified.private.json').read_bytes()
        self.invoke(restore=True)
        with self.assertRaisesRegex(ValueError, 'source identity'):
            self.invoke(retire=True, resume=True)
        for generation in (1, 2):
            result = self.invoke(retire=True, resume=True, closed_generation=generation)
            self.assertEqual(result['closed_generation'], generation)
            self.assertEqual(result['original_files_retired'], 1)
            self.assertFalse(self.source.exists())
            self.invoke(restore=True, closed_generation=generation)
            self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(archive.read_bytes(), old_archive)
        self.assertEqual((self.output / 'target-000000.verified.private.json').read_bytes(), old_receipt)

    def test_new_closed_generation_rejects_changed_bytes_bad_number_or_missing_prior(self):
        self.retire_fixture(); self.invoke(restore=True)
        for number in (-1, True, 1025):
            with self.assertRaisesRegex(ValueError, 'closed-generation'):
                self.invoke(resume=True, closed_generation=number)
        with self.assertRaisesRegex(ValueError, 'prior closed-generation'):
            self.invoke(resume=True, closed_generation=2)
        self.source.write_bytes(b'changed after use')
        with self.assertRaisesRegex(ValueError, 'approved original'):
            self.invoke(resume=True, closed_generation=1)
        self.assertEqual(self.source.read_bytes(), b'changed after use')

    def test_archive_only_keeps_every_original_and_verified_restore(self):
        original = M.digest(self.source); result = self.invoke()
        self.assertEqual(result["original_files_retired"], 0); self.assertEqual(M.digest(self.source), original)

    def test_low_disk_archive_refuses_before_creating_xz_or_retiring_original(self):
        with patch.object(M, 'require_headroom', side_effect=ValueError('reserve fixture')):
            with self.assertRaisesRegex(ValueError, 'reserve fixture'): self.invoke()
        self.assertTrue(self.source.exists())
        self.assertFalse((self.output / 'target-000000.xz').exists())

    def test_low_disk_restore_preserves_verified_archive_and_creates_no_temporary(self):
        self.retire_fixture()
        original_archive = (self.output / 'target-000000.xz').read_bytes()
        with patch.object(M, 'require_headroom', side_effect=ValueError('reserve fixture')):
            with self.assertRaisesRegex(ValueError, 'reserve fixture'): self.invoke(restore=True)
        self.assertFalse(self.source.exists())
        self.assertFalse(list(self.leaf.glob('.*.pending')))
        self.assertEqual((self.output / 'target-000000.xz').read_bytes(), original_archive)

    def test_replaced_coordinator_lock_refuses_before_exact_unlink(self):
        self.approval['retirement_approved'] = True
        original = M.archive_one
        def replace_lock(*args):
            receipt = original(*args)
            lock = self.root / 'campaign.lock'
            lock.rename(self.root / 'old-campaign.lock')
            lock.touch(mode=0o600)
            return receipt
        with patch.object(M, 'archive_one', side_effect=replace_lock):
            with self.assertRaisesRegex(ValueError, 'lock pathname/inode'):
                self.invoke(retire=True)
        self.assertTrue(self.source.exists())
        receipt = M.json_file(self.output / "target-000000.verified.private.json", M.digest(self.output / "target-000000.verified.private.json"))
        M.verify_archive(self.output / "target-000000.xz", receipt["recovery"])

    def test_cli_retirement_refused_before_any_approval_or_source_read(self):
        result = subprocess.run([sys.executable, str(PATH), "--approval", str(self.base / "missing-approval"),
            "--approval-sha256", "0" * 64, "--output", str(self.output), "--retire-approved-files"],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coordinator restore integration not yet admitted", result.stderr)
        self.assertFalse(self.output.exists()); self.assertTrue(self.source.exists())

    def test_explicit_fixture_retirement_and_idempotent_resume(self):
        self.approval["retirement_approved"] = True
        result = self.invoke(retire=True); self.assertFalse(self.source.exists()); self.assertEqual(result["original_files_retired"], 1)
        self.assertEqual(self.invoke(retire=True, resume=True)["original_files_retired"], 1)

    def retire_fixture(self):
        self.approval["retirement_approved"] = True
        original = self.source.read_bytes(); self.invoke(retire=True)
        self.assertFalse(self.source.exists()); return original

    def test_approved_missing_cache_restores_exactly_and_repeated_restore_never_overwrites(self):
        floats = tuple(index * 0.125 for index in range(256))
        self.source.write_bytes(struct.pack("<256d", *floats))
        self.approval["targets"][0].update(sha256=M.digest(self.source), bytes=self.source.stat().st_size)
        original = self.retire_fixture()
        receipts = {path.name: path.read_bytes() for path in self.output.iterdir()}
        result = self.invoke(restore=True)
        self.assertEqual(result["original_files_restored"], 1); self.assertEqual(result["original_files_retired"], 0)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(struct.unpack("<256d", self.source.read_bytes()), floats)
        identity = M.signature(self.source)
        self.assertEqual(self.invoke(restore=True)["original_files_restored"], 0)
        self.assertEqual(M.signature(self.source), identity)
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir()}, receipts)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.leaf.glob(".*.pending")))

    def test_restore_requires_existing_matching_proof_and_archive(self):
        self.retire_fixture(); archive = self.output / "target-000000.xz"
        saved = archive.read_bytes(); archive.write_bytes(b"tampered")
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertFalse(self.source.exists()); archive.write_bytes(saved)
        evidence = self.output / "target-000000.verified.private.json"; evidence.unlink()
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertFalse(self.source.exists())

    def test_restore_existing_changed_symlink_directory_or_hardlink_never_overwrites(self):
        original = self.retire_fixture()
        self.source.write_bytes(b"changed"); self.source.chmod(0o600)
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertEqual(self.source.read_bytes(), b"changed"); self.source.unlink()
        self.source.symlink_to(self.base / "missing")
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.source.unlink(); self.source.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.source.rmdir(); self.source.write_bytes(original); self.source.chmod(0o600)
        alias = self.leaf / "fixture-alias"; os.link(self.source, alias)
        with self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertEqual(alias.read_bytes(), original)

    def test_restore_failure_cleans_only_own_temporary_and_preserves_archive_receipts(self):
        self.retire_fixture(); before = {path.name: path.read_bytes() for path in self.output.iterdir()}
        original = M.verify_archive
        def fail_stream(path, receipt, *, destination=None):
            if destination is not None:
                destination.write(b"partial"); raise ValueError("fixture interrupted restoration")
            return original(path, receipt)
        with patch.object(M, "verify_archive", side_effect=fail_stream), self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertFalse(self.source.exists()); self.assertFalse(list(self.leaf.glob(".*.pending")))
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir()}, before)

    def test_restore_refuses_racing_destination_without_replacing_its_bytes(self):
        self.retire_fixture(); link = M.os.link
        def race(temporary, destination, **kwargs):
            self.source.write_bytes(b"racing writer"); self.source.chmod(0o600)
            return link(temporary, destination, **kwargs)
        with patch.object(M.os, "link", side_effect=race), self.assertRaises(ValueError): self.invoke(restore=True)
        self.assertEqual(self.source.read_bytes(), b"racing writer")
        self.assertFalse(list(self.leaf.glob(".*.pending")))

    def test_restore_refuses_active_stage_locks_and_nonterminal_source(self):
        self.retire_fixture()
        for path in (self.root / "writer.lock", self.leaf / "writer.lock", *(self.root / name for name in M.CAMPAIGN_LOCKS)):
            with path.open("r") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ValueError): self.invoke(restore=True)
        state = self.root / "state.private.json"; value = M.parse(state.read_bytes())
        value["status"] = "STANDARD_SOURCE_RUNNING"; state.write_text(M.canonical(value))
        self.approval["source_terminal_sha256"] = M.digest(state)
        with self.assertRaisesRegex(ValueError, "live/nonterminal"): self.invoke(restore=True)
        self.assertFalse(self.source.exists())

    def test_restore_sqlite_with_wal_is_refused_before_publication(self):
        sqlite = self.leaf / "scores.sqlite"; self.source.rename(sqlite); self.source = sqlite
        self.approval["targets"][0]["path"] = str(sqlite.relative_to(self.root))
        self.retire_fixture(); wal = Path(str(sqlite) + "-wal"); wal.touch(mode=0o600)
        with self.assertRaisesRegex(ValueError, "closed and checkpointed"): self.invoke(restore=True)
        self.assertFalse(sqlite.exists()); self.assertTrue(wal.exists())

    def test_restore_cli_flag_is_explicit_and_retirement_blockade_stays(self):
        result = subprocess.run([sys.executable, str(PATH), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0); self.assertIn("--restore-approved-files", result.stdout)
        self.assertIn("--retire-approved-files", result.stdout)

    @unittest.skipUnless(os.environ.get("UEBA_STAGED_CACHE_INTEGRATION") == "1", "opt-in pinned worker cache integration")
    def test_real_score_cache_reuses_restored_f64_and_sqlite_without_rescoring(self):
        import sqlite3
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from app.calibration import score_cache
        from test_calibration import fixture
        data = self.root / "fixture-data"; data.mkdir(mode=0o700); dataset = fixture(data, schema=2)
        cache = self.root / "cache"; scorer = IsolationForest(n_estimators=1)
        # No real model fit or quality claim: the existing score_cache code
        # commits two deterministic fixture-score slices into its real journal.
        with patch.object(IsolationForest, "fit", side_effect=AssertionError("fixture must never fit")):
            fixture_umask = os.umask(0o077)
            try:
                with patch.object(scorer, "score_samples", side_effect=lambda features: -features[:, 0]) as initial_scoring:
                    first_values, first = score_cache(dataset, "fold1-calibration-ready", scorer, "f" * 64, cache, sort_output=False)
                self.assertEqual(initial_scoring.call_count, 2)
            finally: os.umask(fixture_umask)
            score_journal = next(cache.glob("scores-*/scores.sqlite"))
            vectors = next(cache.glob("vectors-*/features.f64")); vector_journal = vectors.parent / "vectors.sqlite"
            raw = score_journal.parent / "raw.f64"
            files = (raw, score_journal, vectors, vector_journal)
            original_hashes = {path: M.digest(path) for path in files}
            def journal_rows(path):
                with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                    return (db.execute("SELECT * FROM identity ORDER BY singleton").fetchall(),
                            db.execute("SELECT * FROM shards ORDER BY id").fetchall())
            original_rows = {path: journal_rows(path) for path in (score_journal, vector_journal)}
            self.approval["targets"] = [{"path": str(path.relative_to(self.root)), "sha256": original_hashes[path],
                                         "bytes": path.stat().st_size} for path in files]
            self.approval["retirement_approved"] = True
            self.assertEqual(self.invoke(retire=True)["original_files_retired"], 4)
            self.assertTrue(all(not path.exists() for path in files))
            self.assertEqual(self.invoke(restore=True)["original_files_restored"], 4)
            self.assertEqual({path: M.digest(path) for path in files}, original_hashes)
            with patch.object(scorer, "score_samples", side_effect=AssertionError("restored committed cache must not rescore")):
                reused_values, reused = score_cache(dataset, "fold1-calibration-ready", scorer, "f" * 64, cache, sort_output=False)
            np.testing.assert_array_equal(reused_values, first_values)
            self.assertEqual(reused["raw_score_sha256"], first["raw_score_sha256"])
            self.assertEqual(reused["computed_shards"], 0); self.assertEqual(reused["reused_shards"], 2)
            self.assertEqual({path: journal_rows(path) for path in original_rows}, original_rows)
            self.assertEqual({path: M.digest(path) for path in files}, original_hashes)

    @unittest.skipUnless(os.environ.get("UEBA_STAGED_CACHE_INTEGRATION") == "1", "opt-in pinned worker trained-IF cache integration")
    def test_trained_fixture_score_cache_reuses_restored_journals_without_fit_or_score(self):
        import sqlite3
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from app.calibration import score_cache
        from app.model import ModelStore
        from test_calibration import fixture, fitted
        data = self.root / "trained-fixture-data"; data.mkdir(mode=0o700); dataset = fixture(data, schema=2)
        models = self.root / "fixture-models"; models.mkdir(mode=0o700); store = ModelStore(models)
        original_fit = IsolationForest.fit; fixture_fit_count = []
        def tracked_fixture_fit(model, *args, **kwargs):
            fixture_fit_count.append(1); return original_fit(model, *args, **kwargs)
        # Exactly one small real native IF unit fit, not a STRICT composite or
        # component trial. It must never enter the STRICT 360/720 counters.
        with patch.object(IsolationForest, "fit", tracked_fixture_fit): metadata = fitted(store, dataset)
        self.assertEqual(len(fixture_fit_count), 1)
        self.assertEqual(M.digest(models / "source_fitted_fixture.joblib"), metadata["sha256"])
        _, payload = store.load_candidate("source_fitted_fixture"); scorer = payload["model"]
        cache = self.root / "cache"; fixture_umask = os.umask(0o077)
        try:
            first_values, first = score_cache(dataset, "fold1-calibration-ready", scorer, metadata["sha256"], cache, sort_output=False)
        finally: os.umask(fixture_umask)
        score_journal = next(cache.glob("scores-*/scores.sqlite"))
        vectors = next(cache.glob("vectors-*/features.f64")); vector_journal = vectors.parent / "vectors.sqlite"
        files = (score_journal.parent / "raw.f64", score_journal, vectors, vector_journal)
        hashes = {path: M.digest(path) for path in files}
        def journal_rows(path):
            with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                return (db.execute("SELECT * FROM identity ORDER BY singleton").fetchall(),
                        db.execute("SELECT * FROM shards ORDER BY id").fetchall())
        rows = {path: journal_rows(path) for path in (score_journal, vector_journal)}
        self.approval["targets"] = [{"path": str(path.relative_to(self.root)), "sha256": hashes[path],
                                     "bytes": path.stat().st_size} for path in files]
        self.approval["retirement_approved"] = True
        with patch.object(IsolationForest, "fit", side_effect=AssertionError("no fit during storage restore/reuse")), \
                patch.object(IsolationForest, "score_samples", side_effect=AssertionError("no rescoring committed restored cache")):
            self.assertEqual(self.invoke(retire=True)["original_files_retired"], 4)
            self.assertEqual(self.invoke(restore=True)["original_files_restored"], 4)
            self.assertEqual({path: M.digest(path) for path in files}, hashes)
            reused_values, reused = score_cache(dataset, "fold1-calibration-ready", scorer, metadata["sha256"], cache, sort_output=False)
        np.testing.assert_array_equal(reused_values, first_values)
        self.assertEqual(reused["raw_score_sha256"], first["raw_score_sha256"])
        self.assertEqual(reused["computed_shards"], 0); self.assertEqual(reused["reused_shards"], 2)
        self.assertEqual({path: journal_rows(path) for path in rows}, rows)
        self.assertEqual({path: M.digest(path) for path in files}, hashes)

    def test_crash_after_exact_unlink_resumes_from_durable_recovery_and_intent(self):
        self.approval["retirement_approved"] = True; original = M.write_new
        def fail_after_unlink(path, value):
            if path.name.endswith(".retired.private.json"): raise RuntimeError("fixture crash")
            return original(path, value)
        with patch.object(M, "write_new", side_effect=fail_after_unlink), self.assertRaises(RuntimeError): self.invoke(retire=True)
        self.assertFalse(self.source.exists()); self.invoke(retire=True, resume=True)
        self.assertTrue((self.output / "target-000000.retired.private.json").exists())

    def test_both_writer_locks_refuse_live_writer(self):
        for path in (self.root / "writer.lock", self.leaf / "writer.lock", *(self.root / name for name in M.CAMPAIGN_LOCKS)):
            with path.open("r") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ValueError): self.invoke()
            if self.output.exists(): self.output.rmdir()
        self.assertTrue(self.source.exists())

    def test_exact_new_parent_source_layout_supported_but_deeper_layout_refused(self):
        marker = self.root / "predeclared.private.json"; terminal = self.root / "state.private.json"
        nested = self.root / "source"; nested.mkdir(mode=0o700)
        marker.rename(nested / marker.name); terminal.rename(nested / terminal.name)
        approval = {**self.approval, "campaign_root": str(nested)}
        self.assertEqual(M.source_binding(approval), nested)
        deeper = nested / "source"; deeper.mkdir(mode=0o700)
        with self.assertRaises(ValueError): M.source_binding({**approval, "campaign_root": str(deeper)})

    def test_resume_recovery_fields_cannot_change_original_hash_size_or_signature(self):
        self.invoke(); evidence = self.output / "target-000000.verified.private.json"
        original = evidence.read_bytes()
        for field, value in (("original_sha256", "0" * 64), ("original_bytes", 1),
                             ("original_signature", [1, 2]), ("original_signature", [True] * 5),
                             ("archive_bytes", True), ("archive_sha256", "bad")):
            saved = M.parse(original); saved["recovery"][field] = value; evidence.write_text(M.canonical(saved))
            with self.subTest(field=field), self.assertRaises(ValueError): self.invoke(resume=True)
        saved = M.parse(original); saved["recovery"]["unsupported"] = 1; evidence.write_text(M.canonical(saved))
        with self.assertRaises(ValueError): self.invoke(resume=True)
        self.assertTrue(self.source.exists())

    def test_public_lock_is_refused_without_changing_its_mode(self):
        lock = self.leaf / "writer.lock"; lock.chmod(0o644)
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(lock.stat().st_mode & 0o777, 0o644); self.assertTrue(self.source.exists())

    def test_nonterminal_unknown_filename_missing_approval_or_bad_hash_refused(self):
        original = dict(self.approval["targets"][0])
        for name in ("model.joblib", "manifest.json", "writer.lock", "other.f64"):
            self.approval["targets"][0] = dict(original, path="cache/scores-" + "a" * 24 + "/" + name)
            with self.assertRaises(ValueError): self.invoke()
        self.approval["targets"][0] = dict(original, sha256="0" * 64)
        with self.assertRaises(ValueError): self.invoke()
        self.approval["targets"][0] = original
        with self.assertRaises(ValueError): self.invoke(retire=True)
        self.approval["source_terminal_sha256"] = "0" * 64
        with self.assertRaises(ValueError): self.invoke()
        self.assertTrue(self.source.exists())

    def test_symlink_hardlink_and_sqlite_wal_refused(self):
        self.source.rename(self.leaf / "original.f64"); self.source.symlink_to(self.leaf / "original.f64")
        with self.assertRaises(ValueError): self.invoke()
        self.source.unlink(); (self.leaf / "original.f64").rename(self.source)
        os.link(self.source, self.leaf / "alias.f64")
        with self.assertRaises(ValueError): self.invoke(resume=True)
        (self.leaf / "alias.f64").unlink()
        self.source.rename(self.leaf / "scores.sqlite"); self.source = self.leaf / "scores.sqlite"
        self.approval["targets"][0]["path"] = str(self.source.relative_to(self.root))
        Path(str(self.source) + "-wal").touch(mode=0o600)
        with self.assertRaises(ValueError): self.invoke(resume=True)

    def test_restore_failure_bad_archive_and_missing_prior_archive_never_retire(self):
        self.approval["retirement_approved"] = True
        with patch.object(M, "verify_archive", side_effect=ValueError("fixture restore failure")), self.assertRaises(ValueError): self.invoke(retire=True)
        self.assertTrue(self.source.exists())
        # No successful recovery receipt exists, so a missing original cannot resume.
        self.source.unlink()
        with self.assertRaises(ValueError): self.invoke(retire=True, resume=True)

    def test_changed_original_or_archive_detected_on_resume(self):
        self.invoke(); self.source.write_bytes(b"changed")
        with self.assertRaises(ValueError): self.invoke(resume=True)
        archive = self.output / "target-000000.xz"; archive.write_bytes(b"not-xz")
        with self.assertRaises(ValueError): self.invoke(resume=True)

    def test_old_root_escape_duplicate_targets_and_public_files_refused(self):
        for update in ({"campaign_root": str(self.base)}, {"cache_roots": ["../old"]},
                       {"targets": [self.approval["targets"][0]] * 2}):
            original = self.approval; self.approval = {**original, **update}
            with self.assertRaises(ValueError): self.invoke()
            self.approval = original
        self.source.chmod(0o644)
        with self.assertRaises(ValueError): self.invoke()


if __name__ == "__main__": unittest.main()
