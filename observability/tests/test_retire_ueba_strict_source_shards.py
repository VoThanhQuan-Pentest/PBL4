"""Only private opaque-byte fixtures retire; no actual corpus/quality evidence."""
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/retire-ueba-strict-source-shards.py"
SPEC = importlib.util.spec_from_file_location("strict_source_retirement_test", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
S = M.S


class SourceRetirementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.patch = patch.object(S, "RUNTIME", self.base)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.run = self.base / "hybrid-strict-source-fixture-retire-12345678"; self.run.mkdir(mode=0o700)
        self.parent = self.run / "source"; self.parent.mkdir(mode=0o700)
        self.source = self.parent / "standard"; self.source.mkdir(mode=0o700)
        for relative in ("shards", "batches", "verification", "verification/shards"): (self.source / relative).mkdir(mode=0o700)
        for path in (self.parent / "writer.lock", self.source / "generation.lock", *(self.parent / name for name in M.COORDINATOR_LOCKS)):
            path.touch(mode=0o600)
        # Bind the same producer-shaped JVM snapshot before marker/manifest
        # hashes and archive evidence exist. No fixture source is rewritten later.
        self.workspace = self.base / "frozen-workspace"; classes = self.workspace / "backend/target/classes/com/flarefitness/backend"
        classes.mkdir(mode=0o700, parents=True); (self.workspace / "jars").mkdir(mode=0o700)
        S.write_new(classes / "Fixture.class", b"OPAQUE-NOT-A-JAVA-CLASS")
        S.write_new(self.workspace / "jars/fixture.jar", b"OPAQUE-NOT-A-JAR")
        java_classes = {"Fixture.class": S.sha256(b"OPAQUE-NOT-A-JAVA-CLASS")}
        self.write(self.workspace / "snapshot.json", {"classes": java_classes, "jars": {"fixture.jar": S.sha256(b"OPAQUE-NOT-A-JAR")}})
        workspace_sha = self.digest(self.workspace / "snapshot.json")
        identity = {"fixture": "not-real-source", "execution_image_id": M.IMAGE, "java": {"classes": java_classes}}
        dataset_id = "strict-retire-dummy-fixture"
        from app.hybrid_strict_protocol import source_protocol
        protocol = source_protocol(dataset_id)
        self.write(self.parent / "predeclared.private.json", {"scope": "FULL_STRICT_SOURCE", "source_identity": identity,
            "protocol": protocol, "protocol_sha256": S.protocol_sha256(protocol), "fit_or_score_calls": 0, "holdout_numeric_records_read": 0})
        self.terminal = {"status": "COMPLETE_UNQUALIFIED_SOURCE", "stage": "STRICT_SOURCE", "scope": "FULL_STRICT_SOURCE",
            "quality_gate": "NOT_EVALUATED", "folds_completed": [1, 2, 3], "source_identity_before": identity, "source_identity_after": identity,
            "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "downstream_holdout_numeric_records_read": 0}
        self.write(self.parent / "state.private.json", self.terminal)
        binding = {"fixture": "a" * 64}
        self.write(self.source / "generation.identity.json", {"stage": "STRICT", "dataset_id": dataset_id, "source_binding": binding,
            "old_numeric_corpus_read": False, "authentic_capture": False, "fit_or_score_calls": 0})
        generation_sha = self.digest(self.source / "generation.identity.json")
        from app.contract import FEATURE_NAMES_V4
        names = [name for fold in (1, 2, 3) for name in (f"fold{fold}-fit", f"fold{fold}-calibration-ready", f"fold{fold}-calibration-cold", f"fold{fold}-validation")] + ["holdout"]
        splits = {}; self.groups = {}; self.raw = {}
        for index, name in enumerate(names):
            batch_id = f"part{index:02d}-batch000000"; identifier = f"{name}-{batch_id}-000"
            batch = self.source / "batches" / batch_id; batch.mkdir(mode=0o700)
            projection = "shards/" + identifier + ".json"; batch_alias = f"batches/{batch_id}/{identifier}.json"
            verification = "verification/shards/" + identifier + ".json"; raw = b"\xffOPAQUE-NOT-JSON:" + name.encode()
            S.write_new(self.source / projection, raw); os.link(self.source / projection, self.source / batch_alias)
            os.link(self.source / projection, self.source / verification); self.raw[name] = raw
            cohort = "COLD" if "cold" in name else "READY"
            descriptor = {"id": identifier, "path": projection, "sha256": S.sha256(raw), "records": 1, "normal": 1, "positive": 0,
                "families": {"normal": 1}, "cohorts": {cohort: 1}, "from": "2026-04-15T00:00:00Z", "to": "2026-04-15T00:00:00Z"}
            split = {key: value for key, value in descriptor.items() if key not in ("id", "path", "sha256")}
            split["shards"] = [descriptor]; split["sha256"] = S.sha256(S.canonical(split).encode()); splits[name] = split
            self.write(batch / "receipt.json", {"batch_id": batch_id, "split": name, "generation_identity_sha256": generation_sha, "shards": [descriptor]})
            self.groups[name] = {"projection": projection, "batch_alias": batch_alias, "verification_alias": verification,
                                 "sha256": descriptor["sha256"], "bytes": len(raw)}
        manifest = {"catalog_schema_version": 2, "dataset_id": dataset_id, "stage": "STRICT", "data_provenance": "DEMO_ONLY",
            "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
            "source_binding": binding, "generation_identity_sha256": generation_sha, "splits": splits,
            "workspace_snapshot_sha256": workspace_sha, "compiled_feature_sha256": java_classes}
        self.write(self.source / "manifest.json", manifest); self.manifest_sha = self.digest(self.source / "manifest.json")
        os.link(self.source / "manifest.json", self.source / "verification/manifest.json")
        self.write(self.source / "generation.progress.json", {"status": "COMPLETED", "stage": "STRICT", "dataset_id": dataset_id,
            "manifest_sha256": self.manifest_sha, "fit_or_score_calls": 0})
        self.marker_sha = self.digest(self.parent / "predeclared.private.json"); self.terminal_sha = self.digest(self.parent / "state.private.json")
        # Compact fixtures mock only population sizes, never byte/type/path guards.
        with patch.object(S, "validate_standard_manifest"):
            self.archive = S.archive_strict_source(self.source, self.manifest_sha, self.marker_sha, self.terminal_sha)
        labels = self.parent / "labels-fold1"; labels.mkdir(mode=0o700); (labels / "normal").mkdir(mode=0o700)
        self.label_fit = labels / "normal" / Path(self.groups["fold1-fit"]["projection"]).name
        os.link(self.source / self.groups["fold1-fit"]["projection"], self.label_fit)
        self.approval = {"approval_schema_version": 1, "scope": "NEW_STRICT_SOURCE_SHARDS_ONLY", "source_standard": str(self.source),
            "dataset_manifest_sha256": self.manifest_sha, "archive_sidecar_sha256": self.archive["archive_sidecar_sha256"],
            "archive_result_sha256": self.digest(self.source / S.RESULT), "source_marker_sha256": self.marker_sha, "source_terminal_sha256": self.terminal_sha,
            "targets": [self.groups["holdout"]], "retirement_approved": True, "user_approval_reference": "temporary fixture only"}
        self.approval_path = self.base / "approval.private.json"

    def write(self, path, value): path.write_text(S.canonical(value)); path.chmod(0o600)
    def digest(self, path): return S.sha256(path.read_bytes())
    def invoke(self, *, retire=False, resume=False):
        self.write(self.approval_path, self.approval); sha = self.digest(self.approval_path)
        with patch.object(S, "validate_standard_manifest"), \
                patch.object(S.ShardedDataset, "load_shard", side_effect=AssertionError("no JSON row parse")), \
                patch.object(S.ShardedDataset, "iter_shards", side_effect=AssertionError("no holdout rows")):
            return M.run_fixture(self.approval_path, sha, retire=retire, resume=resume)
    def paths(self, name="holdout"): return [self.source / self.groups[name][key] for key in ("projection", "batch_alias", "verification_alias")]

    def production_checkpoint(self):
        """Opaque descriptor/code fixtures; never actual source/campaign/JVM evidence."""
        project = M.ROOT; execution = self.base / "private-execution-tree"
        for relative in M.CODE_FILES:
            path = execution / relative; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            S.write_new(path, (project / relative).read_bytes())
        root_patch = patch.object(M, "ROOT", execution); root_patch.start(); self.addCleanup(root_patch.stop)
        file_patch = patch.object(M.C, "__file__", str(execution / "observability/scripts/continue-ueba-strict.py"))
        file_patch.start(); self.addCleanup(file_patch.stop)
        manifest = S.parse_json((self.source / "manifest.json").read_bytes()); marker = S.parse_json((self.parent / "predeclared.private.json").read_bytes())
        for fold in (1, 2, 3):
            directory = self.parent / f"labels-fold{fold}"; directory.mkdir(mode=0o700, exist_ok=True)
            self.write(directory / "manifest.private.json", {"scope": "FULL_STRICT_SOURCE", "stage": "STRICT_SOURCE", "quality_gate": "NOT_EVALUATED",
                "fold": fold, "standard_manifest_sha256": self.manifest_sha, "standard_fit": manifest["splits"][f"fold{fold}-fit"],
                "source_identity_before": marker["source_identity"], "source_identity_after": marker["source_identity"],
                "fit_or_score_calls": 0, "holdout_numeric_records_read": 0})
        self.code = self.base / "frozen-code"; (self.code / "app").mkdir(mode=0o700, parents=True)
        for name in ("__init__.py", "strict_campaign.py", "selection.py", "frozen_evaluation.py", "storage_budget.py", "pipeline_lock.py"):
            S.write_new(self.code / "app" / name, (project / "ueba-worker/app" / name).read_bytes() or b"# Temporary fixture namespace.\n")
        self.write(self.approval_path, self.approval); self.approval_sha = self.digest(self.approval_path)
        with patch.object(M.C, "RUNTIME", self.base), patch("app.hybrid_strict_dataset.validate_standard_manifest"):
            _, code_sha = M.C.hybrid_code_identity(self.code, M.IMAGE)
            plan = M.C.HybridPlan(self.source, dataset_sha=self.manifest_sha, archive_sha=self.archive["archive_sidecar_sha256"],
                marker_sha=self.marker_sha, terminal_sha=self.terminal_sha, code=self.code, code_sha=code_sha,
                workspace=self.workspace, workspace_sha=self.digest(self.workspace / "snapshot.json"), image=M.IMAGE)
        self.checkpoint = {"checkpoint_schema_version": 1, "scope": "NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR", "status": "QUIESCENT",
            "source_standard": str(self.source), "retirement_approval_sha256": self.approval_sha,
            **{key: self.approval[key] for key in M.SOURCE_PINS}, "continuation_identity_sha256": S.sha256(S.canonical(plan.identity).encode()),
            "identity": plan.identity, "commands": {name: plan.command(stage) for name, stage in (("campaign", "fit"), ("selection", "validation"), ("evaluation", "holdout"))},
            "lock_paths": [str(path) for path in M.lock_paths(self.source)], "active_consumers": [],
            "code_sha256": {name: self.digest(M.ROOT / name) for name in M.CODE_FILES}}
        self.checkpoint_path = self.base / "coordinator.private.json"; self.write(self.checkpoint_path, self.checkpoint)

    def invoke_production(self, *, retire=False, resume=False, expected_checkpoint_sha=None):
        self.write(self.checkpoint_path, self.checkpoint)
        with patch.object(S, "validate_standard_manifest"), patch("app.hybrid_strict_dataset.validate_standard_manifest"), \
                patch.object(M.C, "RUNTIME", self.base), patch.dict(os.environ, {"UEBA_DIAGNOSTIC_IMAGE_ID": M.IMAGE}), \
                patch.object(S.ShardedDataset, "load_shard", side_effect=AssertionError("no numeric parse")), \
                patch.object(S.ShardedDataset, "iter_shards", side_effect=AssertionError("no holdout numeric read")):
            return M.run(self.approval_path, self.approval_sha, retire=retire, resume=resume, coordinator_checkpoint=self.checkpoint_path,
                         coordinator_checkpoint_sha256=expected_checkpoint_sha or self.digest(self.checkpoint_path))
    def preserved(self):
        self.assertEqual(self.digest(self.source / "manifest.json"), self.manifest_sha)
        self.assertEqual(self.digest(self.source / "verification/manifest.json"), self.manifest_sha)
        self.assertTrue(self.label_fit.exists()); self.assertEqual(self.label_fit.read_bytes(), self.raw["fold1-fit"])
        for name in ("fold1-fit", "fold2-fit", "fold3-fit"):
            for path in self.paths(name): self.assertEqual(path.read_bytes(), self.raw[name])
        for path in (self.source / "batches").glob("*/receipt.json"): self.assertTrue(path.exists())

    def test_default_verifies_only_and_all_three_exact_aliases_remain(self):
        result = self.invoke(); self.assertEqual(result["status"], "VERIFIED_ONLY")
        self.assertEqual(result["original_aliases_deleted"], 0); self.assertFalse((self.source / M.LEDGER).exists())
        for path in self.paths(): self.assertEqual(path.read_bytes(), self.raw["holdout"]); self.assertEqual(path.stat().st_nlink, 3)
        self.preserved()

    def test_production_admission_requires_explicit_retire_and_pinned_quiescent_checkpoint(self):
        self.production_checkpoint()
        verified = self.invoke_production(); self.assertEqual(verified["status"], "VERIFIED_ONLY")
        self.assertTrue(all(path.exists() for path in self.paths())); self.assertFalse((self.source / M.LEDGER).exists())
        with self.assertRaisesRegex(ValueError, "explicit pinned coordinator"):
            M.run(self.approval_path, self.approval_sha, retire=True)
        result = self.invoke_production(retire=True); self.assertEqual(result["status"], "NEW_STRICT_SOURCE_RETIRED")
        self.assertEqual(result["scope"], "NEW_STRICT_SOURCE_RETIRED"); self.assertEqual(result["original_aliases_deleted_this_attempt"], 3)
        self.assertTrue(all(not path.exists() for path in self.paths()))
        view = S.ArchivedShardedDataset(self.source, expected_sha256=self.manifest_sha, expected_archive_sha256=self.archive["archive_sidecar_sha256"])
        self.assertEqual(view._read(self.groups["holdout"]["projection"], S.MAX_SHARD_BYTES), self.raw["holdout"])
        self.assertEqual(self.invoke_production(retire=True, resume=True)["original_aliases_deleted_this_attempt"], 0); self.preserved()

    def test_production_checkpoint_rejects_forged_scope_root_pins_code_commands_and_boolean_version(self):
        self.production_checkpoint(); original = self.checkpoint
        changes = [("checkpoint_schema_version", True), ("scope", "NEW_HYBRID_STRICT_ONE_UNIT_ONLY"), ("source_standard", str(self.base)),
                   ("retirement_approval_sha256", "0" * 64), ("active_consumers", ["fixture-running-consumer"]),
                   ("continuation_identity_sha256", "0" * 64)] + [(key, "0" * 64) for key in M.SOURCE_PINS]
        for key, value in changes:
            self.checkpoint = {**original, key: value}
            with self.subTest(field=key), self.assertRaises(ValueError): self.invoke_production(retire=True)
        self.checkpoint = {**original, "code_sha256": {**original["code_sha256"], M.CODE_FILES[0]: "0" * 64}}
        with self.assertRaisesRegex(ValueError, "code SHA"): self.invoke_production(retire=True)
        self.checkpoint = {**original, "commands": {**original["commands"], "campaign": original["commands"]["campaign"][:-1]}}
        with self.assertRaisesRegex(ValueError, "commands differ"): self.invoke_production(retire=True)
        self.checkpoint = {**original, "identity": {**original["identity"], "image_id": "sha256:" + "0" * 64}}
        with self.assertRaisesRegex(ValueError, "pinned Docker image"): self.invoke_production(retire=True)
        self.checkpoint = original
        with self.assertRaisesRegex(ValueError, "metadata SHA"): self.invoke_production(retire=True, expected_checkpoint_sha="0" * 64)
        self.assertTrue(all(path.exists() for path in self.paths())); self.assertFalse((self.source / M.LEDGER).exists()); self.preserved()

    def test_production_refuses_busy_stage_lock_changed_frozen_code_or_unapproved_targets(self):
        self.production_checkpoint()
        for path in M.lock_paths(self.source):
            with path.open("rb") as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.subTest(lock=path.name), self.assertRaises(ValueError): self.invoke_production(retire=True)
        code = self.code / "app/pipeline_lock.py"; saved = code.read_bytes(); code.write_bytes(b"OPAQUE-CHANGED-FIXTURE-CODE")
        with self.assertRaisesRegex(ValueError, "inventory SHA"): self.invoke_production(retire=True)
        code.write_bytes(saved); self.approval["retirement_approved"] = False; self.write(self.approval_path, self.approval)
        self.approval_sha = self.digest(self.approval_path); self.checkpoint["retirement_approval_sha256"] = self.approval_sha
        with self.assertRaisesRegex(ValueError, "explicit per-source"): self.invoke_production(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths())); self.assertFalse((self.source / M.LEDGER).exists()); self.preserved()

    def test_production_checkpoint_change_after_admission_never_unlinks(self):
        self.production_checkpoint(); original = M.restore_scratch
        def change_checkpoint(source, entry, target):
            original(source, entry, target)
            self.checkpoint_path.write_bytes(self.checkpoint_path.read_bytes() + b"\n")
        with patch.object(M, "restore_scratch", side_effect=change_checkpoint), self.assertRaisesRegex(ValueError, "protected source metadata changed"):
            self.invoke_production(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths())); self.assertFalse((self.source / M.LEDGER).exists()); self.preserved()

    def test_fixture_retire_three_aliases_and_bounded_archive_byte_readback(self):
        result = self.invoke(retire=True); self.assertEqual(result["original_aliases_deleted_this_attempt"], 3)
        self.assertTrue(all(not path.exists() for path in self.paths()))
        view = S.ArchivedShardedDataset(self.source, expected_sha256=self.manifest_sha, expected_archive_sha256=self.archive["archive_sidecar_sha256"])
        self.assertEqual(view._read(self.groups["holdout"]["projection"], S.MAX_SHARD_BYTES), self.raw["holdout"])
        self.assertEqual(self.invoke(retire=True, resume=True)["original_aliases_deleted_this_attempt"], 0); self.preserved()

    def test_crash_after_first_exact_unlink_resumes_remaining_known_links(self):
        original = M.fsync_directory
        def interrupt(path):
            original(path)
            if path == self.source / "shards": raise RuntimeError("fixture crash after first unlink")
        with patch.object(M, "fsync_directory", side_effect=interrupt), self.assertRaises(RuntimeError): self.invoke(retire=True)
        self.assertFalse(self.paths()[0].exists()); self.assertTrue(self.paths()[1].exists()); self.assertEqual(self.paths()[1].stat().st_nlink, 2)
        result = self.invoke(retire=True, resume=True); self.assertEqual(result["original_aliases_deleted_this_attempt"], 2)
        self.preserved()

    def test_crash_after_all_unlinks_before_completion_resumes_from_durable_intent(self):
        original = S.write_new
        def interrupt(path, raw):
            if path.name.endswith(".completed.private.json"): raise RuntimeError("fixture completion crash")
            return original(path, raw)
        with patch.object(S, "write_new", side_effect=interrupt), self.assertRaises(RuntimeError): self.invoke(retire=True)
        self.assertTrue(all(not path.exists() for path in self.paths()))
        result = self.invoke(retire=True, resume=True); self.assertEqual(result["original_aliases_deleted_this_attempt"], 0)
        self.preserved()

    def test_extra_hardlink_bad_receipt_and_unknown_batch_files_refuse_without_deletion(self):
        extra = self.source / "extra-alias.json"; os.link(self.paths()[0], extra)
        with self.assertRaisesRegex(ValueError, "hardlinks"): self.invoke(retire=True)
        extra.unlink()  # Temporary fixture only.
        batch = self.paths()[1].parent; receipt = batch / "receipt.json"; original = receipt.read_bytes()
        self.write(receipt, {"batch_id": batch.name, "split": "other", "shards": []})
        with self.assertRaisesRegex(ValueError, "membership"): self.invoke(retire=True)
        receipt.write_bytes(original)
        unknown = batch / "unknown.json"; unknown.write_bytes(b"fixture"); unknown.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unknown"): self.invoke(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths()))

    def test_all_five_locks_and_nonterminal_source_refuse(self):
        for path in (self.parent / "writer.lock", self.source / "generation.lock", *(self.parent / name for name in M.COORDINATOR_LOCKS)):
            with path.open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ValueError): self.invoke(retire=True)
        self.write(self.parent / "state.private.json", {**self.terminal, "status": "LABEL_FOLDS_RUNNING"})
        self.approval["source_terminal_sha256"] = self.digest(self.parent / "state.private.json")
        with self.assertRaisesRegex(ValueError, "completed pinned"): self.invoke(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths()))

    def test_all_five_hardlinked_locks_refuse_without_deleting_payload_aliases(self):
        for path in (self.parent / "writer.lock", self.source / "generation.lock", *(self.parent / name for name in M.COORDINATOR_LOCKS)):
            alias = self.base / "fixture-lock-alias"; os.link(path, alias)
            with self.subTest(lock=path.name), self.assertRaisesRegex(ValueError, "single-link"): self.invoke(retire=True)
            alias.unlink()  # Temporary fixture only.
            self.assertTrue(all(path.exists() for path in self.paths()))
        self.assertEqual(self.paths()[0].stat().st_nlink, 3); self.preserved()

    def test_replaced_coordinator_lock_refuses_before_each_exact_unlink(self):
        original = M.unchanged; lock = self.parent / "campaign.lock"
        def replace_during_check(snapshots):
            original(snapshots)
            if (self.source / M.LEDGER).exists() and not (self.base / "fixture-displaced-lock").exists():
                lock.rename(self.base / "fixture-displaced-lock"); lock.touch(mode=0o600)
        with patch.object(M, "unchanged", side_effect=replace_during_check), self.assertRaisesRegex(ValueError, "unchanged source lock"):
            self.invoke(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths())); self.preserved()

        original_fsync = M.fsync_directory
        (self.base / "fixture-displaced-lock").unlink()  # Temporary fixture only.
        def replace_after_first_unlink(directory):
            original_fsync(directory)
            if directory == self.source / "shards":
                lock.rename(self.base / "fixture-displaced-lock"); lock.touch(mode=0o600)
        with patch.object(M, "fsync_directory", side_effect=replace_after_first_unlink), self.assertRaisesRegex(ValueError, "unchanged source lock"):
            self.invoke(retire=True, resume=True)
        self.assertFalse(self.paths()[0].exists())
        self.assertTrue(self.paths()[1].exists()); self.assertTrue(self.paths()[2].exists()); self.preserved()

    def test_wrong_pins_fit_target_traversal_alias_or_symlink_are_not_retirement_groups(self):
        original = dict(self.approval)
        for key in ("dataset_manifest_sha256", "archive_sidecar_sha256", "archive_result_sha256", "source_marker_sha256", "source_terminal_sha256"):
            self.approval = {**original, key: "0" * 64}
            with self.subTest(key=key), self.assertRaises(ValueError): self.invoke(retire=True)
        self.approval = original
        for target in (self.groups["fold1-fit"], {**self.groups["holdout"], "batch_alias": "../outside.json"},
                       {**self.groups["holdout"], "verification_alias": "verification/shards/unknown.json"}):
            self.approval = {**original, "targets": [target]}
            with self.assertRaises(ValueError): self.invoke(retire=True)
        self.approval = original; path = self.paths()[2]; saved = self.source / "saved-alias.json"; path.rename(saved); path.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"): self.invoke(retire=True)
        self.assertTrue(self.paths()[0].exists())

    def test_corrupt_partial_archive_or_changed_original_never_unlinks(self):
        projection = self.paths()[0]; original = projection.read_bytes(); projection.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes changed"): self.invoke(retire=True)
        projection.write_bytes(original)
        archive = self.source / (self.groups["holdout"]["projection"] + ".xz"); archive.write_bytes(archive.read_bytes()[:20])
        with self.assertRaises(ValueError): self.invoke(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths()))

    def test_real_deletion_cli_blocked_before_missing_approval_or_source_read(self):
        result = subprocess.run([sys.executable, str(PATH), "--approval", str(self.base / "missing"), "--approval-sha256", "0" * 64,
                                 "--retire-approved-files"], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0); self.assertIn("Material source deletion blocked", result.stderr)
        self.assertTrue(all(path.exists() for path in self.paths()))

    def test_tampered_durable_intent_cannot_inherit_partial_retirement(self):
        original = M.fsync_directory
        def interrupt(path):
            original(path)
            if path == self.source / "shards": raise RuntimeError("fixture crash")
        with patch.object(M, "fsync_directory", side_effect=interrupt), self.assertRaises(RuntimeError): self.invoke(retire=True)
        ledger = self.source / M.LEDGER / self.digest(self.approval_path)
        pending = next(ledger.glob("*.pending.private.json")); saved = pending.read_bytes(); record = S.parse_json(saved)
        record["original_signature"][1] += 1; self.write(pending, record)
        with self.assertRaisesRegex(ValueError, "inode/size"): self.invoke(retire=True, resume=True)
        self.assertTrue(self.paths()[1].exists()); self.assertTrue(self.paths()[2].exists())
        pending.write_bytes(saved)
        self.invoke(retire=True, resume=True); self.preserved()

    def test_unknown_source_or_verification_file_and_changed_verification_manifest_refuse(self):
        for directory in (self.source / "shards", self.source / "verification/shards"):
            extra = directory / "unknown.json"; extra.write_bytes(b"fixture-unknown"); extra.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "unknown source"): self.invoke(retire=True)
            extra.unlink()  # Temporary fixture only.
        manifest = self.source / "verification/manifest.json"
        manifest.unlink(); self.write(manifest, {"changed": "fixture-only"})
        with self.assertRaisesRegex(ValueError, "metadata SHA"): self.invoke(retire=True)
        self.assertTrue(all(path.exists() for path in self.paths()))


if __name__ == "__main__": unittest.main()
