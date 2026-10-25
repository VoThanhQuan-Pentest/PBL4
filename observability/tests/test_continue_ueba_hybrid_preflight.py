"""Mocked future source metadata only; never campaign/model/holdout evidence."""
from contextlib import ExitStack
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("hybrid_continuation_preflight", Path(__file__).resolve().parents[1] / "scripts/continue-ueba-strict.py")
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class HybridPreflightTest(unittest.TestCase):
    def setUp(self):
        from app.hybrid_strict_protocol import protocol_sha256, source_protocol
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.coordinator = self.base / "frozen-continuation.py"
        self.file(self.coordinator, Path(M.__file__).read_bytes())
        self.run = self.base / "hybrid-strict-source-future-fixture-12345678"; self.run.mkdir(mode=0o700)
        self.source = self.run / "source"; self.source.mkdir(mode=0o700)
        self.standard = self.source / "standard"; self.standard.mkdir(mode=0o700)
        self.code = self.base / "frozen-code"; (self.code / "app").mkdir(mode=0o700, parents=True)
        for name in ("__init__.py", "strict_campaign.py", "selection.py", "frozen_evaluation.py", "storage_budget.py"):
            self.file(self.code / "app" / name, b"# inert fixture, never executed\n")
        self.workspace = self.base / "frozen-java"; self.workspace.mkdir(mode=0o700)
        class_name = "service/siem/AccountRiskEngine.class"
        class_path = self.workspace / "backend/target/classes/com/flarefitness/backend" / class_name
        class_path.parent.mkdir(mode=0o700, parents=True)
        self.file(class_path, b"NOT_A_CLASS_NEVER_EXECUTED")
        (self.workspace / "jars").mkdir(mode=0o700)
        self.file(self.workspace / "jars" / "fixture.jar", b"NOT_A_JAR_NEVER_EXECUTED")
        classes = {class_name: M.digest(class_path)}
        self.snapshot_sha = self.document(self.workspace / "snapshot.json", {
            "classes": classes, "jars": {"fixture.jar": M.digest(self.workspace / "jars" / "fixture.jar")}})
        self.dataset_sha, self.archive_sha, self.image = "a" * 64, "b" * 64, "sha256:" + "c" * 64
        protocol = source_protocol("new-hybrid-test-20261005")
        identity = {"fixture_only": "not-real-full-source-proof", "java": {"classes": classes}}
        self.marker = {"scope": "FULL_STRICT_SOURCE", "protocol": protocol, "protocol_sha256": protocol_sha256(protocol),
                       "source_identity": identity, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0}
        self.terminal = {"status": "COMPLETE_UNQUALIFIED_SOURCE", "stage": "STRICT_SOURCE", "scope": "FULL_STRICT_SOURCE",
                         "quality_gate": "NOT_EVALUATED", "folds_completed": [1, 2, 3], "fit_or_score_calls": 0,
                         "holdout_numeric_records_read": 0, "downstream_holdout_numeric_records_read": 0,
                         "source_identity_before": identity, "source_identity_after": identity}
        marker_sha = self.document(self.source / "predeclared.private.json", self.marker)
        terminal_sha = self.document(self.source / "state.private.json", self.terminal)
        binding = {"fixture-producer": "d" * 64}
        generation_sha = self.document(self.standard / "generation.identity.json", {
            "stage": "STRICT", "dataset_id": protocol["dataset_id"], "source_binding": binding,
            "old_numeric_corpus_read": False, "authentic_capture": False, "fit_or_score_calls": 0})
        self.document(self.standard / "generation.progress.json", {"status": "COMPLETED", "stage": "STRICT",
            "dataset_id": protocol["dataset_id"], "manifest_sha256": self.dataset_sha, "fit_or_score_calls": 0})
        splits = {}
        for fold in (1, 2, 3):
            splits[f"fold{fold}-fit"] = {"records": 50000, "normal": 50000, "positive": 0, "cohorts": {"READY": 50000}}
            for cohort in ("ready", "cold"):
                splits[f"fold{fold}-calibration-{cohort}"] = {"normal": 1000000, "positive": 0}
            splits[f"fold{fold}-validation"] = {"normal": 1000000, "positive": 1000}
            directory = self.source / f"labels-fold{fold}"; directory.mkdir(mode=0o700)
            self.document(directory / "manifest.private.json", {"scope": "FULL_STRICT_SOURCE", "stage": "STRICT_SOURCE",
                "quality_gate": "NOT_EVALUATED", "fold": fold, "standard_manifest_sha256": self.dataset_sha,
                "standard_fit": splits[f"fold{fold}-fit"], "source_identity_before": identity, "source_identity_after": identity,
                "fit_or_score_calls": 0, "holdout_numeric_records_read": 0})
        splits["holdout"] = {"normal": 10000000, "positive": 10000}
        manifest = {"dataset_id": protocol["dataset_id"], "stage": "STRICT", "feature_schema_version": 4,
                    "telemetry_contract_version": 3, "data_provenance": "DEMO_ONLY", "compiled_feature_sha256": classes,
                    "workspace_snapshot_sha256": self.snapshot_sha,
                    "generation_identity_sha256": generation_sha, "source_binding": binding, "splits": splits}
        self.catalog = SimpleNamespace(manifest=manifest, split=lambda name: splits[name])
        self.arguments = {"dataset_sha": self.dataset_sha, "archive_sha": self.archive_sha, "marker_sha": marker_sha,
                          "terminal_sha": terminal_sha, "code": self.code, "code_sha": M.hybrid_code_identity(self.code, self.image)[1],
                          "workspace": self.workspace, "workspace_sha": self.snapshot_sha, "image": self.image}

    def file(self, path, raw): path.write_bytes(raw); path.chmod(0o600)

    def document(self, path, value):
        self.file(path, M.canonical(value).encode())
        return M.digest(path)

    def build(self, **changes):
        with ExitStack() as stack:
            stack.enter_context(patch.object(M, "RUNTIME", self.base))
            stack.enter_context(patch.object(M, "__file__", str(self.coordinator)))
            factory = stack.enter_context(patch("app.archived_catalog.ArchivedShardedDataset", return_value=self.catalog))
            stack.enter_context(patch.object(M.subprocess, "run", side_effect=AssertionError("preflight cannot dispatch Docker")))
            stack.enter_context(patch.object(M, "write", side_effect=AssertionError("preflight cannot write receipts")))
            result = M.HybridPlan(self.standard, **(self.arguments | changes))
            factory.assert_called_once_with(self.standard, expected_sha256=self.dataset_sha, expected_archive_sha256=self.archive_sha)
            return result

    def test_plan_pins_every_command_and_never_claims_model_or_capacity_admission(self):
        plan = self.build()
        with patch.object(plan, "require_headroom", return_value={"free_bytes": 19_000_000_000, "reserve_bytes": M.RESERVE_BYTES}):
            result = plan.preflight()
        self.assertFalse(result["execution_admitted"]); self.assertFalse(result["lifecycle_admitted"])
        self.assertFalse(result["storage"]["full_campaign_capacity_guaranteed"])
        self.assertEqual(result["storage"]["retained_model_publications_maximum"], 1080)
        self.assertEqual(result["storage"]["maximum_model_publication_cap_total_bytes"], 1080 * 128 * 1024 ** 2)
        self.assertEqual(result["storage"]["source_boot_model_class"]["initial_calibration_records"], 5000)
        for stage, command in result["commands"].items():
            self.assertEqual(command[:3], ["docker", "run", "-d"])
            self.assertIn("--coordinated", command); self.assertIn(self.dataset_sha, command); self.assertIn(self.archive_sha, command)
            self.assertIn(self.image, command); self.assertEqual(command[command.index("--entrypoint") + 1], "python")
            self.assertNotIn("--restart", command); self.assertNotIn("--rm", command)
            if stage in ("fit", "validation"): self.assertIn("--max-new-runs", command)
            if stage == "recalibration": self.assertIn("--max-new-recalibrations", command)
        self.assertEqual(result["fit_or_score_calls"], 0); self.assertEqual(result["holdout_numeric_records_read"], 0)

    def test_low_space_checkpoint_and_arbitrary_approval_never_admit_execution(self):
        approval = self.base / "operator-checkpoint.json"
        approval_sha = self.document(approval, {"retirement_approved": True, "unverified_fixture_only": True})
        plan = self.build(lifecycle_approval=approval, lifecycle_approval_sha=approval_sha)
        with patch.object(plan, "require_headroom", side_effect=ValueError("insufficient reserve")):
            result = plan.preflight()
        self.assertFalse(result["storage"]["next_fit_unit_admissible"])
        self.assertFalse(result["lifecycle_checkpoint_is_retirement_authority"])
        self.assertFalse(result["execution_admitted"])

    def test_scoped_live_or_source_identity_changed_metadata_is_refused(self):
        for change in ({"scope": "SCOPED_TEST"}, {"status": "RUNNING"}, {"source_identity_after": {"changed": True}},
                       {"downstream_holdout_numeric_records_read": 1}):
            sha = self.document(self.source / "state.private.json", self.terminal | change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "completed independent FULL"):
                self.build(terminal_sha=sha)

    def test_missing_pins_tampered_code_and_bytecode_are_refused(self):
        with self.assertRaisesRegex(ValueError, "code inventory SHA"):
            self.build(code_sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "trusted continuation metadata SHA"):
            self.build(marker_sha=None)
        (self.code / "app" / "__pycache__").mkdir()
        with self.assertRaisesRegex(ValueError, "bytecode"):
            self.build()

    def test_actual_producer_missing_compiled_map_uses_both_pinned_workspace_bindings(self):
        self.catalog.manifest.pop("compiled_feature_sha256")
        before = (self.source / "predeclared.private.json").read_bytes()
        plan = self.build()
        self.assertEqual(plan.identity["java_snapshot_sha256"], self.snapshot_sha)
        self.assertEqual((self.source / "predeclared.private.json").read_bytes(), before)
        self.catalog.manifest["workspace_snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "JVM class inventory"):
            self.build()
        self.catalog.manifest["workspace_snapshot_sha256"] = self.snapshot_sha
        changed = self.marker | {"source_identity": self.marker["source_identity"] | {"java": {"classes": {"unexpected.class": "a" * 64}}}}
        sha = self.document(self.source / "predeclared.private.json", changed)
        # Label/terminal identity checks reject drift before any JVM fallback.
        with self.assertRaises(ValueError): self.build(marker_sha=sha)


class HybridContinuationCliTest(unittest.TestCase):
    def test_default_legacy_cli_still_dispatches_the_original_runner(self):
        with patch("sys.argv", ["continue", "--dataset", "/fixture", "--fit-container-id", "a" * 64]), patch.object(M, "Runner") as runner:
            M.main()
        runner.assert_called_once_with(Path("/fixture"), "a" * 64)
        runner.return_value.run.assert_called_once()

    def test_hybrid_execution_is_blocked_before_any_preflight_read(self):
        with patch("sys.argv", ["continue", "--mode", "hybrid-source", "--dataset", "/fixture"]), \
                patch.object(M, "HybridPlan", side_effect=AssertionError("execution cannot read or dispatch")), \
                patch.object(M, "Runner", side_effect=AssertionError("cannot fall back to legacy")), \
                self.assertRaises(SystemExit) as failure:
            M.main()
        self.assertEqual(failure.exception.code, 2)

    def test_preflight_requires_every_explicit_checkpoint_and_does_not_fall_back(self):
        with patch("sys.argv", ["continue", "--mode", "hybrid-source", "--dataset", "/fixture", "--preflight"]), \
                patch.object(M, "HybridPlan", side_effect=AssertionError("missing checkpoints cannot read")), \
                self.assertRaises(SystemExit) as failure:
            M.main()
        self.assertEqual(failure.exception.code, 2)

    def test_exact_terminal_handle_is_required_without_restart_semantics(self):
        identity, container, image = "a" * 64, "b" * 64, "sha256:" + "c" * 64
        value = {"Id": container, "Image": image, "Config": {"Labels": {"flare.strict.identity": identity}},
                 "State": {"Status": "running", "ExitCode": 0}}
        options = {"container_id": container, "image": image, "identity_sha": identity}
        self.assertFalse(M.hybrid_terminal_ready(value, **options))
        value["State"] = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
        self.assertTrue(M.hybrid_terminal_ready(value, **options))
        for change in ({"Id": "d" * 64}, {"State": {"Status": "exited", "ExitCode": 137}},
                       {"State": {"Status": "exited", "ExitCode": 0, "OOMKilled": True}}):
            with self.assertRaises(ValueError): M.hybrid_terminal_ready(value | change, **options)


if __name__ == "__main__": unittest.main()
