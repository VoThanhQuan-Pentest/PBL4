"""Mock Docker and fabricated metadata only; no real source/campaign/model proof."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_continue_ueba_hybrid_preflight as fixtures

M = fixtures.M


class HybridOneUnitTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.HybridPreflightTest(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        for name in (*M.FIT_SOURCES, "validation.py", "risk_replay.py"):
            self.fixture.file(self.fixture.code / "app" / name, b"# inert fixture, not executable training evidence\n")
        # An empty package initializer is legitimate; all metadata stays nonempty.
        self.fixture.file(self.fixture.code / "app" / "__init__.py", b"")
        for fold in (1, 2, 3):
            fit = self.fixture.catalog.split(f"fold{fold}-fit"); fit["sha256"] = str(fold) * 64
            path = self.fixture.source / f"labels-fold{fold}" / "manifest.private.json"
            label = json.loads(path.read_text()); label["standard_fit"] = fit; self.fixture.document(path, label)
        self.fixture.arguments["code_sha"] = M.hybrid_code_identity(self.fixture.code, self.fixture.image)[1]
        self.plan = self.fixture.build()
        self.run = self.plan.protocol["campaign"][0]
        self.container = "e" * 64
        self.before = {"actual_fits_completed": 0, "validation_runs_completed": 0, "completed_recalibrations": 0}
        self.approval = {"approval_schema_version": 1, "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
                         "source_standard": str(self.plan.dataset), "continuation_identity_sha256": self.plan.identity_sha256,
                         "stage": "fit", "unit_id": self.run["run_id"], "expected_before": self.before,
                         "execution_approved": True, "retirement_approved": False,
                         "user_approval_reference": "private future fixture only, never actual campaign approval"}
        self.approval_path = self.fixture.base / "one-unit-approval.private.json"
        self.approval_sha = self.fixture.document(self.approval_path, self.approval)
        self.state_path = self.plan.dataset / "hybrid-one-unit" / (self.approval_sha + ".private.json")
        self.fingerprint = {"sources": {name: self.plan.identity["python_sources"][name] for name in M.FIT_SOURCES},
                            "dependencies": {name: "fixture-version" for name in ("scikit-learn", "numpy", "scipy", "joblib")}}

    def fit_completed(self):
        for name in ("hybrid-runs", "hybrid-models"): (self.plan.dataset / name).mkdir(mode=0o700, exist_ok=True)
        identity = {"dataset_manifest_sha256": self.plan.identity["dataset_sha256"], "code_fingerprint": self.fingerprint,
                    "model_kind": M.HYBRID_KIND, "recipe_version": 1,
                    "labeled_training_manifest_sha256_by_fold": self.plan.identity["labeled_manifest_sha256_by_fold"]}
        self.fixture.document(self.plan.dataset / "hybrid-campaign.identity.json", identity)
        source, calibrated = "hybrid_fit_fixture_0001", "hybrid_cal_fixture_0001"
        for version in (source, calibrated): self.fixture.file(self.plan.dataset / "hybrid-models" / (version + ".joblib"), b"NOT_A_MODEL_" + version.encode())
        receipt = {**self.run, "status": "FITTED_CALIBRATED", "dataset_manifest_sha256": self.plan.identity["dataset_sha256"],
                   "code_fingerprint": self.fingerprint, "model_kind": M.HYBRID_KIND, "recipe_version": 1,
                   "labeled_training_manifest_sha256": self.plan.identity["labeled_manifest_sha256_by_fold"]["1"],
                   "normal_fit_split_sha256": self.plan.catalog.split("fold1-fit")["sha256"],
                   "fit_split_sha256": self.plan.catalog.split("fold1-fit")["sha256"], "training_windows": 50000,
                   "calibration_scope": "STRICT", "quality_gate": "NOT_RUN", "actual_composite_trials": 1,
                   "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0,
                   "source_model_version": source, "source_model_sha256": M.digest(self.plan.dataset / "hybrid-models" / (source + ".joblib")),
                   "model_version": calibrated, "model_sha256": M.digest(self.plan.dataset / "hybrid-models" / (calibrated + ".joblib"))}
        self.fixture.document(self.plan.dataset / "hybrid-runs" / (self.run["run_id"] + ".json"), receipt)
        self.fixture.document(self.plan.dataset / "hybrid-campaign.progress.json", {**identity,
            "status": "STOPPED_AT_RUN_BOUNDARY", "actual_fits_completed": 1, "last_run_id": self.run["run_id"], "quality_gate": "NOT_RUN"})

    def inspection(self, status="exited", exit_code=0):
        return {"Id": self.container, "Image": self.plan.image,
                "Config": {"Labels": {"flare.strict.identity": self.plan.identity_sha256}},
                "State": {"Status": status, "ExitCode": exit_code, "OOMKilled": False}}

    def context(self, docker):
        stack = ExitStack()
        stack.enter_context(patch.object(self.plan, "recheck", return_value=None))
        stack.enter_context(patch.object(self.plan, "require_headroom", return_value={"reserve_bytes": M.RESERVE_BYTES}))
        stack.enter_context(patch.object(M.subprocess, "run", side_effect=docker))
        stack.enter_context(patch.object(M.time, "sleep", return_value=None))
        return stack

    def test_one_approved_unit_persists_exact_handle_before_wait_and_no_successor(self):
        launches = []
        def docker(command, **kwargs):
            if command[1:3] == ["container", "ls"]: return SimpleNamespace(returncode=0, stdout="")
            if command[1] == "run":
                launches.append(command)
                state = json.loads(self.state_path.read_text()); self.assertEqual(state["status"], "DISPATCH_INTENT")
                self.assertIsNone(state["container_id"])
                return SimpleNamespace(returncode=0, stdout=self.container)
            state = json.loads(self.state_path.read_text()); self.assertEqual(state["container_id"], self.container)
            self.fit_completed()
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection()]))
        with self.context(docker): result = M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
        self.assertEqual(result["status"], "SUCCEEDED"); self.assertEqual(len(launches), 1)
        self.assertEqual(result["result"]["counts"], self.before | {"actual_fits_completed": 1})
        self.assertEqual(result["quality_gate"], "NOT_RUN"); self.assertFalse(result["retirement_authority"])
        self.assertEqual(launches[0][launches[0].index("--user") + 1], "1000:1000")
        self.assertEqual(launches[0][launches[0].index("--cpus") + 1], "2")
        self.assertEqual(M.next_hybrid_unit(self.plan)["stage"], "validation")

    def test_observation_timeout_resumes_same_running_handle_without_restart(self):
        calls, polls = [], 0
        def docker(command, **kwargs):
            nonlocal polls
            calls.append(command)
            if command[1:3] == ["container", "ls"]: return SimpleNamespace(returncode=0, stdout="")
            if command[1] == "run": return SimpleNamespace(returncode=0, stdout=self.container)
            polls += 1
            if polls == 1: raise M.subprocess.TimeoutExpired(command, 15)
            if polls == 2: return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection("running")]))
            self.fit_completed()
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection()]))
        with self.context(docker):
            pending = M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
            self.assertEqual(pending["status"], "OBSERVATION_UNAVAILABLE"); self.assertEqual(pending["container_id"], self.container)
            result = M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(sum(command[1] == "run" for command in calls), 1)
        self.assertEqual(sum(command[1:3] == ["container", "ls"] for command in calls), 1)

    def test_terminal_failure_is_retained_and_never_restarted(self):
        launches = []
        def docker(command, **kwargs):
            if command[1:3] == ["container", "ls"]: return SimpleNamespace(returncode=0, stdout="")
            if command[1] == "run": launches.append(command); return SimpleNamespace(returncode=0, stdout=self.container)
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection(exit_code=137)]))
        with self.context(docker):
            with self.assertRaisesRegex(ValueError, "child failed"):
                M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
            self.assertEqual(json.loads(self.state_path.read_text())["status"], "FAILED")
            with self.assertRaisesRegex(ValueError, "failed one-unit"):
                M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
        self.assertEqual(len(launches), 1)

    def test_ambiguous_dispatch_adopts_only_the_named_exact_identity_without_relaunch(self):
        launches = []
        def docker(command, **kwargs):
            if command[1:3] == ["container", "ls"]: return SimpleNamespace(returncode=0, stdout="")
            if command[1] == "run":
                launches.append(command)
                raise M.subprocess.TimeoutExpired(command, 15)
            self.assertEqual(command[-1], json.loads(self.state_path.read_text())["container_name"])
            self.fit_completed()
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection()]))
        with self.context(docker):
            unknown = M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
            self.assertEqual(unknown["status"], "DISPATCH_UNKNOWN"); self.assertIsNone(unknown["container_id"])
            completed = M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
        self.assertEqual(completed["container_id"], self.container); self.assertEqual(completed["status"], "SUCCEEDED")
        self.assertEqual(len(launches), 1)

    def test_replaced_coordinator_inode_is_refused_after_terminal_observation(self):
        def docker(command, **kwargs):
            if command[1:3] == ["container", "ls"]: return SimpleNamespace(returncode=0, stdout="")
            if command[1] == "run": return SimpleNamespace(returncode=0, stdout=self.container)
            lock = self.state_path.parent / "coordinator.lock"
            temporary = self.fixture.base / "replacement-fixture.lock"; self.fixture.file(temporary, b"")
            M.os.replace(temporary, lock)  # Only this test's temporary lock inode.
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.inspection()]))
        with self.context(docker), self.assertRaisesRegex(ValueError, "lock pathname/inode changed"):
            M.execute_hybrid_one_unit(self.plan, self.approval_path, self.approval_sha)
        self.assertEqual(json.loads(self.state_path.read_text())["status"], "FAILED")

    def test_stage_and_ordinal_bind_distinct_names_for_successive_units(self):
        commands = [self.plan.command(stage, ordinal) for stage, ordinal in
                    (("fit", 1), ("fit", 2), ("validation", 1), ("validation", 2), ("recalibration", 1), ("recalibration", 2))]
        self.assertEqual(len({command[command.index("--name") + 1] for command in commands}), 6)

    def test_watermark_drift_and_wrong_before_counts_refuse_before_dispatch(self):
        for condition in ("watermark", "identity", "counts"):
            with self.subTest(condition=condition), ExitStack() as stack:
                stack.enter_context(patch.object(self.plan, "recheck", side_effect=ValueError("identity drift") if condition == "identity" else None))
                stack.enter_context(patch.object(self.plan, "require_headroom", side_effect=ValueError("reserve refused") if condition == "watermark" else None))
                docker = stack.enter_context(patch.object(M.subprocess, "run", side_effect=AssertionError("cannot dispatch")))
                approval = self.approval | ({"expected_before": self.before | {"actual_fits_completed": 1}} if condition == "counts" else {})
                sha = self.fixture.document(self.approval_path, approval)
                with self.assertRaises(ValueError): M.execute_hybrid_one_unit(self.plan, self.approval_path, sha)
                docker.assert_not_called()
                self.assertEqual(M.digest(self.approval_path), sha)  # Approval counts never rewritten.

    def test_retirement_or_generic_lifecycle_approval_is_not_campaign_authority(self):
        for change in ({"retirement_approved": True}, {"scope": "NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR"}, {"execution_approved": False}):
            sha = self.fixture.document(self.approval_path, self.approval | change)
            with self.assertRaisesRegex(ValueError, "one-unit campaign-run approval"):
                M.campaign_run_approval(self.plan, self.approval_path, sha)

    def test_failed_or_incomplete_orphan_receipt_cannot_start_a_new_unit(self):
        directory = self.plan.dataset / "hybrid-runs"; directory.mkdir(mode=0o700)
        for status in ("FAILED", "CALIBRATING"):
            self.fixture.document(directory / (self.run["run_id"] + ".json"), {"status": status})
            with self.assertRaises(ValueError): M.next_hybrid_unit(self.plan)

    def test_selected_holdout_gate_is_strict_and_does_not_score(self):
        identity = {"dataset_manifest_sha256": self.plan.identity["dataset_sha256"], "fit_code_fingerprint": self.fingerprint,
                    "model_kind": M.HYBRID_KIND, "recipe_version": 1,
                    "selection_sources": {name: self.plan.identity["python_sources"][name] for name in ("selection.py", "validation.py", "risk_replay.py")},
                    "production_classes": self.plan.java_classes}
        recalibrations = {run["run_id"]: {"model_version": "hybrid_top_fixture_" + str(index), "fold": run["fold"], "config": run["config"],
                          "model_sha256": "a" * 64, "calibration_sha256": "b" * 64, "policy_sha256": "c" * 64, "model_state_sha256": "d" * 64}
                          for index, run in enumerate(self.plan.protocol["campaign"][:45])}
        representative = next(receipt for receipt in recalibrations.values() if receipt["fold"] == 3 and receipt["config"]["random_state"] == 42)
        counts = {"actual_fits_completed": 360, "validation_runs_completed": 360, "completed_recalibrations": 45}
        records = {"counts": counts, "fingerprint": self.fingerprint, "recalibrations": recalibrations}
        selected = {**representative, **counts, "status": "SELECTED", "model_kind": M.HYBRID_KIND, "recipe_version": 1,
                    "dataset_sha256": self.plan.identity["dataset_sha256"], "additional_fit_calls_in_recalibration": 0,
                    "holdout_scored": False, "selection_identity": identity}
        M.hybrid_selected(self.plan, selected, records)
        for change in ({"status": "NO_QUALIFIED_CONFIG"}, {"completed_recalibrations": 44}, {"holdout_scored": True},
                       {"additional_fit_calls_in_recalibration": 1}, {"actual_fits_completed": True}):
            with self.assertRaises(ValueError): M.hybrid_selected(self.plan, selected | change, records)


class HybridHoldoutBoundaryTest(unittest.TestCase):
    """Minimal inert plans avoid loading training dependencies for gate checks."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        source = base / "source"; source.mkdir(mode=0o700)
        dataset = source / "standard"; dataset.mkdir(mode=0o700)
        campaign = [{"run_id": f"fixture_run_{configuration:02d}_{member:02d}",
                     "config": {"max_iter": configuration + 1, "max_leaf_nodes": 2, "l2_regularization": 0}}
                    for configuration in range(24) for member in range(15)]
        self.plan = SimpleNamespace(dataset=dataset, protocol={"campaign": campaign}, identity_sha256="a" * 64,
                                    recheck=lambda: None, require_headroom=lambda *args: None)
        self.run = campaign[0]; self.container = "e" * 64; self.fingerprint = {"fixture_only": True}
        self.before = {"actual_fits_completed": 0, "validation_runs_completed": 0, "completed_recalibrations": 0}
        self.approval = {"approval_schema_version": 1, "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
                         "source_standard": str(dataset), "continuation_identity_sha256": self.plan.identity_sha256,
                         "stage": "fit", "unit_id": self.run["run_id"], "expected_before": self.before,
                         "execution_approved": True, "retirement_approved": False,
                         "user_approval_reference": "fabricated gate test only, not campaign authority"}
        self.approval_path = base / "one-unit-approval.private.json"

    def file(self, path, body):
        path.write_bytes(body); path.chmod(0o600)

    def document(self, path, value):
        self.file(path, M.canonical(value).encode())
        return M.digest(path)

    def context(self, docker):
        stack = ExitStack()
        stack.enter_context(patch.object(M.subprocess, "run", side_effect=docker))
        return stack

    def test_exact_audit_marker_blocks_holdout_transition_before_holdout_metadata(self):
        campaign = self.plan.protocol["campaign"]
        counts = {"actual_fits_completed": 360, "validation_runs_completed": 360, "completed_recalibrations": 45}
        records = {"fits": {run["run_id"]: {} for run in campaign},
                   "validations": {run["run_id"]: {} for run in campaign}, "counts": counts, "fingerprint": self.fingerprint}
        fields = ("max_iter", "max_leaf_nodes", "l2_regularization")
        configurations = {M.canonical({key: run["config"][key] for key in fields}):
                          {"configuration": {key: run["config"][key] for key in fields}} for run in campaign}
        ranking = {"validation_runs_completed": 360, "configurations": list(configurations.values())}
        selected = {"model_version": "hybrid_selected_fixture_0001"}
        holdout_reads = []
        def receipt(path):
            if path.name == "hybrid-ranking.json": return ranking
            if path.name == "hybrid-selection.json": return selected
            holdout_reads.append(path)
            return None
        with ExitStack() as stack:
            stack.enter_context(patch.object(M, "hybrid_records", return_value=records))
            stack.enter_context(patch.object(M, "selection_binding", return_value=None))
            stack.enter_context(patch.object(M, "hybrid_selected", return_value=None))
            stack.enter_context(patch.object(M, "private_receipt", side_effect=receipt))
            docker = stack.enter_context(patch.object(M.subprocess, "run", side_effect=AssertionError("cannot dispatch")))
            self.assertEqual(M.next_hybrid_unit(self.plan),
                             {"stage": "holdout", "unit_id": selected["model_version"], "before": counts})
            holdout_reads.clear()
            for directory in (self.plan.dataset, self.plan.dataset.parent):
                with self.subTest(marker_directory=directory.name):
                    marker = directory / "holdout-access-audit.private.json"
                    self.file(marker, b"{}")  # Malformed fabricated audit must fail closed.
                    try:
                        with self.assertRaises(ValueError): M.next_hybrid_unit(self.plan)
                        self.assertEqual(holdout_reads, [])
                    finally:
                        marker.unlink()  # Only this test's temporary marker.
            docker.assert_not_called()

    def test_audit_markers_leave_fit_and_validation_boundaries_unchanged(self):
        for directory in (self.plan.dataset, self.plan.dataset.parent):
            self.file(directory / "holdout-access-audit.private.json", b"{}")
        with patch.object(M, "require_unblocked_holdout", side_effect=AssertionError("not a holdout transition")), \
                patch.object(M, "hybrid_records", return_value={"fits": {}, "validations": {}, "counts": self.before}):
            self.assertEqual(M.next_hybrid_unit(self.plan), {"stage": "fit", "unit_id": self.run["run_id"], "before": self.before})
        counts = self.before | {"actual_fits_completed": 1}
        with patch.object(M, "require_unblocked_holdout", side_effect=AssertionError("not a holdout transition")), \
                patch.object(M, "hybrid_records", return_value={"fits": {self.run["run_id"]: {}}, "validations": {}, "counts": counts}):
            self.assertEqual(M.next_hybrid_unit(self.plan), {"stage": "validation", "unit_id": self.run["run_id"], "before": counts})

    def test_retained_holdout_states_cannot_bypass_audit_gate_or_inspect_docker(self):
        counts = {"actual_fits_completed": 360, "validation_runs_completed": 360, "completed_recalibrations": 45}
        approval = self.approval | {"stage": "holdout", "unit_id": "hybrid_selected_fixture_0001", "expected_before": counts}
        sha = self.document(self.approval_path, approval)
        ledger = self.plan.dataset / "hybrid-one-unit"; ledger.mkdir(mode=0o700)
        path = ledger / (sha + ".private.json")
        state = {"identity_sha256": self.plan.identity_sha256, "approval_sha256": sha,
                 "stage": "holdout", "unit_id": approval["unit_id"], "before": counts,
                 "container_name": "fabricated-holdout-child", "container_id": self.container}
        for directory in (self.plan.dataset, self.plan.dataset.parent):
            marker = directory / "holdout-access-audit.private.json"
            self.file(marker, b"{}")
            try:
                for status in ("DISPATCH_INTENT", "DISPATCH_UNKNOWN", "DISPATCHED", "RUNNING", "OBSERVATION_UNAVAILABLE"):
                    with self.subTest(marker_directory=directory.name, status=status):
                        self.document(path, state | {"status": status})
                        before = path.read_bytes()
                        with self.context(lambda *args, **kwargs: self.fail("cannot inspect or dispatch Docker")), \
                                patch.object(M, "next_hybrid_unit", side_effect=AssertionError("retained state skips next unit")), \
                                self.assertRaises(ValueError):
                            M.execute_hybrid_one_unit(self.plan, self.approval_path, sha)
                        self.assertEqual(path.read_bytes(), before)
            finally:
                marker.unlink()  # Only this test's temporary marker.


class HybridOneUnitCliTest(unittest.TestCase):
    def test_execute_flag_requires_specific_approval_before_preflight_reads(self):
        with patch("sys.argv", ["continue", "--mode", "hybrid-source", "--dataset", "/fixture", "--execute-one-unit"]), \
                patch.object(M, "HybridPlan", side_effect=AssertionError("approval required before reads")), self.assertRaises(SystemExit):
            M.main()


if __name__ == "__main__": unittest.main()
