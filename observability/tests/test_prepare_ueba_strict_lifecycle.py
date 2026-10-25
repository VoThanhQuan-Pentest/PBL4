"""Private opaque fixtures only; never corpus, campaign or runtime evidence."""
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("strict_lifecycle_prepare_test", DIRECTORY.parent / "scripts/prepare-ueba-strict-lifecycle.py")
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
FIXTURE_SPEC = importlib.util.spec_from_file_location("strict_lifecycle_opaque_fixture", DIRECTORY / "test_retire_ueba_strict_source_shards.py")
F = importlib.util.module_from_spec(FIXTURE_SPEC); FIXTURE_SPEC.loader.exec_module(F)


class PrepareLifecycleTest(unittest.TestCase):
    def setUp(self):
        fixture = F.SourceRetirementTest(); self.addCleanup(fixture.doCleanups); fixture.setUp()
        fixture.production_checkpoint(); self.fixture = fixture
        for obj, name, value in ((M, "R", F.M), (M, "S", F.S), (M, "C", F.M.C), (F.M.C, "RUNTIME", fixture.base)):
            change = patch.object(obj, name, value); change.start(); self.addCleanup(change.stop)
        change = patch("app.hybrid_strict_dataset.validate_standard_manifest"); change.start(); self.addCleanup(change.stop)
        self.observer = "9" * 64
        shim = fixture.base / "docker"
        shim.write_bytes((DIRECTORY.parent / "scripts/strict-lifecycle-docker-shim.py").read_bytes()); shim.chmod(0o700)
        program = patch.object(M.shutil, "which", return_value=str(shim)); program.start(); self.addCleanup(program.stop)
        environment = patch.dict(os.environ, {"UEBA_DIAGNOSTIC_IMAGE_ID": F.M.IMAGE,
            "UEBA_LIFECYCLE_DOCKER_SHIM_SHA256": F.S.sha256(shim.read_bytes()),
            "UEBA_LIFECYCLE_DOCKER_PROXY_SHA256": "1" * 64,
            "UEBA_LIFECYCLE_DOCKER_SOURCE_SHA256": F.S.sha256(str(fixture.source).encode())})
        environment.start(); self.addCleanup(environment.stop)
        hostname = patch.object(M.os, "uname", return_value=type("Uname", (), {"nodename": self.observer[:12]})())
        hostname.start(); self.addCleanup(hostname.stop)
        self.approval_path = fixture.base / "new-lifecycle-approval.private.json"
        self.checkpoint_path = fixture.base / "new-lifecycle-coordinator.private.json"
        self.inputs = {"dataset": fixture.source, "dataset_sha": fixture.manifest_sha,
            "archive_sha": fixture.archive["archive_sidecar_sha256"], "archive_result_sha": fixture.digest(fixture.source / F.S.RESULT),
            "marker_sha": fixture.marker_sha, "terminal_sha": fixture.terminal_sha,
            "code": fixture.code, "code_sha": F.M.C.hybrid_code_identity(fixture.code, F.M.IMAGE)[1],
            "workspace": fixture.workspace, "workspace_sha": fixture.digest(fixture.workspace / "snapshot.json"),
            "image": F.M.IMAGE, "user_approval_reference": "User-approved temporary opaque fixture only",
            "observer_container_id": self.observer, "approval_path": self.approval_path, "checkpoint_path": self.checkpoint_path}
        self.inputs["observer_code_sha"] = F.S.sha256(Path(M.__file__).read_bytes())
        self.containers = {self.observer: self.container(self.observer, running=True, observer=True)}

    def container(self, identifier, *, running, observer=False, mounts=None, labels=None, status=None):
        return {"Id": identifier, "Image": F.M.IMAGE, "State": {"Status": status or ("running" if running else "exited"), "Running": running},
            "Config": {"Hostname": identifier[:12], "Labels": {M.OBSERVER_LABEL: "metadata-only"} if observer else labels or {},
                       "Cmd": ["metadata-fixture"], "Entrypoint": ["python"], "Env": []}, "Mounts": mounts or []}

    def docker(self, command, **kwargs):
        self.assertEqual(command[0], "docker")
        self.assertTrue(kwargs.get("capture_output")); self.assertTrue(kwargs.get("text"))
        if command[1:] == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
            return subprocess.CompletedProcess(command, 0, "\n".join(self.containers) + "\n", "")
        self.assertEqual(command[1:4], ["inspect", "--type", "container"])
        return subprocess.CompletedProcess(command, 0, F.S.canonical([self.containers[command[4]]]), "")

    def invoke(self, **changes):
        original_read = F.S.ShardedDataset._read
        def metadata_read(dataset, relative, maximum):
            self.assertEqual(relative, "manifest.json", "no numeric original resource may be opened")
            return original_read(dataset, relative, maximum)
        with patch.object(M.subprocess, "run", side_effect=self.docker), \
                patch.object(F.S, "read_bytes", wraps=F.S.read_bytes) as reads, \
                patch.object(F.S, "restore_xz", side_effect=AssertionError("no original/XZ payload reads")), \
                patch("app.archived_catalog.restore_xz", side_effect=AssertionError("no archive payload decode")), \
                patch.object(F.S.ShardedDataset, "_read", autospec=True, side_effect=metadata_read), \
                patch.object(F.S.ShardedDataset, "load_shard", side_effect=AssertionError("no numeric parsing")), \
                patch.object(F.S.ShardedDataset, "iter_shards", side_effect=AssertionError("no numeric iteration")), \
                patch.object(F.M, "bound_source", side_effect=AssertionError("no retirement payload verification")), \
                patch.object(F.M, "run", side_effect=AssertionError("no retirement dispatch")):
            result = M.prepare(**{**self.inputs, **changes})
            self.assertTrue(all(Path(call.args[0]).name in {"receipt.json", "manifest.json", "predeclared.private.json", "state.private.json", "generation.identity.json",
                    "generation.progress.json", F.S.SIDECAR, F.S.RESULT, self.approval_path.name, self.checkpoint_path.name}
                for call in reads.call_args_list))
            return result

    def test_default_metadata_only_initializes_existing_coordinated_stage_contract_without_payload_read(self):
        for name in F.M.COORDINATOR_LOCKS: (self.fixture.parent / name).unlink()
        result = self.invoke()
        self.assertEqual(result["status"], "VERIFIED_METADATA_ONLY"); self.assertEqual(result["targets"], 10)
        self.assertFalse(self.approval_path.exists()); self.assertFalse(self.checkpoint_path.exists())
        for path in F.M.lock_paths(self.fixture.source):
            self.assertTrue(path.is_file()); self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.fixture.preserved()

    def test_prepare_issues_exact_existing_schema_and_verify_rebuilds_every_binding(self):
        result = self.invoke(write=True)
        self.assertEqual(result["status"], "PREPARED_METADATA_ONLY")
        self.assertEqual(self.approval_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.checkpoint_path.stat().st_mode & 0o777, 0o600)
        approval = F.M.load_approval(self.approval_path, result["approval_sha256"])
        self.assertEqual(set(approval), F.M.APPROVAL_FIELDS)
        self.assertEqual({target["projection"] for target in approval["targets"]},
                         {group["projection"] for split, group in self.fixture.groups.items() if not split.endswith("-fit")})
        checkpoint = F.S.metadata(self.checkpoint_path, F.S.MAX_METADATA, result["checkpoint_sha256"])[0]
        self.assertEqual(set(checkpoint), F.M.CHECKPOINT_FIELDS); self.assertEqual(checkpoint["active_consumers"], [])
        self.assertEqual(checkpoint["lock_paths"], [str(path) for path in F.M.lock_paths(self.fixture.source)])
        verified = self.invoke(approval_sha=result["approval_sha256"], checkpoint_sha=result["checkpoint_sha256"])
        self.assertEqual(verified["status"], "VERIFIED_LIFECYCLE_METADATA_ONLY"); self.fixture.preserved()
        self.assertFalse((self.fixture.source / F.M.LEDGER).exists())

    def test_bounded_batch_is_exact_manifest_slice_and_retains_existing_approval_schema(self):
        eligible = sorted(group["projection"] for split, group in self.fixture.groups.items() if not split.endswith("-fit"))
        result = self.invoke(write=True, target_start=2, target_count=3)
        approval = F.M.load_approval(self.approval_path, result["approval_sha256"])
        self.assertEqual([value["projection"] for value in approval["targets"]], eligible[2:5])
        self.assertEqual(set(approval), F.M.APPROVAL_FIELDS)
        self.assertEqual(result["targets"], 3); self.assertEqual(result["original_aliases"], 9)
        self.invoke(target_start=2, target_count=3,
            approval_sha=result["approval_sha256"], checkpoint_sha=result["checkpoint_sha256"])
        with self.assertRaises(ValueError):
            self.invoke(target_start=3, target_count=3,
                approval_sha=result["approval_sha256"], checkpoint_sha=result["checkpoint_sha256"])
        self.fixture.preserved()

    def test_later_batch_prepares_after_earlier_exact_fixture_retirement_without_absence_selection(self):
        eligible = sorted(group["projection"] for split, group in self.fixture.groups.items() if not split.endswith("-fit"))
        first = self.invoke(write=True, target_count=2)
        with patch.object(F.S, "validate_standard_manifest"), \
                patch.object(F.S.ShardedDataset, "load_shard", side_effect=AssertionError("no numeric fixture decoding")):
            retired = F.M.run_fixture(self.approval_path, first["approval_sha256"], retire=True)
        self.assertEqual(retired["original_aliases_deleted_this_attempt"], 6)
        with self.assertRaises(OSError): self.invoke(target_count=2)
        self.approval_path = self.fixture.base / "next-batch-approval.private.json"
        self.checkpoint_path = self.fixture.base / "next-batch-coordinator.private.json"
        self.inputs.update(approval_path=self.approval_path, checkpoint_path=self.checkpoint_path)
        second = self.invoke(write=True, target_start=2, target_count=2)
        approval = F.M.load_approval(self.approval_path, second["approval_sha256"])
        self.assertEqual([value["projection"] for value in approval["targets"]], eligible[2:4])
        for split, group in self.fixture.groups.items():
            if split.endswith("-fit"):
                self.assertTrue((self.fixture.source / group["projection"]).is_file())

    def test_invalid_or_implicit_target_ranges_refuse_without_operator_artifacts(self):
        for start, count in ((-1, 2), (True, 2), (10, 1), (1, None), (0, 0), (0, True), (0, 257), (0, 1.0)):
            with self.subTest(start=start, count=count), self.assertRaises(ValueError):
                self.invoke(write=True, target_start=start, target_count=count)
            self.assertFalse(self.approval_path.exists()); self.assertFalse(self.checkpoint_path.exists())

    def test_selected_batch_keeps_receipt_and_alias_tamper_checks_and_always_checks_fit(self):
        eligible = sorted((group["projection"], split, group) for split, group in self.fixture.groups.items() if not split.endswith("-fit"))
        _, _, group = eligible[0]
        path = self.fixture.source / group["batch_alias"]
        saved = path.read_bytes(); path.unlink(); path.write_bytes(saved); path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "three-alias"):
            self.invoke(target_count=1)
        path.unlink(); os.link(self.fixture.source / group["projection"], path)
        fit = next(group for split, group in self.fixture.groups.items() if split.endswith("-fit"))
        fit_path = self.fixture.source / fit["verification_alias"]
        fit_path.unlink()
        with self.assertRaises(OSError): self.invoke(target_start=1, target_count=1)

    def test_prepare_never_overwrites_and_changed_pins_targets_receipts_or_aliases_refuse(self):
        self.invoke(write=True)
        before = self.approval_path.read_bytes(), self.checkpoint_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "fresh"): self.invoke(write=True)
        self.assertEqual(before, (self.approval_path.read_bytes(), self.checkpoint_path.read_bytes()))
        with self.assertRaises(ValueError): self.invoke(archive_result_sha="0" * 64)
        receipt = self.fixture.source / self.fixture.groups["holdout"]["batch_alias"]
        saved = receipt.read_bytes(); receipt.unlink(); receipt.write_bytes(saved); receipt.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "three-alias"): self.invoke()
        self.assertTrue(self.approval_path.exists()); self.assertTrue(self.checkpoint_path.exists())

    def test_actual_active_source_mount_or_matching_identity_is_refused(self):
        identifier = "2" * 64
        source_alias = self.fixture.base / "source-alias"; source_alias.symlink_to(self.fixture.source.parent)
        for kwargs in ({"mounts": [{"Source": str(self.fixture.source.parent)}]},
                       {"mounts": [{"Source": str(self.fixture.base)}]},
                       {"mounts": [{"Source": str(source_alias)}]},
                       {"labels": {"flare.strict.identity": self.fixture.checkpoint["continuation_identity_sha256"]}},
                       {"mounts": [{"Source": str(self.fixture.source)}], "status": "created", "running": False}):
            self.containers[identifier] = self.container(identifier, **{"running": True, **kwargs})
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "active Docker consumer"): self.invoke(write=True)
            self.assertFalse(self.approval_path.exists()); self.assertFalse(self.checkpoint_path.exists())
        self.containers[identifier] = self.container(identifier, running=False, mounts=[{"Source": str(self.fixture.source)}])
        self.invoke()

    def test_inventory_failure_or_unproven_self_exclusion_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "observer code"): self.invoke(observer_code_sha="0" * 64)
        for name in ("UEBA_LIFECYCLE_DOCKER_SHIM_SHA256", "UEBA_LIFECYCLE_DOCKER_PROXY_SHA256", "UEBA_LIFECYCLE_DOCKER_SOURCE_SHA256"):
            with patch.dict(os.environ, {name: "not-a-trusted-pin"}), self.assertRaisesRegex(ValueError, "shim/proxy"):
                self.invoke()
        with patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "private failure")), self.assertRaises(ValueError):
            M.prepare(**self.inputs, write=True)
        for field, value in (("Image", "sha256:" + "0" * 64), ("Config", {"Hostname": self.observer[:12], "Labels": {}})):
            original = self.containers[self.observer]; self.containers[self.observer] = {**original, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "observer"): self.invoke()
            self.containers[self.observer] = original
        self.containers = {}
        with self.assertRaisesRegex(ValueError, "inventory"): self.invoke()

    def test_all_five_locks_remain_exclusive_and_stable(self):
        for path in F.M.lock_paths(self.fixture.source):
            with path.open("rb") as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.subTest(path=path.name), self.assertRaises(ValueError): self.invoke(write=True)
        original = M.actual_consumers
        def replace_lock(*args):
            consumers = original(*args)
            path = self.fixture.parent / "campaign.lock"; path.unlink(); path.touch(mode=0o600)
            return consumers
        with patch.object(M, "actual_consumers", side_effect=replace_lock), self.assertRaisesRegex(ValueError, "lock changed|held stage lock"):
            self.invoke(write=True)
        self.assertFalse(self.approval_path.exists()); self.assertFalse(self.checkpoint_path.exists())

    def test_observation_is_repeated_before_checkpoint_and_consumer_arrival_keeps_partial_metadata(self):
        original = M.actual_consumers; calls = 0
        def arrive(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                identifier = "3" * 64
                self.containers[identifier] = self.container(identifier, running=True, mounts=[{"Source": str(self.fixture.source)}])
            return original(*args)
        with patch.object(M, "actual_consumers", side_effect=arrive), self.assertRaisesRegex(ValueError, "active Docker consumer"):
            self.invoke(write=True)
        self.assertTrue(self.approval_path.exists()); self.assertFalse(self.checkpoint_path.exists()); self.fixture.preserved()

    def test_receipt_tampering_and_frozen_python_jvm_or_existing_checkpoint_drift_refuse(self):
        result = self.invoke(write=True)
        receipt = self.fixture.source / "batches" / "part12-batch000000" / "receipt.json"
        original = receipt.read_bytes(); value = F.S.parse_json(original); value["shards"] = []
        self.fixture.write(receipt, value)
        with self.assertRaisesRegex(ValueError, "receipt"): self.invoke()
        receipt.write_bytes(original)
        for path in (self.fixture.code / "app/pipeline_lock.py", self.fixture.workspace / "backend/target/classes/com/flarefitness/backend/Fixture.class"):
            raw = path.read_bytes(); path.write_bytes(raw + b"fixture drift")
            with self.subTest(path=path.name), self.assertRaises(ValueError): self.invoke()
            path.write_bytes(raw)
        value = F.S.parse_json(self.checkpoint_path.read_bytes()); value["commands"]["campaign"] = []
        self.fixture.write(self.checkpoint_path, value)
        with self.assertRaisesRegex(ValueError, "metadata SHA"):
            self.invoke(approval_sha=result["approval_sha256"], checkpoint_sha=result["checkpoint_sha256"])

    def test_completed_source_metadata_must_precede_stage_lock_creation(self):
        for name in F.M.COORDINATOR_LOCKS: (self.fixture.parent / name).unlink()
        terminal = {**self.fixture.terminal, "status": "RUNNING"}; self.fixture.write(self.fixture.parent / "state.private.json", terminal)
        with self.assertRaisesRegex(ValueError, "completed independent"): self.invoke(write=True)
        self.assertTrue(all(not (self.fixture.parent / name).exists() for name in F.M.COORDINATOR_LOCKS))

    def test_replacement_or_public_destination_cannot_be_adopted(self):
        self.checkpoint_path.symlink_to(self.fixture.checkpoint_path)
        with self.assertRaisesRegex(ValueError, "fresh"): self.invoke(write=True)
        self.assertFalse(self.approval_path.exists())
        self.checkpoint_path.unlink(); output = self.fixture.base / "public-output"; output.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, "owner-controlled"):
            self.invoke(write=True, approval_path=output / "approval.private.json")
        self.assertFalse((output / "approval.private.json").exists())


if __name__ == "__main__":
    unittest.main()
