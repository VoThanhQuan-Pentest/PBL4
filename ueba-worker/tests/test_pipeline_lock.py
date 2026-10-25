"""Private coordinator/CLI fixtures only: no fits, scoring or holdout reads."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.pipeline_lock import CAMPAIGN_LOCKS, coordinated_stage
from app import selection, strict_campaign


def write(path, value):
    path.write_text(json.dumps(value)); path.chmod(0o600)


def fixture(root):
    source = root / "source"; source.mkdir(mode=0o700)
    standard = source / "standard"; standard.mkdir(mode=0o700)
    identity = {"fixture_only": "no-source-generation-or-quality-evidence"}
    write(source / "predeclared.private.json", {"scope": "FULL_STRICT_SOURCE", "protocol": {}, "source_identity": identity})
    write(source / "state.private.json", {"status": "COMPLETE_UNQUALIFIED_SOURCE", "stage": "STRICT_SOURCE",
          "scope": "FULL_STRICT_SOURCE", "folds_completed": [1, 2, 3], "fit_or_score_calls": 0,
          "source_identity_before": identity, "source_identity_after": identity})
    return standard


class PipelineLockTest(unittest.TestCase):
    def test_default_is_filesystem_free_and_fixed_names_match_archive_contract(self):
        self.assertEqual(CAMPAIGN_LOCKS, {"campaign.lock", "selection.lock", "evaluation.lock"})
        with patch("app.pipeline_lock._directory", side_effect=AssertionError("no filesystem access")), \
                patch("app.pipeline_lock.os.open", side_effect=AssertionError("no lock file")):
            with coordinated_stage("/nonexistent/dataset", "campaign"): pass
        for stage in ("../campaign", "other", None):
            with self.assertRaises(ValueError):
                with coordinated_stage("/unused", stage): pass
        with self.assertRaises(ValueError):
            with coordinated_stage("/unused", "campaign", enabled=1): pass

    def test_exclusive_nonblocking_parent_lock_and_release_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary))
            with coordinated_stage(standard, "campaign", enabled=True):
                path = standard.parent / "campaign.lock"
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertFalse((standard / "campaign.lock").exists())
                with self.assertRaisesRegex(ValueError, "already active"):
                    with coordinated_stage(standard, "campaign", enabled=True): pass
                with coordinated_stage(standard, "selection", enabled=True): pass
            with self.assertRaisesRegex(RuntimeError, "consumer failed"):
                with coordinated_stage(standard, "campaign", enabled=True): raise RuntimeError("consumer failed")
            with coordinated_stage(standard, "campaign", enabled=True): pass

    def test_live_scoped_changed_and_boolean_source_receipts_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary)); path = standard.parent / "state.private.json"
            original = json.loads(path.read_bytes())
            for changes in ({"status": "STANDARD_SOURCE_RUNNING"}, {"scope": "SCOPED_TEST"},
                            {"fit_or_score_calls": False}, {"folds_completed": [True, 2, 3]},
                            {"source_identity_after": {"different": True}}):
                write(path, {**original, **changes})
                with self.assertRaises(ValueError):
                    with coordinated_stage(standard, "campaign", enabled=True): pass
            write(path, original); path.chmod(0o644)
            with self.assertRaises(ValueError):
                with coordinated_stage(standard, "campaign", enabled=True): pass

    def test_symlink_hardlink_public_and_nonregular_locks_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); standard = fixture(root); path = standard.parent / "campaign.lock"
            other = root / "other"; other.write_bytes(b""); other.chmod(0o600)
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                with coordinated_stage(standard, "campaign", enabled=True): pass
            path.unlink(); os.link(other, path)
            with self.assertRaises(ValueError):
                with coordinated_stage(standard, "campaign", enabled=True): pass
            path.unlink(); path.write_bytes(b""); path.chmod(0o644)
            with self.assertRaises(ValueError):
                with coordinated_stage(standard, "campaign", enabled=True): pass
            path.unlink(); os.mkfifo(path, 0o600)
            with self.assertRaises(ValueError):
                with coordinated_stage(standard, "campaign", enabled=True): pass

    def test_all_public_wrappers_hold_the_stage_through_the_entire_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary))
            cases = ((strict_campaign, "fit_one", "_fit_one", "campaign", (standard, "fixture-run")),
                     (strict_campaign, "search", "_search", "campaign", (standard, 60)),
                     (selection, "validate_all", "_validate_all", "selection", (standard, standard)),
                     (selection, "choose", "_choose", "selection", (standard, standard)))
            for module, public, private, stage, args in cases:
                def body(*args, **kwargs):
                    with self.assertRaisesRegex(ValueError, "already active"):
                        with coordinated_stage(standard, stage, enabled=True): pass
                    if public == "search":
                        self.assertIsInstance(kwargs.pop("coordinator_fd"), int)
                    self.assertEqual(kwargs, {"expected_sha256": "a" * 64, "expected_archive_sha256": "b" * 64})
                    return "owned-fixture-return"
                with patch.object(module, private, side_effect=body):
                    self.assertEqual(getattr(module, public)(*args, coordinated=True,
                                     expected_sha256="a" * 64, expected_archive_sha256="b" * 64), "owned-fixture-return")
                with coordinated_stage(standard, stage, enabled=True): pass

    def test_explicit_factory_hashes_and_legacy_default_reader_are_separate(self):
        directory = Path("/fixture/not-read")
        dataset = SimpleNamespace(manifest={"stage": "STRICT"})
        cases = ((strict_campaign, "fit_one", "approved_run", (directory, "fixture-run")),
                 (selection, "validate_all", "selection_identity", (directory, directory)),
                 (selection, "choose", "selection_identity", (directory, directory)))
        for module, public, stop, args in cases:
            with patch.object(module, "open_owned_dataset", return_value=dataset) as factory, \
                    patch.object(module, "ShardedDataset", return_value=dataset) as legacy, \
                    patch.object(module, stop, side_effect=RuntimeError("stop before any numeric consumer")):
                with self.assertRaises(RuntimeError): getattr(module, public)(*args)
                legacy.assert_called_once_with(directory); factory.assert_not_called(); legacy.reset_mock()
                with self.assertRaises(RuntimeError):
                    getattr(module, public)(*args, expected_sha256="a" * 64, expected_archive_sha256="b" * 64)
                factory.assert_called_once_with(directory, expected_sha256="a" * 64, expected_archive_sha256="b" * 64)
                legacy.assert_not_called()

    def test_search_child_receives_hashes_not_reentrant_coordination_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary)); run = {"run_id": "fixture-only-run", "fold": 1}
            dataset = SimpleNamespace(manifest={"stage": "STRICT"}, sha256="a" * 64)
            model_root = standard / "strict-models"; model_root.mkdir(mode=0o700)
            artifact = model_root / "fixture-model.joblib"; artifact.write_bytes(b"NOT_A_MODEL_NO_FITS")
            artifact.chmod(0o600)
            commands = []
            def start(command, **kwargs):
                commands.append(command)
                self.assertEqual(len(kwargs["pass_fds"]), 1)
                inherited = os.fstat(kwargs["pass_fds"][0]); path = (standard.parent / "campaign.lock").stat()
                self.assertEqual((inherited.st_dev, inherited.st_ino), (path.st_dev, path.st_ino))
                def wait(timeout):
                    with self.assertRaisesRegex(ValueError, "already active"):
                        with coordinated_stage(standard, "campaign", enabled=True): pass
                    write(standard / "strict-runs/fixture-only-run.json", {"status": "FITTED_CALIBRATED",
                          "model_version": "fixture-model", "model_sha256": strict_campaign.sha(artifact)})
                    return 0
                return SimpleNamespace(pid=12345, wait=wait)
            with patch("app.strict_campaign.open_owned_dataset", return_value=dataset), \
                    patch("app.strict_campaign.validate_fit_recipe"), patch("app.strict_campaign.fingerprint", return_value={}), \
                    patch("app.strict_campaign.campaign_runs", return_value=[run]), \
                    patch("app.strict_campaign.run_identity", return_value={}), \
                    patch("app.strict_campaign.subprocess.Popen", side_effect=start), patch("builtins.print"):
                strict_campaign.search(standard, 60, coordinated=True, expected_sha256="a" * 64, expected_archive_sha256="b" * 64)
            self.assertEqual(len(commands), 1); command = commands[0]
            self.assertIn("--dataset-sha256", command); self.assertIn("a" * 64, command)
            self.assertIn("--archive-sha256", command); self.assertIn("b" * 64, command)
            self.assertNotIn("--coordinated", command)
            with coordinated_stage(standard, "campaign", enabled=True): pass

    def test_cli_opt_in_and_hashes_reach_each_public_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary))
            for module, command, consumer in ((strict_campaign, "search", "search"),
                                               (strict_campaign, "_fit", "fit_one"),
                                               (selection, "validate", "validate_all"), (selection, "choose", "choose")):
                arguments = ["owned-fixture-cli", command, "--dataset", str(standard), "--coordinated",
                             "--dataset-sha256", "a" * 64, "--archive-sha256", "b" * 64]
                if module is selection: arguments.extend(["--workspace", str(standard)])
                if command == "_fit": arguments.extend(["--run-id", "fixture-run"])
                with patch("sys.argv", arguments), patch.object(module, consumer, return_value={}) as called, patch("builtins.print"):
                    module.main()
                self.assertEqual(called.call_args.kwargs, {"coordinated": True, "expected_sha256": "a" * 64,
                                                         "expected_archive_sha256": "b" * 64})

    def test_inherited_description_keeps_lock_after_parent_context_closes(self):
        with tempfile.TemporaryDirectory() as temporary:
            standard = fixture(Path(temporary))
            with coordinated_stage(standard, "campaign", enabled=True) as descriptor:
                inherited = os.dup(descriptor)
            try:
                with self.assertRaisesRegex(ValueError, "already active"):
                    with coordinated_stage(standard, "campaign", enabled=True): pass
            finally: os.close(inherited)
            with coordinated_stage(standard, "campaign", enabled=True): pass


if __name__ == "__main__": unittest.main()
