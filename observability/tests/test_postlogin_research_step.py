from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import postlogin_research_step as step
from ueba_research_artifacts import publish


class ResearchStepTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.code = self.output / "input.py"
        self.code.write_text("# version one\n")
        self.state = {"elapsed_seconds": 777., "cap_seconds": 28800,
                      "pilot_cap_seconds": 7200, "group_seconds": {}, "active_unit": None,
                      "disk_reserve_bytes": 1, "otp_reserve_seconds": 3600,
                      "checkpoint_reserve_seconds": 300, "recovered_interrupted_units": 0}
        publish(self.output / "budget.private.json", self.state)
        publish(self.output / "operator-state.private.json", {})

    def run_job(self, unit, expression, maximum=10):
        return step.run(self.output, unit, "setup", maximum,
                        [sys.executable, "-c", expression], [self.code])

    def test_committed_unit_reuses_only_identical_inputs_and_does_not_repeat_side_effect(self):
        path = self.output / "count"
        expression = f"from pathlib import Path; p=Path({str(path)!r}); p.write_text(p.read_text()+'x' if p.exists() else 'x')"
        self.assertEqual(self.run_job("same", expression), 0)
        after = json.loads((self.output / "budget.private.json").read_text())
        self.assertGreater(after["elapsed_seconds"], 777)
        self.assertEqual(self.run_job("same", expression), 0)
        self.assertEqual(path.read_text(), "x")
        self.code.write_text("# version two\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.run_job("same", expression)

    def test_real_timeout_bounds_process_and_accounts_time(self):
        self.assertEqual(self.run_job("timeout", "import time; time.sleep(30)", maximum=1), 124)
        result = json.loads((self.output / "timeout.receipt.private.json").read_text())
        self.assertEqual(result["status"], "STOP_TIMEOUT")
        self.assertLess(result["elapsed_seconds"], 5)
        self.assertIsNone(json.loads((self.output / "budget.private.json").read_text())["active_unit"])

    def test_recovery_refuses_live_process_and_charges_missing_unit_conservatively(self):
        now = step.utc()
        self.state["active_unit"] = {"id": "lost", "group": "pilot", "pid": __import__('os').getpid(),
            "process_start": step.process_start(__import__('os').getpid()), "cap_seconds": 60,
            "deadline_utc": (now - timedelta(seconds=20)).isoformat()}
        with self.assertRaisesRegex(RuntimeError, "LIVE_JOB"):
            step.recover_active(self.state, now)
        self.state["active_unit"]["pid"] = None
        step.recover_active(self.state, now)
        self.assertEqual(self.state["elapsed_seconds"], 837)
        self.assertEqual(self.state["group_seconds"]["pilot"], 60)

    def test_unknown_spawn_waits_for_independent_deadline(self):
        self.state["active_unit"] = {"group": "pilot", "pid": None, "cap_seconds": 60,
            "deadline_utc": (step.utc() + timedelta(seconds=60)).isoformat()}
        with self.assertRaisesRegex(RuntimeError, "DEADLINE"):
            step.recover_active(self.state)

    def test_manual_hold_does_not_launch_command(self):
        publish(self.output / "operator-hold.private.json", {"hold_new_units": True})
        with self.assertRaisesRegex(RuntimeError, "OPERATOR_HOLD"):
            self.run_job("held", "raise Exception('must not execute')")

    def test_mutating_input_during_job_cannot_publish_a_passing_receipt(self):
        expression = f"from pathlib import Path; Path({str(self.code)!r}).write_text('# changed while running')"
        self.assertEqual(self.run_job("changed", expression), 65)
        receipt = json.loads((self.output / "changed.receipt.private.json").read_text())
        self.assertEqual(receipt["status"], "INPUT_CHANGED_DURING_JOB")

    def test_quota_missing_stale_or_exhausted_never_blocks_local_work(self):
        for i, state in enumerate(({}, {"quota": {"used_percent_5h": 97}},
                {"quota": {"used_percent_5h": 100, "used_percent_weekly": 100,
                           "observed_at_utc": "2000-01-01T00:00:00Z"}})):
            publish(self.output / "operator-state.private.json", state)
            self.assertEqual(self.run_job(f"quota-ignored-{i}", "pass"), 0)

    def test_checkpoint_reserve_is_preserved_for_preparation_jobs(self):
        self.state.update(reserve_checkpoint_for_all_groups=True, cap_seconds=1077.)
        publish(self.output / "budget.private.json", self.state)
        with self.assertRaisesRegex(RuntimeError, "STOP_BUDGET"):
            self.run_job("reserve", "raise Exception('must not run')")


if __name__ == "__main__":
    unittest.main()
