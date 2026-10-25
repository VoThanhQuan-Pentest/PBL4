import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "observability/scripts"
sys.path[:0] = [str(SCRIPTS), str(ROOT / "ueba-worker")]
spec = importlib.util.spec_from_file_location("postlogin_runner", SCRIPTS / "run-ueba-postlogin-pilot.py")
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
from ueba_research_artifacts import publish


class PilotRunnerTest(unittest.TestCase):
    def fixture(self, directory):
        publish(directory / "operator-state.private.json", {"phase": "FIXTURE_NO_FITS"})
        publish(directory / "p3-source-benchmark.receipt.private.json", {"elapsed_seconds": 0})

    def test_kernel_deadline_and_conservative_recovery_do_not_depend_on_chat(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.fixture(directory)
            script = """
import sys,importlib.util,time
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[2]]
spec=importlib.util.spec_from_file_location('pilot',Path(sys.argv[1])/'run-ueba-postlogin-pilot.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from postlogin_pilot_artifacts import writer
with writer(Path(sys.argv[3])):
    budget=m.Budget(Path(sys.argv[3]));budget.begin('fixture-native-wait',seconds=1)
    time.sleep(30)
"""
            result = subprocess.run([sys.executable, "-B", "-c", script, str(SCRIPTS), str(ROOT / "ueba-worker"), str(directory)], timeout=5)
            self.assertEqual(result.returncode, -14)
            budget = runner.Budget(directory)
            self.assertGreaterEqual(budget.state["elapsed_seconds"], 1)
            self.assertEqual(budget.state["recovered_interrupted_units"], 1)
            self.assertEqual(budget.state["composite_invocations"], 0)

    def test_operator_quota_hold_prevents_starting_a_new_fit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.fixture(directory)
            budget = runner.Budget(directory)
            publish(directory / "operator-hold.private.json", {"hold_new_units": True})
            with self.assertRaisesRegex(runner.BudgetStop, "STOP_QUOTA_RESERVE"):
                budget.begin("fixture-training", composite=True)
            self.assertEqual(budget.state["composite_invocations"], 0)

    def test_fit_caps_are_cumulative_and_never_reset_by_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.fixture(directory)
            budget = runner.Budget(directory)
            budget.state["composite_invocations"] = 7; budget.save()
            resumed = runner.Budget(directory)
            with self.assertRaisesRegex(runner.BudgetStop, "STOP_FIT_CAP"):
                resumed.begin("fixture-training", composite=True)

    def test_fixed_primary_delta_and_protected_slice_regressions(self):
        record = {"tp": 92, "fn": 8, "fp": 3, "tn": 997}
        baseline = {"counts": {scope: {"global": record.copy(), "postlogin/OBSERVED": record.copy(),
                     "cohort/COLD": {"tp": 98, "fn": 2, "fp": 0, "tn": 1000}}
                     for scope in ("MODEL_ONLY", "SIEM_FINAL")}}
        candidate = copy.deepcopy(baseline)
        for scope in candidate["counts"]:
            for group in ("global", "postlogin/OBSERVED"):
                candidate["counts"][scope][group].update(tp=95, fn=5)
        self.assertEqual(runner.compare(baseline, candidate)["status"], "GO")
        candidate["counts"]["SIEM_FINAL"]["cohort/COLD"]["fn"] = 3
        self.assertEqual(runner.compare(baseline, candidate)["status"], "STOP_NO_IMPROVEMENT")
        candidate = copy.deepcopy(baseline)
        for scope in candidate["counts"]:
            candidate["counts"][scope]["postlogin/OBSERVED"].update(tp=94, fn=6)
        self.assertEqual(runner.compare(baseline, candidate)["status"], "STOP_NO_IMPROVEMENT")

    def test_quota_and_unit_boundaries_do_not_freeze_a_terminal_result(self):
        self.assertTrue(runner.result_phase("STOP_QUOTA_RESERVE").startswith("pilot-checkpoint-"))
        self.assertTrue(runner.result_phase("STOP_AT_COMMITTED_FIT_BOUNDARY").startswith("pilot-checkpoint-"))
        self.assertEqual(runner.result_phase("STOP_NO_IMPROVEMENT"), "pilot-result")


if __name__ == "__main__":
    unittest.main()
