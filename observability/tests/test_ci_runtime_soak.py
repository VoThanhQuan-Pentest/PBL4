"""Exercise stability verdicts with a controlled clock, without Docker or live data."""
import importlib.util
from pathlib import Path
import unittest
import os
import subprocess

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-ci-runtime-soak.py"
SPEC = importlib.util.spec_from_file_location("ci_runtime_soak", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class RuntimeSoakTest(unittest.TestCase):
    def test_rollback_rejects_the_primary_project_and_missing_candidate_identity(self):
        script = SCRIPT.with_name("verify-ci-backend-rollback.sh")
        for project, sha in [("flare-otp-local", "a" * 40), ("pbl4-observability-runtime-123-1", "")]:
            with self.subTest(project=project):
                result = subprocess.run([str(script), "/nonexistent"], capture_output=True, text=True,
                    env={**os.environ, "GITHUB_ACTIONS": "true", "COMPOSE_PROJECT_NAME": project, "GITHUB_SHA": sha})
                self.assertEqual(2, result.returncode)

    def states(self):
        return [dict(id=str(i), running=True, oom=False, restarts=0, health="healthy") for i in range(10)]

    def test_restart_oom_unhealthy_and_missing_container_fail_the_gate(self):
        baseline = GATE.validate_states(self.states())
        for field, value in [("restarts", 1), ("oom", True), ("health", "unhealthy"), ("running", False)]:
            changed = self.states()
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                GATE.validate_states(changed, baseline)
        with self.assertRaises(RuntimeError):
            GATE.validate_states(self.states()[:-1], baseline)

    def test_requires_a_full_hour_and_records_at_least_thirty_complete_cycles(self):
        current = [0]
        def sleep(seconds):
            current[0] += seconds
        result = GATE.observe(3600, lambda: (4 * GATE.GIB, 40 * GATE.GIB), clock=lambda: current[0], sleep=sleep)
        self.assertEqual(3600, result["continuous_seconds"])
        self.assertEqual(61, result["cycles"])
        self.assertEqual(244, result["http_evaluations"])
        self.assertFalse(result["fixed_model_qualified"])

    def test_probe_failure_aborts_instead_of_silently_retrying_a_bad_interval(self):
        def failure():
            raise RuntimeError("HTTP failed")
        with self.assertRaisesRegex(RuntimeError, "HTTP failed"):
            GATE.observe(3600, failure)


if __name__ == "__main__":
    unittest.main()
