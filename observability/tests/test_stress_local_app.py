import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("owned_local_load", Path(__file__).resolve().parents[1] / "scripts/stress-local-app.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class OwnedLoadContractTest(unittest.TestCase):
    def gateway(self):
        return {"Config": {"Labels": {"com.docker.compose.project": "flare-local-elk"}}, "State": {"Running": True},
                "HostConfig": {"PortBindings": {"8082/tcp": [{"HostIp": "127.0.0.1", "HostPort": "28088"}]}}}

    def test_external_aws_unowned_loopback_and_redirect_origins_are_refused(self):
        self.assertEqual(module.verify_target("http://127.0.0.1:28088", self.gateway()), "http://127.0.0.1:28088")
        for origin in ("http://52.77.184.249", "http://localhost:28088", "http://127.0.0.1:8088", "http://user:pass@127.0.0.1:28088", "http://127.0.0.1:28088/anything"):
            with self.subTest(origin=origin), self.assertRaises(ValueError): module.verify_target(origin, self.gateway())
        value = self.gateway(); value["Config"]["Labels"]["com.docker.compose.project"] = "other-project"
        with self.assertRaises(ValueError): module.verify_target("http://127.0.0.1:28088", value)

    def test_full_plan_has_real_one_hour_soak_and_five_minute_ramp_steps(self):
        self.assertEqual(module.DEFAULT_STAGES[-1], ("SOAK", 10, 3600))
        self.assertEqual([rate for _, rate, _ in module.DEFAULT_STAGES[:-1]], [1, 5, 10, 25])
        self.assertTrue(all(seconds == 300 for _, _, seconds in module.DEFAULT_STAGES[:-1]))
        self.assertEqual(module.percentile([4, 1, 3, 2], .95), 4)

    def states(self):
        return {name: {"running": True, "restart_count": 0,
                       "oom_killed": False, "health": None}
                for name in module.CONTAINERS.values()}

    def test_stability_gate_requires_all_pipeline_services_without_restart(self):
        before = self.states()
        after = self.states()
        result = module.assess_service_stability(before, after, collector_recovery_exercised=False)
        self.assertTrue(result["passed"])
        self.assertEqual(result["unexpected_restarts"], [])
        self.assertIn(module.CONTAINERS["logstash"], module.CONTAINERS.values())

    def test_only_the_explicit_filebeat_buffer_restart_is_allowlisted(self):
        before = self.states()
        after = self.states()
        after[module.CONTAINERS["filebeat"]]["restart_count"] = 1
        allowed = module.assess_service_stability(before, after, collector_recovery_exercised=True)
        self.assertTrue(allowed["passed"])
        denied = module.assess_service_stability(before, after, collector_recovery_exercised=False)
        self.assertFalse(denied["passed"])
        self.assertEqual(denied["unexpected_restarts"], [module.CONTAINERS["filebeat"]])

    def test_elasticsearch_or_logstash_restart_oom_and_unhealthy_state_fail_gate(self):
        before = self.states()
        for name, field, value in (
                ("elasticsearch", "restart_count", 1),
                ("logstash", "restart_count", 1),
                ("elasticsearch", "oom_killed", True),
                ("logstash", "health", "unhealthy")):
            with self.subTest(name=name, field=field):
                after = self.states()
                after[module.CONTAINERS[name]][field] = value
                result = module.assess_service_stability(
                    before, after, collector_recovery_exercised=False)
                self.assertFalse(result["passed"])


if __name__ == "__main__": unittest.main()
