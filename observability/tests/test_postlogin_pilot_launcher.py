import importlib.util
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("pilot_launcher", SCRIPTS / "launch-ueba-postlogin-pilot.py")
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)


class PilotLauncherTest(unittest.TestCase):
    def test_configured_97_percent_stops_at_the_boundary_and_requires_fresh_observation(self):
        now = datetime(2026, 10, 19, tzinfo=timezone.utc)
        quota = {"stop_new_units_used_percent": 97, "used_percent_5h": 96,
                 "observed_at_utc": now.isoformat()}
        launcher.check_quota(quota, now=now)
        launcher.check_quota({**quota, "used_percent_5h": 96.999}, now=now)
        launcher.check_quota(quota, now=now + timedelta(seconds=300))
        for used in (97, 98, 100):
            with self.subTest(used=used), self.assertRaisesRegex(ValueError, "fresh live quota"):
                launcher.check_quota({**quota, "used_percent_5h": used}, now=now)
        for age in (-1, 301):
            with self.subTest(age=age), self.assertRaisesRegex(ValueError, "fresh live quota"):
                launcher.check_quota(quota, now=now + timedelta(seconds=age))

    def test_unconfigured_historical_quota_retains_80_percent_default(self):
        now = datetime(2026, 10, 19, tzinfo=timezone.utc)
        quota = {"used_percent_5h": 79, "observed_at_utc": now.isoformat()}
        launcher.check_quota(quota, now=now)
        with self.assertRaisesRegex(ValueError, "fresh live quota"):
            launcher.check_quota({**quota, "used_percent_5h": 80}, now=now)

    def test_invalid_quota_configuration_cannot_bypass_admission(self):
        now = datetime(2026, 10, 19, tzinfo=timezone.utc)
        quota = {"used_percent_5h": 50, "stop_new_units_used_percent": 97,
                 "observed_at_utc": now.isoformat()}
        for field in ("used_percent_5h", "stop_new_units_used_percent"):
            for value in (None, True, "97", float("nan"), float("inf"), -1, 101):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    launcher.check_quota({**quota, field: value}, now=now)
        with self.assertRaises(ValueError):
            launcher.check_quota({**quota, "stop_new_units_used_percent": 0}, now=now)

    def test_terminal_round_cannot_be_reopened_and_corruption_fails_closed(self):
        from ueba_research_artifacts import commit
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            launcher.reject_terminal_round(output)
            commit(output, {"status": "STOP_NO_IMPROVEMENT"}, phase="pilot-result")
            with self.assertRaisesRegex(ValueError, "round is terminal"):
                launcher.reject_terminal_round(output)
            (output / "pilot-result.receipt.private.json").write_text('{}')
            with self.assertRaisesRegex(ValueError, "integrity"):
                launcher.reject_terminal_round(output)

    def test_actual_container_caps_are_verified_and_each_mismatch_is_refused(self):
        config = {"NetworkMode": "none", "Memory": 2 * 1024**3, "NanoCpus": 2_000_000_000,
                  "ReadonlyRootfs": True, "PidsLimit": 128}
        with patch.object(launcher, "command", return_value=json.dumps(config)):
            self.assertEqual(launcher.inspect_container("owned-fixture"), config)
        for key, value in (("NetworkMode", "bridge"), ("Memory", 0), ("NanoCpus", 0),
                           ("ReadonlyRootfs", False), ("PidsLimit", 0)):
            with patch.object(launcher, "command", return_value=json.dumps({**config, key: value})):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    launcher.inspect_container("owned-fixture")


if __name__ == "__main__": unittest.main()
