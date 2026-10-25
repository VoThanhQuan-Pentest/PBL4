"""Offline safety contracts for post-apply, SSM-only host firewall sync."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/sync-aws-host-firewall.sh"
WEB_ID = "i-0740371b276b1f296"
MONITOR_ID = "i-00b945b767fa67a90"
ADMIN_CIDR = "171.225.185.61/32"
TESTER_CIDR = "171.225.185.61/32"


class AwsHostFirewallTest(unittest.TestCase):
    def fixture(self, root, **overrides):
        bindir = root / "bin"
        bindir.mkdir()
        capture = root / "ssm-commands.jsonl"
        terraform = bindir / "terraform-fixture"
        terraform.write_text("""#!/bin/sh
case "$4" in
  web_instance_id) printf '%s' i-0740371b276b1f296 ;;
  monitor_instance_id) printf '%s' i-00b945b767fa67a90 ;;
  *) exit 2 ;;
esac
""")
        terraform.chmod(0o700)
        aws = bindir / "aws"
        aws.write_text(r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
web = "i-0740371b276b1f296"
monitor = "i-00b945b767fa67a90"
admin = os.environ.get("TEST_ADMIN_CIDR", "171.225.185.61/32")
tester = os.environ.get("TEST_TESTER_CIDR", "171.225.185.61/32")
if args[:2] == ["ec2", "describe-instances"]:
    print(json.dumps([
      {"ID": web, "State": "running", "PrivateIP": "10.20.10.10", "Tags": [{"Key":"Project","Value":"flare-aws-elk-lab"},{"Key":"Name","Value":"flare-aws-elk-lab-web"}]},
      {"ID": monitor, "State": "running", "PrivateIP": "10.20.10.20", "Tags": [{"Key":"Project","Value":"flare-aws-elk-lab"},{"Key":"Name","Value":"flare-aws-elk-lab-monitor"}]}
    ]))
elif args[:2] == ["ec2", "describe-security-groups"]:
    value = " ".join(args)
    if "flare-aws-elk-lab-web-sg" in value:
        result = {"SecurityGroups":[{"GroupId":"sg-web","IpPermissions":[
          {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":admin}]},
          {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":tester}]}
        ]}]}
    else:
        result = {"SecurityGroups":[{"GroupId":"sg-monitor","IpPermissions":[
          {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":admin}]},
          {"IpProtocol":"tcp","FromPort":5044,"ToPort":5044,"UserIdGroupPairs":[{"GroupId":"sg-web"}]},
          {"IpProtocol":"tcp","FromPort":9200,"ToPort":9200,"UserIdGroupPairs":[{"GroupId":"sg-web"}]}
        ]}]}
    print(json.dumps(result))
elif args[:2] == ["ssm", "describe-instance-information"]:
    state = os.environ.get("TEST_SSM_STATUS", "Online")
    ids = [web, monitor] if state == "Online" else [web]
    print(json.dumps(ids))
elif args[:2] == ["ssm", "send-command"]:
    request = json.loads(args[args.index("--cli-input-json") + 1])
    with open(os.environ["SYNC_COMMAND_CAPTURE"], "a") as stream:
        stream.write(json.dumps(request) + "\n")
    command_id = "a" * 36 if request["InstanceIds"] == [web] else "b" * 36
    print(command_id)
elif args[:2] == ["ssm", "get-command-invocation"]:
    print(os.environ.get("TEST_COMMAND_STATUS", "Success"))
else:
    raise SystemExit("unexpected aws call")
''')
        aws.chmod(0o700)
        environment = os.environ.copy()
        environment.update({
            "PATH": str(bindir) + os.pathsep + environment["PATH"],
            "FLARE_TERRAFORM_BIN": str(terraform),
            "AWS_PROFILE": "owned-test-profile",
            "AWS_REGION": "ap-southeast-1",
            "SYNC_COMMAND_CAPTURE": str(capture),
        })
        environment.update(overrides)
        return environment, capture

    def run_sync(self, env, admin=ADMIN_CIDR, tester=TESTER_CIDR):
        return subprocess.run(["bash", str(SCRIPT), admin, tester], env=env,
                              capture_output=True, text=True, timeout=30)

    def test_sync_requires_verified_sgs_and_online_ssm_then_sets_exact_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            env, capture = self.fixture(Path(directory))
            result = self.run_sync(env)
            self.assertEqual(result.returncode, 0, result.stderr)
            requests = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertEqual([request["InstanceIds"] for request in requests], [[WEB_ID], [MONITOR_ID]])
            web_script = requests[0]["Parameters"]["commands"][0]
            monitor_script = requests[1]["Parameters"]["commands"][0]
            self.assertIn(f"ufw allow from {ADMIN_CIDR} to any port 22 proto tcp", web_script)
            self.assertIn(f"ufw allow from {TESTER_CIDR} to any port 80 proto tcp", web_script)
            self.assertIn("ufw status numbered", web_script)
            self.assertNotIn("ufw --force reset", web_script)
            self.assertIn(f"ufw allow from {ADMIN_CIDR} to any port 22 proto tcp", monitor_script)
            self.assertIn("ufw allow from 10.20.10.10 to any port 5044 proto tcp", monitor_script)
            self.assertIn("ufw allow from 10.20.10.10 to any port 9200 proto tcp", monitor_script)
            self.assertNotIn("0.0.0.0/0", web_script + monitor_script)

    def test_invalid_cidr_and_offline_ssm_refuse_before_send_command(self):
        with tempfile.TemporaryDirectory() as directory:
            env, capture = self.fixture(Path(directory))
            invalid = self.run_sync(env, "0.0.0.0/0", TESTER_CIDR)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertFalse(capture.exists())
            env["TEST_SSM_STATUS"] = "ConnectionLost"
            offline = self.run_sync(env)
            self.assertNotEqual(offline.returncode, 0)
            self.assertFalse(capture.exists())

    def test_allowlist_mismatch_refuses_before_send_command(self):
        with tempfile.TemporaryDirectory() as directory:
            env, capture = self.fixture(Path(directory), TEST_TESTER_CIDR="198.51.100.20/32")
            result = self.run_sync(env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("security group", result.stderr)
            self.assertFalse(capture.exists())


if __name__ == "__main__":
    unittest.main()
