"""Offline command-contract tests: no AWS requests or real SSH sessions."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/aws-ssm-ssh.sh"


class AwsSsmSshTest(unittest.TestCase):
    def environment(self, root):
        binary = root / "bin"; binary.mkdir()
        def executable(name, source):
            path = binary / name; path.write_text(source); path.chmod(0o700); return path
        terraform = executable("terraform-fixture", "#!/bin/sh\ncase \"$4\" in\n"
            "web_instance_id) printf i-0740371b276b1f296 ;;\nweb_elastic_ip) printf 52.77.184.249 ;;\n"
            "monitor_instance_id) printf i-00b945b767fa67a90 ;;\nmonitor_elastic_ip) printf 18.138.13.58 ;;\n"
            "*) exit 2 ;;\nesac\n")
        executable("session-manager-plugin", "#!/bin/sh\nexit 0\n")
        executable("ssh", "#!/usr/bin/env python3\nimport json,os,sys\n"
            "with open(os.environ['OWNED_SSH_CAPTURE'],'w') as stream:\n"
            " json.dump({'args':sys.argv[1:],'profile':os.environ['AWS_PROFILE'],'region':os.environ['AWS_REGION']},stream)\n")
        key = root / "owned-empty-key"; key.write_text(""); key.chmod(0o600)
        capture = root / "capture.json"
        environment = os.environ.copy()
        environment.update(PATH=str(binary) + ":" + os.environ["PATH"], FLARE_TERRAFORM_BIN=str(terraform),
            FLARE_SSH_KEY_FILE=str(key), SSM_PLUGIN_BIN_DIR=str(binary), AWS_PROFILE="owned-test-profile",
            AWS_REGION="ap-southeast-1", OWNED_SSH_CAPTURE=str(capture))
        return environment, capture

    def test_both_roles_keep_verified_host_keys_and_use_only_ssm_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            environment, capture = self.environment(Path(directory))
            for role, instance, ip in (("web", "i-0740371b276b1f296", "52.77.184.249"),
                                       ("monitor", "i-00b945b767fa67a90", "18.138.13.58")):
                actual = subprocess.run(["bash", str(SCRIPT), role, "hostname"], env=environment, capture_output=True, text=True)
                self.assertEqual(actual.returncode, 0, actual.stderr)
                value = json.loads(capture.read_text()); args = value["args"]
                self.assertIn("StrictHostKeyChecking=yes", args); self.assertIn("HostKeyAlias=" + ip, args)
                self.assertEqual(args[:2], ["-F", "/dev/null"]); self.assertIn("IdentitiesOnly=yes", args)
                self.assertIn("BatchMode=yes", args); self.assertEqual(args[-2:], ["ubuntu@" + instance, "hostname"])
                proxy = next(arg for arg in args if arg.startswith("ProxyCommand="))
                self.assertIn("AWS-StartSSHSession", proxy); self.assertIn("--target %h", proxy)
                self.assertNotIn("StrictHostKeyChecking=no", args)
                self.assertEqual(value["profile"], "owned-test-profile"); self.assertEqual(value["region"], "ap-southeast-1")

    def test_invalid_roles_or_unverified_plugin_fail_before_connecting(self):
        with tempfile.TemporaryDirectory() as directory:
            environment, capture = self.environment(Path(directory))
            for role in ("../private", "i-unknown", ""):
                actual = subprocess.run(["bash", str(SCRIPT), role], env=environment, capture_output=True, text=True)
                self.assertEqual(actual.returncode, 2); self.assertFalse(capture.exists())
            environment["SSM_PLUGIN_BIN_DIR"] = str(Path(directory) / "missing")
            actual = subprocess.run(["bash", str(SCRIPT), "web"], env=environment, capture_output=True, text=True)
            self.assertEqual(actual.returncode, 2); self.assertFalse(capture.exists())


if __name__ == "__main__": unittest.main()
