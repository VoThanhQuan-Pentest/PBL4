"""Bounded Docker lifecycle/privacy regression; owned fixtures, no application data."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


IMAGE = os.environ.get("NGINX_TEST_IMAGE", "flare-nginx-hardening-test")
BINARY = os.environ.get("NGINX_DIAGNOSTICS_TEST_BINARY")


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=20, check=check)


class NativeDiagnosticsTest(unittest.TestCase):
    def test_privacy_rotation_exit_and_configuration(self):
        with tempfile.TemporaryDirectory(prefix="owned-nginx-diagnostics-") as directory:
            config = Path(directory) / "nginx.conf"
            config.write_text("""pid /tmp/nginx.pid;
error_log stderr warn;
events {}
http {
client_body_temp_path /tmp/client;
proxy_temp_path /tmp/proxy;
fastcgi_temp_path /tmp/fastcgi;
uwsgi_temp_path /tmp/uwsgi;
scgi_temp_path /tmp/scgi;
access_log off;
server {
listen 8080;
server_name localhost;
error_log stderr warn;
client_max_body_size 4;
location /ready { return 200 'ready'; }
location /api/ { proxy_pass http://127.0.0.1:1; }
location /missing/ { root /owned-missing; }
}
}
""")
            options = ["--network", "none", "--read-only", "--user", "101:101",
                       "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                       "--memory", "64m", "--cpus", "1", "--pids-limit", "64",
                       "--tmpfs", "/tmp:rw,nosuid,size=4m",
                       "--tmpfs", "/var/log/nginx:rw,nosuid,size=2m,uid=101,gid=101",
                       "--tmpfs", "/etc/nginx/conf.d:rw,nosuid,size=1m,uid=101,gid=101",
                       "--mount", f"type=bind,src={config},dst=/owned.conf,readonly"]
            if BINARY:
                options += ["--mount", f"type=bind,src={Path(BINARY).resolve()},dst=/owned-diagnostics,readonly",
                            "--entrypoint", "/owned-diagnostics"]
            cid = docker("run", "-d", *options, IMAGE, "nginx", "-c", "/owned.conf",
                         "-g", "daemon off;").stdout.strip()
            try:
                for _ in range(40):
                    ready = docker("exec", cid, "wget", "-q", "-O", "-",
                                   "http://127.0.0.1:8080/ready", check=False)
                    if ready.returncode == 0:
                        break
                    time.sleep(0.1)
                self.assertEqual(ready.stdout, "ready", docker("logs", cid).stderr)
                status = docker("exec", cid, "cat", "/proc/1/status").stdout
                rss = next(line for line in status.splitlines() if line.startswith("VmRSS:"))
                print(json.dumps({"diagnostic_pid1_rss_kib": int(rss.split()[1])}))
                secret = "OWNED_QUERY_CANARY_6918"
                for uri, expected in [("/api/a?access_token=" + secret, "502"),
                                      ("/api/a?encoded=%4f%57%4e%45%44", "502"),
                                      ("/missing/" + secret, "404")]:
                    response = docker("exec", cid, "wget", "-S", "-O", "/dev/null",
                                      "--header=Referer: https://example.test/?token=" + secret,
                                      "http://127.0.0.1:8080" + uri, check=False)
                    self.assertIn(expected, response.stderr)
                response = docker("exec", cid, "wget", "-S", "-O", "/dev/null",
                                  "--post-data=" + secret, "http://127.0.0.1:8080/api/a", check=False)
                self.assertIn("413", response.stderr)
                log = "/var/log/nginx/native-errors.json.log"
                before = docker("exec", cid, "cat", log).stdout
                self.assertNotIn(secret, before)
                codes = {json.loads(line)["event.code"] for line in before.splitlines()}
                self.assertTrue({"upstream_connect_failed", "file_open_failed",
                                 "request_body_too_large"}.issubset(codes))
                self.assertNotIn(secret, docker("logs", cid).stderr)
                # Existing host logrotate renames *.log and signals container PID1.
                docker("exec", cid, "mv", log, log + ".old")
                docker("kill", "--signal=USR1", cid)
                for _ in range(20):
                    if docker("exec", cid, "test", "-f", log, check=False).returncode == 0:
                        break
                    time.sleep(.1)
                docker("exec", cid, "wget", "-O", "/dev/null",
                       "http://127.0.0.1:8080/api/after-rotation", check=False)
                after = docker("exec", cid, "cat", log).stdout
                self.assertIn("upstream_connect_failed", after)
                self.assertNotIn(secret, after)
                docker("kill", "--signal=QUIT", cid)
                self.assertEqual(docker("wait", cid).stdout.strip(), "0")
            finally:
                docker("rm", "-f", cid, check=False)
            # Diagnostic capture must preserve one-shot nginx -t success/failure.
            valid = docker("run", "--rm", *options, IMAGE, "nginx", "-t", "-c", "/owned.conf", check=False)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            custom = docker("run", "--rm", *options, IMAGE, "sh", "-c", "exit 7", check=False)
            self.assertEqual(custom.returncode, 7)
            daemon = docker("run", "--rm", *options, IMAGE, "nginx", "-c", "/owned.conf", check=False)
            self.assertEqual(daemon.returncode, 0, daemon.stderr)
            config.write_text("OWNED_CONFIG_SECRET invalid;\n")
            invalid = docker("run", "--rm", *options, IMAGE, "nginx", "-t", "-c", "/owned.conf", check=False)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertNotIn("OWNED_CONFIG_SECRET", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
