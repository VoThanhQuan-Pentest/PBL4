"""Contract tests for the fail-closed, local-only pre-import Kibana backup."""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/backup-kibana-before-import.sh"
EXPORT_SCRIPT = ROOT / "observability/scripts/export-kibana-objects.sh"
RUNTIME = ROOT / "observability/runtime"


class FakeKibana(BaseHTTPRequestHandler):
    space_exists = True

    def log_message(self, *_args):
        pass

    def reply(self, code, text, content_type="application/json"):
        payload = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/api/spaces/space/flare-lab":
            self.reply(200 if self.space_exists else 404, "{}")
        elif self.path.startswith("/s/flare-lab/api/detection_engine/rules/_find?"):
            self.reply(200, json.dumps({"total": 2, "data": [
                {"rule_id": "owned-rule-a"}, {"rule_id": "owned-rule-b"}]}))
        else:
            self.reply(404, "{}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/s/flare-lab/api/saved_objects/_export":
            self.reply(200, '{"type":"dashboard","id":"flare-overview"}\n'
                       '{"exportedCount":1}\n', "application/ndjson")
        elif self.path == "/s/flare-lab/api/detection_engine/rules/_export":
            names = [item["rule_id"] for item in json.loads(body)["objects"]]
            self.reply(200, "".join(json.dumps({"rule_id": name}) + "\n" for name in names)
                       + '{"export_summary":{"total_rules":2}}\n', "application/ndjson")
        else:
            self.reply(404, "{}")


class KibanaPreimportBackupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        secret_dir = Path(self.temporary.name) / "monitor"
        secret_dir.mkdir()
        secret_dir.chmod(0o700)
        password_file = secret_dir / "elasticsearch.password"
        password_file.write_text("test-only-password", encoding="utf-8")
        password_file.chmod(0o600)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeKibana)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.backup_root = RUNTIME / ("kibana-backup-contract-" + uuid.uuid4().hex)
        self.env = os.environ.copy()
        self.env.update(OBSERVABILITY_SECRETS_DIR=self.temporary.name,
                        KIBANA_URL=f"http://127.0.0.1:{self.server.server_port}",
                        KIBANA_BACKUP_ROOT=str(self.backup_root))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if (self.backup_root.parent == RUNTIME
                and self.backup_root.name.startswith("kibana-backup-contract-")
                and self.backup_root.exists()):
            shutil.rmtree(self.backup_root)
        self.temporary.cleanup()

    def run_backup(self):
        return subprocess.run([str(SCRIPT)], env=self.env, capture_output=True,
                              text=True, timeout=15, check=False)

    def run_export(self, output, *, overrides=None):
        environment = self.env.copy()
        environment.update(overrides or {})
        return subprocess.run([str(EXPORT_SCRIPT), str(output)], env=environment,
                              capture_output=True, text=True, timeout=15, check=False)

    def test_exports_dashboards_and_rules_to_private_files_before_import(self):
        FakeKibana.space_exists = True
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        created = list(self.backup_root.iterdir())
        self.assertEqual(len(created), 1)
        saved = created[0] / "saved-objects.ndjson"
        rules = created[0] / "detection-rules.ndjson"
        self.assertIn("flare-overview", saved.read_text(encoding="utf-8"))
        self.assertIn("owned-rule-b", rules.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.backup_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(created[0].stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(rules.stat().st_mode), 0o600)

    def test_direct_export_is_loopback_only_and_publishes_private_atomic_file(self):
        self.backup_root.mkdir(mode=0o700)
        output = self.backup_root / "direct-export.ndjson"
        result = self.run_export(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flare-overview", output.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.backup_root.stat().st_mode), 0o700)
        self.assertEqual(list(self.backup_root.glob(".kibana-export.*")), [])

        outside = Path(self.temporary.name) / "outside.ndjson"
        result = self.run_export(outside)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(outside.exists())

        remote = self.backup_root / "remote.ndjson"
        result = self.run_export(remote, overrides={
            "KIBANA_URL": "http://198.51.100.8:5601",
            "OBSERVABILITY_SECRETS_DIR": str(Path(self.temporary.name) / "missing-secrets"),
        })
        self.assertEqual(result.returncode, 2)
        self.assertFalse(remote.exists())

    def test_direct_export_refuses_symlink_and_unprotected_secret_file(self):
        self.backup_root.mkdir(mode=0o700)
        sentinel = self.backup_root / "sentinel.ndjson"
        sentinel.write_text("preserve", encoding="utf-8")
        symlink_output = self.backup_root / "symlink.ndjson"
        symlink_output.symlink_to(sentinel)
        result = self.run_export(symlink_output)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

        password_file = Path(self.temporary.name) / "monitor/elasticsearch.password"
        password_file.chmod(0o644)
        unprotected_output = self.backup_root / "unprotected.ndjson"
        result = self.run_export(unprotected_output)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(unprotected_output.exists())

    def test_first_run_does_not_create_an_empty_backup(self):
        FakeKibana.space_exists = False
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.backup_root.exists())

    def test_rejects_non_loopback_origin_before_reading_credentials(self):
        self.env["KIBANA_URL"] = "http://localhost:5601@evil.example"
        result = self.run_backup()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.backup_root.exists())


if __name__ == "__main__":
    unittest.main()
