"""HTTP contract test using a loopback-only worker in an isolated test container."""

import json
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from app.model import FEATURE_NAMES
from tests.test_model import normal


class WorkerApiTest(unittest.TestCase):
    def test_train_activate_score_with_service_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "test-only-ueba-service-token-32-characters"
            token_file = root / "token"
            token_file.write_text(token, encoding="utf-8")
            token_file.chmod(0o600)
            models = root / "models"
            models.mkdir()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            environment = os.environ.copy()
            environment.update(UEBA_SERVICE_TOKEN_FILE=str(token_file), UEBA_MODEL_DIR=str(models))
            process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                 "--port", str(port), "--workers", "1"],
                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                base = f"http://127.0.0.1:{port}"
                for _ in range(100):
                    if process.poll() is not None:
                        self.fail("worker exited before becoming healthy")
                    try:
                        health = self.request(base, "/health")
                        break
                    except urllib.error.URLError:
                        time.sleep(0.1)
                else:
                    self.fail("worker did not become healthy")
                self.assertEqual(health["feature_names"], list(FEATURE_NAMES))
                self.assertFalse(health["model_available"])
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.putrequest("POST", "/internal/v1/score")
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", str(12 * 1024 * 1024 + 1))
                    connection.endheaders()
                    oversized = connection.getresponse()
                    self.assertEqual(oversized.status, 413)
                    oversized.read()
                finally:
                    connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    chunks = (b"x" * (1024 * 1024) for _ in range(13))
                    connection.request("POST", "/internal/v1/score", body=chunks,
                                       headers={"Content-Type": "application/json"},
                                       encode_chunked=True)
                    oversized_stream = connection.getresponse()
                    detail = oversized_stream.read().decode("utf-8", errors="replace")
                    self.assertEqual(oversized_stream.status, 413, detail)
                finally:
                    connection.close()

                with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                    self.request(base, "/internal/v1/score", {"feature_schema_version": 1,
                                                                  "feature_names": FEATURE_NAMES,
                                                                  "vectors": [normal(0)]})
                self.assertEqual(unauthorized.exception.code, 403)
                with self.assertRaisesRegex(AssertionError, "feature names or order"):
                    self.request(base, "/internal/v1/score", {"feature_schema_version": 1,
                            "feature_names": list(reversed(FEATURE_NAMES)),
                            "vectors": [normal(0)]}, token)
                self.assertFalse(self.request(base, "/internal/v1/score",
                                              {"feature_schema_version": 1,
                                               "feature_names": FEATURE_NAMES,
                                               "vectors": [normal(0)]}, token)["available"])

                job = self.request(base, "/internal/v1/train", {
                    "model_version": "candidate_api_test",
                    "feature_schema_version": 1,
                    "feature_names": FEATURE_NAMES,
                    "samples": [normal(index) for index in range(600)],
                    "calibration": [normal(index) for index in range(600, 720)],
                }, token)
                self.assertEqual(job["status"], "QUEUED")
                for _ in range(100):
                    state = self.request(base, f"/internal/v1/jobs/{job['job_id']}", token=token)
                    if state["status"] in {"SUCCEEDED", "FAILED", "INTERRUPTED"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(state["status"], "SUCCEEDED")

                activated = self.request(base, "/internal/v1/models/activate",
                                         {"model_version": "candidate_api_test"}, token)
                self.assertEqual(activated["feature_schema_version"], 1)
                results = self.request(base, "/internal/v1/score", {
                    "feature_schema_version": 1,
                    "feature_names": FEATURE_NAMES,
                    "vectors": [normal(1), [500, 40, 0, 20, 10, 5, 4, 3, 1, 1, 1]],
                }, token)
                self.assertTrue(results["available"])
                self.assertEqual(results["model_version"], "candidate_api_test")
                self.assertGreaterEqual(results["results"][1]["normal_percentile"],
                                        results["results"][0]["normal_percentile"])
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    @staticmethod
    def request(base, path, payload=None, token=None):
        headers = {"Accept": "application/json"}
        if token is not None:
            headers["X-UEBA-Token"] = token
        if payload is not None:
            headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exception:
            if token is not None:
                raise AssertionError(f"worker rejected authenticated request: {exception.read().decode()}") from exception
            raise


if __name__ == "__main__":
    unittest.main()
