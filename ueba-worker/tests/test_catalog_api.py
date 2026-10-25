"""Real loopback HTTP recipe -> worker fitting/calibration; preview cannot activate."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from app.operator_catalog import OperatorCatalog
from app.policy import ScorePolicy, canonical
from test_calibration import fixture


def installed(root):
    catalog = root / "catalog"; catalog.mkdir()
    data = catalog / "calibration-owned-fixture"; data.mkdir(); dataset = fixture(data)
    entry = {"recipe_id": "owned-preview-recipe", "dataset_id": "calibration-owned-fixture", "mode": "PILOT", "fold": 1,
             "manifest_sha256": dataset.sha256,
             "config": {"n_estimators": 200, "max_samples": 128, "max_features": 1.0, "random_state": 42},
             "score_policy": ScorePolicy.strict().wire()}
    (catalog / "catalog.json").write_text(canonical({"entries": [], "strict_entries": [entry]}))
    return catalog, dataset


class CatalogApiTest(unittest.TestCase):
    def test_loopback_id_only_job_uses_real_forest_and_cannot_activate_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalog, dataset = installed(root)
            token = "owned-catalog-api-test-token-at-least-32-characters"
            token_file = root / "token"; token_file.write_text(token); token_file.chmod(0o600)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
            environment = os.environ.copy()
            environment.update(UEBA_SERVICE_TOKEN_FILE=str(token_file), UEBA_MODEL_DIR=str(root / "models"),
                               UEBA_EXPERIMENT_CATALOG_DIR=str(catalog))
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--workers", "1"],
                                       env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = f"http://127.0.0.1:{port}"
            def request(path, payload=None, credential=token):
                headers = {"Content-Type": "application/json"}
                if credential: headers["X-UEBA-Token"] = credential
                data = json.dumps(payload).encode() if payload is not None else None
                with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers), timeout=5) as response:
                    return response.status, json.load(response)
            try:
                for _ in range(100):
                    if process.poll() is not None: self.fail("owned worker exited before health")
                    try: request("/health"); break
                    except urllib.error.URLError: time.sleep(0.05)
                else: self.fail("owned worker health timeout")
                payload = {"model_version": "catalog_api_preview_model", "recipe_id": "owned-preview-recipe"}
                with self.assertRaises(urllib.error.HTTPError) as denied: request("/internal/v1/train-catalog", payload, None)
                self.assertEqual(denied.exception.code, 403)
                with self.assertRaises(urllib.error.HTTPError) as arbitrary:
                    request("/internal/v1/train-catalog", payload | {"samples": [[999]], "path": "/private/model", "config": {"n_estimators": 1}})
                self.assertEqual(arbitrary.exception.code, 422)
                with self.assertRaises(urllib.error.HTTPError) as unknown:
                    request("/internal/v1/train-catalog", payload | {"recipe_id": "unregistered-recipe"})
                self.assertEqual(unknown.exception.code, 400)
                status, queued = request("/internal/v1/train-catalog", payload)
                self.assertEqual(status, 202); self.assertEqual(queued["status"], "QUEUED")
                for _ in range(200):
                    _, state = request("/internal/v1/jobs/" + queued["job_id"])
                    if state["status"] in ("SUCCEEDED", "FAILED", "INTERRUPTED"): break
                    time.sleep(0.05)
                self.assertEqual(state["status"], "SUCCEEDED", state.get("error_type"))
                self.assertEqual(state["metadata"]["training_windows"], 600)
                self.assertEqual(state["metadata"]["calibration_windows"], 600)
                self.assertEqual(state["metadata"]["calibration_scope"], "PILOT_ONLY")
                self.assertEqual(state["metadata"]["recipe_id"], payload["recipe_id"])
                self.assertEqual(state["metadata"]["dataset_manifest_sha256"], dataset.sha256)
                self.assertEqual(state["quality_gate"], "NOT_RUN")
                with self.assertRaises(urllib.error.HTTPError) as cannot_activate:
                    request("/internal/v1/models/activate", {"model_version": payload["model_version"]})
                self.assertEqual(cannot_activate.exception.code, 400)
                activation = {"model_version": payload["model_version"], "request_id": "a" * 32}
                status, queued_activation = request("/internal/v1/models/activation-jobs", activation)
                self.assertEqual(status, 202); self.assertEqual(queued_activation["job_id"], activation["request_id"])
                for _ in range(100):
                    _, activation_result = request("/internal/v1/jobs/" + activation["request_id"])
                    if activation_result["status"] in ("SUCCEEDED", "FAILED", "INTERRUPTED"): break
                    time.sleep(0.05)
                self.assertEqual(activation_result["status"], "FAILED")
                self.assertFalse(request("/internal/v1/models/primary")[1]["available"])
                self.assertEqual(request("/internal/v1/models/activation-jobs", activation)[1]["job_id"], activation["request_id"])
                evaluation = {"model_version": payload["model_version"], "recipe_id": payload["recipe_id"]}
                with self.assertRaises(urllib.error.HTTPError) as no_evaluation_auth:
                    request("/internal/v1/evaluations/catalog", evaluation, None)
                self.assertEqual(no_evaluation_auth.exception.code, 403)
                with self.assertRaises(urllib.error.HTTPError) as uploaded_labels:
                    request("/internal/v1/evaluations/catalog", evaluation | {"labels": [1], "path": "/private/data"})
                self.assertEqual(uploaded_labels.exception.code, 422)
                with self.assertRaises(urllib.error.HTTPError) as preview_evaluation:
                    request("/internal/v1/evaluations/catalog", evaluation)
                self.assertEqual(preview_evaluation.exception.code, 400)
                shadow = {"model_version": payload["model_version"], "request_id": "c" * 32}
                with self.assertRaises(urllib.error.HTTPError) as no_shadow_auth:
                    request("/internal/v1/shadow-runs", shadow, None)
                self.assertEqual(no_shadow_auth.exception.code, 403)
                with self.assertRaises(urllib.error.HTTPError) as fake_clock:
                    request("/internal/v1/shadow-runs", shadow | {"elapsed_monotonic_seconds": 86400})
                self.assertEqual(fake_clock.exception.code, 422)
                code, shadow_job = request("/internal/v1/shadow-runs", shadow)
                self.assertEqual(code, 202); self.assertEqual(shadow_job["job_id"], shadow["request_id"])
                for _ in range(100):
                    _, shadow_result = request("/internal/v1/jobs/" + shadow["request_id"])
                    if shadow_result["status"] in ("SUCCEEDED", "FAILED", "INTERRUPTED"): break
                    time.sleep(0.05)
                self.assertEqual(shadow_result["status"], "FAILED")  # PILOT_ONLY never qualifies.
                self.assertEqual(request("/internal/v1/shadow-runs", shadow)[1]["job_id"], shadow["request_id"])
                with self.assertRaises(urllib.error.HTTPError) as shadow_conflict:
                    request("/internal/v1/shadow-runs", shadow | {"model_version": "another_owned_model"})
                self.assertEqual(shadow_conflict.exception.code, 409)
                self.assertFalse(request("/health")[1]["model_available"])
                with self.assertRaises(urllib.error.HTTPError) as duplicate: request("/internal/v1/train-catalog", payload)
                self.assertEqual(duplicate.exception.code, 409)
                self.assertEqual((root / "models/jobs" / (queued["job_id"] + ".json")).stat().st_mode & 0o777, 0o600)
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()

    def test_paths_duplicates_scope_changes_and_manifest_tampering_are_not_operator_recipes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalog, _ = installed(root)
            registry = OperatorCatalog(catalog)
            self.assertEqual(registry.recipe("owned-preview-recipe").mode, "PILOT")
            with self.assertRaises(ValueError): registry.recipe("../private-file")
            path = catalog / "calibration-owned-fixture/manifest.json"
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "binding mismatch"): registry.recipe("owned-preview-recipe")


if __name__ == "__main__": unittest.main()
