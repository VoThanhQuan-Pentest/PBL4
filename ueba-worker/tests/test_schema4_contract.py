"""Small real schema-4 fixtures validate contracts and guards, not accuracy."""

import hashlib
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

import numpy as np

from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_NAMES_V3, FEATURE_NAMES_V4, FEATURE_SCHEMAS, feature_array
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from app.quality_proof import verify_quality


def vector(index=0, *, cold=False):
    requests = 40 + index % 7
    return [requests, 2, 0, 0, 1, 0, 2, 1, 0, 0, 0, 0, 0, 2 / requests, 0,
            requests, 1, 0, 1, 1 / (requests - 1), 0, 0, 0, 0, 2,
            requests, 2, 0, 0, 1, requests, requests, 1, 600, 1, 3 if cold else 48, 0.5]


def numeric_row(index=0, *, cold=False, name="schema4-contract"):
    return {"frame_id": f"{name}-frame-{index:06d}", "account_id": f"{name}-account-{index:06d}",
            "window_start": "2026-04-01T00:00:00Z", "label": 0, "family": "normal",
            "cohort": "COLD" if cold else "READY", "baseline_established": not cold,
            "trusted_window_count": 3 if cold else 48, "features": vector(index, cold=cold)}


def write_catalogue(root, *, schema=4, telemetry=None, populations=None):
    """Operator-owned test files, with every claimed population derived from rows."""
    (root / "shards").mkdir()
    populations = populations or (("holdout", 1, False),)
    splits = {}
    for name, size, cold in populations:
        rows = [numeric_row(index, cold=cold, name=name) for index in range(size)]
        for row in rows:
            if name.endswith("-fit"): row["window_start"] = "2026-01-01T00:00:00Z"
            elif "calibration" in name: row["window_start"] = "2026-02-01T00:00:00Z"
        if schema != 4:
            for row in rows: row["features"] = row["features"][:len(FEATURE_SCHEMAS[schema])]
        data = canonical(rows).encode(); identity = f"{name}-000000"
        relative = f"shards/{identity}.json"; (root / relative).write_bytes(data)
        stats = validate_rows(rows, schema)
        descriptor = {"id": identity, "path": relative, "sha256": hashlib.sha256(data).hexdigest(), **stats}
        split = {**stats, "shards": [descriptor]}
        split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest(); splits[name] = split
    manifest = {"catalog_schema_version": 2, "dataset_id": "schema4-owned-fixture", "stage": "PILOT",
                "feature_schema_version": schema, "telemetry_contract_version": telemetry if telemetry is not None else (3 if schema == 4 else 2),
                "feature_names": list(FEATURE_SCHEMAS[schema]), "data_provenance": "DEMO_ONLY", "splits": splits}
    (root / "manifest.json").write_text(canonical(manifest))
    return manifest


class Schema4ContractTest(unittest.TestCase):
    def test_exact_prefix_and_unchanged_strict_targets(self):
        self.assertEqual(FEATURE_NAMES_V4[:25], FEATURE_NAMES_V3)
        self.assertEqual(len(FEATURE_NAMES_V4), 37)
        self.assertEqual(feature_array([vector()], 256, 4).shape, (1, 37))
        policy = ScorePolicy.strict(schema=4)
        self.assertTrue(policy.document["policy_id"].startswith("strict-v4d-"))
        self.assertEqual(policy.document["telemetry_contract_version"], 3)
        for schema in (2, 3):
            old = ScorePolicy.strict(schema=schema)
            for section in ("quality", "risk", "shadow"):
                self.assertEqual(policy.document[section], old.document[section])
            self.assertEqual(old.document["telemetry_contract_version"], 2)
            self.assertNotEqual(policy.sha256, old.sha256)
        self.assertEqual(ScorePolicy.from_wire(policy.wire()), policy)
        with self.assertRaises(ValueError): ScorePolicy.legacy(4)
        for old_schema in (1, 2, 3):
            with self.assertRaises(ValueError): feature_array([vector()], 256, old_schema)

    def test_new_counts_are_numeric_nonnegative_integers(self):
        for field in (25, 26, 27, 28, 29, 30, 31, 32, 34, 35):
            for invalid in (-1, 0.5, True, "1", float("inf"), float("nan")):
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    value = vector(); value[field] = invalid; feature_array([value], 256, 4)

    def test_coverage_sentinels_sessions_history_and_bounds_cannot_be_invented(self):
        invalids = ((25, 41), (31, 41), (27, 41), (28, 41), (26, 0), (26, 21), (26, 41),
                    (29, 41), (30, 41), (30, 0), (32, 41), (32, 0), (34, 40),
                    (33, -1), (33, 86401), (35, 1345), (36, -20.01), (36, 20.01))
        for field, invalid in invalids:
            with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                value = vector(); value[field] = invalid; feature_array([value], 256, 4)
        value = vector(); value[27:29] = [21, 20]
        with self.assertRaises(ValueError): feature_array([value], 256, 4)
        value = vector(); value[25:31] = [10, 2, 5, 4, 2, 1]
        with self.assertRaises(ValueError): feature_array([value], 256, 4)
        value = vector(); value[31:35] = [3, 2, 600, 2]
        with self.assertRaises(ValueError): feature_array([value], 256, 4)

    def test_missing_metadata_is_zero_and_observed_boundary_values_are_valid(self):
        value = vector(); value[25:] = [0] * 12
        self.assertEqual(feature_array([value], 256, 4).shape, (1, 37))
        for field in (26, 29, 30, 32, 33, 34, 36):
            with self.subTest(field=field), self.assertRaises(ValueError):
                invalid = value.copy(); invalid[field] = 1; feature_array([invalid], 256, 4)
        # Entire endpoint metadata may truthfully consist of sentinel observations.
        value = vector(); value[25:31] = [40, 0, 20, 20, 0, 0]
        value[33], value[35], value[36] = 86400, 1344, -20
        feature_array([value], 256, 4)
        value[36] = 20; feature_array([value], 256, 4)

    def test_schema2_rates_and_schema3_context_are_still_validated(self):
        for field, invalid in ((13, 0), (14, 1), (15, 41), (15, 0), (16, 900), (17, 21),
                               (18, 40), (19, 0), (20, 21), (21, -21), (22, 1), (23, 1), (24, 3)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                value = vector(); value[field] = invalid; feature_array([value], 256, 4)

    def test_cold_short_history_does_not_fabricate_a_ready_personal_baseline(self):
        row = numeric_row(cold=True)
        self.assertEqual(validate_rows([row], 4)["cohorts"], {"COLD": 1})
        self.assertNotEqual(row["features"][35], 0); self.assertNotEqual(row["features"][36], 0)
        for index in (8, 9, 10, 11, 12, 20, 21):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "cold-start"):
                invalid = numeric_row(cold=True); invalid["features"][index] = 1; validate_rows([invalid], 4)
        row["baseline_established"] = True
        with self.assertRaises(ValueError): validate_rows([row], 4)
        row = numeric_row(); row["raw_session"] = "never-a-model-feature"
        with self.assertRaisesRegex(ValueError, "contract"): validate_rows([row], 4)

    def test_schema4_catalogues_require_new_telemetry_and_demo_provenance(self):
        for schema, telemetry, accepted in ((2, 2, True), (3, 2, True), (4, 3, True),
                                             (4, 2, False), (2, 3, False), (3, 3, False)):
            with self.subTest(schema=schema, telemetry=telemetry), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); write_catalogue(root, schema=schema, telemetry=telemetry)
                if accepted:
                    dataset = ShardedDataset(root); dataset.load_shard("holdout", 0)
                else:
                    with self.assertRaises(ValueError): ShardedDataset(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); document = write_catalogue(root)
            document["data_provenance"] = "PRODUCTION_VERIFIED"
            (root / "manifest.json").write_text(canonical(document))
            with self.assertRaises(ValueError): ShardedDataset(root)

    def test_registered_loopback_recipe_performs_real_small_fit_score_and_rejects_promotion(self):
        # 600 fit + 120 per-cohort calibration rows are only a contract fixture.
        # They do not satisfy strict calibration, holdout, quality or elapsed shadow requirements.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalog = root / "catalog"; catalog.mkdir()
            data = catalog / "schema4-owned-fixture"; data.mkdir()
            write_catalogue(data, populations=(("fold1-fit", 600, False),
                            ("fold1-calibration-ready", 120, False), ("fold1-calibration-cold", 120, True)))
            dataset = ShardedDataset(data); policy = ScorePolicy.strict(schema=4)
            entry = {"recipe_id": "schema4-preview-recipe", "dataset_id": dataset.manifest["dataset_id"],
                     "mode": "PILOT", "fold": 1, "manifest_sha256": dataset.sha256,
                     "config": {"n_estimators": 200, "max_samples": 128, "max_features": 1.0, "random_state": 42},
                     "score_policy": policy.wire()}
            (catalog / "catalog.json").write_text(canonical({"entries": [], "strict_entries": [entry]}))
            token = "schema4-owned-loopback-token-at-least-32-characters"
            token_file = root / "token"; token_file.write_text(token); token_file.chmod(0o600)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
            environment = os.environ.copy()
            environment.update(UEBA_SERVICE_TOKEN_FILE=str(token_file), UEBA_MODEL_DIR=str(root / "models"),
                               UEBA_EXPERIMENT_CATALOG_DIR=str(catalog))
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                                        "--port", str(port), "--workers", "1"], env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = f"http://127.0.0.1:{port}"

            def request(path, payload=None):
                encoded = json.dumps(payload).encode() if payload is not None else None
                headers = {"Content-Type": "application/json", "X-UEBA-Token": token}
                with urllib.request.urlopen(urllib.request.Request(base + path, data=encoded, headers=headers), timeout=5) as response:
                    return response.status, json.load(response)

            def job(job_id):
                for _ in range(300):
                    state = request("/internal/v1/jobs/" + job_id)[1]
                    if state["status"] in ("SUCCEEDED", "FAILED", "INTERRUPTED"): return state
                    time.sleep(0.05)
                self.fail("small schema-4 fixture exceeded its bounded job timeout")

            try:
                for _ in range(100):
                    if process.poll() is not None: self.fail("owned worker exited before health")
                    try: healthy = request("/health")[1]; break
                    except urllib.error.URLError: time.sleep(0.05)
                else: self.fail("owned worker health timeout")
                self.assertEqual(healthy["supported_feature_schemas"], [1, 2, 3, 4])
                inline = {"model_version": "schema4_inline_refused", "feature_schema_version": 4,
                          "feature_names": list(FEATURE_NAMES_V4), "samples": [vector()] * 600,
                          "calibration": [vector()] * 120, "score_policy": policy.wire()}
                with self.assertRaises(urllib.error.HTTPError) as denied: request("/internal/v1/train", inline)
                self.assertEqual(denied.exception.code, 422)
                selected = {"model_version": "schema4_recipe_guard", "recipe_id": entry["recipe_id"]}
                with self.assertRaises(urllib.error.HTTPError) as uploaded:
                    request("/internal/v1/train-catalog", selected | {"samples": [vector()], "labels": [0], "path": "/private/model"})
                self.assertEqual(uploaded.exception.code, 422)
                status, queued = request("/internal/v1/train-catalog", selected)
                self.assertEqual(status, 202); state = job(queued["job_id"])
                self.assertEqual(state["status"], "SUCCEEDED", state.get("error_type"))
                metadata = state["metadata"]
                self.assertEqual(metadata["training_windows"], 600)
                self.assertEqual(metadata["calibration_cohort_windows"], {"READY": 120, "COLD": 120})
                self.assertEqual(metadata["feature_schema_version"], 4)
                self.assertEqual(metadata["data_provenance"], "DEMO_ONLY")
                self.assertEqual(metadata["calibration_scope"], "PILOT_ONLY")
                self.assertEqual(state["quality_gate"], "NOT_RUN")
                scored = {"model_version": selected["model_version"], "feature_schema_version": 4,
                          "feature_names": list(FEATURE_NAMES_V4), "vectors": [vector(), vector(cold=True)],
                          "cohorts": ["READY", "COLD"]}
                _, result = request("/internal/v1/score-candidate", scored)
                self.assertTrue(result["available"])
                self.assertEqual([item["scoring_cohort"] for item in result["results"]], ["READY", "COLD"])
                self.assertTrue(all(np.isfinite(item["raw_anomaly_score"]) for item in result["results"]))
                for invalid in (True, "1"):
                    value = vector(); value[29] = invalid
                    with self.subTest(value=invalid), self.assertRaises(urllib.error.HTTPError) as nonnumeric:
                        request("/internal/v1/score-candidate", scored | {"vectors": [value], "cohorts": ["READY"]})
                    self.assertEqual(nonnumeric.exception.code, 422)
                invented = vector(cold=True); invented[20] = 1
                with self.assertRaises(urllib.error.HTTPError) as cold:
                    request("/internal/v1/score-candidate", scored | {"vectors": [invented], "cohorts": ["COLD"]})
                self.assertEqual(cold.exception.code, 400)
                with self.assertRaises(urllib.error.HTTPError) as activation:
                    request("/internal/v1/models/activate", {"model_version": selected["model_version"]})
                self.assertEqual(activation.exception.code, 400)
                _, shadow = request("/internal/v1/shadow-runs", {"model_version": selected["model_version"], "request_id": "d" * 32})
                self.assertEqual(job(shadow["job_id"])["status"], "FAILED")
                self.assertFalse(request("/internal/v1/models/primary")[1]["available"])
                self.assertFalse(request("/health")[1]["model_available"])
                current = ModelStore(root / "models"); version = selected["model_version"]
                loaded, payload = current.load_candidate(version)
                binding = {"model_version": version, "model_sha256": loaded["sha256"], "feature_schema_version": 4,
                           "calibration_sha256": ModelStore.calibration_hash(payload), "policy_sha256": policy.sha256,
                           "dataset_sha256": dataset.sha256}
                with self.assertRaisesRegex(ValueError, "frozen quality evidence"):
                    verify_quality(current.directory, version, policy, binding)
                with self.assertRaisesRegex(ValueError, "shadow run"):
                    current.validate_shadow(version, binding)
                self.assertFalse((current.directory / "active.json").exists())
                self.assertFalse((current.directory / f"{version}.evaluation.json").exists())
                # Local metadata edits do not grant schema-4 production provenance or legacy policy.
                loaded["data_provenance"] = "PRODUCTION_VERIFIED"
                (current.directory / f"{version}.json").write_text(canonical(loaded))
                with self.assertRaisesRegex(ValueError, "DEMO_ONLY"): current.load_candidate(version)
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__ == "__main__": unittest.main()
