import importlib.util
import math
import json
import tempfile
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/stress-ueba-hybrid-candidate.py"
SPEC = importlib.util.spec_from_file_location("candidate_stress_test", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class CandidateStressTest(unittest.TestCase):
    def test_only_exact_owned_loopback_socket_is_accepted(self):
        info = {"Image": M.IMAGE, "State": {"Running": True}, "Config": {"User": "1000:1000", "Labels": {M.LABEL: "nonce"}},
                "HostConfig": {"PortBindings": {"8091/tcp": [{"HostIp": "127.0.0.1", "HostPort": "12345"}]}}}
        self.assertEqual(M.verify_target("http://127.0.0.1:12345", info, "nonce"), "http://127.0.0.1:12345")
        for origin in ("http://example.com:12345", "http://127.0.0.1:12346", "http://token@127.0.0.1:12345", "http://127.0.0.1:12345/path"):
            with self.assertRaises(ValueError): M.verify_target(origin, info, "nonce")
        with self.assertRaises(ValueError): M.verify_target("http://127.0.0.1:12345", info, "different")

    def test_every_response_binds_shape_policy_cohort_and_finite_values(self):
        policy = {"detection_percentile_micro": {"READY": 99995000, "COLD": 99995000}, "warning_percentile_micro": 99900000}
        import json
        meta = {"feature_names": ["f"] * 37, "calibration_sha256": "c" * 64, "score_policy": {"policy_document_json": json.dumps(policy)}}
        payload = {"vectors": [[0.] * 37], "cohorts": ["READY"]}
        reply = {"available": True, "model_version": M.CANDIDATE, "feature_schema_version": 4, "feature_names": meta["feature_names"],
                 "calibration_sha256": meta["calibration_sha256"], "score_policy": meta["score_policy"],
                 "results": [{"raw_anomaly_score": .1, "normal_percentile": 10., "level": "NORMAL_RANGE", "scoring_cohort": "READY"}]}
        M.validate_response(reply, payload, meta)
        reply_strict = reply | {"model_version": "strict_qualified_2026"}
        M.validate_response(reply_strict, payload | {"model_version": "strict_qualified_2026"}, meta,
                            "strict_qualified_2026")
        for key, value in (("results", []), ("model_version", "different"), ("calibration_sha256", "d" * 64), ("available", False)):
            with self.assertRaises(ValueError): M.validate_response(reply | {key: value}, payload, meta)
        for key, value in (("raw_anomaly_score", math.nan), ("normal_percentile", 101), ("scoring_cohort", "COLD"), ("level", "VERY_UNUSUAL")):
            changed = reply | {"results": [reply["results"][0] | {key: value}]}
            with self.assertRaises(ValueError): M.validate_response(changed, payload, meta)

    def test_fixed_ramp_soak_is_bounded_and_never_a_quality_gate(self):
        self.assertEqual(sum(stage[2] for stage in M.STAGES), 420)
        self.assertEqual([stage[1] for stage in M.STAGES], [1, 5, 10, 25, 5])
        self.assertLessEqual(M.CLIENTS, 8); self.assertLessEqual(M.BATCH_SIZE, 256)
        self.assertIn('counts = {"fits": 0, "activation": 0, "recalibration": 0}', M.BOOTSTRAP)
        self.assertNotIn("fit(", M.BOOTSTRAP)
        self.assertIn('uds="/socket/worker.sock"', M.BOOTSTRAP_UDS)
        self.assertIn('"network_mode": "none_unix_socket_only"', M.DRIVER)
        compile(M.BOOTSTRAP_UDS, "candidate-stress-bootstrap", "exec")
        compile(M.DRIVER, "candidate-stress-driver", "exec")

    def test_qualified_runner_rejects_networked_or_writable_worker_containers(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {name: root / name for name in ("service", "models", "owned", "socket")}
            for path in sources.values(): path.mkdir()
            inspected = {"Name": "/strict-runner", "Image": M.IMAGE,
                "Config": {"Labels": {M.LABEL: "run-id"}, "User": "1000:1000"},
                "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "PortBindings": None,
                               "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
                               "Memory": 1024 ** 3, "NanoCpus": 1_000_000_000, "PidsLimit": 64},
                "State": {"Running": True}, "NetworkSettings": {"Ports": {}},
                "Mounts": [{"Destination": "/" + name, "Source": str(path), "RW": name == "socket"}
                           for name, path in sources.items()]}
            required = {"/service": (sources["service"], False), "/models": (sources["models"], False),
                        "/owned": (sources["owned"], False), "/socket": (sources["socket"], True)}
            self.assertTrue(M._verify_network_none_container(inspected, "strict-runner", M.LABEL,
                                                               "run-id", required, running=True)["Running"])
            for field, value in (("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True)):
                changed = {**inspected, "HostConfig": inspected["HostConfig"] | {field: value}}
                with self.assertRaisesRegex(ValueError, "network-none"):
                    M._verify_network_none_container(changed, "strict-runner", M.LABEL,
                        "run-id", required, running=True)
            changed = {**inspected, "NetworkSettings": {"Ports": {"8091/tcp": [{"HostPort": "56000"}]}}}
            with self.assertRaisesRegex(ValueError, "network-none"):
                M._verify_network_none_container(changed, "strict-runner", M.LABEL,
                    "run-id", required, running=True)

    def test_summary_counts_real_status_errors_and_rows(self):
        rows = [{"status": status, "error": error, "latency_seconds": latency, "requested_rows": 10,
                 "validated_rows": 10 if error is None else 0} for status, error, latency in ((200, None, .1), (429, "HTTP", .2), (503, "HTTP", 1.))]
        result = M.summarize(rows)
        self.assertEqual(result["status_counts"], {"200": 1, "429": 1, "503": 1})
        self.assertEqual(result["errors"], 2); self.assertEqual(result["validated_rows"], 10)
        self.assertEqual(result["p95_seconds"], 1.)
        # Harmless source-check fixture only: never unpickle or score its dummy bytes.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); models = root / "models"; catalog = root / "catalog"
            models.mkdir(); catalog.mkdir(); (catalog / "shards").mkdir()
            binary = models / (M.CANDIDATE + ".joblib"); binary.write_bytes(b"numeric-source-check-fixture-only")
            names = ["f" + str(i) for i in range(37)]
            metadata = {"model_kind": M.KIND, "model_state_format": M.FORMAT, "feature_schema_version": 4,
                        "calibration_scope": "PILOT_ONLY", "data_provenance": "DEMO_ONLY", "feature_names": names,
                        "sha256": M.checksum(binary), "calibration_sha256": "c" * 64, "model_state_sha256": "d" * 64}
            (models / (M.CANDIDATE + ".json")).write_text(json.dumps(metadata))
            descriptors = []
            for index, count in enumerate((5000, 5000, 5000, 5000, 1000)):
                path = catalog / "shards" / ("fixture-" + str(index) + ".json")
                path.write_text(json.dumps([{"features": [0.] * 37, "cohort": "READY", "label": 0}] * count))
                descriptors.append({"path": "shards/" + path.name, "records": count, "sha256": M.checksum(path)})
            manifest = {"stage": "PILOT", "feature_names": names, "splits": {"fold1-validation": {"shards": descriptors}}}
            (catalog / "manifest.json").write_text(json.dumps(manifest))
            _, pool, identities = M.sources(models, catalog)
            self.assertEqual(len(pool), 21000); self.assertEqual(len(pool[0][0]), 37)
            self.assertIn(str(binary), identities)
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "checksum"):
                M.sources(models, catalog)

    def _qualified_package_fixture(self, directory):
        import hashlib
        import os
        directory.mkdir(mode=0o750)
        version = "strict_qualified_2026"
        files = {"joblib": version + ".joblib", "metadata": version + ".json",
                 "evaluation": version + ".evaluation.json", "evaluation_identity": version + ".evaluation-identity.json",
                 "metrics": version + ".metrics.sqlite"}
        values = {key: ("fixture:" + key).encode() for key in files}
        metadata = {"model_version": version, "model_kind": M.KIND, "model_state_format": M.FORMAT,
                    "feature_schema_version": 4, "calibration_scope": "STRICT", "data_provenance": "DEMO_ONLY",
                    "feature_names": ["f" + str(index) for index in range(37)],
                    "sha256": hashlib.sha256(values["joblib"]).hexdigest(),
                    "calibration_sha256": "c" * 64, "model_state_sha256": "d" * 64}
        values["metadata"] = json.dumps(metadata).encode()
        passing_scope = {"quality_gate": "PASS", "tp": 10000, "fn": 0, "fp": 0, "tn": 10000000}
        evaluation_identity = {"fresh_holdout_manifest_sha256": "e" * 64,
            "holdout_split_sha256": "f" * 64, "frozen_selection_receipt_sha256": "b" * 64,
            "original_training_manifest_sha256": "a" * 64}
        evaluation = {"status": "SUCCEEDED", "quality_gate": "PASS", "evaluation_scope": "FROZEN_HOLDOUT",
                      "actual_scored_episodes": 10010000, "model_version": version,
                      "model_sha256": metadata["sha256"],
                      "evaluation_identity": evaluation_identity,
                      "scopes": {"MODEL_ONLY": passing_scope, "SIEM_FINAL": passing_scope}}
        values["evaluation"] = json.dumps(evaluation).encode()
        values["evaluation_identity"] = json.dumps(evaluation_identity).encode()
        names = {key: directory / name for key, name in files.items()}
        for key, path in names.items():
            path.write_bytes(values[key]); path.chmod(0o640)
        package = {"format": "UEBA_QUALIFIED_ADOPTION_PACKAGE_V1", "schema_version": 1, "status": "READY",
                   "model_version": version, "data_provenance": "DEMO_ONLY", "quality_gate": "PASS",
                   "feature_schema_version": 4, "model_sha256": metadata["sha256"],
                   "model_state_sha256": metadata["model_state_sha256"],
                   "calibration_sha256": metadata["calibration_sha256"],
                   "recipe_id": "strict-dataset-champion", "original_dataset_id": "strict_dataset",
                   "original_training_manifest_sha256": "a" * 64,
                   "selection_receipt_sha256": "b" * 64, "fresh_holdout_dataset_id": "fresh_holdout",
                   "fresh_holdout_manifest_sha256": "e" * 64, "holdout_split_sha256": "f" * 64,
                   "policy_sha256": "c" * 64,
                   "artifact_sha256": {key: hashlib.sha256(values[key]).hexdigest() for key in files},
                   "strict_reference": {"manifest_sha256": "a" * 64},
                   "selection_proof": {"holdout_scored": False, "actual_composite_trials": 360,
                                       "actual_component_fit_calls": 720, "validation_runs": 360,
                                       "zero_fit_recalibrations": 45}}
        package_path = directory / "candidate-package.json"
        package_path.write_text(json.dumps(package)); package_path.chmod(0o640)
        return package_path

    def test_qualified_package_requires_strict_quality_and_bound_artifacts(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = Path(temporary) / "qualified"
            package_path = self._qualified_package_fixture(package_dir)
            # Test fixture matches the production owner/group/modes required by the script.
            for path in (package_dir, *package_dir.iterdir()):
                os.chown(path, 1000, 1000)
            _, version, metadata, _, _, package = M._strict_package(package_dir, M.checksum(package_path))
            self.assertEqual(version, "strict_qualified_2026")
            self.assertEqual(metadata["calibration_scope"], "STRICT")
            self.assertEqual(package["quality_gate"], "PASS")
            package["quality_gate"] = "NOT_RUN"
            package_path.write_text(json.dumps(package))
            package_path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "quality-passing"):
                M._strict_package(package_dir, M.checksum(package_path))

    def test_qualified_package_rejects_false_positive_rate_at_limit(self):
        import hashlib
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = Path(temporary) / "qualified"
            package_path = self._qualified_package_fixture(package_dir)
            for path in (package_dir, *package_dir.iterdir()): os.chown(path, 1000, 1000)
            version = "strict_qualified_2026"
            evaluation_path = package_dir / (version + ".evaluation.json")
            evaluation = json.loads(evaluation_path.read_text())
            for scope in evaluation["scopes"].values():
                scope["fp"], scope["tn"] = 10000, 9_990_000
            evaluation_path.write_text(json.dumps(evaluation)); evaluation_path.chmod(0o640)
            package = json.loads(package_path.read_text())
            package["artifact_sha256"]["evaluation"] = hashlib.sha256(evaluation_path.read_bytes()).hexdigest()
            package_path.write_text(json.dumps(package)); package_path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "point estimates"):
                M._strict_package(package_dir, M.checksum(package_path))

    def test_strict_stress_sample_positions_are_unique_and_cover_range(self):
        positions = M.deterministic_sample_positions(1_001_000, 21_000)
        self.assertEqual(len(positions), 21_000)
        self.assertIn(0, positions)
        self.assertIn(1_000_999, positions)
        with self.assertRaises(ValueError): M.deterministic_sample_positions(10, 11)


if __name__ == "__main__": unittest.main()
