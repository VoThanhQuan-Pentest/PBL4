"""Bounded pilot plumbing and provenance tests, never model-quality claims."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from app.catalog import ShardedDataset
from app.contract import FEATURE_NAMES_V4
from app.schema4_pilot import Shards, check_declared_endpoints, check_endpoint_proof, observable_shortcut_audit, transport


def episode():
    return {"frame": {"frame_id": "pilot-frame-001", "account_id": "pilot-account-001", "day": 15, "cohort": "COLD",
                      "window_start": "2026-04-15T00:00:00Z", "telemetry_contract_version": 3, "events": [{"event_type": "AUTH"}]},
            "scenario": {"label": 1, "family": "auth_failure_burst", "planned_cause": "auth_failure_burst",
                         "data_provenance": "DEMO_ONLY_SIMULATION", "plan_sha256": "a" * 64},
            "client_ledger": [{"client_denial_only": True}], "evidence": {"simulation_only": True}}


class Schema4PilotTest(unittest.TestCase):
    def test_separate_labels_only_enter_exporter_transport_not_episode_or_client_frames(self):
        value = episode()
        original = deepcopy(value)
        frame = transport(value)
        self.assertEqual(frame["demo_label"], "ABNORMAL")
        self.assertEqual(frame["family"], "auth_failure_burst")
        self.assertNotIn("scenario", frame)
        self.assertNotIn("client_ledger", frame)
        self.assertNotIn("planned_cause", frame)
        self.assertEqual(value, original)

    def test_mixed_representation_unknown_labels_or_capture_promotion_are_refused(self):
        faults = (lambda value: value["frame"].update(label=1), lambda value: value["frame"].update(jwt="private"),
                  lambda value: value["scenario"].update(data_provenance="REAL"),
                  lambda value: value["scenario"].update(label=True), lambda value: value["scenario"].update(family="normal"),
                  lambda value: value["scenario"].update(plan_sha256="not-frozen"))
        for fault in faults:
            with self.subTest(fault=fault):
                value = episode()
                fault(value)
                with self.assertRaises(ValueError):
                    transport(value)

    def test_endpoint_proof_binds_actual_same_frozen_class_but_not_live_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            proof = {"scope": "ACTUAL_IMMUTABLE_ENDPOINT_CLASSIFIER_OFFLINE_ONLY", "workspace_snapshot_sha256": "b" * 64,
                     "endpoint_class_sha256": "c" * 64, "feature_schema_version": 4, "telemetry_contract_version": 3,
                     "http_handler_resolution_proven": False, "authenticated_session_proven": False}
            path.write_text(json.dumps(proof))
            path.chmod(0o600)
            package = {"classes": {"service/siem/EndpointCategory.class": "c" * 64}}
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(check_endpoint_proof(path, checksum, "b" * 64, package), proof)
            with self.assertRaises(ValueError):
                check_endpoint_proof(path, checksum, "d" * 64, package)
            with self.assertRaises(ValueError):
                check_endpoint_proof(path, "e" * 64, "b" * 64, package)
            proof["authenticated_session_proven"] = True
            path.write_text(json.dumps(proof))
            with self.assertRaises(ValueError):
                check_endpoint_proof(path, hashlib.sha256(path.read_bytes()).hexdigest(), "b" * 64, package)

    def test_declared_handler_category_cannot_be_changed_or_claim_unknown_controller(self):
        recipe = {"method": "GET", "handler_pattern": "/api/profile", "endpoint_category": "PROFILE_READ"}
        proof = {"handler_mappings": [recipe]}
        check_declared_endpoints({"endpoint_recipes": [recipe]}, proof)
        with self.assertRaises(ValueError):
            check_declared_endpoints({"endpoint_recipes": [{**recipe, "endpoint_category": "PRIVILEGED"}]}, proof)
        with self.assertRaises(ValueError):
            check_declared_endpoints({"endpoint_recipes": [{**recipe, "handler_pattern": "/api/private-user-id"}]}, proof)

    def test_actual_schema4_shards_keep_cohorts_labels_and_all_declared_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            (root / "shards").mkdir(mode=0o700)
            writer = Shards(root, "fold1-validation")
            for index in range(6):
                positive = index % 2
                writer.append({"frame_id": f"pilot-frame-{index:04d}", "account_id": f"pilot-account-{index:04d}",
                               "window_start": "2026-04-15T00:00:00Z", "label": positive,
                               "family": "auth_failure_burst" if positive else "normal", "cohort": "COLD",
                               "baseline_established": False, "trusted_window_count": 0, "features": [0] * 37})
            split = writer.finish()
            self.assertEqual((split["normal"], split["positive"], split["records"]), (3, 3, 6))
            self.assertEqual(split["cohorts"], {"COLD": 6})
            manifest = {"catalog_schema_version": 2, "dataset_id": "schema4-pilot-test", "stage": "PILOT", "data_provenance": "DEMO_ONLY",
                        "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                        "splits": {"fold1-validation": split}}
            (root / "manifest.json").write_text(json.dumps(manifest))
            dataset = ShardedDataset(root)
            rows = [row for _, shard in dataset.iter_shards("fold1-validation") for row in shard]
            self.assertEqual(len(rows), 6)
            self.assertEqual(sum(row["label"] for row in rows), 3)

    def test_shortcut_summary_is_descriptive_never_feature_selection_or_quality(self):
        rows = []
        for number in range(200):
            features = [0] * 37
            features[3] = 1
            rows.append({"label": number % 2, "family": "auth_failure_burst" if number % 2 else "normal", "cohort": "COLD", "features": features})
        class Dataset:
            def iter_shards(self, name):
                self.last_split = name
                yield {}, rows
        dataset = Dataset()
        audit = observable_shortcut_audit(dataset)
        self.assertEqual(dataset.last_split, "fold1-validation")
        self.assertEqual(audit["normal_login_only_window_count"], 100)
        self.assertEqual(audit["normal_absent_authenticated_session_window_count"], 100)
        self.assertEqual(audit["quality_gate"], "NOT_APPLICABLE")
        self.assertTrue(audit["no_threshold_or_feature_selection"])
        self.assertTrue(audit["manual_protocol_review_required"])


if __name__ == "__main__":
    unittest.main()
