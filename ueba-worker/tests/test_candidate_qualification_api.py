"""Internal proof lookup rechecks stored strict evidence and never activates it."""

import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app import main
from app.policy import ScorePolicy


class FakeStore:
    def __init__(self, directory):
        self.directory = directory
        self.active_version = "prior-primary"

    def load_candidate(self, version):
        return ({"model_version": version, "sha256": "a" * 64,
                 "feature_schema_version": 4, "calibration_scope": "STRICT",
                 "score_policy": {"strict": True}}, {"private": "numeric model state is not returned"})


class CandidateQualificationApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.version = "strict-candidate-v1"
        self.identity = {
            "fresh_holdout_manifest_sha256": "b" * 64,
            "holdout_split_sha256": "c" * 64,
            "frozen_selection_receipt_sha256": "d" * 64,
            "original_training_manifest_sha256": "f" * 64,
            "hybrid_strict_proof": {
                "format": "HYBRID_STRICT_PROOF_V1", "proof_sha256": "8" * 64,
                "selection_sha256": "d" * 64,
                "source_label_manifests": {str(fold): {"artifact_id": f"labels-fold{fold}",
                    "manifest_sha256": str(fold) * 64} for fold in (1, 2, 3)},
            },
        }
        model_bytes = b"candidate numeric state"
        model_sha = hashlib.sha256(model_bytes).hexdigest()
        journal_bytes = b"immutable scoring journal"
        journal_sha = hashlib.sha256(journal_bytes).hexdigest()
        self.evaluation = {
            "status": "SUCCEEDED", "quality_gate": "PASS", "evaluation_scope": "FROZEN_HOLDOUT",
            "data_provenance": "DEMO_ONLY", "evaluation_identity": self.identity,
            "model_version": self.version, "model_sha256": model_sha,
            "scored_journal_sha256": journal_sha,
        }
        self.policy = ScorePolicy.strict(schema=4)
        self.metadata = {
            "model_version": self.version, "sha256": model_sha,
            "feature_schema_version": 4, "calibration_scope": "STRICT",
            "calibration_sha256": "1" * 64, "dataset_manifest_sha256": "f" * 64,
            "model_state_sha256": "2" * 64, "model_state_verifier_sha256": "3" * 64,
            "model_state_format": "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1",
            "model_kind": "normal_plus_incident_research", "recipe_version": 1, "recipe_sha256": "9" * 64,
            "score_policy": self.policy.wire(),
        }
        for suffix, value in (("evaluation.json", self.evaluation),
                              ("evaluation-identity.json", self.identity)):
            path = self.directory / f"{self.version}.{suffix}"
            path.write_text(json.dumps(value, sort_keys=True))
            path.chmod(0o600)
        self.store = FakeStore(self.directory)
        self.store_metadata = self.metadata
        primary_bytes = b"previous active candidate model"
        (self.directory / "prior-primary.joblib").write_bytes(primary_bytes)
        (self.directory / "prior-primary.joblib").chmod(0o600)
        self.store.load_candidate = lambda version: (
            self.store_metadata if version == self.version else
            {"model_version": version, "sha256": hashlib.sha256(primary_bytes).hexdigest()},
            {"private": "numeric model state"})
        self.artifacts = {}
        for key, name, payload in (
                ("joblib", f"{self.version}.joblib", model_bytes),
                ("metadata", f"{self.version}.json", json.dumps(self.metadata, sort_keys=True).encode()),
                ("evaluation", f"{self.version}.evaluation.json", json.dumps(self.evaluation, sort_keys=True).encode()),
                ("evaluation_identity", f"{self.version}.evaluation-identity.json", json.dumps(self.identity, sort_keys=True).encode()),
                ("metrics", f"{self.version}.metrics.sqlite", journal_bytes)):
            path = self.directory / name
            path.write_bytes(payload); path.chmod(0o600)
            self.artifacts[key] = hashlib.sha256(payload).hexdigest()
        self.strict_reference = {
            "recipe_id": "owned-strict-data-champion", "dataset_id": "owned-strict-data",
            "data_provenance": "DEMO_ONLY", "feature_schema_version": 4,
            "training_windows": 50000, "calibration_windows": 2000000,
            "from_utc": "2026-04-01T00:00:00Z", "to_utc": "2026-04-15T00:00:00Z",
            "completed_search_fits": 360,
            "manifest_sha256": "f" * 64, "policy_sha256": self.policy.sha256,
            "blocked_holdout_split_sha256": "8" * 64, "selected_model_sha256": model_sha,
            "selected_calibration_sha256": "1" * 64,
            "model_state_sha256": "2" * 64, "model_state_verifier_sha256": "3" * 64,
            "model_state_format": "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1",
            "model_kind": "normal_plus_incident_research", "recipe_version": 1, "recipe_sha256": "9" * 64,
            "strict_proof_sha256": "8" * 64, "selection_sha256": "d" * 64,
            "source_label_manifest_sha256_by_fold": {str(fold): str(fold) * 64 for fold in (1, 2, 3)},
            "fold": 3, "random_state": 42, "zero_fit_recalibrations": 45,
        }
        adoption_directory = self.directory / "operator-adoptions"
        adoption_directory.mkdir(mode=0o700)
        receipt = {
            "format": "UEBA_QUALIFIED_ADOPTION_V1", "status": "CANDIDATE_INSTALLED",
            "model_version": self.version, "data_provenance": "DEMO_ONLY",
            "recipe_id": self.strict_reference["recipe_id"], "original_dataset_id": "owned-strict-data",
            "artifact_sha256": self.artifacts,
            "model_sha256": self.metadata["sha256"], "model_state_sha256": self.metadata["model_state_sha256"],
            "calibration_sha256": self.metadata["calibration_sha256"], "policy_sha256": self.policy.sha256,
            "original_training_manifest_sha256": self.metadata["dataset_manifest_sha256"],
            "fresh_holdout_manifest_sha256": self.identity["fresh_holdout_manifest_sha256"],
            "holdout_split_sha256": self.identity["holdout_split_sha256"],
            "selection_receipt_sha256": self.identity["frozen_selection_receipt_sha256"],
            "strict_reference": self.strict_reference,
            "selection_proof": {"actual_composite_trials": 360, "actual_component_fit_calls": 720,
                "validation_runs": 360, "zero_fit_recalibrations": 45, "holdout_scored": False},
            "primary_before": {"model_version": "prior-primary",
                "model_sha256": hashlib.sha256(primary_bytes).hexdigest()},
        }
        receipt_path = adoption_directory / f"{self.version}.private.json"
        receipt_path.write_text(json.dumps(receipt, sort_keys=True)); receipt_path.chmod(0o600)
        self.receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def call(self):
        with patch.object(main, "store", return_value=self.store), \
             patch("app.frozen_evaluation.model_binding", return_value={"model_version": self.version}), \
             patch("app.quality_proof.verify_quality") as verify:
            result = main.qualified_candidate(self.version)
        verify.assert_called_once_with(self.directory, self.version, unittest.mock.ANY,
                                       {"model_version": self.version})
        return result

    def test_returns_only_verified_provenance_and_keeps_primary_unchanged(self):
        result = self.call()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertEqual(self.metadata["sha256"], result["metadata"]["sha256"])
        self.assertEqual(self.identity, result["evaluation_identity"])
        self.assertEqual("prior-primary", self.store.active_version)
        self.assertNotIn("payload", result)

    def test_rejects_failed_quality_evidence(self):
        self.evaluation["quality_gate"] = "FAIL"
        (self.directory / f"{self.version}.evaluation.json").write_text(json.dumps(self.evaluation))
        (self.directory / f"{self.version}.evaluation.json").chmod(0o600)
        with self.assertRaises(HTTPException) as failure:
            self.call()
        self.assertEqual(409, failure.exception.status_code)

    def test_rejects_symlink_evidence(self):
        path = self.directory / f"{self.version}.evaluation.json"
        path.unlink()
        path.symlink_to(self.directory / f"{self.version}.evaluation-identity.json")
        with self.assertRaises(HTTPException) as failure:
            self.call()
        self.assertEqual(409, failure.exception.status_code)

    def test_registers_idempotent_operator_adoption_without_claiming_training(self):
        request_id = hashlib.sha256(("UEBA_QUALIFIED_ADOPTION_V1:" + self.receipt_sha).encode()).hexdigest()[:32]
        request = main.QualifiedAdoptionRequest(model_version=self.version,
            adoption_receipt_sha256=self.receipt_sha, request_id=request_id)
        with patch.object(main, "store", return_value=self.store), \
             patch("app.quality_proof.verify_quality"):
            first = main.register_qualified_adoption(request)
            second = main.register_qualified_adoption(request)
        self.assertEqual(first, second)
        self.assertEqual({"job_id": request_id, "status": "SUCCEEDED", "model_version": self.version}, first)
        job = json.loads((self.directory / "jobs" / f"{request_id}.json").read_text())
        self.assertEqual("QUALIFIED_ADOPTION", job["kind"])
        self.assertEqual(self.receipt_sha, job["adoption_receipt_sha256"])
        self.assertEqual("prior-primary", self.store.active_version)

    def test_adoption_request_id_is_derived_from_the_receipt(self):
        request = main.QualifiedAdoptionRequest(model_version=self.version,
            adoption_receipt_sha256=self.receipt_sha, request_id="0" * 32)
        with patch.object(main, "store", return_value=self.store), \
             patch("app.quality_proof.verify_quality"):
            with self.assertRaises(HTTPException) as failure:
                main.register_qualified_adoption(request)
        self.assertEqual(409, failure.exception.status_code)


if __name__ == "__main__":
    unittest.main()
