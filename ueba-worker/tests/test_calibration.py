"""Small real-forest fixtures exercise streamed calibration; not a quality benchmark."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import IsolationForest

from app.calibration import numeric_cache, recalibrate
from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_SCHEMAS
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from test_catalog import row


def fixture(root, *, schema=2):
    (root / "shards").mkdir()
    splits = {}
    populations = (("fold1-fit", 600, "2026-01-01T00:00:00Z", False),
                   ("fold1-calibration-ready", 300, "2026-02-01T00:00:00Z", False),
                   ("fold1-calibration-cold", 300, "2026-02-01T00:00:00Z", True))
    for name, population, at, cold in populations:
        records, descriptors = [], []
        for index in range(population):
            value = row(index + 1, cold)
            value["frame_id"] = f"{name}-frame-{index:06d}"
            value["account_id"] = f"{'cold' if cold else 'mature'}-fixture-account-{index:06d}"
            value["window_start"] = at
            requests = 4 + index % 7; errors = int(index % 13 == 0)
            value["features"] = [requests, errors, 0, 0, int(index % 11 == 0), 0, 1 + index % 3, 1, 0, 0, 0,
                                 0 if cold else (index % 7 - 3) / 4, 0, errors / requests, 0]
            if schema == 3:
                transitions = index % 3
                value["features"].extend([requests, 1, 0, transitions, transitions / (requests - 1), 0, 0, 0, 0, errors])
            records.append(value)
        for number, start in enumerate(range(0, population, 150)):
            rows = records[start:start + 150]; data = canonical(rows).encode()
            identity = f"{name}-{number:06d}"; relative = f"shards/{identity}.json"
            (root / relative).write_bytes(data)
            descriptors.append({"id": identity, "path": relative, "sha256": hashlib.sha256(data).hexdigest(), **validate_rows(rows, schema)})
        split = {**validate_rows(records, schema), "shards": descriptors}
        split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest(); splits[name] = split
    manifest = {"catalog_schema_version": 2, "dataset_id": "calibration-owned-fixture", "stage": "PILOT",
                "feature_schema_version": schema, "telemetry_contract_version": 2, "feature_names": list(FEATURE_SCHEMAS[schema]),
                "data_provenance": "DEMO_ONLY", "splits": splits}
    (root / "manifest.json").write_text(canonical(manifest))
    return ShardedDataset(root)


def fitted(store, dataset):
    samples = [row["features"] for _, rows in dataset.iter_shards("fold1-fit") for row in rows]
    schema = dataset.manifest["feature_schema_version"]
    metadata = store.train("source_fitted_fixture", samples, samples[:120], schema_version=schema, policy=ScorePolicy.strict(schema=schema))
    metadata.update(dataset_manifest_sha256=dataset.sha256, fit_split_sha256=dataset.split("fold1-fit")["sha256"])
    (store.directory / "source_fitted_fixture.json").write_text(canonical(metadata))
    return metadata


class CalibrationTest(unittest.TestCase):
    def environment(self, directory):
        root = Path(directory); data = root / "data"; data.mkdir()
        dataset = fixture(data); store = ModelStore(root / "models"); metadata = fitted(store, dataset)
        return root, dataset, store, metadata

    def test_recalibration_reuses_forest_and_two_actual_cohorts_without_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, source = self.environment(directory)
            with patch.object(IsolationForest, "fit", side_effect=AssertionError("recalibration must not fit")):
                first = recalibrate(store, dataset, 1, "source_fitted_fixture", "recalibrated_fixture_a", ScorePolicy.strict(), root / "cache")
                second = recalibrate(store, dataset, 1, "source_fitted_fixture", "recalibrated_fixture_b",
                                     ScorePolicy.strict(99_999_000), root / "cache")
                recovered = recalibrate(store, dataset, 1, "source_fitted_fixture", "recalibrated_fixture_a", ScorePolicy.strict(), root / "cache")
            self.assertEqual(first["additional_fit_calls"], 0)
            self.assertTrue(recovered["publication_recovered"])
            self.assertEqual(recovered["metadata"], first["metadata"])
            self.assertEqual(first["metadata"]["source_model_sha256"], source["sha256"])
            self.assertEqual(first["metadata"]["calibration_scope"], "PILOT_ONLY")
            self.assertEqual(first["metadata"]["calibration_cohort_windows"], {"READY": 300, "COLD": 300})
            self.assertNotEqual(first["metadata"]["score_policy"]["policy_sha256"], second["metadata"]["score_policy"]["policy_sha256"])
            for cohort in ("READY", "COLD"):
                self.assertEqual(first["calibration_receipts"][cohort]["computed_shards"], 2)
                self.assertEqual(second["calibration_receipts"][cohort]["computed_shards"], 0)
                self.assertEqual(second["calibration_receipts"][cohort]["reused_shards"], 2)
            self.assertIsNone(store.active_version)
            self.assertFalse((store.directory / "active.json").exists())
            self.assertEqual((store.directory / "recalibrated_fixture_a.joblib").stat().st_mode & 0o777, 0o600)
            _, payload = store.load_candidate("recalibrated_fixture_a")
            self.assertEqual(set(payload["calibration_by_cohort"]), {"READY", "COLD"})
            mature = next(dataset.iter_shards("fold1-calibration-ready"))[1][0]["features"]
            cold = next(dataset.iter_shards("fold1-calibration-cold"))[1][0]["features"]
            scores = store.score_candidate("recalibrated_fixture_a", [mature, cold], 2, ["READY", "COLD"])
            self.assertEqual([result["model_scope"] for result in scores["results"]], ["PERSONAL", "GLOBAL_PROXY"])

    def test_interrupted_cache_resumes_committed_shards_not_the_forest_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, _ = self.environment(directory)
            def interrupt(value):
                if value["scored_records"] == 150: raise RuntimeError("owned simulated interruption")
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                recalibrate(store, dataset, 1, "source_fitted_fixture", "interrupted_candidate", ScorePolicy.strict(), root / "cache", progress=interrupt)
            self.assertFalse((store.directory / "interrupted_candidate.joblib").exists())
            result = recalibrate(store, dataset, 1, "source_fitted_fixture", "resumed_candidate", ScorePolicy.strict(), root / "cache")
            self.assertEqual(result["calibration_receipts"]["READY"]["reused_shards"], 1)
            self.assertEqual(result["calibration_receipts"]["READY"]["computed_shards"], 1)

    def test_cached_raw_score_tampering_is_not_a_successful_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, _ = self.environment(directory)
            recalibrate(store, dataset, 1, "source_fitted_fixture", "before_tampering", ScorePolicy.strict(), root / "cache")
            raw = next((root / "cache").glob("scores-*/raw.f64"))
            with raw.open("r+b") as stream: stream.write(np.array([42.0], dtype="<f8").tobytes())
            with self.assertRaisesRegex(ValueError, "checkpoint/bytes changed"):
                recalibrate(store, dataset, 1, "source_fitted_fixture", "after_tampering", ScorePolicy.strict(), root / "cache")
            self.assertFalse((store.directory / "after_tampering.joblib").exists())

    def test_validated_tensor_preserves_input_order_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, _ = self.environment(directory)
            path = numeric_cache(dataset, "fold1-calibration-ready", root / "cache")
            matrix = np.memmap(path, dtype="<f8", mode="r", shape=(300, 15))
            expected = [row["features"] for _, rows in dataset.iter_shards("fold1-calibration-ready") for row in rows]
            self.assertTrue(np.array_equal(matrix, expected)); matrix._mmap.close()
            self.assertEqual(numeric_cache(dataset, "fold1-calibration-ready", root / "cache"), path)
            with path.open("r+b") as stream: stream.write(np.array([42.0], dtype="<f8").tobytes())
            with self.assertRaisesRegex(ValueError, "tensor/source checkpoint changed"):
                numeric_cache(dataset, "fold1-calibration-ready", root / "cache")

    def test_pilot_cannot_activate_even_with_pass_markers_or_a_forged_strict_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, _ = self.environment(directory)
            result = recalibrate(store, dataset, 1, "source_fitted_fixture", "pilot_cannot_activate", ScorePolicy.strict(), root / "cache")
            metadata = result["metadata"]
            forged = {"quality_gate": "PASS", "evaluation_scope": "FROZEN_HOLDOUT", "model_sha256": metadata["sha256"],
                      "calibration_sha256": metadata["calibration_sha256"], "dataset_sha256": dataset.sha256,
                      "policy_sha256": metadata["score_policy"]["policy_sha256"],
                      "scopes": {scope: {"quality_gate": "PASS", "policy_sha256": metadata["score_policy"]["policy_sha256"]}
                                 for scope in ("MODEL_ONLY", "SIEM_FINAL")}}
            (store.directory / "pilot_cannot_activate.evaluation.json").write_text(canonical(forged))
            with self.assertRaisesRegex(ValueError, "independent cohort calibration"):
                store.activate("pilot_cannot_activate")
            metadata["calibration_scope"] = "STRICT"
            (store.directory / "pilot_cannot_activate.json").write_text(canonical(metadata))
            with self.assertRaisesRegex(ValueError, "independent cohort calibration"):
                store.activate("pilot_cannot_activate")
            selection = {"model_version": "pilot_cannot_activate", "model_sha256": metadata["sha256"], "feature_schema_version": 2,
                         "calibration_sha256": metadata["calibration_sha256"], "policy_sha256": metadata["score_policy"]["policy_sha256"],
                         "dataset_sha256": dataset.sha256}
            (store.directory / "active.json").write_text(canonical(selection))
            self.assertIsNone(ModelStore(store.directory).active_version)

    def test_strict_population_and_foreign_fit_bindings_fail_before_scoring(self):
        with tempfile.TemporaryDirectory() as directory:
            root, dataset, store, _ = self.environment(directory)
            original = dataset.sha256
            dataset.sha256 = "0" * 64
            with self.assertRaisesRegex(ValueError, "does not belong"):
                recalibrate(store, dataset, 1, "source_fitted_fixture", "foreign_candidate", ScorePolicy.strict(), root / "cache")
            dataset.sha256 = original; dataset.manifest["stage"] = "STRICT"
            with self.assertRaisesRegex(ValueError, "population"):
                recalibrate(store, dataset, 1, "source_fitted_fixture", "small_strict_candidate", ScorePolicy.strict(), root / "cache")
            self.assertEqual(list((root / "cache").glob("scores-*")), [])


if __name__ == "__main__": unittest.main()
