"""Protected labeled-training contract fixtures, never measured model quality."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from app.contract import FEATURE_NAMES_V4
from app.hybrid_dataset import (CLASS_TARGETS, CLASS_TARGET_NAMES, PILOT_SHA, private_read, training_targets,
                                validate_training_rows, load_hybrid_fit, value_sha)
from app.policy import canonical


def private_fixture_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(canonical(value))


def fixture_rows():
    rows = []
    families = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
    for family, populations in [("normal", (("READY", 2100), ("UNSEEN_READY", 600), ("COLD", 300))),
                                *[(family, (("READY", 140), ("UNSEEN_READY", 40), ("COLD", 20))) for family in families]]:
        for cohort, count in populations:
            for _ in range(count):
                index = len(rows)
                rows.append({"frame_id": f"fixture-frame-{index:06d}", "account_id": f"fixture-acct-{index:06d}",
                             "window_start": "2026-04-15T00:00:00Z", "label": int(family != "normal"),
                             "family": family, "cohort": cohort, "baseline_established": cohort != "COLD",
                             "trusted_window_count": 3 if cohort == "COLD" else 48, "features": [0.0] * len(FEATURE_NAMES_V4)})
    return rows


class HybridDatasetTest(unittest.TestCase):
    def test_explicit_security_and_operational_targets_never_depend_on_feature_values(self):
        rows = [{"label": int(family != "normal"), "family": family, "features": [999]} for family in CLASS_TARGETS]
        self.assertEqual(training_targets(rows), [0, 1, 1, 1, 1, 2])
        for row in rows:
            row["features"] = [0]
        self.assertEqual(training_targets(rows), [0, 1, 1, 1, 1, 2])
        with self.assertRaises(ValueError):
            training_targets([{"label": 0, "family": "http_error_burst"}])

    def test_exact_complete_class_family_cohort_population_and_time(self):
        stats = validate_training_rows(fixture_rows())
        self.assertEqual((stats["records"], stats["normal"], stats["positive"]), (4000, 3000, 1000))
        self.assertEqual(stats["cohorts"], {"COLD": 400, "READY": 2800, "UNSEEN_READY": 800})

    def test_duplicate_temporal_and_cohort_tampering_refused(self):
        for mutation in ("duplicate", "time", "cohort", "family"):
            rows = fixture_rows()
            if mutation == "duplicate":
                rows[1] = deepcopy(rows[0])
            elif mutation == "time":
                rows[0]["window_start"] = "2026-05-03T00:00:00Z"
            elif mutation == "cohort":
                rows[0]["cohort"] = "UNSEEN_READY"
            else:
                rows[3000]["family"] = "http_error_burst"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_training_rows(rows)

    def test_reader_refuses_validation_holdout_and_path_escape_before_io(self):
        for relative in ("holdout.json", "shards/fold1-validation-000000.json", "../manifest.private.json", "/tmp/private.json"):
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "only open"):
                private_read(Path("/nonexistent-fixture"), relative, 1)

    def test_reader_requires_protected_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            path.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "must be private"):
                load_hybrid_fit(path)

    def test_fifo_symlink_and_oversize_refused_without_blocking_or_following(self):
        for kind in ("fifo", "symlink", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "manifest.private.json"
                if kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind == "symlink":
                    target = root / "target.json"
                    private_fixture_write(target, {})
                    path.symlink_to(target)
                else:
                    private_fixture_write(path, {"too_large": "fixture"})
                with self.assertRaises(ValueError):
                    private_read(root, "manifest.private.json", 1)

    def test_malformed_manifest_and_nested_descriptors_raise_value_error(self):
        minimal = {"hybrid_training_schema_version": 1, "stage": "PILOT", "data_provenance": "DEMO_ONLY",
                   "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                   "class_targets": CLASS_TARGETS, "class_target_names": CLASS_TARGET_NAMES,
                   "confirmed_attack_target_available": False, "quality_gate": "NOT_APPLICABLE", "fit_or_score_calls": 0,
                   "dataset_id": "fixture-hybrid-training", "shared_normal_component_source": {
                       "manifest_sha256": PILOT_SHA, "split": "fold1-fit", "rows": 2000,
                       "normal_ready_only": True, "reuse_across_training_components_permitted": True},
                   "frozen_score_only_dataset": {"manifest_sha256": PILOT_SHA, "calibration_start": "2026-05-03T00:00:00Z",
                                                "validation_start": "2026-05-21T00:00:00Z", "fit_use": False},
                   "holdout_numeric_records_read": 0, "source_identity_before": {}, "source_identity_after": {},
                   "unseen_validation_accounts_disjoint_from_all_training": True,
                   "temporal_isolation": {"strictly_exceeds_14_day_history_gap": True}}
        for kind in ("manifest", "source", "declaration", "temporal", "split", "shard", "boolean_schema", "boolean_count"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, manifest = Path(directory), deepcopy(minimal)
                declaration = {"events_generated_before_declaration": 0, "new_labels_generated_before_declaration": 0,
                               "source_identity": {}}
                if kind == "declaration":
                    declaration = []
                private_fixture_write(root / "predeclared.private.json", declaration)
                manifest["predeclared_identity_sha256"] = hashlib.sha256(canonical(declaration).encode()).hexdigest()
                if kind == "manifest":
                    manifest = []
                elif kind == "source":
                    manifest["shared_normal_component_source"] = []
                elif kind == "temporal":
                    manifest["temporal_isolation"] = []
                elif kind == "split":
                    manifest["split"] = []
                elif kind == "shard":
                    split = {"name": "incident-training", "records": 4000, "normal": 3000, "positive": 1000, "shards": [None]}
                    split["sha256"] = value_sha(split)
                    manifest["split"] = split
                elif kind == "boolean_schema":
                    manifest["hybrid_training_schema_version"] = True
                elif kind == "boolean_count":
                    manifest["fit_or_score_calls"] = False
                private_fixture_write(root / "manifest.private.json", manifest)
                with self.assertRaises(ValueError):
                    load_hybrid_fit(root)


if __name__ == "__main__":
    unittest.main()
