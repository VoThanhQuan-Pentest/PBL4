"""Small validation-only fixtures for collision evidence, never quality claims."""

from collections import Counter
import hashlib
from itertools import combinations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_NAMES_V2
from app.policy import canonical
from app.validation_collisions import collision_split, diagnose, oracle_bound
from test_catalog import row


def fixture(root, shard_rows, *, include_unread_holdout=True):
    (root / "shards").mkdir()
    descriptors = []
    stats = Counter()
    families = Counter()
    cohorts = Counter()
    for number, rows in enumerate(shard_rows):
        identity = f"fold1-validation-{number:06d}"
        data = canonical(rows).encode()
        (root / f"shards/{identity}.json").write_bytes(data)
        observed = validate_rows(rows)
        descriptors.append({"id": identity, "path": f"shards/{identity}.json",
                            "sha256": hashlib.sha256(data).hexdigest(), **observed})
        stats.update({key: observed[key] for key in ("records", "normal", "positive")})
        families.update(observed["families"])
        cohorts.update(observed["cohorts"])
    split = {**dict(stats), "families": dict(sorted(families.items())), "cohorts": dict(sorted(cohorts.items())),
             "from": min(part["from"] for part in descriptors), "to": max(part["to"] for part in descriptors),
             "shards": descriptors}
    split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest()
    splits = {"fold1-validation": split}
    if include_unread_holdout:
        holdout = {**descriptors[0], "id": "holdout-unread-000000", "path": "shards/holdout-unread-000000.json"}
        # Deliberately no numeric holdout file. The descriptor is sufficient.
        unread = {key: value for key, value in holdout.items() if key not in ("id", "path", "sha256")}
        unread["shards"] = [holdout]
        unread["sha256"] = hashlib.sha256(canonical(unread).encode()).hexdigest()
        splits["holdout"] = unread
    document = {"catalog_schema_version": 2, "dataset_id": "collision-fixture-v2b", "stage": "PILOT",
                "feature_schema_version": 2, "telemetry_contract_version": 2,
                "feature_names": list(FEATURE_NAMES_V2), "data_provenance": "DEMO_ONLY", "splits": splits}
    (root / "manifest.json").write_text(canonical(document))
    return ShardedDataset(root)


def positive(index, *, cold=False, cohort=None):
    value = row(index, cold)
    value.update(label=1, family="auth_failure_burst")
    if cohort:
        value["cohort"] = cohort
    return value


class OracleMathTest(unittest.TestCase):
    def test_exact_cost_knapsack_does_not_split_an_input_key(self):
        result = oracle_bound([(990, 0), (10, 3)], 1000)
        self.assertEqual(result["necessary_fp_budget_from_total_positives"], 2)
        self.assertEqual(result["precision_feasible_max_tp"], 990)
        self.assertFalse(result["global_recall_strictly_above_99_percent_necessary_condition"])

    def test_total_positive_fp_budget_is_not_its_own_precision_proof(self):
        result = oracle_bound([(1, 0), (498, 2), (501, 3)], 1000)
        self.assertEqual(result["optimistic_relaxed_max_tp"], 499)
        self.assertFalse(result["relaxed_max_satisfies_its_own_precision"])
        self.assertEqual(result["precision_feasible_max_tp"], 1)
        self.assertEqual(result["precision_feasible_min_fp_at_max_tp"], 0)

    def test_exact_integer_precision_boundary_and_empty_subset(self):
        boundary = oracle_bound([(998, 2), (2, 3)], 1000)
        self.assertEqual(boundary["precision_at_feasible_max"], 0.998)
        self.assertEqual(boundary["precision_feasible_max_tp"], 998)
        empty = oracle_bound([(499, 2)], 499)
        self.assertFalse(empty["any_nonempty_precision_feasible_subset"])
        self.assertIsNone(empty["precision_at_feasible_max"])
        self.assertEqual(empty["precision_feasible_max_recall"], 0)

    def test_dp_matches_exhaustive_label_aware_subsets(self):
        groups = [(300, 0), (200, 1), (499, 1), (1, 2)]
        actual = oracle_bound(groups, 1000)
        feasible = []
        relaxed = []
        for size in range(len(groups) + 1):
            for subset in combinations(groups, size):
                tp = sum(p for p, _ in subset)
                fp = sum(n for _, n in subset)
                if fp <= 2:
                    relaxed.append(tp)
                if tp and tp >= 499 * fp:
                    feasible.append(tp)
        self.assertEqual(actual["optimistic_relaxed_max_tp"], max(relaxed))
        self.assertEqual(actual["precision_feasible_max_tp"], max(feasible))

    def test_invalid_or_unbounded_groups_are_rejected(self):
        for groups, population in (([(1, 0)], 1001), ([(1, 0)], 2), ([(True, 0)], 1), ([(1, -1)], 1), ([], 1)):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                oracle_bound(groups, population)


class ValidationCollisionTest(unittest.TestCase):
    def test_input_cost_equal_to_global_fp_budget_is_not_forced_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            normals = [row(index + 1, cold=True) for index in range(2)]
            positives = [positive(index + 3, cold=True) for index in range(1000)]
            dataset = fixture(Path(directory), [normals, positives])
            for summary in collision_split(dataset, "fold1-validation")["representations"].values():
                bounds = summary["slice_necessary_conditions"]
                self.assertEqual(bounds["necessary_global_fp_budget"], 2)
                self.assertEqual(bounds["forced_missed_positive_rows"], 0)
                self.assertEqual(bounds["by_actual_cohort"]["COLD"]["recall_upper_bound"], 1)
                self.assertFalse(bounds["any_observed_slice_provably_fails_strict_recall_requirement"])
                self.assertEqual(summary["oracle"]["precision_feasible_max_tp"], 1000)
                self.assertEqual(summary["oracle"]["precision_feasible_min_fp_at_max_tp"], 2)

    def test_forced_exclusions_verify_all_positive_slice_populations_and_strict_gate_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            normals = [row(index + 1, cold=True) for index in range(3)]
            positives = []
            for index in range(1000):
                anomaly = positive(index + 4, cold=index < 100)
                anomaly["family"] = "request_burst" if index < 200 else "auth_failure_burst"
                if index >= 2:
                    # Only the first two COLD request-burst inputs collide.
                    requests = index + 3
                    anomaly["features"][0] = requests
                if index >= 800:
                    anomaly["cohort"] = "UNSEEN_READY"
                positives.append(anomaly)
            dataset = fixture(Path(directory), [normals, positives])
            evidence = collision_split(dataset, "fold1-validation")
            self.assertEqual(evidence["actual_population_verified"]["positive_by_actual_cohort"],
                             {"COLD": 100, "READY": 700, "UNSEEN_READY": 200})
            for summary in evidence["representations"].values():
                bounds = summary["slice_necessary_conditions"]
                self.assertEqual(bounds["necessary_global_fp_budget"], 2)
                self.assertEqual(bounds["forced_excluded_input_keys"], 1)
                self.assertEqual(bounds["forced_missed_positive_rows"], 2)
                self.assertEqual(summary["positive_population_by_family"],
                                 {"auth_failure_burst": 800, "request_burst": 200})
                for dimension in ("by_family", "by_actual_cohort"):
                    self.assertEqual(sum(value["positive_samples"] for value in bounds[dimension].values()), 1000)
                    self.assertEqual(sum(value["forced_missed_positives"] for value in bounds[dimension].values()), 2)
                cold = bounds["by_actual_cohort"]["COLD"]
                burst = bounds["by_family"]["request_burst"]
                self.assertEqual(cold["positive_samples"], 100)
                self.assertEqual(cold["recall_upper_bound"], 0.98)
                self.assertEqual(burst["positive_samples"], 200)
                self.assertEqual(burst["recall_upper_bound"], 0.99)
                self.assertFalse(cold["strict_recall_above_99_percent_necessary_condition"])
                self.assertFalse(burst["strict_recall_above_99_percent_necessary_condition"])
                self.assertTrue(bounds["by_actual_cohort"]["READY"]["strict_recall_above_99_percent_necessary_condition"])
                self.assertTrue(bounds["any_observed_slice_provably_fails_strict_recall_requirement"])

    def test_two_pass_reads_only_positive_descriptors_then_proves_all_actual_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = fixture(root, [[row(1), row(2)], [positive(3)]])
            with patch.object(dataset, "load_shard", wraps=dataset.load_shard) as load:
                evidence = collision_split(dataset, "fold1-validation")
            self.assertEqual([call.args for call in load.call_args_list],
                             [("fold1-validation", 1), ("fold1-validation", 0), ("fold1-validation", 1)])
            self.assertEqual(evidence["actual_population_verified"]["records"], 3)
            self.assertEqual(evidence["actual_population_verified"]["normal"], 2)
            self.assertEqual(evidence["pass1"]["numeric_records_read"], 1)
            for representation in evidence["representations"].values():
                self.assertEqual(representation["mixed_label_input_keys"], 1)
                self.assertEqual(representation["normal_rows_in_mixed_keys"], 2)
                self.assertEqual(representation["oracle"]["precision_feasible_max_tp"], 0)

    def test_float32_conversion_merges_inputs_that_float64_distinguishes(self):
        with tempfile.TemporaryDirectory() as directory:
            normal = row(1)
            normal["features"][11] = 1.0
            anomaly = positive(2)
            anomaly["features"][11] = 1.0 + 2 ** -25
            self.assertEqual(np.float32(normal["features"][11]), np.float32(anomaly["features"][11]))
            dataset = fixture(Path(directory), [[normal], [anomaly]])
            evidence = collision_split(dataset, "fold1-validation")["representations"]
            self.assertEqual(evidence["float64"]["mixed_label_input_keys"], 0)
            self.assertEqual(evidence["float64"]["oracle"]["precision_feasible_max_tp"], 1)
            self.assertEqual(evidence["float32"]["mixed_label_input_keys"], 1)
            self.assertEqual(evidence["float32"]["oracle"]["precision_feasible_max_tp"], 0)

    def test_ready_and_unseen_share_input_keys_but_cold_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = fixture(Path(directory), [[row(1)], [positive(2, cohort="UNSEEN_READY"), positive(3, cold=True)]])
            result = collision_split(dataset, "fold1-validation")["representations"]["float32"]
            self.assertEqual(result["positive_input_keys"], 2)
            self.assertEqual(result["positive_rows_in_mixed_keys"], 1)
            self.assertEqual(result["collision_positive_rows_by_actual_cohort"], {"UNSEEN_READY": 1})
            self.assertEqual(result["oracle"]["precision_feasible_max_tp"], 1)

    def test_signed_zero_does_not_invent_a_distinguishable_tree_input(self):
        with tempfile.TemporaryDirectory() as directory:
            anomaly = positive(2)
            anomaly["features"][11] = -0.0
            dataset = fixture(Path(directory), [[row(1)], [anomaly]])
            for result in collision_split(dataset, "fold1-validation")["representations"].values():
                self.assertEqual(result["mixed_label_input_keys"], 1)

    def test_holdout_and_fit_names_rejected_before_any_numeric_read(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = fixture(Path(directory), [[row(1)], [positive(2)]])
            with patch.object(dataset, "load_shard", side_effect=AssertionError("numeric read not allowed")):
                for name in ("holdout", "fold1-fit", "fold1-calibration-ready", "fold4-validation"):
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, "only fold"):
                        collision_split(dataset, name)

    def test_second_pass_cannot_accept_tampered_normal_shard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = fixture(root, [[row(1)], [positive(2)]])
            (root / "shards/fold1-validation-000000.json").write_text(canonical([row(99)]))
            with self.assertRaisesRegex(ValueError, "checksum"):
                collision_split(dataset, "fold1-validation")

    def test_schema_does_not_emit_ids_vectors_or_promote_quality(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = fixture(Path(directory), [[row(1)], [positive(2)]])
            evidence = diagnose(dataset, ["fold1-validation"])
            self.assertEqual(evidence["quality_gate"], "NOT_APPLICABLE")
            self.assertEqual(evidence["conclusion_scope"], "NECESSARY_CONDITION_ONLY")
            self.assertEqual(evidence["boundaries"]["numeric_holdout_records_read"], 0)
            encoded = canonical(evidence)
            self.assertNotIn("catalogue-test-account", encoded)
            self.assertNotIn("catalogue-test-frame", encoded)
            self.assertNotIn('"features":', encoded)
            self.assertNotIn("holdout-unread", encoded)
            self.assertEqual(len(evidence["source_binding_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
