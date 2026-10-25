"""Bounded reconstruction/counterexample contract fixtures, never quality proof."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from app.collision_replay import ValidationOnlyDataset, bounds, collision_rows, extract, input_key, input_keys, load_generator, original_sequence


def row(index, label=0, schema=3):
    base = [2,0,0,0,0,0,1,1,0,0,0,0,0,0,0]
    return {"frame_id": f"owned-collision-frame-{index:04d}", "account_id": f"owned-collision-account-{index:04d}",
            "window_start": "2026-04-01T00:00:00Z", "label": label, "family": "request_burst" if label else "normal",
            "cohort": "COLD", "baseline_established": False, "trusted_window_count": 3,
            "features": base + ([2,0,0,0,0,0,0,0,0,0] if schema == 3 else [])}


def population():
    return {"positive": 1000, "positive_by_family": dict.fromkeys(
        ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst"), 200),
        "positive_by_cohort": {"READY": 700, "UNSEEN_READY": 200, "COLD": 100}}


class CollisionReplayTest(unittest.TestCase):
    def test_actual_serving_float32_key_normalizes_signed_zero_and_ready_bucket(self):
        original = row(1); other = deepcopy(original); other["features"][20] = -0.0
        self.assertEqual(input_key(original, 3), input_key(other, 3))
        original["cohort"] = "READY"; other["cohort"] = "UNSEEN_READY"
        self.assertEqual(input_key(original, 3), input_key(other, 3))
        self.assertEqual(input_keys([original, other], 3), [input_key(original, 3), input_key(other, 3)])
        other["cohort"] = "COLD"; self.assertNotEqual(input_key(original, 3), input_key(other, 3))

    def test_one_forced_cold_miss_invalidates_slice_gate_but_is_not_model_accuracy(self):
        result = bounds([row(0, 1), row(1), row(2), row(3)], population())
        self.assertEqual(result["schema_3_mixed_input_keys"], 1)
        self.assertEqual(result["necessary_global_fp_budget"], 2)
        self.assertEqual(result["by_cohort"]["COLD"]["optimistic_recall_upper_bound"], 0.99)
        self.assertTrue(result["any_slice_provably_cannot_meet_strict_recall"])
        self.assertNotIn("accuracy", result); self.assertNotIn("precision", result)

    def test_cost_at_relaxed_budget_is_not_a_forced_miss_and_distinct_timing_can_split_keys(self):
        rows = [row(0, 1), row(1), row(2)]
        self.assertFalse(bounds(rows, population())["any_slice_provably_cannot_meet_strict_recall"])
        rows[0]["features"][15:17] = [1, 10]
        result = bounds(rows, population())
        self.assertEqual(result["schema_3_mixed_input_keys"], 0)
        self.assertEqual(result["by_cohort"]["COLD"]["forced_missed_positives"], 0)

    def test_duplicate_frames_or_forged_population_cannot_relax_fp_budget(self):
        with self.assertRaises(ValueError): bounds([row(1), row(1, 1)], population())
        value = population(); value["positive"] = 2000
        with self.assertRaises(ValueError): bounds([row(1)], value)

    def test_original_account_balancing_preserves_all_positive_indices(self):
        for cohort in ("READY", "COLD"):
            part = SimpleNamespace(normal=100, positive=10, days=2, cohort=cohort)
            maximum = 20 if cohort == "COLD" else 24
            accounts = -(-110 // maximum)
            sequences = [original_sequence(part, account) for account in range(accounts)]
            self.assertEqual(sum(map(len, sequences)), 110)
            self.assertEqual([value for values in sequences for value in values if value is not None], list(range(10)))
            with self.assertRaises(ValueError): original_sequence(part, accounts)

    def test_holdout_rejected_before_any_numeric_read(self):
        dataset = SimpleNamespace(manifest={"feature_schema_version": 2}, split=lambda name: self.fail("must not read numeric holdout"))
        with self.assertRaisesRegex(ValueError, "validation"): collision_rows(dataset, "holdout")

    def test_filesystem_boundary_refuses_nonvalidation_paths_even_when_called_directly(self):
        dataset = object.__new__(ValidationOnlyDataset)
        for path in ("shards/holdout-000000.json", "shards/fold1-fit-000000.json", "../private/token", "strict-models/model.joblib"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "limited to validation"):
                dataset._read(path, 1024)

    def test_generator_mismatch_fails_before_importing_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "generator-original.py").write_text("raise AssertionError('must not execute mismatched code')\n")
            dataset = SimpleNamespace(root=root, manifest={"source_sha256": {"observability/scripts/prepare-ueba-strict.py": "0" * 64}})
            with self.assertRaisesRegex(ValueError, "checksum"): load_generator(dataset)

    def test_replay_parser_requires_actual_schema_prefix_history_and_complete_conservation(self):
        original = row(1, 1, 2)
        actual = {**row(1, 1), "feature_schema_version": 3, "telemetry_contract_version": 2, "data_provenance": "DEMO_ONLY"}
        def invoke(value):
            with tempfile.TemporaryDirectory() as directory, patch("app.collision_replay.subprocess.run",
                    return_value=SimpleNamespace(stdout=(json.dumps(value) + "\n").encode())):
                return extract([{}], [original], "owned-fixture-classpath", Path(directory) / "java.log")
        self.assertEqual(invoke(actual)[0]["features"], actual["features"])
        for fault in ("trusted_window_count", "label", "feature_schema_version", "features"):
            changed = deepcopy(actual)
            if fault == "features": changed[fault][0] = 3
            else: changed[fault] = 999
            with self.subTest(fault=fault), self.assertRaises(ValueError): invoke(changed)


if __name__ == "__main__": unittest.main()
