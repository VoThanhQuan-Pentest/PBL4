"""Scored-array/unit fixtures test selection math; they are not ML accuracy evidence."""

from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import numpy as np

from app.catalog import ShardedDataset, validate_rows
from app.contract import campaign_runs
from app.policy import ScorePolicy, canonical
from app.risk_replay import JavaRiskReplay
from app.model import ModelStore
from app.selection import choose, validate_all
from app.strict_campaign import fit_one
from app.strict_metrics import Confusion
from app.validation import java_rules, midrank, rank_configurations, sweep, validate_candidate
from test_catalog import row
from test_calibration import fixture

ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", Path(__file__).resolve().parents[2]))


def arrays():
    labels = np.array(([0] * 100 + [1] * 5) * 3, dtype="u1")
    families = np.array(([0] * 100 + list(range(1, 6))) * 3, dtype="u1")
    cohorts = np.repeat(np.arange(3, dtype="u1"), 105)
    percentiles = np.where(labels == 1, 100.0, 50.0)
    return percentiles, labels, families, cohorts, np.zeros((315, 3), dtype=bool)


class ValidationMathTest(unittest.TestCase):
    def test_midrank_ties_match_serving_and_are_not_invented_extra_nines(self):
        calibration = np.array([0.5] * 100)
        self.assertEqual(midrank(calibration, np.array([0.5, 0.6])).tolist(), [50.0, 100.0])

    def test_complete_grid_has_distinct_model_and_final_alert_counters(self):
        data = arrays(); data[4][0, 0] = True
        grid = sweep(*data)
        self.assertEqual(len(grid), 192)
        self.assertEqual(len({case["policy"]["policy_sha256"] for case in grid}), 192)
        self.assertTrue(all(case["quality_gate"] == "NOT_APPLICABLE" for case in grid))
        case = next(case for case in grid if ScorePolicy.from_wire(case["policy"]).document["risk"]["rule_risk_threshold"] == 45)
        self.assertEqual(case["scopes"]["MODEL_ONLY"]["fp"], 0)
        self.assertEqual(case["scopes"]["SIEM_FINAL"]["fp"], 1)
        self.assertFalse(case["point_qualified_for_selection"])
        self.assertEqual(sum(group["positive_samples"] for group in case["scopes"]["MODEL_ONLY"]["families"].values()), 15)

    def test_missing_data_wrong_labels_or_nonboolean_rules_are_not_dropped(self):
        for index, invalid in ((0, np.array([float("nan")] * 315)), (1, np.array([2] * 315)),
                               (3, np.array([7] * 315)), (4, np.zeros((315, 3), dtype="u1"))):
            data = list(arrays()); data[index] = invalid
            with self.assertRaises(ValueError): sweep(*data)

    def test_pilot_cannot_become_the_full_validation_or_frozen_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            with self.assertRaisesRegex(ValueError, "pilot"):
                choose(root, ROOT)
            with self.assertRaisesRegex(ValueError, "pilot"):
                validate_all(root, ROOT)

    def test_all_seed_fold_receipts_are_required_and_one_bad_seed_cannot_hide(self):
        grid = sweep(*arrays())
        receipts = [{"fold": run["fold"], "config": run["config"].parameters(), "policies": grid} for run in campaign_runs()]
        self.assertEqual(rank_configurations(receipts)["status"], "RANKED")
        with self.assertRaisesRegex(ValueError, "360"): rank_configurations(receipts[:-1])
        changed = list(receipts); changed[0] = deepcopy(receipts[0])
        first_configuration = (changed[0]["config"]["n_estimators"], changed[0]["config"]["max_samples"], changed[0]["config"]["max_features"])
        for case in changed[0]["policies"]:
            result = case["scopes"]["MODEL_ONLY"]
            for group in (result, *result["families"].values(), *result["cohorts"].values()):
                group.update(Confusion(0, group["tp"] + group["fn"], group["fp"], group["tn"]).metrics())
        ranking = rank_configurations(changed)
        bad = next(value for value in ranking["configurations"] if tuple(value["configuration"][key] for key in ("n_estimators", "max_samples", "max_features")) == first_configuration)
        self.assertFalse(bad["qualified"])
        self.assertEqual(sum(value["qualified"] for value in ranking["configurations"]), 23)


@unittest.skipUnless(shutil.which("java") and (ROOT / "backend/target/ueba-experiment.classpath").is_file(),
                     "pinned Python plus production Java replay workspace required")
class ProductionRuleValidationTest(unittest.TestCase):
    def test_rule_or_model_composition_matches_actual_engine_for_all_rule_thresholds(self):
        rows = []
        for index in range(100):
            value = row(index + 1, index % 2 == 0)
            requests = 2 + index * 2; errors = min(requests, index % 20); failed = index % 8
            value["features"] = [requests, errors, int(index % 9 == 0), failed, 1, int(index % 7 == 0),
                                 min(7, requests), 1, 0, 0, 0, 0, 0, errors / requests, failed / (failed + 1)]
            rows.append(value)
        for threshold in (45, 60, 70):
            policy = ScorePolicy.strict(rule_threshold=threshold)
            with JavaRiskReplay(ROOT, policy) as replay:
                rule_scores = [{"raw_anomaly_score": 0.5, "normal_percentile": 0, "level": "NORMAL_RANGE"} for _ in rows]
                rule = replay.score(rows, rule_scores)
                for percentile in (50.0, 99.99, 100.0):
                    scores = [{"raw_anomaly_score": 0.5, "normal_percentile": percentile,
                               "level": policy.level(percentile, "COLD" if row["cohort"] == "COLD" else "READY")} for row in rows]
                    actual = replay.score(rows, scores)
                    self.assertEqual([row["predictions"]["SIEM_FINAL"] for row in actual],
                                     [row["predictions"]["SIEM_FINAL"] or percentile == 100 for row in rule])

    def test_cached_rules_are_actual_java_decisions_and_resume_is_hash_bound(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root / "data"; data.mkdir(); dataset = fixture(data)
            document = dataset.manifest
            records = [row(1), row(2, True)]
            records[0]["features"] = [150, 30, 5, 15, 0, 2, 7, 1, 0, 0, 0, 0, 0, 0.2, 1]
            path = data / "shards/fold1-validation-000000.json"; path.write_text(canonical(records))
            descriptor = {"id": "fold1-validation-000000", "path": "shards/" + path.name,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **validate_rows(records)}
            split = {**validate_rows(records), "shards": [descriptor]}
            split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest()
            document["splits"]["fold1-validation"] = split
            (data / "manifest.json").write_text(canonical(document)); dataset = ShardedDataset(data)
            actual, receipt = java_rules(dataset, "fold1-validation", root / "cache", ROOT)
            self.assertEqual(actual.tolist(), [[True, True, True], [False, False, False]])
            again, restored = java_rules(dataset, "fold1-validation", root / "cache", ROOT)
            self.assertTrue(np.array_equal(actual, again)); self.assertEqual(restored["computed_shards"], 0)
            self.assertEqual(restored["decision_sha256"], receipt["decision_sha256"])
            with self.assertRaisesRegex(ValueError, "holdout"): java_rules(dataset, "holdout", root / "cache", ROOT)
            # Actual small forest -> cohort calibration -> production Java rules
            # -> all 192 policies. Still not an accuracy/strict-population test.
            trained = fit_one(data, "trees-200-samples-128-features-100-seed-42-fold-1")
            verified = validate_candidate(dataset, ModelStore(data / "strict-models"), trained["model_version"], 1,
                                          root / "validation-cache", ROOT)
            self.assertEqual(len(verified["policies"]), 192)
            self.assertEqual(verified["quality_gate"], "NOT_APPLICABLE")
            self.assertTrue(all(case["scopes"]["MODEL_ONLY"]["normal_samples"] == 2 for case in verified["policies"]))
            cached = next((root / "cache").glob("rules-*/rules.u8"))
            with cached.open("r+b") as stream: stream.write(b"\x00")
            with self.assertRaisesRegex(ValueError, "decisions changed"):
                java_rules(dataset, "fold1-validation", root / "cache", ROOT)


if __name__ == "__main__": unittest.main()
