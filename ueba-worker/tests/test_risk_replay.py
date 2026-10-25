"""Actual Java replay is run on the host; numeric unit cases never claim ML quality."""

from pathlib import Path
import os
import shutil
import unittest

from app.policy import ScorePolicy
from app.risk_replay import JavaRiskReplay, request, response
from test_catalog import row

ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", Path(__file__).resolve().parents[2]))


def scored(percentile):
    return {"raw_anomaly_score": 0.5, "normal_percentile": percentile, "level": ScorePolicy.strict().level(percentile, "READY")}


class RiskReplayContractTest(unittest.TestCase):
    def test_ground_truth_never_crosses_the_decision_boundary(self):
        transmitted = request(ScorePolicy.strict(), [row()], [scored(100)])
        self.assertEqual(set(transmitted["rows"][0]), {"frame_id", "features", "baseline_established",
                                                     "scoring_cohort", "raw_anomaly_score", "normal_percentile", "level"})
        for forbidden in ("label", "family", "account_id", "raw_body"):
            self.assertNotIn(forbidden, transmitted["rows"][0])

    def test_wrong_levels_and_mismatched_responses_do_not_become_journal_rows(self):
        policy = ScorePolicy.strict(); forged = scored(50); forged["level"] = "VERY_UNUSUAL"
        with self.assertRaises(ValueError): request(policy, [row()], [forged])
        valid = {"feature_schema_version": 2, "data_provenance": "DEMO_ONLY", "decision_code": "AccountRiskEngine",
                 "policy_sha256": policy.sha256, "results": [{"frame_id": row()["frame_id"], "model_positive": True, "siem_positive": True}]}
        self.assertTrue(response(policy, [row()], [scored(100)], valid)[0]["predictions"]["MODEL_ONLY"])
        valid["results"][0]["model_positive"] = False
        with self.assertRaises(ValueError): response(policy, [row()], [scored(100)], valid)


@unittest.skipUnless(shutil.which("java") and (ROOT / "backend/target/ueba-experiment.classpath").is_file(),
                     "host compiled Java is required; Docker worker unit suite does not replace this verification")
class RealJavaReplayTest(unittest.TestCase):
    def test_real_production_engine_preserves_both_scopes_and_cold_start(self):
        rows = [row(), row(2, True), row(3)]
        scores = [scored(100), scored(100), scored(99.99)]
        with JavaRiskReplay(ROOT, ScorePolicy.strict()) as replay:
            result = replay.score(rows, scores)
            self.assertEqual([item["predictions"] for item in result],
                             [{"MODEL_ONLY": True, "SIEM_FINAL": True}, {"MODEL_ONLY": True, "SIEM_FINAL": True},
                              {"MODEL_ONLY": False, "SIEM_FINAL": False}])
            self.assertEqual(replay.score(rows, scores), result)

    def test_independent_normal_score_does_not_hide_rule_only_final_alert(self):
        evidence = row()
        evidence["features"] = [150, 30, 5, 15, 0, 2, 7, 1, 0, 0, 0, 2, 0, 0.2, 1]
        with JavaRiskReplay(ROOT, ScorePolicy.strict()) as replay:
            result = replay.score([evidence], [scored(50)])[0]
            self.assertEqual(result["predictions"], {"MODEL_ONLY": False, "SIEM_FINAL": True})


if __name__ == "__main__": unittest.main()
