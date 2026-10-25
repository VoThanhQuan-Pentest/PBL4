"""Actual immutable Java/Python schema4 decision transport; not accuracy proof."""
import os
from pathlib import Path
import shutil
import unittest

from app.policy import ScorePolicy
from app.risk_replay import JavaRiskReplay

ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", Path(__file__).resolve().parents[2]))


@unittest.skipUnless(shutil.which("java") and (ROOT / "backend/target/ueba-experiment.classpath").is_file(),
                     "compiled immutable schema4 Java workspace required")
class Schema4JavaBridgeTest(unittest.TestCase):
    def test_both_scopes_use_actual_engine_and_schema4_policy_without_label_input(self):
        policy = ScorePolicy.strict(schema=4)
        vector = [2,0,0,0,0,0,1,1,0,0,0,0,0,0,0,
                  2,0,0,0,0,0,0,0,0,0,
                  2,1,0,0,0,2,2,1,30,0,3,0.5]
        rows = [{"frame_id": f"schema4-bridge-frame-{index}", "account_id": f"schema4-bridge-account-{index}",
                 "window_start": "2026-04-01T00:00:00Z", "label": 0, "family": "normal", "cohort": "COLD",
                 "baseline_established": False, "trusted_window_count": 3, "features": vector.copy()} for index in range(2)]
        scores = [{"raw_anomaly_score": 0.5, "normal_percentile": percentile,
                   "level": policy.level(percentile, "COLD")} for percentile in (100.0, 99.99)]
        with JavaRiskReplay(ROOT, policy) as replay: actual = replay.score(rows, scores)
        self.assertEqual([item["predictions"] for item in actual],
                         [{"MODEL_ONLY": True, "SIEM_FINAL": True}, {"MODEL_ONLY": False, "SIEM_FINAL": False}])
        self.assertEqual([item["label"] for item in actual], [0, 0])
        self.assertEqual([item["cohort"] for item in actual], ["COLD", "COLD"])


if __name__ == "__main__": unittest.main()
