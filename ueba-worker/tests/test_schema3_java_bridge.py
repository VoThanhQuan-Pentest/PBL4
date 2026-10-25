"""Actual versioned Java decision transport, not a quality benchmark."""
import os
from pathlib import Path
import shutil
import hashlib
import tempfile
import unittest

from app.policy import ScorePolicy
from app.risk_replay import JavaRiskReplay
from app.selection import selection_identity
from test_calibration import fixture

ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", Path(__file__).resolve().parents[2]))


@unittest.skipUnless(shutil.which("java") and (ROOT / "backend/target/ueba-experiment.classpath").is_file(),
                     "compiled production schema-3 workspace required")
class Schema3JavaBridgeTest(unittest.TestCase):
    def test_actual_policy_schema_and_both_decision_layers_are_preserved(self):
        policy = ScorePolicy.strict(schema=3)
        rows = [{"frame_id": "schema3-bridge-frame-" + str(index), "account_id": "schema3-bridge-account-" + str(index),
                 "window_start": "2026-04-01T00:00:00Z", "label": 0, "family": "normal", "cohort": "COLD",
                 "baseline_established": False, "trusted_window_count": 3,
                 "features": [2,0,0,0,0,0,1,1,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0]} for index in range(2)]
        scores = [{"raw_anomaly_score": 0.5, "normal_percentile": value, "level": policy.level(value, "COLD")}
                  for value in (100, 99.99)]
        with JavaRiskReplay(ROOT, policy) as replay:
            actual = replay.score(rows, scores)
        self.assertEqual([row["predictions"] for row in actual],
                         [{"MODEL_ONLY": True, "SIEM_FINAL": True}, {"MODEL_ONLY": False, "SIEM_FINAL": False}])
        self.assertEqual(actual[0]["label"], 0)  # Label is journal data, never sent to Java.

    def test_selection_binds_actual_contextual_exporter_and_all_past_baseline_producers(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = fixture(Path(directory), schema=3)
            classes = ROOT / "backend/target/classes/com/flarefitness/backend"
            names = ("ops/UebaFeatureExport.class", "service/siem/AccountBaselinePolicy.class",
                     "service/siem/AccountBehaviorFeatures.class", "service/siem/AccountRiskEngine.class",
                     "service/siem/SecurityEventNormalizer.class", "service/siem/ContextualBehaviorFeatures.class")
            # Owned binding fixture: do not rewrite any published corpus/holdout.
            dataset.manifest["compiled_feature_sha256"] = {
                name: hashlib.sha256((classes / name).read_bytes()).hexdigest() for name in names}
            identity = selection_identity(dataset, ROOT)
            self.assertEqual(identity["feature_producers"], dataset.manifest["compiled_feature_sha256"])
            for name in names:
                previous = dataset.manifest["compiled_feature_sha256"][name]
                dataset.manifest["compiled_feature_sha256"][name] = "0" * 64
                with self.assertRaisesRegex(ValueError, "differs from frozen dataset"):
                    selection_identity(dataset, ROOT)
                dataset.manifest["compiled_feature_sha256"][name] = previous


if __name__ == "__main__": unittest.main()
