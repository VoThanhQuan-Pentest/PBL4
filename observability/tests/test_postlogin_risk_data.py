from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from postlogin_risk_data import Sampler, stratum_population
from postlogin_risk_rolling import model_features
from postlogin_risk_source import accepted_binding
import tempfile
from ueba_research_artifacts import commit, digest


class FakeData:
    def specifications(self, fold, split):
        return [{"fold": fold, "split": split, "index": i, "cohort": "READY", "account": i,
                 "episode": 0, "window_start": "2026-04-16T00:00:00Z", "cause": "normal"} for i in range(4000)]

    def build(self, spec):
        at = datetime(2026, 4, 16, 0, 10, tzinfo=timezone.utc)
        account = "account-" + str(spec["account"])
        raw = {"attempt": {"event_type": "SENSITIVE_ACTION_ATTEMPT", "action": "EMAIL_CHANGE", "outcome": "ATTEMPT",
                "event_timestamp": at.isoformat(), "actor_user_id": account, "telemetry_contract_version": 4,
                "session_pseudonym": "a" * 64, "session_issued_at": (at - timedelta(seconds=30)).isoformat()},
               "context": [{"event_id": str(i), "event_type": "AUTH", "action": "LOGIN", "outcome": "FAILURE",
                  "actor_user_id": None, "target_user_id": account,
                  "event_timestamp": (at - timedelta(seconds=i + 40)).isoformat()} for i in range(8)],
               "baseline_frames": []}
        old_label = int(not spec["cause"].startswith("benign"))
        return raw, {"label": old_label, "family": "auth_failure_burst" if old_label else "normal",
                     "training_context": old_label, "frame_id": "frame", "cohort": "READY"}


class RiskDataTest(unittest.TestCase):
    def test_legitimate_counterpart_keeps_legacy_label_while_context_is_observation_based(self):
        sampler = Sampler(FakeData(), 1, "fit")
        spec, raw, metadata = sampler.select(3401)
        self.assertEqual(spec["cause"], "benign_retries")
        self.assertEqual(metadata["legacy_planned_label"], 0)
        self.assertEqual(metadata["training_context"], 1)
        self.assertEqual(metadata["family"], "auth_failure_burst")
        self.assertEqual(metadata["expected_rolling"][4], 8)

    def test_population_counts_match_all_declared_splits(self):
        self.assertEqual(sum(stratum_population().values()), 35000)
        self.assertEqual(stratum_population()["READY/normal"], 22000)

    def test_last_free_ready_account_does_not_spend_world_budget_on_reserved_slots(self):
        class RoutineData(FakeData):
            calls = 0
            def build(self, spec):
                self.calls += 1
                raw, old = super().build(spec)
                raw["context"] = []
                return raw, old
        data = RoutineData()
        sampler = Sampler(data, 1, "calibration", list(range(4000)))
        free = (3999 * 997) % 4000
        sampler.used = {(a, "2026-04-16T00:00:00Z") for a in range(4000) if a != free}
        spec, _, metadata = sampler.select(0)
        self.assertEqual(spec["account"], free)
        self.assertEqual(metadata["selection_attempts"], 1)
        self.assertEqual(data.calls, 1)

    def test_parent_batches_require_explicit_pinned_lineage_and_unchanged_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = {"protocol_sha256": "a" * 64, "offset": 0, "count": 1}
            expected = {**before, "protocol_sha256": "b" * 64}
            proof = commit(root, {"binding": before, "rows": ["retained"]}, phase="source-test")
            ancestry = {"source-test": {"protocol_sha256": before["protocol_sha256"], "receipt_sha256": proof["receipt_sha256"]}}
            self.assertTrue(accepted_binding(root, "source-test", before, expected, ancestry))
            self.assertFalse(accepted_binding(root, "source-test", before, expected, {}))
            (root / "source-test.receipt.private.json").write_text('{}')
            self.assertFalse(accepted_binding(root, "source-test", before, expected, ancestry))

    def test_schema6_requires_real_rolling_observations_and_preserves_baseline_projection(self):
        row = {"baseline_features": list(range(37)), "postlogin_features": [0.] * 20,
               "rolling_features": [0., 0., 0., 0., 8., 0., 0., 0.]}
        self.assertEqual(len(model_features(row)), 65)
        self.assertEqual(model_features(row, projection="baseline"), tuple(range(37)))
        del row["rolling_features"]
        with self.assertRaises(ValueError):
            model_features(row)


if __name__ == "__main__":
    unittest.main()
