import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/postlogin_risk_contract.py"
SPEC = importlib.util.spec_from_file_location("risk_contract", PATH)
risk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(risk)


class RiskContractTest(unittest.TestCase):
    def frame(self):
        at = datetime(2026, 4, 16, 12, 1, tzinfo=timezone.utc)
        return {"attempt": {"event_type": "SENSITIVE_ACTION_ATTEMPT", "action": "EMAIL_CHANGE",
            "outcome": "ATTEMPT", "event_timestamp": at.isoformat(), "actor_user_id": "a",
            "telemetry_contract_version": 4, "session_pseudonym": "a" * 64,
            "session_issued_at": (at - timedelta(minutes=5)).isoformat()},
            "context": [], "baseline_frames": []}

    def events(self, frame, number, **fields):
        at = risk.instant(frame["attempt"]["event_timestamp"])
        frame["context"] += [{"event_id": str(i), "event_timestamp": (at - timedelta(seconds=i + 1)).isoformat(),
                               "actor_user_id": "a", **fields} for i in range(number)]

    def test_identical_observations_never_depend_on_actor_or_fixture_metadata(self):
        frame = self.frame()
        self.events(frame, 8, event_type="AUTH", action="LOGIN", outcome="FAILURE")
        counterpart = copy.deepcopy(frame)
        frame.update(planned_cause="attack", actor_role="NONOWNER", label=1)
        counterpart.update(planned_cause="benign", actor_role="OWNER", label=0)
        self.assertEqual(risk.reference(frame), risk.reference(counterpart))
        self.assertEqual(risk.reference(frame)["training_context"], 1)

    def test_future_and_tied_outcomes_do_not_affect_reference(self):
        frame = self.frame()
        expected = risk.reference(frame)
        frame["context"] = [{"event_timestamp": frame["attempt"]["event_timestamp"],
                             "event_type": "SENSITIVE_ACTION_ATTEMPT", "action": "PASSWORD_CHANGE"}] * 8
        self.assertEqual(expected, risk.reference(frame))

    def test_errors_are_not_automatically_security(self):
        frame = self.frame()
        self.events(frame, 40, event_type="HTTP_REQUEST", http_status=503, endpoint_category="PROFILE_READ")
        result = risk.reference(frame)
        self.assertEqual(result["training_context"], 2)
        self.assertEqual(result["family"], "http_error_burst")
        frame = self.frame()
        self.events(frame, 4, event_type="HTTP_REQUEST", http_status=404)
        self.assertEqual(risk.reference(frame)["training_context"], 0)

    def test_reset_is_not_authenticated_password_change(self):
        frame = self.frame()
        self.events(frame, 8, event_type="DOMAIN_ACTION", action="PASSWORD_RESET")
        self.assertEqual(risk.reference(frame)["label"], 0)

    def test_missing_association_is_retained_as_undetermined(self):
        frame = self.frame()
        frame["attempt"].pop("session_pseudonym")
        result = risk.reference(frame)
        self.assertIsNone(result["label"])
        self.assertEqual(result["coverage"], "UNDETERMINED")

    def test_model_projection_excludes_proof_and_metadata(self):
        row = {"baseline_features": [0.] * 37, "postlogin_features": [1.] * 20,
               "otp": "123456", "actor_role": "OWNER", "planned_cause": "fixture"}
        self.assertEqual(len(risk.model_features(row)), 57)
        self.assertEqual(len(risk.model_features(row, projection="baseline")), 37)
        row["postlogin_features"] += [1.] * 4
        with self.assertRaises(ValueError):
            risk.model_features(row)

    def test_rejects_future_or_foreign_history(self):
        frame = self.frame()
        frame["baseline_frames"] = [{"account_id": "a", "window_start": frame["attempt"]["event_timestamp"], "events": []}]
        with self.assertRaises(ValueError):
            risk.reference(frame)


if __name__ == "__main__":
    unittest.main()
