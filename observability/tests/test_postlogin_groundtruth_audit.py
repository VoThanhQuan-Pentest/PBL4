import copy
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("groundtruth_audit", SCRIPTS / "audit-ueba-postlogin-groundtruth.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class GroundTruthAuditTest(unittest.TestCase):
    def fixture(self):
        manifest = {"sealed_at": "2026-10-19T00:00:00Z", "plans": []}
        source, snapshots, outcomes = [], [], []
        for case, role in (("a", "OWNER"), ("b", "NONOWNER")):
            manifest["plans"].append({"case_id": case, "pair_id": "pair", "actor_role": role,
                                      "operation": "EMAIL_CHANGE", "valid_proof": True})
            for event, second, kind in (("login", 1, "AUTH"), ("target", 3, "SENSITIVE_ACTION_ATTEMPT"),
                                        ("future", 4, "DOMAIN_ACTION")):
                source.append({"event_id": case + event, "account_id": "account-" + case,
                               "event_type": kind, "action": "LOGIN" if kind == "AUTH" else "EMAIL_CHANGE",
                               "outcome": "ATTEMPT" if kind == "SENSITIVE_ACTION_ATTEMPT" else "SUCCESS",
                               "event_timestamp": "2026-10-19T00:00:0" + str(second) + "Z",
                               "telemetry_contract_version": 4, "session_pseudonym": case * 64,
                               "session_issued_at": "2026-10-19T00:00:01Z"})
            snapshots.append({"case_id": case, "feature_version": "postlogin-before-action-v1",
                              "feature_names": audit.EXPECTED_NAMES.copy(), "values": [0, 1, 1, 1] + [0] * 16,
                              "as_of": "2026-10-19T00:00:03Z", "input_event_ids": [case + "login"],
                              "authenticated_session_covered": True, "same_session_login_observed": True})
            outcomes.append({"case_id": case, "pair_id": "pair", "actor_role": role, "operation": "EMAIL_CHANGE",
                             "ground_truth": "AUTHORIZED_OWNER_ACTION" if role == "OWNER" else "CONTROLLED_UNAUTHORIZED_ACTION",
                             "account_mutated": True, "label_source": "SEALED_ROLE_MANIFEST"})
        return manifest, source, snapshots, outcomes

    def test_opposite_role_labels_may_have_identical_numeric_features(self):
        manifest, source, snapshots, outcomes = self.fixture()
        _, vectors = audit.validate_inputs(manifest, source, snapshots, outcomes)
        self.assertEqual(vectors["a"], vectors["b"])
        self.assertNotEqual(outcomes[0]["ground_truth"], outcomes[1]["ground_truth"])

    def test_current_outcome_future_and_cross_account_context_are_rejected(self):
        for invalid in ("atarget", "afuture", "blogin"):
            data = self.fixture()
            data[2][0]["input_event_ids"].append(invalid)
            with self.assertRaisesRegex(ValueError, "Past-only context"):
                audit.validate_inputs(*data)

    def test_oracle_fields_cannot_enter_observations_transport_or_numeric_names(self):
        changes = [lambda data: data[1][0].update(actor_role="OWNER"),
                   lambda data: data[2][0].update(ground_truth=0),
                   lambda data: data[2][0]["feature_names"].__setitem__(0, "ground_truth")]
        for change in changes:
            data = self.fixture()
            change(data)
            with self.assertRaises(ValueError):
                audit.validate_inputs(*data)

    def test_labels_cannot_follow_verifier_result_or_be_rewritten_after_capture(self):
        data = self.fixture()
        data[0]["plans"][0]["valid_proof"] = False
        data[3][0]["account_mutated"] = False
        audit.validate_inputs(*data)  # Owner typo remains an owner label.
        changed = copy.deepcopy(data)
        changed[3][0]["ground_truth"] = "CONTROLLED_UNAUTHORIZED_ACTION"
        with self.assertRaisesRegex(ValueError, "independent role oracle"):
            audit.validate_inputs(*changed)

    def test_labels_sealed_after_first_observation_are_rejected(self):
        data = self.fixture()
        data[0]["sealed_at"] = "2026-10-19T00:00:02Z"
        with self.assertRaisesRegex(ValueError, "sealed before"):
            audit.validate_inputs(*data)


if __name__ == "__main__":
    unittest.main()
