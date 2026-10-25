import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from postlogin_action_trial_report import summarize


def fixture():
    scenarios = ("OWNER_VALID_PROOF", "OWNER_VALID_PROOF", "WRONG_CODE", "OTHER_SESSION", "EXPIRED",
                 "AUTH_VERSION_CHANGED", "OWNER_WITHOUT_PROOF_CONTROL", "SESSION_AND_MAILBOX_COMPROMISED_CONTROL")
    rows = []
    for operation in ("EMAIL_CHANGE", "PASSWORD_CHANGE"):
        for i, scenario in enumerate(scenarios):
            committed = scenario in ("OWNER_VALID_PROOF", "SESSION_AND_MAILBOX_COMPROMISED_CONTROL")
            status = 200 if committed else 401 if scenario == "AUTH_VERSION_CHANGED" else (
                409 if scenario in ("OTHER_SESSION", "EXPIRED") else 400)
            rows.append(dict(operation=operation, ordinal=i, scenario=scenario, committed=committed,
                             http_status=status, correct=True, replay_safe=True))
    return dict(status="CONTROLLED_TRIALS_COMPLETE", smtp_verified=False,
                planned_eligible_owners_per_operation=2, planned_invalid_proofs_per_operation=4,
                outcomes=rows, execution_latency_excludes_smtp_and_human={})


class ActionTrialReportTest(unittest.TestCase):
    def test_controlled_evidence_never_becomes_population_or_real_transport_pass(self):
        result = summarize(fixture())
        self.assertFalse(result["planned_count_screen_complete"])
        self.assertFalse(result["global_activation"])
        self.assertTrue(result["action_false_block_population_gate"].startswith("INCONCLUSIVE"))
        self.assertEqual(result["operations"]["EMAIL_CHANGE"]["eligible_owner_operations"], 2)

    def test_partial_duplicate_and_post_outcome_scenario_change_are_rejected(self):
        base = fixture()
        for field, value in (("status", "PARTIAL_NOT_GATE_PASS"), ("smtp_verified", True)):
            changed = copy.deepcopy(base); changed[field] = value
            with self.assertRaises(ValueError): summarize(changed)
        changed = copy.deepcopy(base); changed["outcomes"][0]["ordinal"] = 1
        with self.assertRaises(ValueError): summarize(changed)
        changed = copy.deepcopy(base); changed["outcomes"][2]["scenario"] = "OWNER_VALID_PROOF"
        with self.assertRaises(ValueError): summarize(changed)

    def test_backend_failure_and_unauthorized_commit_cannot_count_as_prevention(self):
        for field, value in (("http_status", 500), ("committed", True), ("replay_safe", False)):
            changed = fixture(); changed["outcomes"][2][field] = value
            with self.assertRaises(ValueError): summarize(changed)


if __name__ == "__main__":
    unittest.main()
