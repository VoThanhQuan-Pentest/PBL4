from collections import Counter
from datetime import timedelta
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "observability/scripts"), str(ROOT / "ueba-worker")]
import postlogin_pilot_data as data


class PostloginPilotDataTest(unittest.TestCase):
    def test_fixed_counts_three_contexts_and_unseen_account_isolation(self):
        fitting = list(data.specifications(1, "fit"))
        calibration = list(data.specifications(1, "calibration"))
        validation = list(data.specifications(1, "validation"))
        self.assertEqual([len(fitting), len(calibration), len(validation)], [4000, 10000, 21000])
        self.assertEqual(sum(s["normal_fit"] for s in fitting), 2000)
        self.assertEqual(sum(s["cause"] in data.NORMAL_CAUSES for s in fitting), 3000)
        self.assertEqual(Counter(s["cause"] for s in validation if s["cause"] in data.FAMILIES), {f: 200 for f in data.FAMILIES})
        self.assertEqual(Counter(s["cohort"] for s in calibration), {"READY": 5000, "COLD": 5000})
        fitted = {s["account"] for s in fitting}
        self.assertFalse(fitted & {s["account"] for s in validation if s["cohort"] == "UNSEEN_READY"})
        for values in (fitting, calibration, validation):
            self.assertEqual(len(values), len({(s["account"], s["window_start"]) for s in values}))
        self.assertGreater(min(data.moment(s["window_start"]) for s in calibration) - max(data.moment(s["window_start"]) for s in fitting), timedelta(days=14))
        self.assertGreater(min(data.moment(s["window_start"]) for s in validation) - max(data.moment(s["window_start"]) for s in calibration), timedelta(days=14))

    def test_every_family_uses_only_past_context_and_no_future_target_outcome(self):
        fitting = list(data.specifications(1, "fit"))
        for index in (0, 3000, 3200, 3400, 3600, 3800):
            frame, metadata = data.build(fitting[index])
            self.assertEqual(frame["attempt"]["outcome"], "ATTEMPT")
            self.assertTrue(all(data.moment(e["event_timestamp"]) < data.moment(metadata["as_of"]) for e in frame["context"]))
            self.assertTrue(all(data.moment(f["window_start"]) < data.moment(metadata["window_start"]) for f in frame["baseline_frames"]))
            self.assertEqual(metadata["frame_id"], frame["frame_id"])
            for event in [frame["attempt"], *frame["context"]]:
                self.assertFalse(set(event) & {"label", "family", "planned_cause", "plan_sha256", "hidden_intent", "token", "jti"})

    def test_email_retains_session_and_password_revokes_before_later_requests(self):
        specification = list(data.specifications(1, "fit"))[3600]
        frame, _ = data.build(specification)
        changes = [e for e in frame["context"] if e["event_type"] == "DOMAIN_ACTION"]
        self.assertTrue(any(e["action"] == "EMAIL_CHANGE" for e in changes))
        self.assertTrue(any(e["action"] == "PASSWORD_CHANGE" for e in changes))
        for event in changes:
            if event["action"] != "PASSWORD_CHANGE":
                continue
            at = data.moment(event["event_timestamp"])
            future = [e for e in [*frame["context"], frame["attempt"]]
                      if e.get("session_pseudonym") == event["session_pseudonym"]
                      and data.moment(e["event_timestamp"]) > at + timedelta(milliseconds=1)]
            self.assertEqual(future, [])


if __name__ == "__main__":
    unittest.main()
