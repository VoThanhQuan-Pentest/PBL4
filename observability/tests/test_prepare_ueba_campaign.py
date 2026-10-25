import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-campaign.py"
SPEC = importlib.util.spec_from_file_location("campaign_fixture", SCRIPT)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class CampaignFixtureTest(unittest.TestCase):
    def test_event_frames_are_deterministic_physically_valid_and_do_not_contain_features(self):
        anchor = datetime(2026, 7, 1, tzinfo=timezone.utc)
        for account in (1, 6, 70, 150, 151, 200):
            for family in ("normal",) + GENERATOR.FAMILIES:
                with self.subTest(account=account, family=family):
                    first = GENERATOR.frame("campaign-fixture", account, 50, 3, anchor, family)
                    self.assertEqual(first, GENERATOR.frame("campaign-fixture", account, 50, 3, anchor, family))
                    self.assertNotIn("features", first)
                    start = datetime.fromisoformat(first["window_start"].replace("Z", "+00:00"))
                    self.assertGreater(len(first["events"]), 0)
                    self.assertLessEqual(len(first["events"]), 4096)
                    for event in first["events"]:
                        timestamp = datetime.fromisoformat(event["event_timestamp"].replace("Z", "+00:00"))
                        self.assertGreaterEqual(timestamp, start)
                        self.assertLess(timestamp, start + timedelta(minutes=15))
                        self.assertFalse({"password", "token", "cookie", "raw_body", "url"} & set(event))

    def test_exactly_one_thousand_validation_assignments_are_balanced_and_independent(self):
        a = GENERATOR.assignments(100, range(1, 151), range(32, 36))
        b = GENERATOR.assignments(200, range(1, 151), range(39, 43))
        self.assertEqual(len(a), 1000)
        self.assertFalse(set(a) & set(b))
        for family in GENERATOR.FAMILIES: self.assertEqual(list(a.values()).count(family), 200)

    def test_holdout_accounts_cannot_leak_into_any_fit_or_calibration(self):
        for fit, calibration, validation in GENERATOR.FOLDS.values():
            self.assertLess(fit[1], calibration[0])
            self.assertLess(calibration[1], validation[0])
            self.assertLess(validation[1], 50)
            self.assertLessEqual(calibration[1] - fit[0] + 1, 30)
        chosen = GENERATOR.choose([{"window_start": str(i), "account_id": "fixed", "frame_id": f"id-{i}"}
                                  for i in range(100)], 50, 42)
        self.assertEqual(len({row["frame_id"] for row in chosen}), 50)
        with self.assertRaises(ValueError): GENERATOR.choose([], 1, 42)


if __name__ == "__main__": unittest.main()
