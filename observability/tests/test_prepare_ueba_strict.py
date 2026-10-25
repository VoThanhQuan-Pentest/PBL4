"""Generator invariants; these cases do not claim model accuracy."""

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-strict.py"
SPEC = importlib.util.spec_from_file_location("strict_generator", PATH)
GENERATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GENERATOR
SPEC.loader.exec_module(GENERATOR)


class StrictGeneratorTest(unittest.TestCase):
    def test_strict_recipe_declares_all_three_folds_and_untouched_final_population(self):
        parts = GENERATOR.recipe("STRICT")
        for fold in (1, 2, 3):
            self.assertEqual(sum(part.normal for part in parts if part.split == f"fold{fold}-fit"), 50000)
            for cohort in ("ready", "cold"):
                self.assertEqual(sum(part.normal for part in parts if part.split == f"fold{fold}-calibration-{cohort}"), 1000000)
            validation = [part for part in parts if part.split == f"fold{fold}-validation"]
            self.assertEqual(sum(part.normal for part in validation), 1000000)
            self.assertEqual(sum(part.positive for part in validation), 1000)
        final = [part for part in parts if part.split == "holdout"]
        self.assertEqual(sum(part.normal for part in final), 10000000)
        self.assertEqual(sum(part.positive for part in final), 10000)
        self.assertEqual({part.cohort for part in final}, {"READY", "UNSEEN_READY", "COLD"})
        for fold in (1, 2, 3):
            fit = next(part for part in parts if part.split == f"fold{fold}-fit")
            calibration = next(part for part in parts if part.split == f"fold{fold}-calibration-ready")
            validation = next(part for part in parts if part.split == f"fold{fold}-validation")
            self.assertGreater(calibration.day - (fit.day + fit.days - 1), 14)
            self.assertGreater(validation.day - (calibration.day + calibration.days - 1), 14)
        validation = next(part for part in parts if part.split == "fold3-validation")
        self.assertGreater(final[0].day - (validation.day + validation.days - 1), 14)

    def test_assignment_counts_and_cold_account_history_stay_bounded(self):
        for normal, positive in ((1000, 10), (1003, 17), (10000, 100)):
            self.assertEqual(sum(value[1] for value in GENERATOR.proportions(normal, positive)), normal)
            self.assertEqual(sum(value[2] for value in GENERATOR.proportions(normal, positive)), positive)
            part = GENERATOR.Part("pilot", "COLD", 15, 7, normal, positive)
            counted = positives = 0
            for batch in GENERATOR.actor_batches(part):
                self.assertLessEqual(len(batch), 128)
                for _, evaluations in batch:
                    self.assertLessEqual(len(evaluations) + 3, 23)
                    counted += len(evaluations); positives += sum(index is not None for _, index in evaluations)
            self.assertEqual(counted, normal + positive); self.assertEqual(positives, positive)

    def test_same_ip_and_browser_attacks_are_real_raw_requests_without_invented_groups(self):
        part = GENERATOR.Part("pilot", "READY", 15, 7, 1000, 10)
        anchor = datetime(2026, 7, 1, tzinfo=timezone.utc)
        familiar = 0
        for index in range(100):
            frame, known = GENERATOR.make_frame("strict-owned-test", part, 1, 0, anchor, positive_index=index)
            familiar += known
            self.assertEqual(frame["telemetry_contract_version"], 2)
            self.assertEqual(frame["family"], GENERATOR.FAMILIES[index % 5])
            for event in frame["events"]:
                self.assertNotIn("route_group", event); self.assertNotIn("user_agent_family", event)
                if event["event_type"] == "HTTP_REQUEST":
                    self.assertTrue(event["request_path"].startswith("/api/"))
                    self.assertNotIn("?", event["request_path"])
                    self.assertLess(datetime.fromisoformat(event["event_timestamp"].replace("Z", "+00:00")),
                                    datetime.fromisoformat(frame["window_start"].replace("Z", "+00:00")) + timedelta(minutes=15))
        self.assertEqual(familiar, 60)

    def test_context_precedes_evaluation_and_generation_is_reproducible(self):
        anchor = datetime(2026, 7, 1, tzinfo=timezone.utc)
        for cohort in ("READY", "UNSEEN_READY", "COLD"):
            part = GENERATOR.Part("pilot", cohort, 15, 7, 1000, 10)
            evaluated, _ = GENERATOR.make_frame("strict-owned-test", part, 7, 0, anchor)
            again, _ = GENERATOR.make_frame("strict-owned-test", part, 7, 0, anchor)
            self.assertEqual(evaluated, again)
            for index in range(3 if cohort == "COLD" else 48):
                context, _ = GENERATOR.make_frame("strict-owned-test", part, 7, index, anchor, context=True)
                self.assertLess(context["window_start"], evaluated["window_start"])
                self.assertEqual(context["account_id"], evaluated["account_id"])
                self.assertEqual(context["demo_label"], "NORMAL")


if __name__ == "__main__": unittest.main()
