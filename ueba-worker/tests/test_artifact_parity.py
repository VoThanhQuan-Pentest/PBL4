from pathlib import Path
import tempfile
import unittest

from app.artifact_parity import reproduce, verify_receipt
from app.policy import ScorePolicy
from app.strict_campaign import approved_run, run_identity


class FrozenMetadataFixture:
    sha256 = "a" * 64
    manifest = {"stage": "STRICT"}
    def split(self, name): return {"sha256": "b" * 64}


class ArtifactParityGuardTest(unittest.TestCase):
    def setUp(self):
        self.dataset = FrozenMetadataFixture()
        self.run = approved_run("trees-200-samples-128-features-100-seed-42-fold-3")
        self.receipt = {**run_identity(self.dataset, self.run), "status": "FITTED_CALIBRATED",
                        "quality_gate": "NOT_RUN", "training_windows": 50000,
                        "calibration_cohort_windows": {"READY": 1000000, "COLD": 1000000},
                        "score_policy": ScorePolicy.strict().wire()}

    def test_only_matching_full_frozen_receipt_is_eligible_for_reproduction(self):
        verify_receipt(self.dataset, self.run, self.receipt)
        for change in ({"status": "CALIBRATING"}, {"quality_gate": "PASS"}, {"training_windows": 600},
                       {"dataset_manifest_sha256": "c" * 64}, {"fit_split_sha256": "c" * 64},
                       {"code_fingerprint": {}}, {"calibration_cohort_windows": {"READY": 1000, "COLD": 1000}},
                       {"score_policy": ScorePolicy.legacy(2).wire()}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_receipt(self.dataset, self.run, self.receipt | change)

    def test_pilot_wrong_fold_and_wrong_seed_cannot_be_full_reproduction_evidence(self):
        pilot = FrozenMetadataFixture(); pilot.manifest = {"stage": "PILOT"}
        with self.assertRaises(ValueError): verify_receipt(pilot, self.run, self.receipt)
        for run_id in ("trees-200-samples-128-features-100-seed-42-fold-1",
                       "trees-200-samples-128-features-100-seed-11-fold-3"):
            with self.assertRaises(ValueError): verify_receipt(self.dataset, approved_run(run_id), self.receipt)

    def test_output_cannot_alias_reference_or_overwrite_existing_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "reference"; source.mkdir()
            for output in (source, source / "child", root):
                with self.assertRaises(ValueError): reproduce(source, output, self.run["run_id"])
            output = root / "diagnostic"; output.mkdir(); marker = output / "retain-me"
            marker.write_text("earlier diagnostic")
            with self.assertRaises(ValueError): reproduce(source, output, self.run["run_id"])
            self.assertEqual(marker.read_text(), "earlier diagnostic")
            alias = root / "alias"; alias.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError): reproduce(source, alias, self.run["run_id"])


if __name__ == "__main__": unittest.main()
