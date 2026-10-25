import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from postlogin_capture_catalog import BASELINE, POSTLOGIN, load_capture, validate_rows
from ueba_research_artifacts import commit, digest, publish


def fixture():
    plans = [{"case_id": str(i), "pair_id": "pair", "action": "EMAIL_CHANGE", "role": role}
             for i, role in enumerate(("OWNER", "NONOWNER"))]
    oracle = {"sealed_at": "2026-01-01T00:00:00Z", "plans": plans}
    snapshots = [{"case_id": p["case_id"], "as_of": "2026-01-01T00:00:01Z", "feature_version": "postlogin-action-proof-lab-v2",
                  "current_outcome_known": False, "account_mutation_observed_at_capture": False,
                  "proof_stage": "SERVER_BODY_ADVICE_BEFORE_PROFILE_SERVICE", "feature_names": list(POSTLOGIN),
                  "values": [0.] * 24, "baseline_feature_names": list(BASELINE), "baseline_features": [0.] * 37,
                  "baseline_established": False, "trusted_window_count": 0, "server_proof_state": "NOT_OBSERVED"}
                 for p in plans]
    outcomes = [{"case_id": p["case_id"], "ground_truth": "AUTHORIZED_OWNER_ACTION" if p["role"] == "OWNER" else "CONTROLLED_UNAUTHORIZED_ACTION",
                 "label_source": "SEALED_ROLE_MANIFEST"} for p in plans]
    return oracle, snapshots, outcomes


class CaptureCatalogTest(unittest.TestCase):
    def test_legacy_prefix_is_never_padded_and_source_ids_are_namespaced(self):
        oracle, snapshots, outcomes = fixture()
        a = validate_rows(oracle, snapshots, outcomes, "source-a")
        b = validate_rows(oracle, snapshots, outcomes, "source-b")
        self.assertNotEqual(a[0]["episode_id"], b[0]["episode_id"])
        for row in snapshots:
            del row["baseline_features"]; row["feature_version"] = "postlogin-action-proof-lab-v1"
        with self.assertRaisesRegex(ValueError, "never zero-fill"):
            validate_rows(oracle, snapshots, outcomes, "s")
        self.assertTrue(all(r["features"] is None for r in validate_rows(oracle, snapshots, outcomes, "s", allow_legacy=True)))

    def test_label_swap_or_future_outcome_is_rejected(self):
        oracle, snapshots, outcomes = fixture()
        outcomes[0]["ground_truth"] = "CONTROLLED_UNAUTHORIZED_ACTION"
        with self.assertRaisesRegex(ValueError, "sealed role oracle"):
            validate_rows(oracle, snapshots, outcomes, "s")
        oracle, snapshots, outcomes = fixture(); snapshots[0]["current_outcome_known"] = True
        with self.assertRaisesRegex(ValueError, "future target outcome"):
            validate_rows(oracle, snapshots, outcomes, "s")
        oracle, snapshots, outcomes = fixture(); oracle["sealed_at"] = "2026-01-02T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "oracle must precede"):
            validate_rows(oracle, snapshots, outcomes, "s")

    def test_capture_member_tampering_is_rejected(self):
        oracle, snapshots, outcomes = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            values = {"oracle.private.json": oracle, "precommit.private.json": snapshots,
                      "outcomes.private.json": outcomes, "controls.private.json": {}}
            for name, value in values.items(): publish(root / name, value)
            commit(root, {"status": "PROOF_SIGNAL_OBSERVED_RESEARCH_ONLY", "fit_calls": 0,
                          "real_http_jwt_mysql_redis_otp": True,
                          "files_sha256": {n: digest(root / n) for n in values}}, phase="capture")
            self.assertEqual(len(load_capture(root)[0]), 2)
            publish(root / "outcomes.private.json", [])
            with self.assertRaisesRegex(ValueError, "capture member changed"): load_capture(root)


if __name__ == "__main__": unittest.main()
