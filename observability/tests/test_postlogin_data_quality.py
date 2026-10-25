import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from postlogin_data_quality import collision_report, features, load_split
from ueba_research_artifacts import commit


def row(label, value=0):
    return {"baseline_features": [value] * 37, "postlogin_features": [0] * 20,
            "label": label, "training_context": label, "baseline_established": True}


class DataQualityTest(unittest.TestCase):
    def test_collision_bound_accounts_for_shared_normal_cost(self):
        rows = [row(0), row(1), row(1), row(1, 1), row(0, 2)]
        result = collision_report(rows, 57)
        self.assertEqual(result["unavoidable_errors_if_one_decision_per_vector"], 1)
        self.assertEqual(result["empirical_oracle_maximum_tp_at_fpr_budget"], 1)
        self.assertEqual(result["rows_in_opposite_label_groups"], 3)

    def test_no_positive_labels_or_nonfinite_values_are_fabricated(self):
        with self.assertRaises(ValueError): features({**row(1), "training_context": 0})
        bad = row(0); bad["baseline_features"][0] = float("nan")
        with self.assertRaises(ValueError): features(bad)

    def test_changed_committed_bytes_and_holdout_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            phase = "source-f1-fit-0000"
            commit(root, {"binding": {"protocol_sha256": "p", "fold": 1, "split": "fit", "offset": 0, "count": 1},
                          "rows": [row(0)]}, phase=phase)
            self.assertEqual(len(load_split(root, "fit", "p", 1)[0]), 1)
            with self.assertRaises(ValueError): load_split(root, "holdout", "p", 1)
            path = root / (phase + ".receipt.private.json")
            path.write_text(path.read_text() + " ")
            with self.assertRaisesRegex(ValueError, "checksum"): load_split(root, "fit", "p", 1)


if __name__ == "__main__": unittest.main()
