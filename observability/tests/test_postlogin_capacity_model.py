from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from app.normal_support import NormalSupportScorer
from postlogin_capacity_model import CapacityBeforeAttemptScorer


class CapacityReuseTest(unittest.TestCase):
    def test_wrong_normal_population_is_rejected_before_classifier_fit(self):
        normal = NormalSupportScorer(8, 256, "euclidean", 42)
        normal.to_state = lambda: {"fit_rows": [[1] * 37] * 256}
        x = np.zeros((256, 57))
        with patch("postlogin_capacity_model.HistGradientBoostingClassifier") as classifier:
            with self.assertRaisesRegex(ValueError, "FIT rows/order differ"):
                CapacityBeforeAttemptScorer().fit_reusing_normal(normal, x, x, [0] * 100 + [1] * 100 + [2] * 56)
            classifier.assert_not_called()

    def test_verified_reuse_calls_classifier_once_and_never_normal_fit(self):
        normal = NormalSupportScorer(8, 256, "euclidean", 42)
        state = {"fit_rows": [[0] * 37] * 256, "parameters": normal.parameters()}
        normal.to_state = lambda: state
        classifier = Mock(); classifier.classes_ = np.array([0, 1, 2]); classifier.fit.return_value = classifier
        x = np.zeros((256, 57)); labels = [0] * 100 + [1] * 100 + [2] * 56
        with patch.object(NormalSupportScorer, "from_state", return_value=normal), \
                patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("unexpected normal fit")), \
                patch("postlogin_capacity_model.HistGradientBoostingClassifier", return_value=classifier) as factory:
            model = CapacityBeforeAttemptScorer().fit_reusing_normal(normal, x, x, labels)
            factory.assert_called_once_with(**CapacityBeforeAttemptScorer.capacity_parameters)
            classifier.fit.assert_called_once()
            self.assertIs(model.normal, normal)
            with self.assertRaisesRegex(ValueError, "already fitted"):
                model.fit_reusing_normal(normal, x, x, labels)
        with self.assertRaisesRegex(ValueError, "requires checksum-bound reuse"):
            CapacityBeforeAttemptScorer().fit(x, x, labels)


if __name__ == "__main__": unittest.main()
