"""Small structural checks for the test-only, non-candidate diagnostic."""
import unittest

import numpy as np

from tests.schema4_density_saturation_probe import comparison, leaf_groups


class DensitySaturationProbeTest(unittest.TestCase):
    def test_equal_leaves_can_preserve_distinct_float32_numeric_vectors(self):
        arrays = np.zeros((2, 37))
        arrays[:, 3] = [7, 8]
        leaves = np.array([[11, 24], [11, 24]])
        result = comparison(0, 1, np.array([0.6, 0.6]), leaves, arrays,
                            (np.zeros(37), np.ones(37) * 7))
        self.assertFalse(result["same_float32_vector"])
        self.assertEqual(result["differing_float32_feature_names"], ["failed_login_count"])
        self.assertEqual(result["same_leaf_in_tree_count"], 2)
        self.assertTrue(result["exact_raw_score_collision"])

    def test_mixed_leaf_groups_do_not_merge_merely_equal_scores(self):
        leaves = np.array([[1, 2], [1, 2], [3, 4]])
        rows = [{"label": 0}, {"label": 1}, {"label": 0}]
        self.assertEqual(leaf_groups(leaves, rows), [[0, 1]])


if __name__ == "__main__":
    unittest.main()
