import unittest
from app.contract import feature_array
from app.robustness import VALID, INVALID, case


class RobustnessRecipeTest(unittest.TestCase):
    def test_twenty_different_case_kinds_follow_expected_contract_at_boundaries(self):
        self.assertEqual(len(VALID) + len(INVALID), 20)
        for kind in VALID:
            for index in (0, 1, 255, 4999): feature_array([case(kind, index)], 1, 2)
        for kind in INVALID:
            for index in (0, 1, 255, 4999):
                with self.subTest(kind=kind, index=index), self.assertRaises((ValueError, TypeError)):
                    feature_array([case(kind, index)], 1, 2)


if __name__ == "__main__": unittest.main()
