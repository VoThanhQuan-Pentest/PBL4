"""Contract/geometry tests only, not representative quality evidence."""

import unittest
from unittest.mock import patch

import numpy as np

from app.normal_density import CONFIGURATIONS, NormalDensityScorer
from test_normal_support import normal


class NormalDensityTest(unittest.TestCase):
    def test_predeclared_grid_and_invalid_types(self):
        self.assertEqual(len(CONFIGURATIONS), 24)
        for parameters in ((True, 256, "euclidean", 42), (8, True, "euclidean", 42),
                           (1, 256, "euclidean", 42), (8, 256, "cosine", 42),
                           (8, 256, "euclidean", 0)):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                NormalDensityScorer(*parameters)

    def test_lifecycle_and_input_boundary(self):
        scorer = NormalDensityScorer()
        with self.assertRaisesRegex(ValueError, "not fitted"):
            scorer.score_samples([normal()])
        with self.assertRaisesRegex(ValueError, "smaller"):
            scorer.fit([normal()] * 128)
        scorer.fit([normal(i) for i in range(256)])
        with self.assertRaisesRegex(ValueError, "already fitted"):
            scorer.fit([normal()] * 256)
        for rows in ([], [[0] * 36], [{"features": normal()}], [normal()] * 10001):
            with self.subTest(kind=type(rows).__name__), self.assertRaises(ValueError):
                scorer.score_samples(rows)
        for value in (True, "1", complex(1), float("nan"), float("inf")):
            row = normal(); row[3] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                scorer.score_samples([row])

    def test_fit_only_scaling_caller_mutation_and_duplicate_batch_semantics(self):
        rows = [normal(i) for i in range(300)]
        scorer = NormalDensityScorer().fit(rows)
        center, scale = scorer._center.copy(), scorer._scale.copy()
        duplicate = scorer.anomaly_scores([normal()] * 40)
        np.testing.assert_allclose(duplicate, duplicate[0], rtol=1e-12, atol=1e-12)
        query = normal(); query[7] = 2
        self.assertGreater(scorer.anomaly_scores([query])[0], duplicate[0])
        expected = scorer.score_samples([query, normal()])
        rows[0][7] = 99
        np.testing.assert_allclose(scorer.score_samples([query, normal()]), expected, rtol=1e-12)
        np.testing.assert_array_equal(scorer._center, center)
        np.testing.assert_array_equal(scorer._scale, scale)
        self.assertEqual(scorer.fit_count, 300)
        self.assertEqual(len(scorer.parameters()["feature_names"]), 37)
        self.assertEqual(scorer.parameters()["applicability"], "UNQUALIFIED_RESEARCH_ONLY")

    def test_fixed_seed_and_score_direction(self):
        rows = [normal(i) for i in range(1100)]
        for metric in ("euclidean", "manhattan"):
            first = NormalDensityScorer(4, 128, metric, 11).fit(rows)
            second = NormalDensityScorer(4, 128, metric, 11).fit(rows)
            third = NormalDensityScorer(4, 128, metric, 23).fit(rows)
            np.testing.assert_array_equal(first._indices, second._indices)
            self.assertFalse(np.array_equal(first._indices, third._indices))
            np.testing.assert_allclose(first.score_samples([normal()]), second.score_samples([normal()]))
            np.testing.assert_array_equal(first.anomaly_scores([normal()]), -first.score_samples([normal()]))

    def test_monotone_log_representation_large_ratios_and_ties(self):
        scorer = NormalDensityScorer().fit([normal(i) for i in range(256)])
        ratios = np.array([0.0, 0.5, 1.0, 1.0, 1e6, 1e12, np.finfo(np.float64).max])
        with patch.object(scorer._estimator, "score_samples", return_value=-ratios):
            scores = scorer.anomaly_scores([normal()] * len(ratios))
        np.testing.assert_array_equal(scores, np.log1p(ratios))
        self.assertTrue(np.isfinite(scores).all())
        self.assertTrue(np.all(np.abs(scores) < 1_000_000))
        self.assertTrue(np.array_equal(np.sign(np.diff(scores)), np.sign(np.diff(ratios))))
        self.assertEqual(scores[2], scores[3])
        self.assertEqual(scorer.parameters()["recipe_version"], 2)
        for invalid in (np.array([np.nan]), np.array([np.inf]), np.array([-1.0]), np.zeros(2)):
            with patch.object(scorer._estimator, "score_samples", return_value=-invalid), self.assertRaises(ValueError):
                scorer.anomaly_scores([normal()])
