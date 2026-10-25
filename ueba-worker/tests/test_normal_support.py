"""Support-distance contract fixtures, not representative detection benchmarks."""

import copy
import json
import unittest
from unittest.mock import patch

import numpy as np

from app.contract import FEATURE_NAMES_V4
from app.normal_support import MAX_REFERENCE_ROWS, MAX_SCORE_ROWS, NormalSupportScorer


def normal(index=0):
    requests = 40 + index % 7
    return [requests, 2, 0, 0, 1, 0, 2, 1, 0, 0, 0, 0, 0, 2 / requests, 0,
            requests, 1, 0, 1, 1 / (requests - 1), 0, 0, 0, 0, 2,
            requests, 2, 0, 0, 1, requests, requests, 1, 600, 1, 48, 0.5]


def login_only(failed, *, cold=False):
    # Legal source totals: failed-login telemetry can exist without HTTP events.
    return [0, 0, 0, failed, 0, 0, 0, 1, 0, 0, 0, -7.783640596221253 if not cold else 0,
            -2.772588722239781 if not cold else 0, 0, int(failed > 0), 0, 0, 0, 0, 0,
            4 * np.log1p(failed) if not cold else 0, 0, min(5, failed), 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 if cold else 48,
            -2.302585092994046 if cold else -1.9459101490553132]


class NormalSupportTest(unittest.TestCase):
    def test_fixed_recipe_fit_and_sklearn_sign_contract(self):
        scorer = NormalSupportScorer()
        with self.assertRaisesRegex(ValueError, "not fitted"):
            scorer.anomaly_scores([normal()])
        with self.assertRaisesRegex(ValueError, "not fitted"):
            scorer.to_state()
        with self.assertRaisesRegex(ValueError, "at least 8"):
            scorer.fit([normal()] * 7)
        self.assertIs(scorer.fit([normal(i) for i in range(56)]), scorer)
        query = normal(); query[3], query[14], query[22] = 10, 10 / 11, 5
        anomaly = scorer.anomaly_scores([normal(), query])
        np.testing.assert_array_equal(scorer.score_samples([normal(), query]), -anomaly)
        self.assertGreater(anomaly[1], anomaly[0])
        with self.assertRaisesRegex(ValueError, "already fitted"):
            scorer.fit([query] * 8)
        self.assertEqual(scorer.reference_count, 56)

    def test_duplicate_queries_reference_order_and_batching_are_stable(self):
        rows = [normal(i) for i in range(56)]
        scorer = NormalSupportScorer().fit(rows)
        duplicate = scorer.anomaly_scores([normal()] * 40)
        np.testing.assert_array_equal(duplicate, np.zeros(40))
        query = normal(); query[7] = 2
        expected = scorer.anomaly_scores([query])[0]
        np.testing.assert_array_equal(scorer.anomaly_scores([query] * 40), np.full(40, expected))
        reversed_scorer = NormalSupportScorer().fit(rows[::-1])
        np.testing.assert_array_equal(reversed_scorer.anomaly_scores([query]), [expected])

    def test_scaling_is_fit_only_robust_and_keeps_constants_and_sparse_features(self):
        rows = [normal()] * 31 + [normal(1)]
        rows[-1][8] = 1
        scorer = NormalSupportScorer().fit(rows)
        before = scorer.to_state()
        query = normal(); query[7], query[9], query[35] = 2, 1, 3
        self.assertGreater(scorer.anomaly_scores([query])[0], 0)
        self.assertEqual(scorer.to_state(), before)
        self.assertEqual(len(before["center"]), 37)
        self.assertEqual(before["scale"][7], 1)  # A constant source dimension remains active.
        self.assertEqual(before["scale"][35], 1)  # History is not masked to conceal COLD mismatch.
        self.assertAlmostEqual(before["scale"][8], np.log(2))  # Sparse observed flag fallback.
        self.assertEqual(before["training_scope"], "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED")
        self.assertEqual(before["applicability"], "UNQUALIFIED_RESEARCH_ONLY")
        rows[0][7] = 99  # Caller-owned buffers cannot mutate the fitted reference.
        self.assertEqual(scorer.to_state(), before)

    def test_legal_seven_vs_eight_neighbors_do_not_clip_outside_fit_extent(self):
        # Only the declared source features differ; no labels or cohort metadata
        # enter fitting. This fixture demonstrates score geometry, not quality.
        scorer = NormalSupportScorer().fit([login_only(i % 8) for i in range(64)])
        for cold in (False, True):
            scores = scorer.anomaly_scores([login_only(i, cold=cold) for i in (7, 8, 9)])
            with self.subTest(cold=cold):
                self.assertGreater(scores[1], scores[0])
                self.assertGreater(scores[2], scores[1])
        self.assertEqual(scorer.to_state()["feature_names"], list(FEATURE_NAMES_V4))

    def test_schema_four_numeric_boundary_and_resource_bounds(self):
        scorer = NormalSupportScorer().fit([normal()] * 8)
        invalids = ([], None, np.array(0), [[0] * 36], [[0] * 1000],
                    [{"features": normal()}], [normal()] * (MAX_SCORE_ROWS + 1))
        for rows in invalids:
            with self.subTest(rows_type=type(rows).__name__), self.assertRaises(ValueError):
                scorer.anomaly_scores(rows)
        for value in (True, "40", complex(40, 1), np.complex128(40), float("inf"),
                      float("nan"), 1_000_001, 1 << 1024):
            row = normal(); row[0] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                scorer.anomaly_scores([row])
        for index, value in ((13, 0), (25, 100), (35, 1345), (36, 21)):
            row = normal(); row[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                scorer.anomaly_scores([row])
        with self.assertRaises(ValueError):
            NormalSupportScorer().fit([normal()] * (MAX_REFERENCE_ROWS + 1))

    def test_json_state_restores_exact_semantics_without_fit_or_executable_input(self):
        scorer = NormalSupportScorer().fit([normal(i) for i in range(56)])
        state = json.loads(json.dumps(scorer.export_state(), allow_nan=False))
        with patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("must not refit")):
            restored = NormalSupportScorer.from_state(state)
        queries = [normal(i) for i in range(12)]
        np.testing.assert_array_equal(restored.anomaly_scores(queries), scorer.anomaly_scores(queries))
        self.assertEqual(restored.to_state(), state)
        state["fit_rows"][0][7] = 2
        self.assertNotEqual(restored.to_state(), state)
        with self.assertRaises(ValueError):
            NormalSupportScorer.from_state(object())

    def test_state_recipe_scaling_bounds_and_shape_are_bound(self):
        base = NormalSupportScorer().fit([normal(i) for i in range(56)]).to_state()
        updates = (("state_version", True), ("state_version", 2), ("reference_count", True),
                   ("reference_count", MAX_REFERENCE_ROWS + 1), ("reference_count", 55),
                   ("fit_count", True), ("fit_count", 55),
                   ("applicability", "QUALIFIED"), ("training_scope", "ALL_ROWS"),
                   ("fit_rows", [normal()] * (MAX_REFERENCE_ROWS + 1)),
                   ("fit_rows", [normal()] * 7), ("center", [0] * 36),
                   ("center", [1 << 1024] * 37),
                   ("scale", [float("nan")] * 37), ("parameters", {"callable": "eval"}),
                   ("feature_names", list(reversed(FEATURE_NAMES_V4))))
        for field, value in updates:
            state = copy.deepcopy(base); state[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                NormalSupportScorer.from_state(state)
        for field in ("center", "scale"):
            state = copy.deepcopy(base); state[field][0] += 0.001
            with self.subTest(field=field), self.assertRaises(ValueError):
                NormalSupportScorer.from_state(state)
        state = copy.deepcopy(base); state["label"] = 0
        with self.assertRaises(ValueError):
            NormalSupportScorer.from_state(state)

    def test_reference_chunk_and_nearly_constant_fit_have_finite_exact_results(self):
        rows = [normal(i) for i in range(1032)]
        for index, row in enumerate(rows):
            row[36] = 0.5 + (index % 2) * 1e-12
        scorer = NormalSupportScorer().fit(rows)
        query = normal(); query[36] = 20
        scores = scorer.anomaly_scores([normal(), query])
        self.assertTrue(np.isfinite(scores).all())
        self.assertGreater(scores[1], scores[0])
        self.assertEqual(scorer.to_state()["scale"][36], 1e-9)

    def test_predeclared_campaign_grid_and_seeded_reference_selection(self):
        rows = [normal(i) for i in range(1_100)]
        for neighbors in (1, 4, 8):
            for count in (128, 256, 512, 1024):
                for metric in ("euclidean", "manhattan"):
                    with self.subTest(neighbors=neighbors, count=count, metric=metric):
                        scorer = NormalSupportScorer(neighbors, count, metric, 11).fit(rows)
                        self.assertEqual(scorer.reference_count, count)
                        self.assertEqual(scorer.fit_count, len(rows))
                        self.assertEqual(scorer.parameters()["recipe_mode"], "CAMPAIGN_SUBSAMPLED")
                        state = scorer.to_state()
                        indices = np.sort(np.random.default_rng(11).choice(len(rows), count, replace=False))
                        self.assertEqual(state["reference_indices"], indices.tolist())
                        restored = NormalSupportScorer.from_state(json.loads(json.dumps(state)))
                        np.testing.assert_array_equal(restored.score_samples([normal()]), scorer.score_samples([normal()]))
        first = NormalSupportScorer(8, 128, "euclidean", 11).fit(rows)
        second = NormalSupportScorer(8, 128, "euclidean", 23).fit(rows)
        self.assertNotEqual(first.to_state()["reference_indices"], second.to_state()["reference_indices"])
        self.assertEqual(first.to_state()["center"], second.to_state()["center"])
        self.assertEqual(first.to_state()["scale"], second.to_state()["scale"])

    def test_campaign_scaling_uses_all_fit_rows_not_selected_references(self):
        rows = [normal()] * 256
        indices = np.sort(np.random.default_rng(11).choice(len(rows), 128, replace=False))
        outside = next(i for i in range(len(rows)) if i not in indices)
        rows[outside] = normal(); rows[outside][8] = 1
        scorer = NormalSupportScorer(1, 128, "manhattan", 11).fit(rows)
        self.assertAlmostEqual(scorer.to_state()["scale"][8], np.log(2))
        query = normal(); query[8] = 1
        self.assertAlmostEqual(scorer.anomaly_scores([query])[0], 1 / 37)
        self.assertEqual(scorer.n_features_in_, 37)
        for parameters in ((0, 128, "euclidean", 42), (True, 128, "euclidean", 42),
                           (8, 129, "euclidean", 42), (8, 128, "cosine", 42),
                           (8, 128, "euclidean", True), (8, 128, "euclidean", 99),
                           (1, None, "euclidean", 42), (8, None, "manhattan", 42)):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                NormalSupportScorer(*parameters)
        with self.assertRaisesRegex(ValueError, "smaller"):
            NormalSupportScorer(8, 1024, "euclidean", 42).fit([normal()] * 700)

    def test_campaign_numeric_selection_and_recipe_cannot_be_relabelled(self):
        base = NormalSupportScorer(4, 128, "manhattan", 42).fit([normal(i) for i in range(256)]).to_state()
        for field, value in (("neighbor_count", True), ("random_state", 11),
                             ("reference_count", 256), ("metric", "euclidean"),
                             ("recipe_mode", "DIAGNOSTIC_FULL_REFERENCE")):
            state = copy.deepcopy(base); state["parameters"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                NormalSupportScorer.from_state(state)
        state = copy.deepcopy(base); state["reference_indices"][0] = True
        with self.assertRaises(ValueError):
            NormalSupportScorer.from_state(state)
        state = copy.deepcopy(base); state["reference_indices"] = state["reference_indices"][::-1]
        with self.assertRaises(ValueError):
            NormalSupportScorer.from_state(state)

    def test_maximum_fit_population_is_accepted_without_increasing_campaign_reference_budget(self):
        scorer = NormalSupportScorer(8, 128, "euclidean", 42).fit([normal()] * MAX_REFERENCE_ROWS)
        self.assertEqual(scorer.fit_count, MAX_REFERENCE_ROWS)
        self.assertEqual(scorer.reference_count, 128)
        np.testing.assert_array_equal(scorer.anomaly_scores([normal()]), [0])


if __name__ == "__main__":
    unittest.main()
