"""Isolated component contracts, not real incident precision/recall evidence."""

import unittest
from unittest.mock import patch

import numpy as np

from app.contract import MODEL_KINDS
from app.hybrid_incident import (CONFIGURATIONS, MODEL_KIND, HybridIncidentScorer,
                                 HybridResearchConfig, training_labels)
from test_normal_support import normal


def labeled_fixture():
    rows, labels = [], []
    for label in range(3):
        for index in range(60):
            row = normal(index)
            if label == 1:
                row[7] = 2
            elif label == 2:
                row[2] = 10
            rows.append(row); labels.append(label)
    return rows, labels


class HybridIncidentTest(unittest.TestCase):
    def test_declared_grid_typed_recipe_and_research_scope(self):
        self.assertEqual(len(CONFIGURATIONS), 24)
        # Operator-owned registration is added by the worker integration. This
        # class alone still does not constitute a qualified serving candidate.
        self.assertEqual(MODEL_KIND, "normal_plus_incident_research")
        for values in ((True, 31, 1, 42), (200, 5, 1, 42), (200, 31, 1, 0), (200, 31, 0.0, 42)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                HybridResearchConfig(*values)
        with self.assertRaises(ValueError):
            HybridIncidentScorer({"max_iter": 200})
        parameters = HybridIncidentScorer().parameters()
        self.assertFalse(parameters["early_stopping"])
        self.assertFalse(parameters["calibration_used_in_fit"])
        self.assertEqual(len(parameters["feature_names"]), 37)

    def test_label_shape_types_classes_and_minimum_context_population(self):
        targets = [0] * 20 + [1] * 20 + [2] * 20
        np.testing.assert_array_equal(training_labels(targets, 60), targets)
        for value in (True, "1", 1.0, -1, 3, float("nan")):
            changed = targets.copy(); changed[0] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                training_labels(changed, 60)
        for labels in ([], [0] * 60, [[0]] * 60, targets[:-1], np.array(0)):
            with self.assertRaises(ValueError):
                training_labels(labels, 60)

    def test_two_components_fit_no_online_refit_and_caller_mutation(self):
        rows, labels = labeled_fixture()
        normals = [normal(i) for i in range(256)]
        scorer = HybridIncidentScorer(HybridResearchConfig(100, 15, 1, 42))
        with self.assertRaisesRegex(ValueError, "not fitted"):
            scorer.anomaly_scores([normal()])
        self.assertIs(scorer.fit(normals, rows, labels), scorer)
        self.assertEqual(scorer.normal_fit_count, 256)
        self.assertEqual(scorer.labeled_fit_count, 180)
        self.assertEqual(scorer._classifier.n_iter_, 100)
        self.assertFalse(scorer._classifier.do_early_stopping_)
        self.assertEqual(len(scorer._classifier.validation_score_), 0)
        with self.assertRaises(AttributeError):
            scorer.config = HybridResearchConfig()
        query = normal(); query[7] = 2
        before = scorer.anomaly_scores([normal(), query])
        rows[0][7] = 99; normals[0][7] = 99; labels[0] = 2
        np.testing.assert_array_equal(scorer.anomaly_scores([normal(), query]), before)
        self.assertGreater(before[1], before[0])
        with self.assertRaisesRegex(ValueError, "already fitted"):
            scorer.fit(normals, rows, labels)
        with patch.object(scorer._classifier, "fit", side_effect=AssertionError("no online fit")), \
                patch.object(scorer._normal, "fit", side_effect=AssertionError("no online fit")):
            parts = scorer.score_components([normal(), query, normal()])
        self.assertEqual(parts["uncalibrated_context_probabilities"].shape, (3, 3))
        np.testing.assert_allclose(parts["uncalibrated_context_probabilities"].sum(axis=1), 1)
        self.assertEqual(parts["raw_anomaly_score"][0], parts["raw_anomaly_score"][2])
        np.testing.assert_array_equal(scorer.score_samples([normal()]), -scorer.anomaly_scores([normal()]))

    def test_margin_avoids_saturated_probabilities_and_novelty_remains_available(self):
        rows, labels = labeled_fixture()
        scorer = HybridIncidentScorer(HybridResearchConfig(100, 15, 0, 11)).fit(
            [normal(i) for i in range(256)], rows, labels)
        logits = np.array([[0., 1000., -1000.], [1000., 0., -1000.]])
        with patch.object(scorer._classifier, "_raw_predict", return_value=logits), \
                patch.object(scorer._normal, "anomaly_scores", return_value=np.array([0., 1e12])):
            parts = scorer.score_components([normal(), normal()])
        self.assertEqual(parts["incident_margin"][0], 1000)
        self.assertEqual(parts["raw_anomaly_score"][0], 1000)
        self.assertAlmostEqual(parts["raw_anomaly_score"][1], np.log(1e12))
        self.assertTrue(np.isfinite(parts["raw_anomaly_score"]).all())
        for invalid in (np.zeros((2, 2)), np.array([[0., np.nan, 0.], [0., 0., 0.]])):
            with patch.object(scorer._classifier, "_raw_predict", return_value=invalid), self.assertRaises(ValueError):
                scorer.anomaly_scores([normal(), normal()])
        for invalid in (np.array([-1., 0.]), np.array([np.inf, 0.]), np.zeros(1)):
            with patch.object(scorer._normal, "anomaly_scores", return_value=invalid), self.assertRaises(ValueError):
                scorer.anomaly_scores([normal(), normal()])
