"""Tiny unit-fixture state safety checks, never research benchmark evidence."""

import copy
import json
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig, MODEL_KIND
from app.hybrid_semantic import from_state, to_state, state_sha256, verifier_sha256
from app.normal_support import NormalSupportScorer
from app.contract import MODEL_KINDS
from test_hybrid_incident import labeled_fixture
from test_normal_support import normal


class HybridSemanticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exactly one normal fit and one classifier fit, only this existing fixture.
        rows, labels = labeled_fixture()
        cls.model = HybridIncidentScorer(HybridResearchConfig(100, 15, 1, 42)).fit(
            [normal(i) for i in range(256)], rows, labels)
        cls.state = to_state(cls.model)
        cls.queries = [normal(), rows[60], rows[120], normal(13)]

    def changed(self):
        return copy.deepcopy(self.state)

    def test_plain_numeric_roundtrip_exact_predictions_without_fit(self):
        state = json.loads(json.dumps(self.state, allow_nan=False))
        with patch.object(HistGradientBoostingClassifier, "fit", side_effect=AssertionError("no refit")), \
                patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("no refit")):
            restored = from_state(state)
        numeric = np.asarray(self.queries, dtype=np.float64)
        transformed = np.sign(numeric) * np.log1p(np.abs(numeric))
        np.testing.assert_array_equal(self.model._classifier._raw_predict(transformed),
                                      restored._classifier._raw_predict(transformed))
        before, after = self.model.score_components(self.queries), restored.score_components(self.queries)
        for key in before:
            np.testing.assert_array_equal(before[key], after[key])
        self.assertEqual((restored.normal_fit_count, restored.labeled_fit_count), (256, 180))
        self.assertEqual(to_state(restored), state)
        # The operator-owned worker now recognizes the type; qualification and
        # activation remain separate gates, not properties of numeric restore.
        self.assertIn(MODEL_KIND, MODEL_KINDS)

    def test_canonical_numeric_hash_and_source_identity(self):
        expected = state_sha256(self.state)
        self.assertEqual(expected, state_sha256(self.model))
        self.assertEqual(expected, state_sha256(from_state(self.state)))
        self.assertEqual(len(verifier_sha256()), 64)
        changed = self.changed()
        changed["classifier_state"]["predictors"][0][0]["value"][1] += 0.125
        self.assertNotEqual(expected, state_sha256(changed))
        changed = self.changed()
        changed["classifier_state"]["baseline"][0][0] = -0.0
        self.assertNotEqual(expected, state_sha256(changed))

    def test_malformed_shapes_parameters_and_unknown_fields(self):
        changes = (
            lambda s: s.update(unknown=1),
            lambda s: s.update(state_version=True),
            lambda s: s.update(verifier_sha256="0" * 64),
            lambda s: s["parameters"].update(early_stopping=True),
            lambda s: s["parameters"]["config"].update(max_iter=1),
            lambda s: s["classifier_state"].update(classes=[0, 2, 1]),
            lambda s: s["classifier_state"].update(n_features=36),
            lambda s: s["classifier_state"].update(baseline=[[0., 0.]]),
            lambda s: s["classifier_state"].update(predictors=[]),
            lambda s: s["classifier_state"]["predictors"][0].pop(),
            lambda s: s["classifier_state"].update(bin_thresholds=[[]] * 36),
            lambda s: s["classifier_state"]["bin_thresholds"].__setitem__(0, [1., 1.]),
            lambda s: s["classifier_state"]["bin_thresholds"].__setitem__(0, [0.] * 255),
            lambda s: s["classifier_state"]["predictors"][0][0].update(unknown=[]),
        )
        for change in changes:
            state = self.changed(); change(state)
            with self.subTest(change=change), self.assertRaises(ValueError):
                from_state(state)

    def test_native_node_graph_flags_ranges_and_nonfinite_rejected(self):
        modifications = (
            ("left", 0, 999), ("left", 0, 0), ("right", 0, 1),
            ("feature_idx", 0, 37), ("feature_idx", 0, -1),
            ("is_categorical", 0, 1), ("bitset_idx", 0, 1),
            ("is_leaf", 0, 2), ("is_leaf", 0, True),
            ("missing_go_to_left", 0, 2), ("bin_threshold", 0, 255),
            ("depth", 0, 1), ("count", 0, 179), ("count", 1, 0),
            ("count", 1, 2**32), ("value", 0, float("nan")),
            ("num_threshold", 0, float("inf")), ("gain", 0, float("-inf")),
        )
        for field, index, value in modifications:
            state = self.changed()
            state["classifier_state"]["predictors"][0][0][field][index] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                from_state(state)
        state = self.changed()
        fields = state["classifier_state"]["predictors"][0][0]
        for name, values in fields.items():
            values.append(values[-1])
        with self.assertRaisesRegex(ValueError, "unreachable"):
            from_state(state)
        state = self.changed()
        fields = state["classifier_state"]["predictors"][0][0]
        for name, values in fields.items():
            fields[name] = [values[0]] * 30
        with self.assertRaises(ValueError):
            from_state(state)
        state = self.changed()
        fields = state["classifier_state"]["predictors"][0][0]
        leaf = fields["is_leaf"].index(1)
        fields["count"][leaf] = 19
        with self.assertRaises(ValueError):
            from_state(state)

    def test_normal_and_labeled_row_budgets_and_count_binding(self):
        for key, value in (("normal_fit_count", 255), ("normal_fit_count", 50001),
                           ("labeled_fit_count", 59), ("labeled_fit_count", 100001),
                           ("labeled_fit_count", 181)):
            state = self.changed(); state[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                from_state(state)
        state = self.changed(); state["normal_state"]["fit_rows"][0] = [0.] * 38
        with self.assertRaises(ValueError): from_state(state)
        state = self.changed(); state["normal_state"]["fit_rows"][0][0] = float("nan")
        with self.assertRaises(ValueError): from_state(state)
        with patch("app.hybrid_semantic.MAX_NUMERIC_BYTES", 100), self.assertRaisesRegex(ValueError, "budget"):
            from_state(self.state)

    def test_export_refuses_subclasses_categories_unknown_objects_and_native_dtypes(self):
        class Disguised(HybridIncidentScorer):
            pass
        with self.assertRaises(ValueError): to_state(Disguised())
        changed = copy.deepcopy(self.model)
        changed._classifier.unrecognized = object()
        with self.assertRaises(ValueError): to_state(changed)
        changed = copy.deepcopy(self.model)
        changed._classifier._preprocessor = object()
        with self.assertRaises(ValueError): to_state(changed)
        changed = copy.deepcopy(self.model)
        changed._classifier._bin_mapper.is_categorical_[0] = 1
        with self.assertRaises(ValueError): to_state(changed)
        changed = copy.deepcopy(self.model)
        changed._classifier._predictors[0][0].raw_left_cat_bitsets = np.zeros((1, 8), dtype=np.uint32)
        with self.assertRaises(ValueError): to_state(changed)
        changed = copy.deepcopy(self.model)
        changed._classifier._baseline_prediction = changed._classifier._baseline_prediction.astype(np.float32)
        with self.assertRaises(ValueError): to_state(changed)
        class DisguisedClassifier(HistGradientBoostingClassifier):
            pass
        changed = copy.deepcopy(self.model)
        changed._classifier.__class__ = DisguisedClassifier
        with self.assertRaises(ValueError): to_state(changed)


if __name__ == "__main__":
    unittest.main()
