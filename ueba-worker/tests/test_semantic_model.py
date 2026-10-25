from io import BytesIO
import copy
import hashlib
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.tree import _tree

from app.semantic_model import state_sha256


def payload():
    values = np.asarray([[4.0 + index % 7, 0.0, index % 3] for index in range(600)])
    model = IsolationForest(n_estimators=200, max_samples=128, random_state=42, n_jobs=1).fit(values)
    return {"model": model, "calibration_scores": np.sort(-model.score_samples(values[:100]))}


class SemanticModelTest(unittest.TestCase):
    def test_actual_repeat_fit_has_exact_numeric_identity(self):
        self.assertEqual(state_sha256(payload()), state_sha256(payload()))

    def test_only_padding_is_ignored_not_any_learned_numeric_field(self):
        original = payload(); changed = copy.deepcopy(original)
        expected = state_sha256(original)
        tree = changed["model"].estimators_[0].tree_
        state = tree.__getstate__(); nodes = state["nodes"]
        used = np.zeros(nodes.dtype.itemsize, dtype=bool)
        for field, offset in nodes.dtype.fields.values(): used[offset:offset + field.itemsize] = True
        gaps = np.flatnonzero(~used); self.assertGreater(len(gaps), 0)
        raw = nodes.view(np.uint8).reshape(-1, nodes.dtype.itemsize)
        raw[:, gaps] ^= np.uint8(0x5A); tree.__setstate__(state)
        self.assertEqual(state_sha256(changed), expected)
        old_bytes, new_bytes = BytesIO(), BytesIO()
        joblib.dump(original, old_bytes); joblib.dump(changed, new_bytes)
        self.assertNotEqual(hashlib.sha256(old_bytes.getvalue()).hexdigest(), hashlib.sha256(new_bytes.getvalue()).hexdigest())
        state = tree.__getstate__(); state["nodes"]["threshold"][0] += 0.125; tree.__setstate__(state)
        self.assertNotEqual(state_sha256(changed), expected)
        changed = copy.deepcopy(original); changed["model"].offset_ += 0.01
        self.assertNotEqual(state_sha256(changed), expected)
        changed = copy.deepcopy(original); changed["calibration_scores"][0] += 0.001
        self.assertNotEqual(state_sha256(changed), expected)

    def test_unknown_payload_and_state_are_refused_not_ignored(self):
        original = payload()
        for changed in (original | {"unrecognized": 1}, original | {"model": object()},
                        original | {"calibration_scores": np.asarray([object()])}):
            with self.assertRaises(ValueError): state_sha256(changed)
        changed = copy.deepcopy(original); changed["model"].unexpected_state = object()
        with self.assertRaises(ValueError): state_sha256(changed)

    def test_tree_constructor_identity_is_not_lost_in_getstate(self):
        original = payload(); changed = copy.deepcopy(original)
        tree = changed["model"].estimators_[0].tree_
        replacement = _tree.Tree(tree.n_features + 1, tree.n_classes, tree.n_outputs)
        replacement.__setstate__(tree.__getstate__())
        changed["model"].estimators_[0].tree_ = replacement
        self.assertNotEqual(state_sha256(original), state_sha256(changed))

    def test_aggregate_budgets_apply_even_to_individually_small_values(self):
        original = payload()
        with patch("app.semantic_model.MAX_VISITS", 100):
            with self.assertRaisesRegex(ValueError, "aggregate.*traversal"): state_sha256(original)
        with patch("app.semantic_model.MAX_TOTAL_ARRAY_BYTES", 100):
            with self.assertRaisesRegex(ValueError, "aggregate.*numeric-byte"): state_sha256(original)


if __name__ == "__main__": unittest.main()
