"""One predeclared PILOT_ONLY capacity experiment, with verified normal reuse."""
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_incident import training_labels
from app.normal_support import NormalSupportScorer, _signed_log
from postlogin_pilot_model import BeforeAttemptScorer


class CapacityBeforeAttemptScorer(BeforeAttemptScorer):
    recipe_version = 3
    capacity_parameters = {"max_iter": 400, "max_leaf_nodes": 63, "l2_regularization": 0,
                           "random_state": 42, "learning_rate": .1, "min_samples_leaf": 20,
                           "max_bins": 255, "early_stopping": False, "categorical_features": None,
                           "class_weight": None}

    def fit(self, *args, **kwargs):
        raise ValueError("this trial requires checksum-bound reuse of the identical normal FIT component")

    def fit_reusing_normal(self, normal_model, normal_rows, labeled_rows, labels):
        if self.classifier is not None:
            raise ValueError("capacity candidate is already fitted")
        normal_rows, labeled_rows = self.features(normal_rows), self.features(labeled_rows)
        if type(normal_model) is not NormalSupportScorer:
            raise ValueError("existing normal-support component required")
        state = normal_model.to_state()
        if not np.array_equal(np.asarray(state["fit_rows"]), normal_rows[:, :37]):
            raise ValueError("reused normal component FIT rows/order differ")
        expected = NormalSupportScorer(8, 256, "euclidean", 42).parameters()
        if state["parameters"] != expected:
            raise ValueError("reused normal recipe differs")
        targets = training_labels(labels, len(labeled_rows))
        self.normal = NormalSupportScorer.from_state(state)
        self.classifier = HistGradientBoostingClassifier(**self.capacity_parameters).fit(
            _signed_log(labeled_rows), targets)
        if not np.array_equal(self.classifier.classes_, [0, 1, 2]):
            raise ValueError("three context classes required")
        return self
