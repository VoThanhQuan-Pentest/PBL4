"""Recipe5: fixed baseline37 vs candidate65 on the SAME observable-context source.

Research only. Percentiles and component outputs are not attack probabilities.
This object cannot be adopted by the historical strict schema4 model store.
"""
import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_incident import training_labels
from app.normal_support import NormalSupportScorer, _signed_log

PARAMETERS = {"max_iter": 100, "max_leaf_nodes": 15, "l2_regularization": 0,
              "random_state": 42, "learning_rate": .1, "min_samples_leaf": 20,
              "max_bins": 255, "early_stopping": False, "categorical_features": None, "class_weight": None}


class ObservableContextScorer:
    recipe_version = 5
    feature_schema_version = 6
    applicability = "PILOT_ONLY_RULE_DISTILLATION"

    def __init__(self, projection):
        if projection not in ("baseline", "candidate"):
            raise ValueError("explicit baseline37 or candidate65 projection required")
        self.projection = projection
        self.normal = None
        self.classifier = None

    def values(self, values):
        values = np.asarray(values, dtype=np.float64)
        if values.ndim != 2 or values.shape[1] != 65 or not np.isfinite(values).all():
            raise ValueError("finite schema6 full-width input required")
        return values[:, :37] if self.projection == "baseline" else values

    def fit(self, normal, labeled, labels, reserve_component):
        if self.normal is not None or self.classifier is not None:
            raise ValueError("scorer already fitted")
        normal, labeled = self.values(normal), self.values(labeled)
        targets = training_labels(labels, len(labeled))
        reserve_component("normal")
        self.normal = NormalSupportScorer(8, 256, "euclidean", 42).fit(normal[:, :37])
        reserve_component("classifier")
        self.classifier = HistGradientBoostingClassifier(**PARAMETERS).fit(_signed_log(labeled), targets)
        return self

    def anomaly_scores(self, rows):
        rows = self.values(rows)
        if self.normal is None or self.classifier is None:
            raise ValueError("unfitted scorer")
        logits = self.classifier._raw_predict(_signed_log(rows))
        margin = logsumexp(logits[:, 1:], axis=1) - logits[:, 0]
        novelty = np.log(self.normal.anomaly_scores(rows[:, :37]) + 1e-12)
        result = np.maximum(margin, novelty)
        if not np.isfinite(result).all():
            raise ValueError("nonfinite scores")
        return result

    def contexts(self, rows):
        return np.argmax(self.classifier._raw_predict(_signed_log(self.values(rows))), axis=1)
