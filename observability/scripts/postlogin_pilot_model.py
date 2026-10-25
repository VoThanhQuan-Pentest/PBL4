"""One PILOT_ONLY hypothesis: extra before-attempt inputs for the incident classifier.

Normal support still fits exactly the same 37 numeric prefix columns. No IDs,
labels, session keys or scenario metadata enter either numeric component.
This recipe-2 research object cannot be loaded/adopted by strict ModelStore.
"""
import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig, training_labels
from app.normal_support import NormalSupportScorer, _signed_log

MODEL_KIND = "normal_plus_incident_research"


def new_model(kind):
    if kind == "baseline": return HybridIncidentScorer(HybridResearchConfig(100, 15, 0, 42))
    if kind == "candidate": return BeforeAttemptScorer()
    raise ValueError("one fixed baseline and one fixed candidate only")


class BeforeAttemptScorer:
    recipe_version = 2
    applicability = "PILOT_ONLY_UNQUALIFIED"

    def __init__(self):
        self.normal = None
        self.classifier = None

    @staticmethod
    def features(values):
        values = np.asarray(values, dtype=np.float64)
        if values.ndim != 2 or values.shape[1] != 57 or not np.isfinite(values).all():
            raise ValueError("37 server prefix plus 20 precommit features required")
        return values

    def fit(self, normal, labeled, labels):
        if self.classifier is not None: raise ValueError("candidate already fitted")
        normal, labeled = self.features(normal), self.features(labeled)
        targets = training_labels(labels, len(labeled))
        self.normal = NormalSupportScorer(8, 256, "euclidean", 42).fit(normal[:, :37])
        self.classifier = HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15, l2_regularization=0,
            random_state=42, learning_rate=0.1, min_samples_leaf=20, max_bins=255, early_stopping=False,
            categorical_features=None, class_weight=None).fit(_signed_log(labeled), targets)
        return self

    def anomaly_scores(self, rows):
        rows = self.features(rows)
        if self.normal is None or self.classifier is None: raise ValueError("candidate not fitted")
        logits = self.classifier._raw_predict(_signed_log(rows))
        margin = logsumexp(logits[:, 1:], axis=1) - logits[:, 0]
        novelty = np.log(self.normal.anomaly_scores(rows[:, :37]) + 1e-12)
        result = np.maximum(margin, novelty)
        if not np.isfinite(result).all(): raise ValueError("invalid candidate scores")
        return result
