"""Authorized normal-behaviour + labeled-incident research, not serving admission.

The normal component fits only verified normal READY windows. The supervised
component has separately verified chronological labeled training rows, including
operational failures. Neither calibration, validation nor holdout may be fitted.
Labels, IDs and planned causes never enter either numeric feature matrix.
"""

from dataclasses import asdict, dataclass
from itertools import product

import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier

from app.contract import CAMPAIGN_SEEDS, FEATURE_NAMES_V4
from app.normal_support import NormalSupportScorer, MAX_REFERENCE_ROWS, MAX_SCORE_ROWS, _features, _signed_log

MODEL_KIND = "normal_plus_incident_research"
RECIPE_VERSION = 1
MAX_LABELED_ROWS = 100_000
DISTANCE_LOG_EPSILON = 1e-12
CLASS_NAMES = ("NORMAL", "SECURITY_BEHAVIOR_CONTEXT", "OPERATIONAL_FAILURE_CONTEXT")
CONFIGURATIONS = tuple(product((100, 200, 400), (15, 31, 63, 127), (0, 1)))


@dataclass(frozen=True)
class HybridResearchConfig:
    max_iter: int = 200
    max_leaf_nodes: int = 31
    l2_regularization: int = 1
    random_state: int = 42

    def __post_init__(self):
        if (any(type(value) is not int for value in asdict(self).values())
                or (self.max_iter, self.max_leaf_nodes, self.l2_regularization) not in CONFIGURATIONS
                or self.random_state not in CAMPAIGN_SEEDS):
            raise ValueError("hybrid recipe outside predeclared research grid")


def training_labels(values, count):
    if (not isinstance(values, (list, tuple, np.ndarray))
            or isinstance(values, np.ndarray) and values.ndim != 1 or len(values) != count):
        raise ValueError("corresponding independently verified training labels required")
    if any(isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer))
           or value not in (0, 1, 2) for value in values):
        raise ValueError("explicit three-class integer training labels required")
    result = np.asarray(values, dtype=np.int64)
    if result.shape != (count,) or any(np.count_nonzero(result == label) < 20 for label in (0, 1, 2)):
        raise ValueError("all three training contexts require at least20 verified rows")
    return result


class HybridIncidentScorer:
    """One composite trial contains two genuine component fits, no online update.

    Fixed fusion is max(supervised log-positive-odds margin, log(distance+eps)).
    Unlike bounded-probability fusion, novelty is not bounded below1 by design.
    The two axes still have different natural scales: independent cohort normal
    calibration assesses the fused score, not a claim of calibrated likelihood.
    Labels are planned simulation contexts, never confirmed real attacks.
    Operator-owned worker integration may persist its validated numeric state.
    Registration alone is not quality admission or permission to activate it.
    """

    def __init__(self, config=None):
        self._config = config if config is not None else HybridResearchConfig()
        if type(self._config) is not HybridResearchConfig:
            raise ValueError("typed predeclared hybrid configuration required")
        self._normal = self._classifier = None
        self.normal_fit_count = self.labeled_fit_count = 0

    @property
    def config(self):
        return self._config

    def parameters(self):
        return {"model_kind": MODEL_KIND, "recipe_version": RECIPE_VERSION,
                "config": asdict(self.config), "feature_names": list(FEATURE_NAMES_V4),
                "supervised_transform": "UNIFORM_SIGNED_LOG1P_ALL37",
                "normal_recipe": NormalSupportScorer(8, 256, "euclidean", self.config.random_state).parameters(),
                "classifier": "HIST_GRADIENT_BOOSTING_THREE_CLASS",
                "class_names": list(CLASS_NAMES), "early_stopping": False,
                "learning_rate": 0.1, "min_samples_leaf": 20, "max_bins": 255,
                "class_weight": None, "categorical_features": None,
                "fusion": "MAX_LOG_POSITIVE_ODDS_MARGIN_AND_LOG_SUPPORT_DISTANCE_PLUS_EPSILON",
                "distance_log_epsilon": DISTANCE_LOG_EPSILON,
                "supervised_margin": "LOGSUMEXP_CLASS1_CLASS2_RAW_LOGITS_MINUS_CLASS0_RAW_LOGIT",
                "internal_logits_api": "PINNED_SKLEARN_RAW_PREDICT_USED_BY_PREDICT_PROBA",
                "calibration_used_in_fit": False, "training_scope": "SEPARATE_CHRONOLOGICAL_TRAINING_ONLY",
                "context_probability_applicability": "UNCALIBRATED_TRAINING_PRIOR_NOT_REAL_WORLD_RISK",
                "applicability": "UNQUALIFIED_RESEARCH_ONLY"}

    def fit(self, normal_ready_rows, labeled_rows, labels):
        if self._classifier is not None:
            raise ValueError("hybrid scorer already fitted")
        normal = _features(normal_ready_rows, MAX_REFERENCE_ROWS)
        labeled = _features(labeled_rows, MAX_LABELED_ROWS)
        targets = training_labels(labels, len(labeled))
        normal_model = NormalSupportScorer(8, 256, "euclidean", self.config.random_state).fit(normal)
        classifier = HistGradientBoostingClassifier(**asdict(self.config), learning_rate=0.1,
            min_samples_leaf=20, max_bins=255, early_stopping=False,
            categorical_features=None, class_weight=None).fit(_signed_log(labeled), targets)
        if not np.array_equal(classifier.classes_, np.array([0, 1, 2])):
            raise ValueError("explicit trained context class ordering required")
        self._normal, self._classifier = normal_model, classifier
        self.normal_fit_count, self.labeled_fit_count = len(normal), len(labeled)
        return self

    def score_components(self, rows):
        if self._classifier is None:
            raise ValueError("hybrid scorer not fitted")
        features = _features(rows, MAX_SCORE_ROWS)
        logits = self._classifier._raw_predict(_signed_log(features))
        if logits.shape != (len(features), 3) or not np.isfinite(logits).all():
            raise ValueError("invalid hybrid learned context logits")
        margin = logsumexp(logits[:, 1:], axis=1) - logits[:, 0]
        distance = self._normal.anomaly_scores(features)
        if distance.shape != (len(features),) or not np.isfinite(distance).all() or (distance < 0).any():
            raise ValueError("invalid hybrid normal support distances")
        novelty = np.log(distance + DISTANCE_LOG_EPSILON)
        fused = np.maximum(margin, novelty)
        probabilities = np.exp(logits - logsumexp(logits, axis=1, keepdims=True))
        if (not np.isfinite(fused).all() or np.any(np.abs(fused) > 1_000_000)
                or not np.isfinite(probabilities).all()):
            raise ValueError("invalid finite hybrid diagnostic scores")
        return {"raw_anomaly_score": fused, "incident_margin": margin,
                "normal_support_distance": distance, "normal_novelty_log_score": novelty,
                "uncalibrated_context_probabilities": probabilities}

    def anomaly_scores(self, rows):
        return self.score_components(rows)["raw_anomaly_score"]

    def score_samples(self, rows):
        return -self.anomaly_scores(rows)
