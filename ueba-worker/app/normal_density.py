"""FIT-only local-density diagnostic, deliberately absent from serving contracts.

All schema-4 features and the existing normal-support transform are retained.
Local Outlier Factor compares a query's reachability density to its neighbours,
instead of comparing raw distances across heterogeneous normal regimes. Neither
labels, calibration, thresholds nor cohort IDs enter fitting. This experiment
does not qualify any model or change the primary. Caller must establish that FIT
contains independently verified normal READY windows.
"""

from itertools import product

import numpy as np
from sklearn.neighbors import LocalOutlierFactor

from app.contract import CAMPAIGN_SEEDS, FEATURE_NAMES_V4
from app.normal_support import MAX_REFERENCE_ROWS, MAX_SCORE_ROWS, _features, _scaling, _signed_log

MODEL_KIND = "normal_local_density_research"
RECIPE_VERSION = 2
NEIGHBOUR_GRID = (4, 8, 16)
REFERENCE_GRID = (128, 256, 512, 1024)
METRIC_GRID = ("euclidean", "manhattan")
CONFIGURATIONS = tuple(product(NEIGHBOUR_GRID, REFERENCE_GRID, METRIC_GRID))


class NormalDensityScorer:
    """Non-refittable novelty-only LOF with predeclared bounded recipes.

    This object is not serialized, registered or accepted by ModelStore. Any
    serving integration would require a separate numeric-state verifier and
    strict evaluation. Score-only queries cannot update FIT preprocessing.
    """

    def __init__(self, neighbor_count=8, reference_count=256, metric="euclidean", random_state=42):
        if (type(neighbor_count) is not int or type(reference_count) is not int
                or type(metric) is not str or type(random_state) is not int
                or (neighbor_count, reference_count, metric) not in CONFIGURATIONS
                or random_state not in CAMPAIGN_SEEDS):
            raise ValueError("local-density recipe outside predeclared diagnostic grid")
        self._config = neighbor_count, reference_count, metric, random_state
        self._estimator = self._center = self._scale = self._indices = None
        self.fit_count = 0

    def parameters(self):
        k, count, metric, seed = self._config
        return {"model_kind": MODEL_KIND, "recipe_version": RECIPE_VERSION,
                "neighbor_count": k, "reference_count": count, "metric": metric,
                "random_state": seed, "feature_names": list(FEATURE_NAMES_V4),
                "transform": "UNIFORM_SIGNED_LOG1P", "scaling_population": "ALL_NORMAL_READY_FIT",
                "reference_selection": "PCG64_NO_REPLACEMENT_SORTED_INDICES",
                "center": "FIT_MEDIAN", "scale": "FIT_IQR_LINEAR_QUANTILES",
                "zero_iqr_scale": "FIT_MEDIAN_POSITIVE_ABSOLUTE_DEVIATION_OR_ONE",
                "scale_floor": 1e-9, "estimator": "SKLEARN_LOCAL_OUTLIER_FACTOR",
                "novelty": True, "algorithm": "brute", "n_jobs": 1,
                "contamination": "auto", "decision_function_used": False,
                "raw_score_representation": "LOG1P_NONNEGATIVE_LOF_NOVELTY_RATIO",
                "representation_reason": "FINITE_JAVA_RAW_NUMBER_CONTRACT_NO_CLIPPING",
                "score_samples_direction": "LOWER_IS_MORE_ANOMALOUS",
                "applicability": "UNQUALIFIED_RESEARCH_ONLY"}

    def fit(self, rows):
        if self._estimator is not None:
            raise ValueError("local-density scorer already fitted")
        values = _features(rows, MAX_REFERENCE_ROWS)
        k, count, metric, seed = self._config
        if len(values) < count:
            raise ValueError("FIT smaller than predeclared reference budget")
        center, scale = _scaling(values)
        indices = np.sort(np.random.default_rng(seed).choice(len(values), count, replace=False))
        references = (_signed_log(values[indices]) - center) / scale
        estimator = LocalOutlierFactor(n_neighbors=k, algorithm="brute", metric=metric,
                                      contamination="auto", novelty=True, n_jobs=1).fit(references)
        for array in (center, scale, indices):
            array.setflags(write=False)
        self._center, self._scale, self._indices, self._estimator = center, scale, indices, estimator
        self.fit_count = len(values)
        return self

    def score_samples(self, rows):
        if self._estimator is None:
            raise ValueError("local-density scorer not fitted")
        values = _features(rows, MAX_SCORE_ROWS)
        transformed = (_signed_log(values) - self._center) / self._scale
        ratio = -self._estimator.score_samples(transformed)
        if ratio.shape != (len(values),) or not np.isfinite(ratio).all() or (ratio < 0).any():
            raise ValueError("invalid local-density diagnostic scores")
        # LOF reachability densities include a fixed numerical denominator floor.
        # Duplicate normal references can therefore produce finite ratios >1e6,
        # which the unchanged production Java wire rejects. Uniform log1p is a
        # monotone representation, not clipping or a changed detection threshold.
        # Apply it to BOTH independent calibration and queries. Floating-point
        # ties are still assessed using actual transformed values and midranks.
        result = -np.log1p(ratio)
        if not np.isfinite(result).all() or np.any(np.abs(result) > 1_000_000):
            raise ValueError("invalid local-density wire representation")
        return result

    def anomaly_scores(self, rows):
        return -self.score_samples(rows)
