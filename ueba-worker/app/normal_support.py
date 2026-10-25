"""Isolated, normal-only support-distance research scorer; never a quality gate.

The caller must supply only independently verified normal READY FIT rows. A
numeric feature vector cannot establish label, cohort or split provenance. No
IDs, labels, calibration, thresholds or serving policy enter this estimator.
READY fitting does not qualify COLD (or any other cohort) for serving.

All 37 features remain in the metric, including constant source/device/history
features. Uniform signed-log compression and robust FIT-only scaling make the
distance interpretable, but do not remove correlated/redundant features or
distribution mismatch. Mean nearest-neighbour distance is continuous, not a
probability or normal percentile. Exact brute-force inference is a bounded
prototype, not evidence that million-row calibration is operationally feasible.
"""

from __future__ import annotations

import numpy as np

from app.contract import CAMPAIGN_SEEDS, FEATURE_NAMES_V4, feature_array


MODEL_KIND = "normal_support_distance"
RECIPE_VERSION = 1
MAX_REFERENCE_ROWS = 50_000
MAX_SCORE_ROWS = 10_000
NEIGHBOURS = 8
CAMPAIGN_NEIGHBOURS = (1, 4, 8)
CAMPAIGN_REFERENCE_COUNTS = (128, 256, 512, 1_024)
CAMPAIGN_METRICS = ("euclidean", "manhattan")
QUERY_CHUNK_ROWS = 16
REFERENCE_CHUNK_ROWS = 1_024
SCALE_FLOOR = 1e-9
TRAINING_SCOPE = "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED"
APPLICABILITY = "UNQUALIFIED_RESEARCH_ONLY"


def _features(rows, maximum: int) -> np.ndarray:
    """Use the real schema-4 boundary, rejecting complex and coercible inputs."""
    if not isinstance(rows, (list, tuple, np.ndarray)):
        raise ValueError("bounded numeric feature windows required")
    try:
        if not 1 <= len(rows) <= maximum:
            raise ValueError("bounded numeric feature windows required")
        if any(not isinstance(row, (list, tuple, np.ndarray))
               or len(row) != len(FEATURE_NAMES_V4)
               or any(isinstance(value, (complex, np.complexfloating)) for value in row)
               for row in rows):
            raise ValueError("numeric feature vector required")
        return feature_array(rows, maximum, 4).copy()
    except (TypeError, OverflowError):
        raise ValueError("numeric feature vector required") from None


def _signed_log(rows: np.ndarray) -> np.ndarray:
    return np.sign(rows) * np.log1p(np.abs(rows))


def _scaling(reference: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    transformed = _signed_log(reference)
    center = np.median(transformed, axis=0)
    quartiles = np.quantile(transformed, (0.25, 0.75), axis=0, method="linear")
    scale = quartiles[1] - quartiles[0]
    for column in np.flatnonzero(scale == 0):
        deviations = np.abs(transformed[:, column] - center[column])
        positive = deviations[deviations > 0]
        # Sparse but observed variation stays represented; truly constant
        # features are not dropped and retain unit signed-log scale.
        scale[column] = float(np.median(positive)) if len(positive) else 1.0
    return center, np.maximum(scale, SCALE_FLOOR)


class NormalSupportScorer:
    """Predeclared non-refittable recipes, using bounded schema-4 FIT vectors.

    ``anomaly_scores`` returns higher values farther from FIT support.
    ``score_samples`` returns its negative for sklearn/worker compatibility.
    ``to_state``/``from_state`` preserve plain numeric semantic state without
    loading executable pickle input. The state contains private FIT vectors;
    callers must protect persisted files and establish their provenance. Fit
    rows are retained only to bind/recheck full-population preprocessing during
    numeric restoration, not used as distances beyond the chosen reference set.
    """

    n_features_in_ = len(FEATURE_NAMES_V4)
    model_kind = MODEL_KIND
    recipe_version = RECIPE_VERSION

    def __init__(self, neighbor_count: int = 8, reference_count: int | None = None,
                 metric: str = "euclidean", random_state: int = 42):
        # Full-reference default is a single diagnostic, not part of the 24
        # campaign recipes. The campaign grid was declared before scoring:
        # 3 k values * 4 reference budgets * 2 metrics, with five seed choices.
        if (type(neighbor_count) is not int or type(random_state) is not int
                or type(metric) is not str or random_state not in CAMPAIGN_SEEDS
                or (reference_count is None and (neighbor_count, metric, random_state) != (8, "euclidean", 42))
                or (reference_count is not None and (
                    type(reference_count) is not int or reference_count not in CAMPAIGN_REFERENCE_COUNTS
                    or neighbor_count not in CAMPAIGN_NEIGHBOURS or metric not in CAMPAIGN_METRICS))):
            raise ValueError("support recipe is outside the predeclared research grid")
        self._configuration = neighbor_count, reference_count, metric, random_state
        self._fit_rows: np.ndarray | None = None
        self._reference_indices: np.ndarray | None = None
        self._reference: np.ndarray | None = None
        self._center: np.ndarray | None = None
        self._scale: np.ndarray | None = None
        self._standardized: np.ndarray | None = None

    def parameters(self) -> dict:
        """Recipe/configuration binding; not an existing IF campaign identity."""
        neighbor_count, reference_count, metric, random_state = self._configuration
        return {"model_kind": MODEL_KIND, "recipe_version": RECIPE_VERSION,
                "recipe_mode": "DIAGNOSTIC_FULL_REFERENCE" if reference_count is None else "CAMPAIGN_SUBSAMPLED",
                "neighbor_count": neighbor_count, "reference_count": reference_count,
                "metric": metric, "random_state": random_state,
                "feature_schema_version": 4, "transform": "UNIFORM_SIGNED_LOG1P",
                "center": "FIT_MEDIAN", "scale": "FIT_IQR_LINEAR_QUANTILES",
                "zero_iqr_scale": "FIT_MEDIAN_POSITIVE_ABSOLUTE_DEVIATION_OR_ONE",
                "scale_floor": SCALE_FLOOR, "feature_weighting": "ALL_37_EQUAL",
                "distance_normalization": "RMS" if metric == "euclidean" else "MEAN_ABSOLUTE",
                "aggregation": "MEAN_K_NEAREST_DISTANCE", "search": "EXACT_NUMPY_DIRECT_SUBTRACTION",
                "reference_selection": "ALL_FIT_ROWS" if reference_count is None else "PCG64_NO_REPLACEMENT_SORTED_INDICES",
                "scaling_population": "ALL_FIT_ROWS_BEFORE_REFERENCE_SELECTION",
                "max_reference_rows": MAX_REFERENCE_ROWS, "max_score_rows": MAX_SCORE_ROWS,
                "query_chunk_rows": QUERY_CHUNK_ROWS, "reference_chunk_rows": REFERENCE_CHUNK_ROWS,
                "score_samples_direction": "LOWER_IS_MORE_ANOMALOUS"}

    @property
    def reference_count(self) -> int:
        return 0 if self._reference is None else len(self._reference)

    @property
    def fit_count(self) -> int:
        return 0 if self._fit_rows is None else len(self._fit_rows)

    def _selection(self, count: int) -> np.ndarray:
        _, reference_count, _, random_state = self._configuration
        if reference_count is None:
            return np.arange(count, dtype=np.int64)
        if count < reference_count:
            raise ValueError("normal FIT population is smaller than the selected reference budget")
        return np.sort(np.random.default_rng(random_state).choice(count, reference_count, replace=False))

    def _install(self, fit_rows: np.ndarray, indices: np.ndarray,
                 center: np.ndarray, scale: np.ndarray) -> None:
        reference = fit_rows[indices]
        standardized = (_signed_log(reference) - center) / scale
        for value in (fit_rows, indices, reference, center, scale, standardized):
            value.setflags(write=False)
        self._fit_rows, self._reference_indices = fit_rows, indices
        self._reference, self._center, self._scale = reference, center, scale
        self._standardized = standardized

    def fit(self, rows) -> NormalSupportScorer:
        if self._reference is not None:
            raise ValueError("support scorer is already fitted")
        reference = _features(rows, MAX_REFERENCE_ROWS)
        if len(reference) < self._configuration[0]:
            raise ValueError(f"support fitting requires at least {self._configuration[0]} normal FIT windows")
        indices = self._selection(len(reference))
        center, scale = _scaling(reference)
        self._install(reference, indices, center, scale)
        return self

    def anomaly_scores(self, rows) -> np.ndarray:
        if self._reference is None:
            raise ValueError("support scorer is not fitted")
        features = _features(rows, MAX_SCORE_ROWS)
        queries = (_signed_log(features) - self._center) / self._scale
        result = np.empty(len(queries), dtype=np.float64)
        neighbor_count, _, metric, _ = self._configuration
        for start in range(0, len(queries), QUERY_CHUNK_ROWS):
            query = queries[start:start + QUERY_CHUNK_ROWS]
            nearest = np.full((len(query), neighbor_count), np.inf)
            for offset in range(0, self.reference_count, REFERENCE_CHUNK_ROWS):
                reference = self._standardized[offset:offset + REFERENCE_CHUNK_ROWS]
                # Direct differences give exact duplicate distances of zero,
                # without dot-product cancellation. The largest 3-D scratch
                # is 16 * 1024 * 37 float64s (~4.6 MiB), independent of FIT size.
                differences = query[:, None, :] - reference[None, :, :]
                if metric == "euclidean":
                    np.square(differences, out=differences)
                else:
                    np.abs(differences, out=differences)
                distances = np.mean(differences, axis=2)
                candidates = np.concatenate((nearest, distances), axis=1)
                nearest = np.partition(candidates, neighbor_count - 1, axis=1)[:, :neighbor_count]
            # Sorting also fixes floating-point reduction order across ties and
            # reference permutations. Query batch composition cannot change it.
            ordered = np.sort(nearest, axis=1)
            if metric == "euclidean":
                np.sqrt(ordered, out=ordered)
            result[start:start + len(query)] = np.mean(ordered, axis=1)
        return result

    def score_samples(self, rows) -> np.ndarray:
        return -self.anomaly_scores(rows)

    def to_state(self) -> dict:
        if self._reference is None:
            raise ValueError("support scorer is not fitted")
        return {"state_version": 1, "parameters": self.parameters(),
                "feature_names": list(FEATURE_NAMES_V4), "training_scope": TRAINING_SCOPE,
                "applicability": APPLICABILITY, "reference_count": self.reference_count,
                "fit_count": self.fit_count, "fit_rows": self._fit_rows.tolist(),
                "reference_indices": self._reference_indices.tolist(), "center": self._center.tolist(),
                "scale": self._scale.tolist()}

    export_state = to_state

    @classmethod
    def from_state(cls, state: dict) -> NormalSupportScorer:
        required = {"state_version", "parameters", "feature_names", "training_scope", "applicability",
                    "fit_count", "reference_count", "fit_rows", "reference_indices", "center", "scale"}
        if (not isinstance(state, dict) or set(state) != required or type(state["state_version"]) is not int
                or state["state_version"] != 1 or not isinstance(state["parameters"], dict)
                or state["feature_names"] != list(FEATURE_NAMES_V4)
                or state["training_scope"] != TRAINING_SCOPE or state["applicability"] != APPLICABILITY
                or type(state["fit_count"]) is not int or not 1 <= state["fit_count"] <= MAX_REFERENCE_ROWS
                or type(state["reference_count"]) is not int
                or not 1 <= state["reference_count"] <= MAX_REFERENCE_ROWS):
            raise ValueError("invalid support numeric state contract")
        config = state["parameters"]
        config_keys = ("neighbor_count", "reference_count", "metric", "random_state")
        if not all(key in config for key in config_keys):
            raise ValueError("invalid support recipe state")
        model = cls(**{key: config[key] for key in config_keys})
        expected_parameters = model.parameters()
        if (set(config) != set(expected_parameters)
                or any(type(config[key]) is not type(value) or config[key] != value
                       for key, value in expected_parameters.items())):
            raise ValueError("invalid support recipe state")
        reference = _features(state["fit_rows"], MAX_REFERENCE_ROWS)
        if len(reference) != state["fit_count"] or len(reference) < model._configuration[0]:
            raise ValueError("support FIT count differs from numeric state")
        indices = model._selection(len(reference))
        stored_indices = state["reference_indices"]
        if (not isinstance(stored_indices, list) or len(stored_indices) != len(indices)
                or state["reference_count"] != len(indices)
                or any(type(value) is not int for value in stored_indices)
                or not np.array_equal(indices, stored_indices)):
            raise ValueError("support reference selection differs from numeric state")
        center, scale = _scaling(reference)
        for name, expected in (("center", center), ("scale", scale)):
            values = state[name]
            if (not isinstance(values, list) or len(values) != len(FEATURE_NAMES_V4)
                    or any(type(value) not in (int, float) for value in values)):
                raise ValueError("support FIT-only scaling differs from numeric state")
            try:
                matches = np.array_equal(np.asarray(values, dtype=np.float64), expected)
            except (TypeError, OverflowError):
                matches = False
            if not matches:
                raise ValueError("support FIT-only scaling differs from numeric state")
        # Restoration checks/rebuilds learned state without invoking fit().
        model._install(reference, indices, center, scale)
        return model
