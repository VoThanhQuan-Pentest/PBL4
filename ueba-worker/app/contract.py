"""Shared, bounded feature/model recipes; no client-selected executable pipelines."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import product
import hashlib
import json
import re
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from app.hybrid_incident import HybridResearchConfig

SCHEMA_VERSION = 1
FEATURE_NAMES = (
    "request_count", "http_4xx_count", "http_5xx_count",
    "failed_login_count", "successful_login_count", "sensitive_action_count",
    "distinct_route_group_count", "distinct_source_ip_count",
    "new_ip_flag", "new_user_agent_flag", "unusual_hour_flag",
)
FEATURE_COUNT = len(FEATURE_NAMES)
FEATURE_NAMES_V2 = FEATURE_NAMES + (
    "request_log_mad_deviation", "route_group_log_mad_deviation",
    "http_client_error_rate", "failed_login_rate",
)
FEATURE_NAMES_V3 = FEATURE_NAMES_V2 + (
    "request_peak_10s", "request_gap_median_seconds", "request_gap_cv",
    "route_transition_count", "route_transition_rate", "failed_login_log_mad_deviation",
    "sensitive_action_log_mad_deviation", "failed_login_peak_60s", "sensitive_action_peak_60s",
    "consecutive_client_error_peak",
)
FEATURE_NAMES_V4 = FEATURE_NAMES_V3 + (
    "endpoint_metadata_count", "distinct_endpoint_category_count",
    "unmatched_endpoint_request_count", "unresolved_endpoint_request_count",
    "write_request_count", "same_endpoint_peak_10s", "session_metadata_count",
    "distinct_authenticated_session_count", "minimum_authenticated_session_age_seconds",
    "workflow_transition_count", "prior_request_window_count", "short_history_request_log_ratio",
)
FEATURE_SCHEMAS = {1: FEATURE_NAMES, 2: FEATURE_NAMES_V2, 3: FEATURE_NAMES_V3, 4: FEATURE_NAMES_V4}
CAMPAIGN_SEEDS = (11, 23, 42, 73, 101)
IF_MODEL_KIND = "isolation_forest"
SUPPORT_MODEL_KIND = "normal_support_distance"
HYBRID_MODEL_KIND = "normal_plus_incident_research"
MODEL_KINDS = (IF_MODEL_KIND, SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND)
MODEL_RECIPE_FIELDS = ("model_kind", "recipe_version", "recipe_sha256")


def validate_version(version: str) -> None:
    if not isinstance(version, str) or not re.fullmatch(r"[a-z0-9_-]{8,64}", version):
        raise ValueError("invalid model version")


@dataclass(frozen=True)
class TrainingConfig:
    n_estimators: int = 200
    max_samples: int = 256
    max_features: float = 1.0
    random_state: int = 42

    def __post_init__(self):
        if (type(self.n_estimators) is not int or self.n_estimators not in (200, 400, 600)
                or type(self.max_samples) is not int or self.max_samples not in (128, 256, 512, 1024)
                or type(self.max_features) not in (int, float) or self.max_features not in (0.75, 1.0)
                or type(self.random_state) is not int or self.random_state not in CAMPAIGN_SEEDS):
            raise ValueError("training configuration is outside the approved campaign")

    def parameters(self) -> dict:
        return {**asdict(self), "contamination": "auto", "n_jobs": 1}


@dataclass(frozen=True)
class SupportTrainingConfig:
    """Predeclared 24 normal-support recipes; never derived from validation."""
    neighbor_count: int = 8
    reference_count: int = 256
    metric: str = "euclidean"
    random_state: int = 42

    def __post_init__(self):
        if (type(self.neighbor_count) is not int or self.neighbor_count not in (1, 4, 8)
                or type(self.reference_count) is not int or self.reference_count not in (128, 256, 512, 1024)
                or type(self.metric) is not str or self.metric not in ("euclidean", "manhattan")
                or type(self.random_state) is not int or self.random_state not in CAMPAIGN_SEEDS):
            raise ValueError("support configuration is outside the approved campaign")

    def parameters(self) -> dict:
        return asdict(self)


def recipe_binding(config: TrainingConfig | SupportTrainingConfig | HybridResearchConfig) -> dict:
    if type(config) is TrainingConfig: kind = IF_MODEL_KIND
    elif type(config) is SupportTrainingConfig: kind = SUPPORT_MODEL_KIND
    else:
        # Lazy import avoids contract -> hybrid -> normal-support -> contract.
        from app.hybrid_incident import HybridResearchConfig
        if type(config) is not HybridResearchConfig:
            raise ValueError("known typed training recipe required")
        kind = HYBRID_MODEL_KIND
    parameters = asdict(config) if kind == HYBRID_MODEL_KIND else config.parameters()
    identity = {"model_kind": kind, "recipe_version": 1, "config": parameters}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {"model_kind": kind, "recipe_version": 1,
            "recipe_sha256": hashlib.sha256(encoded.encode()).hexdigest()}


def model_recipe_binding(document: dict) -> dict:
    """All-absent legacy IF is supported; partial or unknown identities fail closed."""
    if not isinstance(document, dict): raise ValueError("model recipe mapping required")
    present = [name in document for name in MODEL_RECIPE_FIELDS]
    if not any(present): return {"model_kind": IF_MODEL_KIND, "recipe_version": 1, "recipe_sha256": None}
    if (not all(present) or document["model_kind"] not in MODEL_KINDS
            or type(document["recipe_version"]) is not int or document["recipe_version"] != 1
            or not isinstance(document["recipe_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", document["recipe_sha256"])):
        raise ValueError("invalid model kind/recipe identity")
    return {name: document[name] for name in MODEL_RECIPE_FIELDS}


def parse_training_config(kind: str, values: dict) -> TrainingConfig | SupportTrainingConfig | HybridResearchConfig:
    if not isinstance(values, dict): raise ValueError("typed training configuration required")
    if kind == HYBRID_MODEL_KIND:
        from app.hybrid_incident import HybridResearchConfig
        if set(values) != set(HybridResearchConfig.__dataclass_fields__):
            raise ValueError("explicit hybrid recipe fields required")
        return HybridResearchConfig(**values)
    if kind == SUPPORT_MODEL_KIND:
        return SupportTrainingConfig(**values)
    if kind != IF_MODEL_KIND: raise ValueError("unknown model kind")
    fields = set(TrainingConfig.__dataclass_fields__)
    if set(values) <= fields: return TrainingConfig(**values)
    if set(values) not in (fields, fields | {"contamination", "n_jobs"}):
        raise ValueError("invalid isolation forest recipe fields")
    config = TrainingConfig(**{key: values[key] for key in fields})
    if set(values) != fields and (values != config.parameters() or type(values["n_jobs"]) is not int):
        raise ValueError("invalid isolation forest resource recipe")
    return config


def campaign_runs(model_kind: str = IF_MODEL_KIND) -> list[dict]:
    """360 unique experiment identities, not a count of fitting calls or retries."""
    if model_kind == HYBRID_MODEL_KIND:
        from app.hybrid_incident import CONFIGURATIONS, HybridResearchConfig
        return [{"run_id": f"hybrid-v1-iterations-{iterations}-leaves-{leaves}-l2-{l2}-seed-{seed}-fold-{fold}",
                 "fold": fold, "config": HybridResearchConfig(iterations, leaves, l2, seed)}
                for (iterations, leaves, l2), seed, fold in product(CONFIGURATIONS, CAMPAIGN_SEEDS, (1, 2, 3))]
    if model_kind == SUPPORT_MODEL_KIND:
        return [
            {"run_id": f"support-v1-k-{k}-references-{refs}-metric-{metric}-seed-{seed}-fold-{fold}",
             "fold": fold, "config": SupportTrainingConfig(k, refs, metric, seed)}
            for k, refs, metric, seed, fold in product(
                (1, 4, 8), (128, 256, 512, 1024), ("euclidean", "manhattan"), CAMPAIGN_SEEDS, (1, 2, 3))
        ]
    if model_kind != IF_MODEL_KIND: raise ValueError("unknown campaign model kind")
    return [
        {"run_id": f"trees-{trees}-samples-{samples}-features-{int(fraction * 100)}-seed-{seed}-fold-{fold}",
         "fold": fold, "config": TrainingConfig(trees, samples, fraction, seed)}
        for trees, samples, fraction, seed, fold in product(
            (200, 400, 600), (128, 256, 512, 1024), (0.75, 1.0), CAMPAIGN_SEEDS, (1, 2, 3))
    ]


def feature_array(rows: list[list[float]], maximum: int, schema_version: int = 1) -> np.ndarray:
    if type(schema_version) is not int or schema_version not in FEATURE_SCHEMAS:
        raise ValueError("incompatible feature schema")
    if not 1 <= len(rows) <= maximum:
        raise ValueError("invalid number of feature windows")
    if schema_version == 4 and any(
            not isinstance(row, (list, tuple, np.ndarray))
            or any(isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, float, np.number)) for value in row)
            for row in rows):
        raise ValueError("numeric feature vector required")
    array = np.asarray(rows, dtype=np.float64)
    count = len(FEATURE_SCHEMAS[schema_version])
    if array.ndim != 2 or array.shape[1] != count or not np.isfinite(array).all():
        raise ValueError(f"each feature window must contain {count} finite numbers")
    if (np.abs(array) > 1_000_000).any():
        raise ValueError("feature magnitude exceeds the accepted bound")
    counts = array[:, :8]
    if (counts < 0).any() or (counts != np.floor(counts)).any():
        raise ValueError("event counts must be non-negative integers")
    if (array[:, 1] + array[:, 2] > array[:, 0]).any() or (array[:, 6] > array[:, 0]).any():
        raise ValueError("HTTP counts or route groups exceed request count")
    if not np.isin(array[:, 8:11], (0, 1)).all():
        raise ValueError("novelty flags must be binary")
    if schema_version in (2, 3, 4):
        if (np.abs(array[:, 11:13]) > 20).any():
            raise ValueError("personal deviations exceed the accepted bound")
        expected_errors = array[:, 1] / np.maximum(1, array[:, 0])
        expected_failures = array[:, 3] / np.maximum(1, array[:, 3] + array[:, 4])
        if (not np.allclose(array[:, 13], expected_errors, rtol=0, atol=1e-9)
                or not np.allclose(array[:, 14], expected_failures, rtol=0, atol=1e-9)):
            raise ValueError("rate features do not match server event counts")
    if schema_version in (3, 4):
        temporal_counts = array[:, (15, 18, 22, 23, 24)]
        if (temporal_counts < 0).any() or (temporal_counts != np.floor(temporal_counts)).any():
            raise ValueError("contextual counts must be nonnegative integers")
        if ((array[:, 15] > array[:, 0]).any() or (array[:, 18] > np.maximum(0, array[:, 0] - 1)).any()
                or (array[:, 22] > array[:, 3]).any() or (array[:, 23] > array[:, 5]).any()
                or (array[:, 24] > array[:, 1]).any()):
            raise ValueError("contextual counts exceed source event totals")
        for peak, total in ((15, 0), (22, 3), (23, 5)):
            if ((array[:, total] > 0) & (array[:, peak] < 1)).any():
                raise ValueError("nonempty event sources require a positive rolling peak")
        if ((array[:, 16] < 0).any() or (array[:, 16] >= 900).any()
                or (array[:, 17] < 0).any() or (array[:, 17] > 20).any()
                or (np.abs(array[:, 20:22]) > 20).any()):
            raise ValueError("contextual duration or deviation is outside its bound")
        if ((array[:, 0] < 2)[:, None] & (array[:, 16:18] != 0)).any():
            raise ValueError("a singleton source cannot have request-gap statistics")
        transitions = array[:, 18] / np.maximum(1, array[:, 0] - 1)
        if not np.allclose(array[:, 19], transitions, rtol=0, atol=1e-9):
            raise ValueError("route-transition rate differs from its source count")
    if schema_version == 4:
        metadata_counts = array[:, (25, 26, 27, 28, 29, 30, 31, 32, 34, 35)]
        if (metadata_counts < 0).any() or (metadata_counts != np.floor(metadata_counts)).any():
            raise ValueError("endpoint, session and history counts must be non-negative integers")
        if ((array[:, 25] > array[:, 0]).any() or (array[:, 31] > array[:, 0]).any()
                or (array[:, 27] + array[:, 28] > array[:, 25]).any()):
            raise ValueError("metadata coverage or endpoint sentinels exceed request count")
        matched = array[:, 25] - array[:, 27] - array[:, 28]
        if ((array[:, 26] > matched).any() or (array[:, 26] > 20).any()
                or ((matched > 0) & (array[:, 26] < 1)).any()
                or (array[:, 29] > matched).any() or (array[:, 30] > matched).any()
                or ((matched > 0) & (array[:, 30] < 1)).any()):
            raise ValueError("endpoint category, write count or rolling peak differs from matched coverage")
        if ((array[:, 32] > array[:, 31]).any()
                or ((array[:, 31] > 0) & (array[:, 32] < 1)).any()
                or (array[:, 34] > np.maximum(0, array[:, 31] - array[:, 32])).any()):
            raise ValueError("authenticated session or workflow counts exceed session coverage")
        if ((array[:, 33] < 0).any() or (array[:, 33] > 86400).any()
                or ((array[:, 31] == 0) & (array[:, 33] != 0)).any()):
            raise ValueError("authenticated session age is outside its source bound")
        if ((array[:, 35] > 1344).any() or (np.abs(array[:, 36]) > 20).any()
                or ((array[:, 35] == 0) & (array[:, 36] != 0)).any()):
            raise ValueError("short-history feature is outside its source bound")
    return array
