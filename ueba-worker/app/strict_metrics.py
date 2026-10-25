"""Streaming-quality math. Counter unit fixtures are never presented as a scored benchmark."""

from dataclasses import dataclass
import math
import numpy as np
from scipy.stats import beta

from app.policy import ScorePolicy, PROBABILITY_SCALE

SCOPES = ("MODEL_ONLY", "SIEM_FINAL")
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")


@dataclass(frozen=True)
class Confusion:
    tp: int
    fn: int
    fp: int
    tn: int

    def __post_init__(self):
        if any(type(value) is not int or value < 0 for value in (self.tp, self.fn, self.fp, self.tn)):
            raise ValueError("invalid confusion counters")

    @property
    def positives(self): return self.tp + self.fn
    @property
    def normals(self): return self.fp + self.tn
    @property
    def predictions(self): return self.tp + self.fp

    def metrics(self):
        return {"tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn,
                "normal_samples": self.normals, "positive_samples": self.positives,
                "precision": self.tp / self.predictions if self.predictions else None,
                "recall": self.tp / self.positives if self.positives else None,
                "false_positive_rate": self.fp / self.normals if self.normals else None}


def exact_bounds(successes, trials, alpha):
    if type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials or not 0 < alpha < 1:
        raise ValueError("invalid binomial bound input")
    if trials == 0: return {"lower": 0.0, "upper": 1.0, "available": False}
    lower = float(beta.ppf(alpha, successes, trials - successes + 1)) if successes else 0.0
    upper = float(beta.ppf(1 - alpha, successes + 1, trials - successes)) if successes < trials else 1.0
    return {"lower": lower, "upper": upper, "available": True}


def confidence_for(counts: Confusion, policy: ScorePolicy, clusters=None):
    quality = policy.document["quality"]
    alpha = quality["alpha_numerator"] / quality["alpha_denominator"] / quality["global_comparisons"]
    exact = {"precision": exact_bounds(counts.tp, counts.predictions, alpha),
             "recall": exact_bounds(counts.tp, counts.positives, alpha),
             "false_positive_rate": exact_bounds(counts.fp, counts.normals, alpha)}
    result = {"method": "exact_binomial_and_account_day_cluster_bootstrap",
              "iid_assumption_warning": "Exact binomial bounds assume IID; cluster bounds do not prove deployment representativeness.",
              "familywise_confidence": 0.95, "comparisons": quality["global_comparisons"],
              "one_sided_alpha": alpha, "exact": exact, "cluster_available": False,
              "conservative": {name: dict(value) for name, value in exact.items()}}
    if clusters is None: return result
    matrix = np.asarray(clusters, dtype=np.int64)
    if matrix.ndim != 2 or matrix.shape[1] != 4 or len(matrix) < 2 or (matrix < 0).any():
        raise ValueError("At least two real account/day clusters with TP,FN,FP,TN are required")
    if matrix.sum(axis=0).tolist() != [counts.tp, counts.fn, counts.fp, counts.tn]:
        raise ValueError("cluster counters do not match aggregate counters")
    rng = np.random.default_rng(42)
    precision, recall, fpr = [], [], []
    for _ in range(quality["cluster_resamples"]):
        tp, fn, fp, tn = matrix[rng.integers(0, len(matrix), len(matrix))].sum(axis=0)
        if tp + fp: precision.append(tp / (tp + fp))
        if tp + fn: recall.append(tp / (tp + fn))
        if fp + tn: fpr.append(fp / (fp + tn))
    cluster = {}
    for name, values in (("precision", precision), ("recall", recall), ("false_positive_rate", fpr)):
        bounds = np.quantile(values, [alpha, 1 - alpha]).tolist() if values else [0.0, 1.0]
        cluster[name] = {"lower": bounds[0], "upper": bounds[1], "available": bool(values)}
        result["conservative"][name] = {"lower": min(exact[name]["lower"], bounds[0]),
                                          "upper": max(exact[name]["upper"], bounds[1]),
                                          "available": exact[name]["available"] and bool(values)}
    result.update(cluster_available=True, cluster=cluster, clusters=len(matrix), resamples=quality["cluster_resamples"])
    return result


def strict_gate(counts: Confusion, policy: ScorePolicy, families, cohorts, confidence, *, scope, stage="FROZEN_HOLDOUT"):
    if not policy.strict_gate or scope not in SCOPES or stage not in ("FROZEN_HOLDOUT", "VALIDATION", "STRESS"):
        raise ValueError("invalid strict gate scope/stage")
    quality = policy.document["quality"]
    metrics = counts.metrics()
    reasons = []
    if counts.normals < quality["minimum_normal"] or counts.positives < quality["minimum_positive"]:
        reasons.append("INSUFFICIENT_POPULATION")
    targets = {"precision": quality["precision_min_ppm"] / PROBABILITY_SCALE,
               "recall": quality["recall_min_ppm"] / PROBABILITY_SCALE,
               "false_positive_rate": quality["fpr_max_ppm"] / PROBABILITY_SCALE}
    point_ok = (metrics["precision"] is not None and metrics["precision"] >= targets["precision"]
                and metrics["recall"] is not None and metrics["recall"] > targets["recall"]
                and metrics["false_positive_rate"] is not None and metrics["false_positive_rate"] < targets["false_positive_rate"])
    if not point_ok: reasons.append("POINT_METRIC_GATE_FAILED")
    bounds = confidence.get("conservative", {})
    ci_ok = (confidence.get("comparisons") == 6 and confidence.get("cluster_available") is True
             and all(bounds.get(name, {}).get("available") for name in targets)
             and bounds["precision"]["lower"] >= targets["precision"]
             and bounds["recall"]["lower"] > targets["recall"]
             and bounds["false_positive_rate"]["upper"] < targets["false_positive_rate"])
    if not ci_ok: reasons.append("CONFIDENCE_GATE_FAILED")
    if set(families) != set(FAMILIES) or sum(row.positives for row in families.values()) != counts.positives:
        raise ValueError("family populations do not match global positive population")
    for family, row in families.items():
        if row.positives < quality["minimum_family_positive"] or row.tp / row.positives <= 0.99:
            reasons.append("FAMILY_RECALL_OR_POPULATION_FAILED:" + family)
    if set(cohorts) != {"READY", "UNSEEN_READY", "COLD"}:
        raise ValueError("all applicability cohorts must be reported")
    if sum(row.normals for row in cohorts.values()) != counts.normals or sum(row.positives for row in cohorts.values()) != counts.positives:
        raise ValueError("cohort counters do not match global population")
    for cohort, row in cohorts.items():
        if not row.positives or row.tp / row.positives <= 0.99:
            reasons.append("COHORT_RECALL_FAILED:" + cohort)
    return {**metrics, **policy.wire(), "scope": scope, "evaluation_scope": stage,
            "data_provenance": "DEMO_ONLY", "confidence": confidence, "failure_reasons": reasons,
            "quality_gate": ("PASS" if not reasons else "FAIL") if stage == "FROZEN_HOLDOUT" else "NOT_APPLICABLE",
            "families": {key: value.metrics() for key, value in families.items()},
            "cohorts": {key: value.metrics() for key, value in cohorts.items()}}
