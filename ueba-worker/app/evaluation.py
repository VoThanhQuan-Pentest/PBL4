"""Independent model metrics, with fixed lab gates and cluster-aware uncertainty."""

from collections import defaultdict
import numpy as np

FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
MIN_RECALL = 0.90
MAX_FPR = 0.02
MIN_FAMILY_RECALL = 0.80


def evaluate_percentiles(percentiles, labels, families, groups=None, *, bootstrap_samples=2000,
                         evaluation_scope="FROZEN_HOLDOUT") -> dict:
    if evaluation_scope not in ("FROZEN_HOLDOUT", "VALIDATION", "STRESS"):
        raise ValueError("invalid evaluation scope")
    scores = np.asarray(percentiles, dtype=np.float64)
    truth = np.asarray(labels)
    if (scores.ndim != 1 or truth.ndim != 1 or len(scores) != len(truth) or len(scores) != len(families)
            or not 1 <= len(scores) <= 20_000 or not np.isfinite(scores).all()
            or (scores < 0).any() or (scores > 100).any() or not np.isin(truth, (0, 1)).all()):
        raise ValueError("invalid labelled evaluation")
    if any(not isinstance(family, str) or (label == 1 and family not in FAMILIES)
           for label, family in zip(truth, families)):
        raise ValueError("invalid evaluation family")
    predicted = scores >= 99  # Actual serving UNUSUAL/VERY_UNUSUAL boundary, not predict().
    positive = truth == 1
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & ~positive))
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    precision = tp / (tp + fp) if tp + fp else None
    family_metrics = {}
    for family in FAMILIES:
        selected = positive & (np.asarray(families) == family)
        count = int(np.sum(selected))
        hits = int(np.sum(predicted & selected))
        family_metrics[family] = {"positive_samples": count, "tp": hits,
                                  "fn": count - hits, "recall": hits / count if count else None}
    sizes_ok = fp + tn >= 10_000 and tp + fn >= 1_000 and all(
        item["positive_samples"] >= 200 for item in family_metrics.values())
    families_ok = all(item["recall"] is not None and item["recall"] >= MIN_FAMILY_RECALL
                      for item in family_metrics.values())
    passed = sizes_ok and recall is not None and recall >= MIN_RECALL and fpr is not None and fpr <= MAX_FPR and families_ok
    result = {"scope": "MODEL_ONLY", "evaluation_scope": evaluation_scope,
              "data_provenance": "DEMO_ONLY", "percentile_threshold": 99,
              "normal_samples": fp + tn, "positive_samples": tp + fn,
              "tp": tp, "fp": fp, "tn": tn, "fn": fn,
              "precision": precision, "recall": recall, "false_positive_rate": fpr,
              "families": family_metrics, "minimum_sizes_met": sizes_ok,
              "quality_gate": ("PASS" if passed else "FAIL") if evaluation_scope == "FROZEN_HOLDOUT" else "NOT_APPLICABLE",
              "gates": {"minimum_recall": MIN_RECALL, "maximum_false_positive_rate": MAX_FPR,
                        "minimum_family_recall": MIN_FAMILY_RECALL}}
    if groups is not None:
        if len(groups) != len(scores) or any(not isinstance(group, str) or not 1 <= len(group) <= 160 for group in groups):
            raise ValueError("invalid account/day clusters")
        if not 1 <= bootstrap_samples <= 2000:
            raise ValueError("invalid bootstrap sample count")
        confusion = defaultdict(lambda: np.zeros(4, dtype=np.int64))
        for group, actual, flagged in zip(groups, positive, predicted):
            confusion[group][0 if actual and flagged else 1 if actual else 2 if flagged else 3] += 1
        clusters = np.stack(list(confusion.values()))
        if len(clusters) >= 2:
            rng = np.random.default_rng(42)
            recalls, fprs = [], []
            for _ in range(bootstrap_samples):
                hits, misses, false, correct = clusters[rng.integers(0, len(clusters), len(clusters))].sum(axis=0)
                if hits + misses: recalls.append(hits / (hits + misses))
                if false + correct: fprs.append(false / (false + correct))
            result["confidence_95"] = {
                "method": "account_day_cluster_bootstrap", "clusters": len(clusters),
                "resamples": bootstrap_samples,
                "recall": np.quantile(recalls, [0.025, 0.975]).tolist() if recalls else None,
                "false_positive_rate": np.quantile(fprs, [0.025, 0.975]).tolist() if fprs else None,
            }
        else:
            result["confidence_95"] = {"method": "insufficient_independent_clusters", "clusters": len(clusters)}
    return result
