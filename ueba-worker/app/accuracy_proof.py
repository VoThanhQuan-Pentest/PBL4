"""Derived accuracy evidence from the unchanged simultaneous recall/FPR bounds.

This cannot admit a model or establish data provenance. Parent evaluation must
verify its scored journal and confidence evidence. No new fitted parameter,
threshold tuning, policy hash, or statistical comparison is introduced.
"""
import math

from app.strict_metrics import Confusion, SCOPES, exact_bounds


def _probability(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def derive_accuracy(counts, confidence, *, scope):
    if not isinstance(counts, Confusion) or scope not in SCOPES or not isinstance(confidence, dict):
        raise ValueError("checked confusion counters, scope and parent confidence required")
    total = counts.positives + counts.normals
    prevalence = counts.positives / total if total else None
    accuracy = (counts.tp + counts.tn) / total if total else None
    result = {"format": "DERIVED_ACCURACY_FROM_RECALL_FPR_V1", "scope": scope,
              "scored_rows": total, "positive_samples": counts.positives, "normal_samples": counts.normals,
              "point_accuracy": accuracy, "observed_prevalence": prevalence,
              "required_accuracy_strictly_above": 0.98,
              "point_condition_satisfied": total > 0 and 100 * (counts.tp + counts.tn) > 98 * total,
              "confidence_available": False, "derived_accuracy_lower_bound": None,
              "derived_confidence_condition_satisfied": False, "quality_gate": "NOT_APPLICABLE",
              "parent_scored_journal_and_confidence_verification_required": True,
              "additional_statistical_comparisons": 0,
              "derivation": "prevalence*recall_lower + (1-prevalence)*(1-fpr_upper)"}
    if not counts.positives or not counts.normals:
        return result
    alpha = 0.05 / 6
    if (confidence.get("comparisons") != 6 or confidence.get("cluster_available") is not True
            or confidence.get("familywise_confidence") != 0.95
            or not _probability(confidence.get("one_sided_alpha"))
            or not math.isclose(confidence["one_sided_alpha"], alpha, rel_tol=0, abs_tol=1e-15)):
        return result
    exact, conservative = confidence.get("exact", {}), confidence.get("conservative", {})
    if not isinstance(exact, dict) or not isinstance(conservative, dict):
        raise ValueError("typed existing confidence bounds required")
    expected = {"recall": exact_bounds(counts.tp, counts.positives, alpha),
                "false_positive_rate": exact_bounds(counts.fp, counts.normals, alpha)}
    for name in expected:
        observed, bound = exact.get(name), conservative.get(name)
        if (not isinstance(observed, dict) or not isinstance(bound, dict)
                or observed.get("available") is not True or bound.get("available") is not True
                or any(not _probability(value.get(key)) for value in (observed, bound) for key in ("lower", "upper"))
                or any(value["lower"] > value["upper"] for value in (observed, bound))):
            raise ValueError("complete finite ordered existing confidence bounds required")
        if (any(not math.isclose(observed[key], expected[name][key], rel_tol=0, abs_tol=1e-12) for key in ("lower", "upper"))
                or bound["lower"] > observed["lower"] + 1e-12 or bound["upper"] < observed["upper"] - 1e-12):
            raise ValueError("confidence population or conservativeness mismatch")
    lower = prevalence * conservative["recall"]["lower"] + (1 - prevalence) * (1 - conservative["false_positive_rate"]["upper"])
    result.update(confidence_available=True, derived_accuracy_lower_bound=lower,
                  derived_confidence_condition_satisfied=lower > 0.98,
                  inherited_familywise_confidence=0.95, inherited_comparisons=6)
    return result
