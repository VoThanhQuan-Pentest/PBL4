"""Read-only full pilot source verification; never opens a holdout."""
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json

from postlogin_risk_data import COUNTS
from postlogin_risk_rolling import model_features
from postlogin_risk_contract import THRESHOLDS
from postlogin_data_quality import audit as legacy_structural_audit
from ueba_research_artifacts import canonical, digest


def reference_context(values):
    requests, endpoints, errors4, errors5, failures, sensitive, typical, available = values
    volume = requests >= THRESHOLDS["request_minimum"] and available == 1 and typical > 0 and requests >= 4 * typical
    if available == 0:
        volume = requests >= THRESHOLDS["request_without_history_minimum"]
    review = (failures >= 8 or sensitive >= 5 or volume
              or requests >= 50 and endpoints >= 7 and errors4 >= .45 * requests)
    return 1 if review else 2 if requests >= 40 and errors5 >= .35 * requests else 0


def audit_history(row):
    # Frozen schema4 context_frames explicitly supplies 3 windows to COLD and
    # 48 to READY/UNSEEN_READY. COLD means insufficient history (<30), not none.
    cold = row["cohort"] == "COLD"
    expected = 3 if cold else 48
    if (row["baseline_established"] is not (not cold) or row["trusted_window_count"] != expected
            or len(row["context_frame_ids"]) != expected or row["rolling_features"][7] != 1):
        raise ValueError("cohort history differs from frozen 3/48-window source or Java readiness")


def load_source(output, fold, protocol_sha):
    from postlogin_pilot_source import read_committed
    from postlogin_risk_source import accepted_binding
    ancestry = json.loads((output / "risk-source-protocol-v4.receipt.private.json").read_text())["continuation"]["inherited_batches"]
    result = read_committed(output, f"risk-source-fold{fold}-result")
    if not result or result["protocol_sha256"] != protocol_sha:
        raise ValueError("complete protocol-bound source fold required before fitting")
    splits, bindings = {}, {}
    for split, count in COUNTS.items():
        rows, hashes = [], []
        for offset in range(0, count, 32):
            unit = f"risk-source-f{fold}-{split}-{offset // 32:04d}"
            retained = read_committed(output, unit)
            expected = {"protocol_sha256": protocol_sha, "fold": fold, "split": split,
                        "offset": offset, "count": min(32, count - offset)}
            if not retained or not accepted_binding(output, unit, retained["binding"], expected, ancestry) or len(retained["rows"]) != expected["count"]:
                raise ValueError("source batch missing or has a different binding/count")
            for row in retained["rows"]:
                model_features(row)
                if (row["feature_schema_version"] != 6 or row["recipe_version"] != 5
                        or row["training_context"] != reference_context(row["rolling_features"])
                        or row["label"] != int(row["training_context"] != 0)):
                    raise ValueError("raw-reference/Java/schema target consistency failed")
            rows.extend(retained["rows"])
            hashes.append(digest(output / (unit + ".commit.private.json")))
        bound = hashlib.sha256(canonical(hashes).encode()).hexdigest()
        if bound != result["split_commit_hashes_sha256"][split]:
            raise ValueError("fold commit inventory differs from actual rows")
        splits[split], bindings[split] = rows, bound
    return splits, bindings


def audit_source(splits):
    report = legacy_structural_audit(splits)
    if (Counter(r["training_context"] for r in splits["fit"]) != {0: 3000, 1: 800, 2: 200}
            or sum(r["normal_fit"] for r in splits["fit"]) != 2000
            or Counter(r["cohort"] for r in splits["calibration"]) != {"READY": 5000, "COLD": 5000}
            or any(r["label"] for r in splits["calibration"])):
        raise ValueError("declared fitting or independent normal calibration population changed")
    validation = splits["validation"]
    if (Counter(r["cohort"] for r in validation) != {"READY": 14700, "UNSEEN_READY": 4200, "COLD": 2100}
            or Counter(r["family"] for r in validation if r["label"]) != {
                "request_burst": 200, "endpoint_scan": 200, "auth_failure_burst": 200,
                "sensitive_action_burst": 200, "http_error_burst": 200}):
        raise ValueError("declared validation cohort/family population changed")
    for split, rows in splits.items():
        groups = defaultdict(set)
        for row in rows:
            groups[model_features(row)].add(row["training_context"])
            audit_history(row)
        mixed = sum(len(labels) > 1 for labels in groups.values())
        if mixed:
            raise ValueError("schema65 still contains contradictory observable-context labels")
        report["splits"][split]["candidate65"] = {"width": 65, "mixed_context_vector_groups": mixed,
            "distinct_vectors": len(groups), "legacy_planned_label_disagreement": sum(
                r["label"] != r["legacy_planned_label"] for r in rows)}
    report["status"] = "OBSERVABLE_CONTEXT_SOURCE_AUDIT_PASS_RESEARCH_ONLY"
    report["scope"] = "Rule-distillation task; not ground truth for owner/nonowner or real incidents"
    report["history_contract"] = {"COLD": {"observed_windows": 3, "baseline_established": False},
                                  "READY_UNSEEN_READY": {"observed_windows": 48, "baseline_established": True},
                                  "java_required_trusted_windows": 30}
    return report
