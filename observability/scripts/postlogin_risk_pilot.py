#!/usr/bin/env python3
"""Fixed research screening on audited schema65 data, not strict qualification.

One baseline and one candidate. Independent normal calibration only. No holdout,
adoption, enforcement or parameter/threshold search is available in this CLI.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
import math
from pathlib import Path
import signal
import time

import joblib
import numpy as np
from app import hybrid_incident, normal_support
from postlogin_risk_model import ObservableContextScorer, PARAMETERS
from postlogin_risk_rolling import contract, model_features
from postlogin_risk_audit import load_source, audit_source, reference_context
from postlogin_risk_source import resource_limits
from postlogin_pilot_artifacts import publish_bundle, read_bundle, writer
from postlogin_pilot_source import read_committed
from ueba_research_artifacts import canonical, commit, digest, private_directory, publish

THRESHOLDS = {"READY": 99.99, "COLD": 99.9995}


def scores(model, values):
    return np.concatenate([model.anomaly_scores(values[i:i + 1000]) for i in range(0, len(values), 1000)])


def group_names(row):
    result = ["global", "cohort/" + row["cohort"], "action/" + row["current_operation"],
              "login/" + ("observed" if row["postlogin_features"][3] else "unobserved")]
    if row["label"]:
        result.append("family/" + row["family"])
    if not row["baseline_established"]:
        result.append("control/sparse_history")
    if row["legacy_planned_label"] == 0 and (row["baseline_features"][8] or row["baseline_features"][9]):
        result.append("control/legitimate_new_client")
    if row["planned_cause"] == "benign_password_maintenance":
        result.append("control/legitimate_sensitive_sequence")
    if row["window_start"] != row["source_window_start"]:
        result.append("control/cross_window")
    return result


def counts(rows, predictions):
    result = {}
    for row, predicted in zip(rows, predictions):
        category = ("tp" if predicted else "fn") if row["label"] else ("fp" if predicted else "tn")
        for name in group_names(row):
            result.setdefault(name, dict(tp=0, fn=0, fp=0, tn=0))[category] += 1
    return result


def points(confusion):
    tp, fn, fp, tn = [confusion[k] for k in ("tp", "fn", "fp", "tn")]
    return {"precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None}


def compare(baseline, candidate):
    before, after = baseline["counts"], candidate["counts"]
    fn = before["global"]["fn"]
    regressions = [name for name in before if after[name]["fp"] > before[name]["fp"]
                   or after[name]["fn"] > before[name]["fn"]]
    if fn < 3:
        metrics = points(before["global"])
        promising = (metrics["precision"] is not None and metrics["precision"] >= .998
                     and metrics["recall"] is not None and metrics["recall"] > .99
                     and metrics["fpr"] is not None and metrics["fpr"] < .001
                     and all(v["tp"] / (v["tp"] + v["fn"]) > .99
                             for v in before.values() if v["tp"] + v["fn"]))
        return {"status": "BASELINE_PROMISING_REQUIRES_REPLICATION" if promising else "INCONCLUSIVE",
                "selected_research_projection": "baseline" if promising else None,
                "primary_baseline_fn": fn, "additional_scoring": "NOT_OPENED_WITHOUT_MATCHING_SOURCE_AND_BUDGET"}
    reduction = fn - after["global"]["fn"]
    target = max(3, math.ceil(.25 * fn))
    go = reduction >= target and not regressions
    return {"status": "GO_RESEARCH_SCREEN_ONLY" if go else "STOP_NO_IMPROVEMENT",
            "selected_research_projection": "candidate" if go else None,
            "baseline_fn": fn, "candidate_fn": after["global"]["fn"],
            "required_fn_reduction": target, "actual_fn_reduction": reduction, "regressions": regressions}


class FitLedger:
    def __init__(self, output, protocol_sha):
        self.path = output / "risk-fit-ledger.private.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            "protocol_sha256": protocol_sha, "composite_invocations_reserved": 0,
            "component_invocations_reserved": 0, "invocations": []}
        if self.state["protocol_sha256"] != protocol_sha:
            raise ValueError("fit ledger belongs to a different protocol")

    def reserve(self, unit, kind):
        field, maximum = ("composite_invocations_reserved", 7) if kind == "composite" else ("component_invocations_reserved", 14)
        if self.state[field] >= maximum:
            raise RuntimeError("STOP_FIT_CAP")
        self.state[field] += 1
        self.state["invocations"].append({"unit": unit, "kind": kind})
        publish(self.path, self.state)


def fit_unit(output, fold, kind, splits, source_bindings, protocol_sha, ledger):
    unit = f"risk-fit-fold{fold}-{kind}"
    binding = {"protocol_sha256": protocol_sha, "source_splits_sha256": source_bindings, "projection": kind}
    existing = read_bundle(output, unit, binding, allow_unmarked=True)
    if existing is not None:
        proof = publish_bundle(output, unit, binding, {})
        return joblib.load(io.BytesIO(existing["model.joblib"])), proof
    ledger.reserve(unit, "composite")
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(900)
    started = time.monotonic()
    x = np.asarray([model_features(row) for row in splits["fit"]], dtype=np.float64)
    normal = x[[i for i, row in enumerate(splits["fit"]) if row["normal_fit"]]]
    y = np.asarray([row["training_context"] for row in splits["fit"]], dtype=np.int64)
    model = ObservableContextScorer(kind).fit(normal, x, y, lambda component: ledger.reserve(unit, component))
    calibration = {}
    for cohort in ("READY", "COLD"):
        rows = [r for r in splits["calibration"] if r["cohort"] == cohort]
        if len(rows) != 5000 or any(r["label"] for r in rows):
            raise ValueError("independent normal-only cohort calibration required")
        calibration[cohort] = np.sort(scores(model, np.asarray([model_features(r) for r in rows], dtype=np.float64)))
    artifact = {"model": model, "calibration": calibration}
    encoded = io.BytesIO(); joblib.dump(artifact, encoded, compress=3)
    restored = joblib.load(io.BytesIO(encoded.getvalue()))
    probes = x[[0, 1999, 2999, 3000, 3199, 3399, 3599, 3799, 3999]]
    if not np.array_equal(scores(model, probes), scores(restored["model"], probes)) or any(
            not np.array_equal(calibration[c], restored["calibration"][c]) for c in calibration):
        raise ValueError("published model/calibration readback differs")
    metadata = {"feature_schema_version": 6, "recipe_version": 5, "full_input_width": 65,
                "classifier_width": 37 if kind == "baseline" else 65, "normal_component_width": 37,
                "normal_fit_rows": 2000, "labeled_fit_rows": 4000, "calibration_rows": 10000,
                "parameters": PARAMETERS, "actual_successful_component_fits": 2,
                "readback_probe_rows": len(probes), "fit_calibration_seconds": time.monotonic() - started,
                "applicability": "PILOT_ONLY_RULE_DISTILLATION"}
    proof = publish_bundle(output, unit, binding,
                           {"model.joblib": encoded.getvalue(), "metadata.json": canonical(metadata).encode()})
    signal.alarm(0)
    return restored, proof


def evaluate(output, fold, kind, artifact, model_proof, rows, protocol_sha, validation_sha):
    phase = f"risk-validation-fold{fold}-{kind}"
    binding = {"model_bundle_sha256": model_proof["bundle_sha256"], "protocol_sha256": protocol_sha,
               "validation_sha256": validation_sha, "thresholds": THRESHOLDS}
    previous = read_committed(output, phase)
    if previous is not None:
        if previous["binding"] != binding:
            raise ValueError("validation binding changed")
        return previous
    x = np.asarray([model_features(row) for row in rows], dtype=np.float64)
    raw = scores(artifact["model"], x)
    predicted = np.zeros(len(rows), dtype=np.uint8)
    for cohort, threshold in THRESHOLDS.items():
        mask = np.asarray([(r["cohort"] == "COLD") == (cohort == "COLD") for r in rows])
        bucket = artifact["calibration"][cohort]
        percentile = (np.searchsorted(bucket, raw[mask], side="left") + np.searchsorted(bucket, raw[mask], side="right")) / (2 * len(bucket)) * 100
        predicted[mask] = percentile >= threshold
    context = artifact["model"].contexts(x).astype(np.uint8)
    confusion = [[int(sum(r["training_context"] == actual and int(p) == guessed for r, p in zip(rows, context)))
                  for guessed in range(3)] for actual in range(3)]
    evidence = publish_bundle(output, f"risk-scores-fold{fold}-{kind}", binding,
        {"scores.float64": raw.astype("<f8").tobytes(), "predicted.uint8": predicted.tobytes(), "contexts.uint8": context.tobytes()})
    report = {"binding": binding, "counts": counts(rows, predicted), "context_confusion_matrix": confusion,
              "score_evidence": evidence, "points": points(counts(rows, predicted)["global"]),
              "legacy_planned_normal_flagged": sum(bool(p) and r["legacy_planned_label"] == 0 for r, p in zip(rows, predicted)),
              "SIEM_FINAL": "NOT_EVALUATED_SCHEMA6_SERVING_NOT_ADMITTED",
              "quality_gate": "NOT_RUN", "holdout_scored": False, "auto_containment": False}
    commit(output, report, phase=phase)
    return report


def run(output, fold):
    if not resource_limits()["verified"]:
        raise RuntimeError("capped offline pilot worker required")
    source_proof = json.loads((output / "risk-source-protocol-v4.commit.private.json").read_text())
    if digest(output / source_proof["receipt"]) != source_proof["receipt_sha256"]:
        raise ValueError("source protocol changed")
    source_protocol = json.loads((output / source_proof["receipt"]).read_text())
    for name, expected in source_protocol["code_sha256"].items():
        if digest(Path(__file__).with_name(name)) != expected:
            raise ValueError("source implementation changed after generation")
    code = [Path(__file__)] + [Path(__file__).with_name(name) for name in (
        "postlogin_risk_model.py", "postlogin_risk_audit.py", "postlogin_data_quality.py",
        "postlogin_pilot_artifacts.py", "ueba_research_artifacts.py")]
    protocol = {"protocol_version": 2, "contract": contract(), "parameters": PARAMETERS, "thresholds": THRESHOLDS, "seed": 42,
                "folds": [1, 2, 3], "primary_objective": "REDUCE_POSTLOGIN_FN_WITH_PROTECTED_SLICE_NONREGRESSION",
                "source_protocol_sha256": source_proof["receipt_sha256"],
                "code_sha256": {p.name: digest(p) for p in code},
                "dependency_sources": {m.__name__: digest(Path(m.__file__)) for m in (hybrid_incident, normal_support)},
                "composite_cap": 7, "component_cap": 14, "maximum_fit_seconds": 900,
                "SIEM_FINAL": "NOT_EVALUATED_BEFORE_SCHEMA6_SERVING_ADMISSION", "holdout_access": "FORBIDDEN",
                "strict_admission": "NOT_FROM_RULE_DISTILLATION_SOURCE_ALONE"}
    proof = commit(output, protocol, phase="risk-pilot-protocol-v2")
    protocol_sha = proof["receipt_sha256"]
    with writer(output):
        previous = read_committed(output, f"risk-pilot-fold{fold}-result")
        if previous is not None:
            if previous["protocol_sha256"] != protocol_sha:
                raise ValueError("pilot result belongs to a different protocol")
            print(canonical({"status": previous["status"], "reused": True})); return
        started = time.monotonic()
        splits, bindings = load_source(output, fold, source_proof["receipt_sha256"])
        audit = audit_source(splits)
        commit(output, {**audit, "split_bindings": bindings}, phase=f"risk-data-audit-fold{fold}")
        ledger = FitLedger(output, protocol_sha)
        results = {}
        for kind in ("baseline", "candidate"):
            model, model_proof = fit_unit(output, fold, kind, splits, bindings, protocol_sha, ledger)
            results[kind] = evaluate(output, fold, kind, model, model_proof, splits["validation"], protocol_sha, bindings["validation"])
        decision = compare(results["baseline"], results["candidate"])
        rule_predictions = [reference_context(row["rolling_features"]) != 0 for row in splits["validation"]]
        budget = json.loads((output / "budget.private.json").read_text())
        source = read_committed(output, f"risk-source-fold{fold}-result")
        remaining = budget["pilot_cap_seconds"] - budget["group_seconds"].get("pilot", 0) - (time.monotonic() - started)
        benchmark = read_committed(output, "risk-source-benchmark-v4")
        full_fold_seconds = max(source["elapsed_seconds"], benchmark["projection_seconds_with_50_percent_margin"] / 1.5)
        projection = 2 * (full_fold_seconds + time.monotonic() - started) * 1.25
        p4 = decision["status"] in ("GO_RESEARCH_SCREEN_ONLY", "BASELINE_PROMISING_REQUIRES_REPLICATION")
        result = {**decision, "protocol_sha256": protocol_sha, "fold": fold,
                  "baseline_counts": results["baseline"]["counts"]["global"],
                  "candidate_counts": results["candidate"]["counts"]["global"],
                  "reference_rule_counts": counts(splits["validation"], rule_predictions)["global"],
                  "reference_rule_scope": "The rule defines this synthetic target; perfect rule agreement is expected, not evidence ML adds detection value",
                  "p4_admitted": p4 and projection <= remaining, "p4_projection_seconds_with_25_percent_margin": projection,
                  "remaining_pilot_seconds": remaining,
                  "p4_status": "STOP_BUDGET_BEFORE_P4" if p4 and projection > remaining else "READY_FOR_P4" if p4 else "NOT_ADMITTED_NO_IMPROVEMENT",
                  "fit_invocations_reserved": ledger.state, "quality_gate": "NOT_RUN", "holdout_scored": False,
                  "strict_admission": "NOT_FROM_RULE_DISTILLATION_SOURCE_ALONE", "auto_containment": False, "aws_changed": False}
        commit(output, result, phase=f"risk-pilot-fold{fold}-result")
        print(canonical(result), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fold", type=int, choices=(1, 2, 3), default=1)
    p.add_argument("--maximum-seconds", type=int, required=True)
    a = p.parse_args()
    run(private_directory(a.output), a.fold)
