"""Run exactly one protocol-bound classifier fit and fixed pilot validation."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import zipfile

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.normal_support import NormalSupportScorer
from app.policy import ScorePolicy
from postlogin_data_quality import load_split, read
from postlogin_pilot_artifacts import publish_bundle, read_bundle, writer
from ueba_research_artifacts import canonical, commit, digest, private_directory
from postlogin_capacity_model import CapacityBeforeAttemptScorer


def run(source, output):
    protocol_path = output / "capacity-trial-protocol.receipt.private.json"
    marker = read(output / "capacity-trial-protocol.commit.private.json")
    if digest(protocol_path) != marker["receipt_sha256"]:
        raise ValueError("trial protocol changed")
    protocol = read(protocol_path)
    for name, expected in protocol["code_sha256"].items():
        if digest(Path(__file__).parent / name) != expected:
            raise ValueError("trial implementation differs from predeclared code")
    if protocol["parameters"] != CapacityBeforeAttemptScorer.capacity_parameters:
        raise ValueError("capacity configuration differs from protocol")
    original = read(source / "pilot.protocol.private.json")
    source_sha = digest(source / "pilot.source.identity.private.json")
    if source_sha != original["source_binding_sha256"] or source_sha != protocol["source_identity_sha256"]:
        raise ValueError("source identity changed")
    frozen_runner = source / "pilot-code/run-ueba-postlogin-pilot.py"
    if digest(frozen_runner) != original["code_sha256"]["run-ueba-postlogin-pilot.py"]:
        raise ValueError("frozen evaluation implementation changed")
    spec = importlib.util.spec_from_file_location("frozen_pilot_evaluation", frozen_runner)
    evaluator = importlib.util.module_from_spec(spec); spec.loader.exec_module(evaluator)
    rows, hashes = {}, {}
    for split in ("fit", "calibration", "validation"):
        rows[split], proofs = load_split(source, split, source_sha)
        hashes[split] = hashlib.sha256(canonical(proofs).encode()).hexdigest()
    evaluator.check_isolation(rows["fit"], rows["calibration"], rows["validation"])
    baseline_unit = "fit-fold1-baseline"
    with zipfile.ZipFile(source / (baseline_unit + ".bundle.zip")) as z:
        baseline_binding = json.loads(z.read("manifest.json"))["binding"]
    for split, name in (("fit", "fit_sha256"), ("calibration", "calibration_sha256"), ("validation", "validation_sha256")):
        if baseline_binding[name] != hashes[split] or baseline_binding[name] != protocol["source_splits_sha256"][split]:
            raise ValueError("baseline reuse input/labels/order identity differs")
    if digest(source / (baseline_unit + ".bundle.zip")) != protocol["baseline_model_bundle_sha256"]:
        raise ValueError("baseline model changed")
    contents = read_bundle(source, baseline_unit, baseline_binding)
    baseline_model = joblib.load(io.BytesIO(contents["model.joblib"]))["model"]
    binding = {"protocol_sha256": digest(protocol_path), "source_splits_sha256": hashes,
               "reused_normal_parent_bundle_sha256": protocol["baseline_model_bundle_sha256"],
               "recipe_version": 3, "feature_columns": 57}
    with writer(output):
        if (output / "capacity-fit.bundle.zip").exists():
            raise ValueError("existing fit must be recovered/verified; never fit again automatically")
        x = evaluator.matrix(rows["fit"], "candidate")
        y = [r["training_context"] for r in rows["fit"]]
        normal = x[[i for i, r in enumerate(rows["fit"]) if r["normal_fit"]]]
        if x.shape != (4000, 57) or normal.shape != (2000, 57):
            raise ValueError("frozen FIT population differs")
        commit(output, {"binding": binding, "maximum_classifier_calls": 1, "maximum_normal_fit_calls": 0},
               phase="capacity-component-invocation")
        calls = 0
        original_classifier_fit, original_normal_fit = HistGradientBoostingClassifier.fit, NormalSupportScorer.fit
        def classifier_fit(self, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1: raise ValueError("one classifier invocation only")
            return original_classifier_fit(self, *args, **kwargs)
        def normal_fit(*args, **kwargs): raise ValueError("normal component must be reused")
        start = time.monotonic()
        try:
            HistGradientBoostingClassifier.fit, NormalSupportScorer.fit = classifier_fit, normal_fit
            model = CapacityBeforeAttemptScorer().fit_reusing_normal(baseline_model._normal, normal, x, y)
        finally:
            HistGradientBoostingClassifier.fit, NormalSupportScorer.fit = original_classifier_fit, original_normal_fit
        if calls != 1: raise ValueError("classifier was not fitted exactly once")
        fit_seconds = time.monotonic() - start
        calibration = {}
        for cohort in ("READY", "COLD"):
            selected = [r for r in rows["calibration"] if r["cohort"] == cohort]
            if len(selected) != 5000 or any(r["label"] for r in selected): raise ValueError("separate normal calibration required")
            calibration[cohort] = np.sort(evaluator.raw_scores(model, evaluator.matrix(selected, "candidate")))
        stream = io.BytesIO(); joblib.dump({"model": model, "calibration": calibration}, stream, compress=3)
        restored = joblib.load(io.BytesIO(stream.getvalue()))
        if not np.array_equal(evaluator.raw_scores(model, x[:16]), evaluator.raw_scores(restored["model"], x[:16])):
            raise ValueError("model artifact readback changed scores")
        metadata = {"recipe_version": 3, "applicability": "PILOT_ONLY_UNQUALIFIED", "actual_classifier_fit_calls": calls,
                    "actual_new_normal_fit_calls": 0, "reused_normal_fit_rows": 2000, "labeled_fit_rows": 4000,
                    "feature_columns": 57, "fit_seconds": fit_seconds, "parameters": model.capacity_parameters}
        fit_marker = publish_bundle(output, "capacity-fit", binding,
                                    {"model.joblib": stream.getvalue(), "metadata.json": canonical(metadata).encode()})
        rules_policy = ScorePolicy.strict(99_990_000, 99_999_500, 70, schema=4)
        rule_binding = {"source_sha256": hashes["validation"], "policy_sha256": rules_policy.sha256,
                        "workspace_identity_sha256": digest(source / "pilot-replay-java/identity.private.json")}
        rules = np.frombuffer(read_bundle(source, "rules-fold1-validation", rule_binding)["rules.bin"], dtype=np.uint8)
        if rules.shape != (21000,) or not np.isin(rules, [0, 1]).all(): raise ValueError("frozen rule cache differs")
        values = evaluator.raw_scores(model, evaluator.matrix(rows["validation"], "candidate"))
        predicted = np.zeros(len(values), dtype=bool)
        for cohort, threshold in (("READY", 99.99), ("COLD", 99.9995)):
            mask = np.array([(r["cohort"] == "COLD") == (cohort == "COLD") for r in rows["validation"]])
            bucket = calibration[cohort]; selected = values[mask]
            percentile = (np.searchsorted(bucket, selected, side="left") + np.searchsorted(bucket, selected, side="right")) / (2 * len(bucket)) * 100
            predicted[mask] = percentile >= threshold
        candidate = {"counts": evaluator.validation_counts(rows["validation"], predicted, rules.astype(bool)),
                     "binding": binding, "fit_bundle": fit_marker, "quality_gate": "NOT_APPLICABLE_PILOT_ONLY",
                     "holdout_scored": False, "auto_containment": False}
        evaluation_marker = commit(output, candidate, phase="capacity-validation-fold1")
        baseline = evaluator.read_committed(source, "validation-fold1-baseline")
        if baseline["binding"]["model_bundle_sha256"] != protocol["baseline_model_bundle_sha256"]:
            raise ValueError("baseline evaluation differs")
        decision = evaluator.compare(baseline, candidate)
        result = {**decision, "phase": "NEW_CAPACITY_RESEARCH_TRIAL", "protocol_sha256": digest(protocol_path),
                  "actual_new_classifier_fits": calls, "actual_new_normal_fits": 0, "baseline_reused": True,
                  "normal_component_reused": True, "fit": fit_marker, "validation": evaluation_marker,
                  "baseline_counts": baseline["counts"]["MODEL_ONLY"]["global"],
                  "candidate_counts": candidate["counts"]["MODEL_ONLY"]["global"],
                  "quality_gate": "NOT_RUN", "holdout_scored": False, "auto_containment": False, "aws_changed": False,
                  "unresolved_counterfactuals": protocol["counterfactual_receipt_sha256"]}
        commit(output, result, phase="capacity-trial-result")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(); run(private_directory(a.source), private_directory(a.output))
