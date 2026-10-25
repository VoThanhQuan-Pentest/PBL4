#!/usr/bin/env python3
"""Bounded diagnosis of already committed validation predictions, zero fits."""
import argparse
import json
import struct
import zipfile

from ueba_research_artifacts import canonical, commit, digest, private_directory


def checked(root, phase):
    marker = json.loads((root / (phase + ".commit.private.json")).read_text())
    path = root / (phase + ".receipt.private.json")
    if marker["receipt"] != path.name or digest(path) != marker["receipt_sha256"]:
        raise ValueError("validation evidence changed")
    return json.loads(path.read_text())


def run(root):
    result = checked(root, "risk-pilot-fold1-result")
    if result["status"] != "STOP_NO_IMPROVEMENT":
        raise ValueError("this diagnostic is scoped to the existing stopped pilot")
    validation = checked(root, "risk-validation-fold1-candidate")
    bundle = root / "risk-scores-fold1-candidate.bundle.zip"
    if digest(bundle) != validation["score_evidence"]["bundle_sha256"]:
        raise ValueError("prediction bytes changed")
    with zipfile.ZipFile(bundle) as archive:
        predicted, context, raw = [archive.read(name) for name in ("predicted.uint8", "contexts.uint8", "scores.float64")]
    if len(predicted) != 21000 or len(context) != 21000 or len(raw) != 21000 * 8:
        raise ValueError("prediction cardinality changed")
    scores = struct.unpack("<21000d", raw)
    cases, index, totals = [], 0, {"fp": 0, "fn": 0}
    for offset in range(0, 21000, 32):
        batch = checked(root, f"risk-source-f1-validation-{offset // 32:04d}")
        for row in batch["rows"]:
            prediction = predicted[index]
            if prediction != row["label"]:
                kind = "fp" if prediction else "fn"
                totals[kind] += 1
                if len(cases) >= 400:
                    raise ValueError("bounded diagnostic case cap reached")
                rolling = row["rolling_features"]
                cases.append({"ordinal": index, "error": kind, "family": row["family"], "cohort": row["cohort"],
                              "operation": row["current_operation"], "raw_reference_context": row["training_context"],
                              "classifier_context": context[index], "fixed_fused_score": scores[index],
                              "rolling_observations": rolling,
                              "requests_over_history_median": rolling[0] / rolling[6] if rolling[6] else None,
                              "diagnostic": "CONTEXT_CLASSIFICATION_MISS" if kind == "fn" and context[index] == 0
                                  else "FIXED_THRESHOLD_MISS" if kind == "fn" else "ALERT_ON_REFERENCE_ROUTINE"})
            index += 1
    if index != 21000 or totals != {"fp": result["candidate_counts"]["fp"], "fn": result["candidate_counts"]["fn"]}:
        raise ValueError("diagnostic totals disagree with committed pilot")
    document = {"status": "STOPPED_PILOT_DIAGNOSIS_COMPLETE", "existing_errors": totals, "cases": cases,
                "decision": "KEEP_STOP_NO_IMPROVEMENT_NO_NEW_FIT_OR_THRESHOLD_CHANGE",
                "reference_rule_scope": "The public rubric defines this synthetic target; rule perfection cannot establish real detection value.",
                "next_research_condition": "A separately approved bounded hypothesis and source with independent outcome evidence; no automatic grid or validation threshold tuning",
                "new_fits": 0, "holdout_scored": False, "auto_containment": False}
    proof = commit(root, document, phase="risk-stopped-pilot-diagnosis")
    print(canonical({"status": document["status"], "errors": totals, "receipt": proof}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    run(private_directory(args.output))
