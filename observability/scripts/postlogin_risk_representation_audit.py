#!/usr/bin/env python3
"""Bounded raw-observation sensitivity audit using the pinned real Java exporter.

Controls remove only prior-window failed logins. They are diagnostic alternate
observations, never relabeled old training rows or proof of real-world intent.
"""
import argparse
import copy
import json
from pathlib import Path
import time

from postlogin_risk_contract import instant, reference, model_features
from postlogin_risk_probe import frozen_generator
from ueba_research_artifacts import commit, digest, private_directory


def run(source, frozen_code, output):
    protocol = {"maximum_pairs": 3, "cohorts": ["READY", "UNSEEN_READY", "COLD"],
                "maximum_candidate_worlds": 200, "new_fits": 0, "new_http_actions": 0,
                "script_sha256": digest(Path(__file__)),
                "reference_code_sha256": digest(Path(__file__).with_name("postlogin_risk_contract.py")),
                "export_adapter_sha256": digest(Path(__file__).with_name("postlogin_pilot_source.py")),
                "source_identity_sha256": digest(source / "pilot.source.identity.private.json"),
                "hypothesis": "Prior-window account failures can change the observable target without changing baseline37+session20",
                "scope": "DIAGNOSTIC_ONLY_NOT_DATA_GENERATION_OR_TRAINING_ADMISSION"}
    commit(output, protocol, phase="risk-representation-protocol-v2")
    data = frozen_generator(source, frozen_code)
    # Import only after the frozen app package has been selected and verified.
    from postlogin_pilot_source import classpath, export_chunk
    cp = classpath(source)
    selected, checked = {}, 0
    started = time.monotonic()
    for spec in data.specifications(1, "validation"):
        if spec["cause"] != "auth_failure_burst" or spec["cohort"] in selected:
            continue
        checked += 1
        raw, metadata = data.build(spec)
        before = reference(raw)
        at = instant(raw["attempt"]["event_timestamp"])
        start = at.replace(minute=at.minute // 15 * 15, second=0, microsecond=0)
        other = copy.deepcopy(raw)
        other["context"] = [e for e in other["context"] if not (
            e.get("event_type") == "AUTH" and e.get("action") == "LOGIN"
            and e.get("outcome") == "FAILURE" and instant(e["event_timestamp"]) < start)]
        after = reference(other)
        if before["training_context"] == after["training_context"]:
            continue
        source_frames = [(raw, metadata), (other, {**metadata, "diagnostic_control": True})]
        cases = [{**spec, "diagnostic_world": n} for n in (0, 1)]
        numeric = export_chunk(output, cases, cp,
                               build=lambda item: copy.deepcopy(source_frames[item["diagnostic_world"]]))
        equal37 = model_features(numeric[0], projection="baseline") == model_features(numeric[1], projection="baseline")
        equal57 = model_features(numeric[0]) == model_features(numeric[1])
        selected[spec["cohort"]] = {"source_index": spec["index"], "source_cohort": spec["cohort"],
            "original_raw_sha256": data.digest(raw), "control_raw_sha256": data.digest(other),
            "reference_before": before, "reference_after": after,
            "baseline37_equal": equal37, "candidate57_equal": equal57,
            "numeric_before": list(model_features(numeric[0])), "numeric_after": list(model_features(numeric[1]))}
        if len(selected) == 3:
            break
    blind = sum(r["candidate57_equal"] for r in selected.values())
    result = {"status": "FIX_REPRESENTATION" if blind else "NO_BLIND_PAIR_FOUND_IN_BOUNDED_AUDIT",
              "pairs": selected, "candidate_worlds_checked": checked, "blind_pairs": blind,
              "elapsed_seconds": time.monotonic() - started, "java_export_actual": True,
              "old_data_or_labels_modified": False, "new_fits": 0, "holdout_scored": False,
              "scope": protocol["scope"], "auto_containment": False, "aws_changed": False}
    proof = commit(output, result, phase="risk-representation-audit-v2")
    print(json.dumps({"status": result["status"], "pairs": len(selected), "blind_pairs": blind,
                      "elapsed_seconds": result["elapsed_seconds"], "receipt": proof}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(private_directory(a.source), a.frozen_code.resolve(), private_directory(a.output))
