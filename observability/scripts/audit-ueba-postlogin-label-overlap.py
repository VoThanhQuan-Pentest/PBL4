#!/usr/bin/env python3
"""Five controlled source counterfactuals after P3 STOP; no fitting or tuning."""
import argparse
import copy
import json
from pathlib import Path
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory
import postlogin_pilot_data as data
from postlogin_pilot_source import classpath, export_chunk


def run(output, audit):
    started = time.monotonic()
    output, audit = private_directory(output), private_directory(audit)
    mappings = [("request_burst", "benign_heavy_burst"), ("endpoint_scan", "benign_endpoint_traversal"),
                ("auth_failure_burst", "benign_retries"), ("sensitive_action_burst", "benign_password_maintenance"),
                ("http_error_burst", "benign_expected_degradation")]
    fitting = list(data.specifications(1, "fit")); specifications = []; observations = []
    for index, (positive, benign) in enumerate(mappings):
        left = copy.deepcopy(fitting[3000 + index * 200 + index % 2])
        right = {**left, "cause": benign}
        frame_left, label_left = data.build(left); frame_right, label_right = data.build(right)
        observations.append({"positive_cause": positive, "benign_cause": benign,
            "planned_labels": [label_left["label"], label_right["label"]],
            "raw_server_observations_equal": frame_left == frame_right,
            "left_frame_sha256": data.digest(frame_left), "right_frame_sha256": data.digest(frame_right)})
        specifications.extend((left, right))
    rows = export_chunk(audit, specifications, classpath(output))
    for index, observation in enumerate(observations):
        left, right = rows[index * 2:index * 2 + 2]
        observation.update(baseline37_equal=left["baseline_features"] == right["baseline_features"],
                           candidate57_equal=left["baseline_features"] + left["postlogin_features"] == right["baseline_features"] + right["postlogin_features"])
    receipt = {"status": "OBSERVATIONAL_LABEL_OVERLAP_CONFIRMED" if all(o["raw_server_observations_equal"] and o["candidate57_equal"] for o in observations) else "MIXED_OBSERVATIONAL_OVERLAP",
        "scope": "Five controlled counterfactual pairs, not a population error bound or a new training round",
        "audit_sha256": digest(__file__), "source_identity_sha256": digest(output / "pilot.source.identity.private.json"),
        "pilot_decision_sha256": digest(output / "decision-fold1.receipt.private.json"), "comparisons": observations,
        "conclusion": "Different planned labels exist for identical server-observable frames. These distinctions cannot be recovered by appending features computed from the same observations. Do not add hidden intent/fixture IDs or relabel to manufacture PASS.",
        "next_action": "Clarify observationally supported label semantics/source eligibility in a new protocol before another training round. The current STOP decision and thresholds remain frozen.",
        "additional_fit_calls": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False,
        "elapsed_seconds": round(time.monotonic() - started, 3)}
    commit(audit, receipt, phase="label-overlap")
    print(canonical(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args(); run(args.output.absolute(), args.audit.absolute())
