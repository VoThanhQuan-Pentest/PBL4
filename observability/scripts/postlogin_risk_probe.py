#!/usr/bin/env python3
"""Twelve bounded frozen-generator control pairs for the NEW observable target.

Does not modify/relabel old data, fit models, export a serving model or admit
long generation. It verifies that the declared rubric removes hidden-intent
dependence while retaining the original external-label evidence.
"""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys
import time

from postlogin_risk_contract import contract, reference
from ueba_research_artifacts import commit, digest, private_directory

COUNTERPARTS = {"request_burst": "benign_heavy_burst", "endpoint_scan": "benign_endpoint_traversal",
                "auth_failure_burst": "benign_retries", "sensitive_action_burst": "benign_password_maintenance",
                "http_error_burst": "benign_expected_degradation"}


def frozen_generator(source, frozen_code):
    identity = json.loads((source / "pilot.source.identity.private.json").read_text())
    generator = source / "pilot-code/postlogin_pilot_data.py"
    if digest(generator) != identity["generator_sha256"]:
        raise ValueError("frozen pilot generator changed")
    sys.path.insert(0, str(frozen_code))
    spec = importlib.util.spec_from_file_location("risk_frozen_pilot_generator", generator)
    data = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data)
    if digest(Path(data.original.__file__)) != identity["original_generator_sha256"]:
        raise ValueError("frozen causal generator changed")
    return data


def run(source, frozen_code, output):
    protocol = {"contract": contract(), "source_identity_sha256": digest(source / "pilot.source.identity.private.json"),
                "script_sha256": digest(Path(__file__)),
                "contract_code_sha256": digest(Path(__file__).with_name("postlogin_risk_contract.py")),
                "maximum_pairs": 12, "maximum_fits": 0, "maximum_http_actions": 0,
                "scope": "SMALL_FIXTURE_NOT_THROUGHPUT_OR_QUALITY_ADMISSION"}
    commit(output, protocol, phase="representation-protocol")
    data = frozen_generator(source, frozen_code)
    specifications = list(data.specifications(1, "validation"))
    chosen = [(item, COUNTERPARTS[family]) for family in COUNTERPARTS
              for item in [s for s in specifications if s["cause"] == family][:2]]
    chosen += [(s, s["cause"]) for s in specifications[:2]]
    rows = []
    start = time.monotonic()
    for spec, counterpart in chosen:
        first, first_truth = data.build(spec)
        second, second_truth = data.build({**spec, "cause": counterpart})
        first_context, second_context = reference(first), reference(second)
        if first != second or first_context != second_context:
            raise ValueError("identical observations must receive identical new context")
        rows.append({"original_validation_index": spec["index"], "original_cause": spec["cause"],
                     "original_labels": [first_truth["label"], second_truth["label"]],
                     "raw_observations_sha256": data.digest(first), "full_observations_equal": True,
                     "new_reference": first_context})
    result = {"status": "OBSERVABLE_CONTEXT_FIXTURE_PASS", "pairs": rows,
              "contexts": dict(Counter(str(r["new_reference"]["training_context"]) for r in rows)),
              "elapsed_seconds": time.monotonic() - start, "new_fits": 0, "new_http_actions": 0,
              "old_source_modified": False, "old_labels_modified": False, "holdout_scored": False,
              "auto_containment": False, "aws_changed": False,
              "scope": protocol["scope"], "quality_gate": "NOT_RUN"}
    proof = commit(output, result, phase="representation-fixture")
    print(json.dumps({"status": result["status"], "pairs": len(rows), "contexts": result["contexts"],
                      "elapsed_seconds": result["elapsed_seconds"], "receipt": proof}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--frozen-code", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(private_directory(args.source), args.frozen_code.resolve(), private_directory(args.output))
