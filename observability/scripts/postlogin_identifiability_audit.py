"""Check full pilot-positive counterfactuals using frozen causal observations.

The matched benign worlds are diagnostic only. They are never training rows,
and their error bounds do not estimate the original validation population.
"""
import argparse
from collections import Counter
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

from ueba_research_artifacts import commit, digest, private_directory, publish

COUNTERPARTS = {"request_burst": "benign_heavy_burst", "endpoint_scan": "benign_endpoint_traversal",
                "auth_failure_burst": "benign_retries", "sensitive_action_burst": "benign_password_maintenance",
                "http_error_burst": "benign_expected_degradation"}


def run(source, output):
    protocol_path = output / "identifiability-protocol.receipt.private.json"
    marker = json.loads((output / "identifiability-protocol.commit.private.json").read_text())
    if digest(protocol_path) != marker["receipt_sha256"]: raise ValueError("audit protocol changed")
    protocol = json.loads(protocol_path.read_text())
    if digest(Path(__file__)) != protocol["script_sha256"]: raise ValueError("audit code changed")
    identity_path = source / "pilot.source.identity.private.json"
    if digest(identity_path) != protocol["source_identity_sha256"]: raise ValueError("source binding changed")
    identity = json.loads(identity_path.read_text())
    data_path = source / "pilot-code/postlogin_pilot_data.py"
    if digest(data_path) != identity["generator_sha256"]: raise ValueError("frozen pilot generator changed")
    spec = importlib.util.spec_from_file_location("identifiability_frozen_data", data_path)
    data = importlib.util.module_from_spec(spec); spec.loader.exec_module(data)
    if digest(Path(data.original.__file__)) != identity["original_generator_sha256"]:
        raise ValueError("frozen original generator changed")
    expected = {value: key for key, value in COUNTERPARTS.items()}
    expected["benign_login_only_retries"] = "auth_failure_burst"
    if data.original.COUNTERPARTS != expected: raise ValueError("counterpart recipe contract changed")
    specifications = [s for s in data.specifications(1, "validation") if s["cause"] in COUNTERPARTS]
    if len(specifications) != 1000 or Counter(s["cause"] for s in specifications) != {k: 200 for k in COUNTERPARTS}:
        raise ValueError("exact original five-family positive population required")
    probe = [s for family in COUNTERPARTS for s in [r for r in specifications if r["cause"] == family][:2]]
    used = {s["index"] for s in probe}; ordered = probe + [s for s in specifications if s["index"] not in used]
    rows = []; start = time.monotonic(); status = "COMPLETE"
    for ordinal, item in enumerate(ordered):
        left, left_label = data.build(item)
        right, right_label = data.build({**item, "cause": COUNTERPARTS[item["cause"]]})
        if left_label["label"] != 1 or right_label["label"] != 0: raise ValueError("opposite external labels changed")
        equal = left == right
        rows.append({"original_validation_index": item["index"], "family": item["cause"],
                     "positive_label": 1, "counterpart_label": 0, "full_observations_equal": equal,
                     "positive_observations_sha256": data.digest(left),
                     "counterpart_observations_sha256": data.digest(right)})
        if ordinal == 9:
            elapsed = time.monotonic() - start
            projection = elapsed / 10 * 1000 * 1.5
            print(json.dumps({"benchmark_pairs": 10, "elapsed_seconds": elapsed,
                              "full_projection_seconds_with_50_percent_margin": projection}), flush=True)
            if projection > protocol["maximum_seconds"] - 10:
                status = "INCONCLUSIVE_BUDGET_PROJECTION"; break
        if (ordinal + 1) % 100 == 0:
            print(json.dumps({"pairs_checked": ordinal + 1, "elapsed_seconds": time.monotonic() - start}), flush=True)
    path = output / "identifiability-pairs.private.json"
    publish(path, rows, maximum=1024 * 1024)
    families = {}
    for family in COUNTERPARTS:
        selected = [r for r in rows if r["family"] == family]; n = len(selected)
        matched = sum(r["full_observations_equal"] for r in selected)
        fp_budget = max(0, math.ceil(n * .001) - 1)
        families[family] = {"checked_pairs": n, "equal_pairs": matched,
                            "max_false_positives_for_strict_fpr_on_matched_normals": fp_budget,
                            "max_true_positives_if_one_decision_per_observation": n - matched + min(matched, fp_budget),
                            "required_true_positives_for_recall_above_99_percent": math.floor(n * .99) + 1}
    result = {"status": status, "pairs_checked": len(rows), "equal_pairs": sum(r["full_observations_equal"] for r in rows),
              "families": families, "pair_file_sha256": digest(path), "elapsed_seconds": time.monotonic() - start,
              "source_identity_sha256": digest(identity_path), "protocol_sha256": digest(protocol_path),
              "scope": "Counterfactual raw before-action observations including past-only histories for every original fold1 positive. Matched controls are not added to any dataset.",
              "interpretation": "An observation-only deterministic decision is identical for each equal pair despite opposite labels. This is a matched-control identifiability constraint, not an error bound for the original normal population or a claim about all real behavior.",
              "java_export_repeated_for_all_pairs": False,
              "prior_five_pair_java_equality_receipt_sha256": protocol["prior_java_equality_receipt_sha256"],
              "new_fits": 0, "new_http_actions": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False}
    proof = commit(output, result, phase="identifiability-audit")
    print(json.dumps({"status": status, "pairs_checked": result["pairs_checked"], "equal_pairs": result["equal_pairs"], "receipt": proof}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(); run(private_directory(args.source), private_directory(args.output))
