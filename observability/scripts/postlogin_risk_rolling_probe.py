#!/usr/bin/env python3
"""Verify the amended real Java producer against raw reference observations."""
import argparse
import copy
import json
from pathlib import Path

import postlogin_risk_rolling as rolling
from postlogin_risk_contract import instant, reference
from postlogin_risk_probe import frozen_generator
from ueba_research_artifacts import commit, digest, private_directory


def run(source, frozen, output):
    prior_path = output / "risk-representation-audit-v2.receipt.private.json"
    prior = json.loads(prior_path.read_text())
    if prior["status"] != "FIX_REPRESENTATION" or prior["blind_pairs"] != 3:
        raise ValueError("actual three-cohort Java blind-pair evidence required")
    amendment = {"contract": rolling.contract(), "prior_blind_pair_receipt_sha256": digest(prior_path),
                 "new_fits": 0, "script_sha256": digest(Path(__file__)),
                 "rolling_code_sha256": digest(Path(rolling.__file__)),
                 "scope": "REPRESENTATION_AMENDMENT_BEFORE_FIT_NOT_A_QUALITY_GATE_CHANGE"}
    commit(output, amendment, phase="rolling-representation-amendment")
    data = frozen_generator(source, frozen)
    from postlogin_pilot_source import export_chunk
    cp = rolling.java_classpath(source, output)
    specifications = {s["index"]: s for s in data.specifications(1, "validation")}
    results = []
    for cohort, evidence in prior["pairs"].items():
        spec = specifications[evidence["source_index"]]
        first, metadata = data.build(spec)
        second = copy.deepcopy(first)
        at = instant(first["attempt"]["event_timestamp"])
        start = at.replace(minute=at.minute // 15 * 15, second=0, microsecond=0)
        second["context"] = [e for e in second["context"] if not (e.get("event_type") == "AUTH"
            and e.get("action") == "LOGIN" and e.get("outcome") == "FAILURE" and instant(e["event_timestamp"]) < start)]
        if (data.digest(first) != evidence["original_raw_sha256"]
                or data.digest(second) != evidence["control_raw_sha256"]):
            raise ValueError("diagnostic raw observations changed")
        worlds = [first, second]
        rows = export_chunk(output, [{**spec, "world": i} for i in (0, 1)], cp,
                            build=lambda item: (copy.deepcopy(worlds[item["world"]]), dict(metadata)), rolling=True)
        for i, row in enumerate(rows):
            if (row["rolling_features"] != rolling.expected_rolling(worlds[i])
                    or list(rolling.model_features(row))[:57] != evidence["numeric_before" if i == 0 else "numeric_after"]):
                raise ValueError("Java/reference rolling parity or legacy57 compatibility failed")
        distinct = rolling.model_features(rows[0]) != rolling.model_features(rows[1])
        if not distinct:
            raise ValueError("amended representation still hides the observed target difference")
        results.append({"cohort": cohort, "legacy57_equal": True, "candidate65_distinct": distinct,
                        "rolling_before": rows[0]["rolling_features"], "rolling_after": rows[1]["rolling_features"],
                        "reference_targets": [reference(w)["training_context"] for w in worlds]})
    receipt = {"status": "ROLLING_REPRESENTATION_PARITY_PASS", "pairs": results,
               "java_overlay_identity_sha256": digest(output / "java-overlay-risk-v2/identity.private.json"),
               "feature_width": 65, "feature_schema_version": 6, "recipe_version": 5,
               "new_fits": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False,
               "scope": "Three diagnostic pairs only; source coverage and pilot quality still require verification"}
    proof = commit(output, receipt, phase="rolling-representation-parity")
    print(json.dumps({"status": receipt["status"], "pairs": len(results), "receipt": proof}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(private_directory(a.source), a.frozen_code.resolve(), private_directory(a.output))
