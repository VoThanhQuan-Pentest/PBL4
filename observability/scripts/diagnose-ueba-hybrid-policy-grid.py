#!/usr/bin/env python3
"""Read-only-model validation over the original predeclared policy grid.

No fitting, model/metadata mutation, selection, holdout, activation or threshold
invention. Reuses the exact existing 8x8x3 policy sweep and actual Java rules.
PILOT point results are exploratory, never independent confidence evidence.
"""

import argparse
import hashlib
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
import numpy as np
from app.catalog import ShardedDataset
from app.contract import recipe_binding, parse_training_config
from app.model import ModelStore
from app.policy import canonical
from app.strict_metrics import FAMILIES
from app.validation import COHORT_NAMES, java_rules, midrank, sweep

CATALOG = ROOT / "observability/runtime/hybrid-bulk-20261004-Y6aJhfoH/normal-catalog-v2"
CATALOG_SHA = "6bc1961168954a7a53287bf4a4eedcd56b94ab3f22c6625803f2cb94b85a9788"
MODELS = ROOT / "observability/runtime/hybrid-bulk-default-20261004-lEGf8VfW/default/models"
VERSION = "bulk_hybrid_calibrated_42"
WORKSPACE = ROOT / "observability/runtime/schema4-java-workspace-20261002-bleITZXE/frozen-exporter"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(output):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.stat().st_mode & 0o077:
        raise ValueError("new private output directory required")
    dataset = ShardedDataset(CATALOG, expected_sha256=CATALOG_SHA)
    store = ModelStore(MODELS)
    metadata, payload = store.load_candidate(VERSION)
    before = {p.name: digest(p) for p in MODELS.iterdir() if p.is_file()}
    rows = [row for _, shard in dataset.iter_shards("fold1-validation") for row in shard]
    config = parse_training_config(metadata["model_kind"], metadata["model_config"])
    if recipe_binding(config)["recipe_sha256"] != metadata["recipe_sha256"]:
        raise ValueError("actual model recipe binding mismatch")
    output.mkdir(mode=0o700)
    declaration = {"model_sha256": metadata["sha256"], "catalog_sha256": dataset.sha256,
                   "scope": "EXISTING_PREDECLARED_POLICY_GRID_PILOT_ONLY", "fit_calls": 0,
                   "thresholds_modified": False, "selection": False, "quality_gate": "NOT_APPLICABLE"}
    def write(name, value):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
    write("predeclared.private.json", declaration)
    raw = np.concatenate([payload["model"].anomaly_scores([row["features"] for row in rows[start:start + 5000]])
                          for start in range(0, len(rows), 5000)])
    labels = np.array([row["label"] for row in rows], dtype="u1")
    families = np.array([0 if row["family"] == "normal" else 1 + FAMILIES.index(row["family"]) for row in rows], dtype="u1")
    cohorts = np.array([COHORT_NAMES.index(row["cohort"]) for row in rows], dtype="u1")
    percentile = np.empty(len(rows), dtype=np.float64)
    for name, codes in (("READY", (0, 1)), ("COLD", (2,))):
        mask = np.isin(cohorts, codes)
        percentile[mask] = midrank(payload["calibration_by_cohort"][name], raw[mask])
    rules, receipt = java_rules(dataset, "fold1-validation", output / "cache", WORKSPACE)
    policies = sweep(percentile, labels, families, cohorts, rules, schema=4)
    after = {p.name: digest(p) for p in MODELS.iterdir() if p.is_file()}
    if before != after:
        raise ValueError("read-only source model artifacts changed")
    result = {"status": "COMPLETED", "policies": policies, "actual_validation_records": len(rows),
              "actual_java_rule_records": len(rows) * 3, "production_rule_receipt": receipt,
              "point_qualified_policies": sum(policy["point_qualified_for_selection"] for policy in policies),
              "model_artifacts_unchanged": True, "fit_calls": 0, "selection_or_activation": False,
              "holdout_records_read": 0, "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY"}
    write("result.private.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.output)
        print(canonical({"status": result["status"], "point_qualified_policies": result["point_qualified_policies"],
                         "fit_calls": 0, "quality_gate": "NOT_APPLICABLE"}))
    except Exception as failure:
        raise SystemExit("Existing policy-grid diagnostic failed: " + type(failure).__name__ + "; no model change") from None
