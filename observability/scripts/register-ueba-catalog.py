#!/usr/bin/env python3
"""Package a completed immutable experiment for the backend's read-only numeric catalogue."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ROOT / "observability/runtime/ueba-experiments"
CATALOG = ROOT / "observability/runtime/ueba-catalog"
FILES = ("manifest.json", "selection.json", "fold3-fit.json", "fold3-calibration.json", "holdout.json")

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()

def payload_hash(records, schema):
    data = {"feature_schema_version": schema,
            "vectors": [[float(value) for value in row["features"][:11 if schema == 1 else 15]] for row in records],
            "labels": [row["label"] for row in records], "families": [row["family"] for row in records],
            "groups": [row["account_id"] + "/" + row["window_start"][:10] for row in records]}
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

def register(dataset):
    if not re.fullmatch(r"[a-z0-9_-]{8,64}", dataset): raise ValueError("Invalid dataset ID")
    source = EXPERIMENTS / dataset
    if source.is_symlink() or source.resolve().parent != EXPERIMENTS.resolve(): raise ValueError("Experiment path outside its scope")
    manifest = json.loads((source / "manifest.json").read_text())
    selection = json.loads((source / "selection.json").read_text())
    result = json.loads((source / "holdout-result.json").read_text())
    if (manifest.get("dataset_id") != dataset or manifest.get("data_provenance") != "DEMO_ONLY"
            or manifest.get("feature_schema_version") != 2 or selection.get("status") != "SELECTED"
            or selection.get("completed_fits") != 360 or selection.get("dataset_manifest_sha256") != digest(source / "manifest.json")
            or result.get("quality_gate") != "PASS" or result.get("scope") != "MODEL_ONLY"
            or result.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or result.get("frozen_holdout_split_sha256") != manifest["splits"]["holdout"]["sha256"]):
        raise ValueError("Completed 360-fit selection and independent passing holdout are required")
    for name in FILES:
        path = source / name
        if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024: raise ValueError("Invalid catalogue source file")
        if name not in ("manifest.json", "selection.json") and digest(path) != manifest["splits"][name[:-5]]["sha256"]:
            raise ValueError("Frozen split checksum mismatch")
    records = json.loads((source / "holdout.json").read_text())["records"]
    v2_hash = payload_hash(records, 2)
    if v2_hash != result.get("evaluation_dataset_sha256"): raise ValueError("Holdout payload did not match its actual evaluation")
    CATALOG.mkdir(mode=0o750, parents=True, exist_ok=True)
    if CATALOG.is_symlink(): raise ValueError("Catalogue root cannot be a symlink")
    target = CATALOG / dataset
    entry = {"recipe_id": dataset + "-champion", "dataset_id": dataset,
             "manifest_sha256": digest(source / "manifest.json"), "selection_sha256": digest(source / "selection.json"),
             "holdout_payload_sha256_v1": payload_hash(records, 1), "holdout_payload_sha256_v2": v2_hash}
    catalog_file = CATALOG / "catalog.json"
    catalog = json.loads(catalog_file.read_text()) if catalog_file.exists() else {"entries": []}
    previous = next((item for item in catalog["entries"] if item["dataset_id"] == dataset), None)
    if previous is not None:
        if previous != entry or not target.is_dir() or any(digest(target / name) != digest(source / name) for name in FILES):
            raise ValueError("An existing recipe changed; retain it and register a new dataset ID")
        print(f"Registered immutable recipe already matches: {entry['recipe_id']}")
        return entry
    if len(catalog["entries"]) >= 4: raise ValueError("Catalogue recipe bound reached")
    target.mkdir(mode=0o750)
    for name in FILES:
        with (source / name).open("rb") as incoming, (target / name).open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        (target / name).chmod(0o640)
    catalog["entries"].append(entry)
    temporary = CATALOG / "catalog.json.tmp"
    with temporary.open("w", encoding="utf-8") as output: json.dump(catalog, output, sort_keys=True, indent=2)
    temporary.chmod(0o640)
    os.replace(temporary, catalog_file)
    print(f"Registered DEMO_ONLY recipe: {entry['recipe_id']} -> {target}; no model upload or activation")
    return entry

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-id", required=True)
    args = parser.parse_args()
    register(args.dataset_id)

if __name__ == "__main__": main()
