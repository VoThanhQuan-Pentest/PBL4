"""Offline, resumable 360-fit selection. Test labels never enter fitting or calibration."""

import argparse
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np

from app.contract import FEATURE_NAMES_V2, TrainingConfig, campaign_runs, feature_array
from app.evaluation import evaluate_percentiles
from app.model import ModelStore


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def fingerprint():
    directory = Path(__file__).resolve().parent
    return {name: digest(directory / name) for name in ("campaign.py", "model.py", "contract.py", "evaluation.py")}


def timestamp(): return datetime.now(timezone.utc).isoformat()


def load_manifest(directory):
    path = directory / "manifest.json"
    if not path.is_file() or path.stat().st_size > 1024 * 1024: raise ValueError("Missing/bounded manifest required")
    manifest = json.loads(path.read_text())
    if manifest.get("data_provenance") != "DEMO_ONLY" or manifest.get("feature_schema_version") != 2:
        raise ValueError("Only DEMO_ONLY schema-v2 experiments are accepted")
    for key in [f"fold{fold}-{kind}" for fold in (1, 2, 3) for kind in ("fit", "calibration", "validation")] + ["holdout"]:
        info = manifest["splits"][key]
        if info["path"] != key + ".json" or len(info["sha256"]) != 64:
            raise ValueError("Invalid frozen split identity")
        split = directory / info["path"]
        if split.resolve().parent != directory.resolve() or split.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Split path/size outside the experiment")
        if digest(split) != info["sha256"]: raise ValueError("Frozen split checksum mismatch")
    return manifest


def load_split(directory, manifest, name):
    info = manifest["splits"][name]
    if digest(directory / info["path"]) != info["sha256"]: raise ValueError("Frozen split changed")
    payload = json.loads((directory / info["path"]).read_text())
    if payload.get("data_provenance") != "DEMO_ONLY" or payload.get("feature_schema_version") != 2 or payload.get("split_name") != name:
        raise ValueError("Split contract mismatch")
    rows = payload["records"]
    if len(rows) != info["windows"] or len({row["frame_id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate/mismatched split windows")
    if not all(row["baseline_established"] for row in rows): raise ValueError("Mature baseline is required in the core benchmark")
    maximum = 50000 if name.endswith("fit") else 10000 if name.endswith("calibration") else 20000
    feature_array([row["features"] for row in rows], maximum, 2)
    if name.endswith(("fit", "calibration")) and any(row["label"] != 0 or row["family"] != "normal" for row in rows):
        raise ValueError("Abnormality leaked into normal fitting/calibration")
    return rows


def validate_fold(fit, calibration, validation):
    parts = [fit, calibration, validation]
    for left, right in zip(parts, parts[1:]):
        if {row["frame_id"] for row in left} & {row["frame_id"] for row in right}:
            raise ValueError("Event/window identity leakage across temporal splits")
        last = max(datetime.fromisoformat(row["window_start"].replace("Z", "+00:00")) for row in left)
        first = min(datetime.fromisoformat(row["window_start"].replace("Z", "+00:00")) for row in right)
        if (first - last).total_seconds() < 1800:
            raise ValueError("At least one completed-window gap is required")
    if len(fit) < 10000 or len(calibration) < 2000: raise ValueError("Insufficient independent normal windows")
    if sum(row["label"] == 0 for row in validation) < 5000 or sum(row["label"] == 1 for row in validation) < 1000:
        raise ValueError("Insufficient labelled validation")


def model_version(run_id): return "campaign_" + hashlib.sha256(run_id.encode()).hexdigest()[:24]


def fit_one(directory, run_id):
    run = next((value for value in campaign_runs() if value["run_id"] == run_id), None)
    if run is None: raise ValueError("Unknown approved fit identity")
    manifest = load_manifest(directory)
    number = run["fold"]
    fit = load_split(directory, manifest, f"fold{number}-fit")
    calibration = load_split(directory, manifest, f"fold{number}-calibration")
    validation = load_split(directory, manifest, f"fold{number}-validation")
    validate_fold(fit, calibration, validation)
    store = ModelStore(directory / "models")
    version = model_version(run_id)
    expected = {"dataset_manifest_sha256": digest(directory / "manifest.json"),
                "code_fingerprint": fingerprint(), "run_id": run_id,
                "split_hashes": {kind: manifest["splits"][f"fold{number}-{kind}"]["sha256"]
                                 for kind in ("fit", "calibration", "validation")}}
    metadata_path = directory / "models" / f"{version}.json"
    before = time.monotonic()
    if metadata_path.exists():
        metadata, payload = store.load_candidate(version)
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise ValueError("Existing candidate does not prove this immutable fit identity")
        fit_reused = True  # Recover completed fitting; never refit to improve a bad metric.
    else:
        metadata = store.train(version, [row["features"] for row in fit], [row["features"] for row in calibration],
                               schema_version=2, config=run["config"])
        metadata.update(expected)
        write_json(metadata_path, metadata)
        metadata, payload = store.load_candidate(version)
        fit_reused = False
    scored = store.score_payload(payload, feature_array([row["features"] for row in validation], 20000, 2), version, 2)
    percentiles = [row["normal_percentile"] for row in scored["results"]]
    metrics = evaluate_percentiles(percentiles, [row["label"] for row in validation],
                                   [row["family"] for row in validation], evaluation_scope="VALIDATION")
    training = np.asarray([row["features"] for row in fit])
    calibration_scores = payload["calibration_scores"]
    _, masses = np.unique(calibration_scores, return_counts=True)
    receipt = {"status": "SUCCEEDED", "run_id": run_id, "fold": number, "config": asdict(run["config"]),
               "model_version": version, "model_sha256": metadata["sha256"], **expected,
               "training_windows": len(fit), "calibration_windows": len(calibration), "validation_windows": len(validation),
               "fit_recovered_without_refit": fit_reused, "runtime_seconds": time.monotonic() - before,
               "completed_at": timestamp(), "metrics": metrics,
               "constant_features": [FEATURE_NAMES_V2[index] for index in range(15) if np.ptp(training[:, index]) == 0],
               "unique_training_vectors": int(len(np.unique(training, axis=0))),
               "unique_calibration_scores": int(len(masses)), "maximum_calibration_tie_mass": float(max(masses) / len(calibration_scores)),
               "dependencies": {name: importlib.metadata.version(name) for name in ("scikit-learn", "numpy", "scipy", "joblib")}}
    write_json(directory / "runs" / (run_id + ".json"), receipt)
    return receipt


def select_configuration(receipts):
    grouped = defaultdict(list)
    for result in receipts:
        if result["status"] != "SUCCEEDED": continue
        config = result["config"]
        grouped[(config["n_estimators"], config["max_samples"], config["max_features"])].append(result)
    qualifying, considered = [], []
    for configuration, values in grouped.items():
        if len(values) != 15 or len({(row["fold"], row["config"]["random_state"]) for row in values}) != 15: continue
        folds = {}
        for fold in (1, 2, 3):
            cases = [row for row in values if row["fold"] == fold]
            recalls = [row["metrics"]["recall"] for row in cases]
            fprs = [row["metrics"]["false_positive_rate"] for row in cases]
            folds[str(fold)] = {"mean_recall": float(np.mean(recalls)), "mean_false_positive_rate": float(np.mean(fprs)),
                               "recall_seed_spread": max(recalls) - min(recalls)}
        passing = all(row["mean_recall"] >= 0.90 and row["mean_false_positive_rate"] <= 0.02
                      and row["recall_seed_spread"] <= 0.05 + 1e-12 for row in folds.values())
        summary = {"configuration": {"n_estimators": configuration[0], "max_samples": configuration[1], "max_features": configuration[2]},
                   "folds": folds, "qualified": passing,
                   "worst_fold_recall": min(row["mean_recall"] for row in folds.values()),
                   "mean_recall": float(np.mean([row["metrics"]["recall"] for row in values])),
                   "mean_false_positive_rate": float(np.mean([row["metrics"]["false_positive_rate"] for row in values]))}
        considered.append(summary)
        if passing:
            candidate = next(row for row in values if row["fold"] == 3 and row["config"]["random_state"] == 42)
            qualifying.append((summary, candidate))
    qualifying.sort(key=lambda pair: (-pair[0]["worst_fold_recall"], -pair[0]["mean_recall"],
                                     pair[0]["mean_false_positive_rate"], pair[0]["configuration"]["n_estimators"],
                                     pair[0]["configuration"]["max_samples"], pair[0]["configuration"]["max_features"]))
    return {"status": "SELECTED" if qualifying else "NO_QUALIFIED_CONFIG", "configurations_considered": considered,
            "selected": {"summary": qualifying[0][0], "candidate": qualifying[0][1]} if qualifying else None,
            "criterion": "three fold means recall>=0.90/FPR<=0.02 and seed spread<=0.05; fixed representative seed42/fold3"}


def search(directory, timeout):
    manifest = load_manifest(directory)
    (directory / "runs").mkdir(mode=0o700, exist_ok=True)
    with (directory / "campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        identity = {"dataset_manifest_sha256": digest(directory / "manifest.json"), "code_fingerprint": fingerprint()}
        existing = directory / "campaign.identity.json"
        if existing.exists() and json.loads(existing.read_text()) != identity:
            raise ValueError("Cannot resume results after dataset/code changes; retain them and use a new experiment")
        if not existing.exists(): write_json(existing, identity)
        receipts = []
        for index, run in enumerate(campaign_runs(), 1):
            path = directory / "runs" / (run["run_id"] + ".json")
            if path.exists():
                receipt = json.loads(path.read_text())
                if any(receipt.get(key) != value for key, value in identity.items()): raise ValueError("Receipt identity mismatch")
                if receipt["status"] != "SUCCEEDED": raise ValueError("Retained failed/interrupted fit requires diagnosis, not silent retry")
                if digest(directory / "models" / (receipt["model_version"] + ".joblib")) != receipt["model_sha256"]:
                    raise ValueError("Completed fit artifact changed")
            else:
                log_path = directory / "runs" / (run["run_id"] + ".log")
                with log_path.open("a") as log:
                    process = subprocess.Popen([sys.executable, "-m", "app.campaign", "_fit", "--dataset", str(directory),
                                                "--run-id", run["run_id"]], stdout=log, stderr=log)
                    write_json(directory / "campaign.live.json", {"status": "RUNNING", "pid": process.pid,
                               "parent_pid": os.getpid(), "run_id": run["run_id"], "started_at": timestamp(), **identity})
                    try: code = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try: process.wait(timeout=15)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                        write_json(path, {"status": "FAILED", "reason": "TIMEOUT", "run_id": run["run_id"], **identity})
                        raise RuntimeError("Managed fit timed out; failure retained") from None
                    if code or not path.exists():
                        if not path.exists(): write_json(path, {"status": "FAILED", "reason": "CHILD_EXIT", "run_id": run["run_id"], **identity})
                        raise RuntimeError("Fit failed; investigate its retained log before resume")
                receipt = json.loads(path.read_text())
            receipts.append(receipt)
            write_json(directory / "campaign.progress.json", {"status": "RUNNING", "completed_fits": len(receipts),
                       "required_fits": 360, "last_run_id": run["run_id"], "updated_at": timestamp(), **identity})
            print(f"FIT {index}/360 {run['run_id']} recall={receipt['metrics']['recall']:.4f} "
                  f"fpr={receipt['metrics']['false_positive_rate']:.4f}", flush=True)
        selection = select_configuration(receipts)
        selection.update(identity, completed_fits=len(receipts), required_fits=360, completed_at=timestamp())
        write_json(directory / "selection.json", selection)
        write_json(directory / "campaign.live.json", {"status": "COMPLETED", "parent_pid": os.getpid(), **identity})
        write_json(directory / "campaign.progress.json", {"status": "COMPLETED", "completed_fits": len(receipts), "required_fits": 360,
                   "selection_status": selection["status"], "updated_at": timestamp(), **identity})
        print(f"360 fits completed; selection={selection['status']}; holdout has not been scored", flush=True)


def holdout(directory):
    manifest = load_manifest(directory)
    selection = json.loads((directory / "selection.json").read_text())
    if selection.get("status") != "SELECTED" or selection.get("completed_fits") != 360:
        raise ValueError("All 360 fits and a qualified representative are required before opening holdout")
    if selection["dataset_manifest_sha256"] != digest(directory / "manifest.json") or selection["code_fingerprint"] != fingerprint():
        raise ValueError("Selection identity changed")
    selected = selection["selected"]["candidate"]
    rows = load_split(directory, manifest, "holdout")
    fit = load_split(directory, manifest, "fold3-fit")
    calibration = load_split(directory, manifest, "fold3-calibration")
    ids = {row["frame_id"] for row in fit + calibration}
    if ids & {row["frame_id"] for row in rows}: raise ValueError("Holdout leaked into final training")
    store = ModelStore(directory / "models")
    metadata, _ = store.load_candidate(selected["model_version"])
    if metadata["sha256"] != selected["model_sha256"]: raise ValueError("Selected model artifact changed")
    result = store.evaluate_candidate(selected["model_version"], [row["features"] for row in rows],
                                     [row["label"] for row in rows], [row["family"] for row in rows],
                                     [row["account_id"] + "/" + row["window_start"][:10] for row in rows])
    result.update(dataset_id=manifest["dataset_id"], frozen_holdout_split_sha256=manifest["splits"]["holdout"]["sha256"])
    write_json(directory / "holdout-result.json", result)
    print(json.dumps({key: result.get(key) for key in ("status", "quality_gate", "recall", "false_positive_rate", "precision", "tp", "fp", "tn", "fn")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("search", "holdout", "_fit"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--fit-timeout", type=int, default=600)
    args = parser.parse_args()
    if not 10 <= args.fit_timeout <= 600: parser.error("Fit timeout must be between 10 and 600 seconds")
    if args.action == "search": search(args.dataset.resolve(), args.fit_timeout)
    elif args.action == "holdout": holdout(args.dataset.resolve())
    else:
        try: fit_one(args.dataset.resolve(), args.run_id)
        except Exception as error:
            # No data bodies/credentials/identities in console errors.
            print("Fit refused/failed: " + type(error).__name__, file=sys.stderr)
            raise SystemExit(2) from None


if __name__ == "__main__": main()
