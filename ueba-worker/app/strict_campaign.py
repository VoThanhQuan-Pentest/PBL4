"""Strict sharded fit/calibration campaign. Completed fitting is not a quality PASS.

The one-fit child is reused by operator jobs. Selection and holdout are separate
stages; this module never opens the holdout's numeric records during fitting.
"""

import argparse
from datetime import datetime, timezone
from dataclasses import asdict
import fcntl
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from app.calibration import cohort_split, recalibrate
from app.catalog import ShardedDataset, utc
from app.contract import HYBRID_MODEL_KIND, IF_MODEL_KIND, MODEL_KINDS, SUPPORT_MODEL_KIND, campaign_runs, recipe_binding
from app.model import ModelStore
from app.owned_dataset import open_owned_dataset
from app.pipeline_lock import coordinated_stage
from app.policy import ScorePolicy, canonical


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream: stream.write(canonical(value))
    temporary.chmod(0o600); os.replace(temporary, path)


def campaign_prefix(model_kind=IF_MODEL_KIND):
    if model_kind == IF_MODEL_KIND: return "strict"
    if model_kind == SUPPORT_MODEL_KIND: return "support"
    if model_kind == HYBRID_MODEL_KIND: return "hybrid"
    raise ValueError("unknown campaign model kind")


def fingerprint(model_kind=IF_MODEL_KIND):
    directory = Path(__file__).resolve().parent
    names = ("strict_campaign.py", "calibration.py", "model.py", "catalog.py", "contract.py", "policy.py")
    if model_kind == SUPPORT_MODEL_KIND: names += ("normal_support.py", "semantic_model.py")
    elif model_kind == HYBRID_MODEL_KIND:
        names += ("hybrid_incident.py", "hybrid_semantic.py", "normal_support.py", "model_state_dispatch.py", "hybrid_strict_dataset.py",
                  "pipeline_lock.py", "owned_dataset.py", "archived_catalog.py", "storage_budget.py")
    elif model_kind != IF_MODEL_KIND: raise ValueError("unknown campaign model kind")
    return {"sources": {name: sha(directory / name) for name in names},
            "dependencies": {name: importlib.metadata.version(name) for name in ("scikit-learn", "numpy", "scipy", "joblib")}}


def timestamp(): return datetime.now(timezone.utc).isoformat()


def validate_new_run_limit(value, name="max_new_runs"):
    """An explicit limit bounds newly completed units, not retained receipts."""
    if value is not None and (type(value) is not int or not 1 <= value <= 360):
        raise ValueError(f"{name} must be an integer from 1 through 360")
    return value


def run_identity(dataset, run, *, _labeled_binding=None):
    binding = recipe_binding(run["config"])
    result = {"dataset_manifest_sha256": dataset.sha256, "code_fingerprint": fingerprint(binding["model_kind"]), "run_id": run["run_id"],
            "fold": run["fold"], "config": asdict(run["config"]) if binding["model_kind"] == HYBRID_MODEL_KIND else run["config"].parameters(),
            "fit_split_sha256": dataset.split(f"fold{run['fold']}-fit")["sha256"]}
    if binding["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): result.update(binding)
    if binding["model_kind"] == HYBRID_MODEL_KIND:
        if _labeled_binding is None:
            _, _, labeled, labeled_sha = hybrid_fold_training(dataset, run["fold"])
        else:
            labeled, labeled_sha = _labeled_binding
        result.update(labeled_training_artifact_id=f"labels-fold{run['fold']}", labeled_training_manifest_sha256=labeled_sha,
            labeled_training_split_sha256=hashlib.sha256(canonical(labeled["sections"]).encode()).hexdigest(),
            normal_fit_split_sha256=dataset.split(f"fold{run['fold']}-fit")["sha256"],
            labeled_training_windows=81500, labeled_class_windows={"0": 71500, "1": 8000, "2": 2000})
    return result


def bounded_run_identity(dataset, run, labeled_bindings):
    """Reuse only matching-fold bindings actually verified during this call."""
    if recipe_binding(run["config"])["model_kind"] != HYBRID_MODEL_KIND:
        return run_identity(dataset, run)
    fold = run["fold"]
    if fold not in labeled_bindings:
        _, _, manifest, digest = hybrid_fold_training(dataset, fold)
        labeled_bindings[fold] = (manifest, digest)
    return run_identity(dataset, run, _labeled_binding=labeled_bindings[fold])


def hybrid_fold_training(dataset, fold):
    """Only complete matching-fold source; never PILOT/SCOPED or holdout I/O."""
    from app.hybrid_strict_dataset import load_hybrid_strict_fit, private_read
    if type(fold) is not int or fold not in (1, 2, 3) or dataset.manifest['stage'] != 'STRICT' or dataset.manifest['feature_schema_version'] != 4:
        raise ValueError('hybrid campaign requires matching strict schema4 fold')
    directory = dataset.root.parent / f'labels-fold{fold}'
    manifest_path = directory / 'manifest.private.json'
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_mode & 0o077:
        raise ValueError('protected complete fold-labeled source required')
    labeled_sha = hashlib.sha256(private_read(directory, 'manifest.private.json', 2 * 1024 * 1024)).hexdigest()
    normal, supervised, manifest = load_hybrid_strict_fit(directory, labeled_sha)
    fit = dataset.split(f'fold{fold}-fit')
    if (manifest['scope'] != 'FULL_STRICT_SOURCE' or manifest['fold'] != fold
            or manifest['standard_manifest_sha256'] != dataset.sha256 or manifest['standard_fit'] != fit
            or len(normal) != 50000 or len(supervised) != 81500
            or normal != [row for _, rows in dataset.iter_shards(f'fold{fold}-fit') for row in rows]):
        raise ValueError('labeled source must equal actual matching-fold normal FIT')
    return normal, supervised, manifest, labeled_sha


class HybridFitCounter:
    """Observe both genuine estimator fits; never replace their implementation."""
    def __enter__(self):
        from app.normal_support import NormalSupportScorer
        from sklearn.ensemble import HistGradientBoostingClassifier
        self.counts = {'normal_component_fit_calls': 0, 'labeled_component_fit_calls': 0}
        self.codes = {NormalSupportScorer.fit.__code__: 'normal_component_fit_calls',
                      inspect.unwrap(HistGradientBoostingClassifier.fit).__code__: 'labeled_component_fit_calls'}
        self.previous = sys.getprofile()
        if self.previous is not None: raise ValueError('ambiguous existing fit profiler')
        sys.setprofile(self.profile)
        return self
    def profile(self, frame, event, argument):
        if event == 'call' and frame.f_code in self.codes: self.counts[self.codes[frame.f_code]] += 1
    def __exit__(self, *arguments): sys.setprofile(self.previous)


def approved_run(run_id, model_kind=IF_MODEL_KIND):
    run = next((item for item in campaign_runs(model_kind) if item["run_id"] == run_id), None)
    if run is None: raise ValueError("unknown approved fit identity")
    return run


def validate_fit_recipe(dataset, fold):
    fit = dataset.split(f"fold{fold}-fit")
    minimum = 50000 if dataset.manifest["stage"] == "STRICT" else 500
    if not minimum <= fit["records"] <= 50000 or fit["positive"] or fit["cohorts"] != {"READY": fit["records"]}:
        raise ValueError("bounded mature all-normal fitting population required")
    for cohort in ("READY", "COLD"):
        part = cohort_split(dataset, f"fold{fold}-calibration-{cohort.lower()}", cohort)
        if dataset.manifest["stage"] == "STRICT" and part["records"] != 1000000:
            raise ValueError("strict campaign requires both million-window calibrations")
        if (utc(part["from"]) - utc(fit["to"])).total_seconds() <= 14 * 86400:
            raise ValueError("temporal baseline-history gap required")


def fit_one(directory: Path, run_id: str, model_kind=IF_MODEL_KIND, *, coordinated=False,
            expected_sha256=None, expected_archive_sha256=None):
    with coordinated_stage(directory, "campaign", enabled=coordinated):
        return _fit_one(directory, run_id, model_kind, expected_sha256=expected_sha256,
                        expected_archive_sha256=expected_archive_sha256)


def _fit_one(directory: Path, run_id: str, model_kind, *, expected_sha256, expected_archive_sha256):
    dataset = (ShardedDataset(directory) if expected_sha256 is None and expected_archive_sha256 is None else
               open_owned_dataset(directory, expected_sha256=expected_sha256, expected_archive_sha256=expected_archive_sha256))
    run = approved_run(run_id, model_kind); fold = run["fold"]
    prefix = campaign_prefix(model_kind)
    schema = dataset.manifest["feature_schema_version"]
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and schema != 4: raise ValueError("support/hybrid campaign requires schema 4")
    policy = ScorePolicy.strict(schema=schema)
    validate_fit_recipe(dataset, fold)
    expected = run_identity(dataset, run)
    version = prefix + "_fit_" + hashlib.sha256(canonical(expected).encode()).hexdigest()[:24]
    clone_version = prefix + "_cal_" + hashlib.sha256((version + dataset.sha256 + policy.sha256).encode()).hexdigest()[:24]
    store = ModelStore(directory / f"{prefix}-models")
    runs = directory / f"{prefix}-runs"; runs.mkdir(mode=0o700, exist_ok=True)
    path = runs / f"{run_id}.json"
    before = time.monotonic()
    if (store.directory / f"{version}.json").is_file():
        metadata, _ = store.load_candidate(version)
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise ValueError("previous fit does not prove this immutable run")
        recovered = True
    else:
        # Only extracted numeric features enter fitting. No account/family/label
        # identifier is present in either sklearn input array.
        samples = [row["features"] for _, rows in dataset.iter_shards(f"fold{fold}-fit") for row in rows]
        if len(samples) != dataset.split(f"fold{fold}-fit")["records"]: raise ValueError("actual fitted population differs from manifest")
        calibration = []
        for _, rows in dataset.iter_shards(f"fold{fold}-calibration-ready"):
            calibration.extend(row["features"] for row in rows[:5000 - len(calibration)])
            if len(calibration) == 5000: break
        labeled_args = {}
        if model_kind == HYBRID_MODEL_KIND:
            from app.hybrid_dataset import training_targets
            _, supervised, _, _ = hybrid_fold_training(dataset, fold)
            labeled_args = {'labeled_samples': [row['features'] for row in supervised], 'labeled_targets': training_targets(supervised)}
        if model_kind == HYBRID_MODEL_KIND:
            with HybridFitCounter() as actual:
                metadata = store.train(version, samples, calibration, schema_version=schema, config=run["config"], policy=policy, **labeled_args)
            if actual.counts != {'normal_component_fit_calls': 1, 'labeled_component_fit_calls': 1}:
                raise ValueError('one composite trial must prove both genuine component fits')
            metadata.update(actual_component_fit_counts=actual.counts)
        else:
            metadata = store.train(version, samples, calibration, schema_version=schema, config=run["config"], policy=policy, **labeled_args)
        metadata.update(expected); write(store.directory / f"{version}.json", metadata)
        recovered = False
    receipt = {**expected, "source_model_version": version, "source_model_sha256": metadata["sha256"],
               "training_windows": metadata["training_windows"], "fit_completed": True,
               "fit_recovered_without_refit": recovered, "data_provenance": "DEMO_ONLY",
               "status": "CALIBRATING", "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()}
    if model_kind == HYBRID_MODEL_KIND:
        if metadata.get('actual_component_fit_counts') != {'normal_component_fit_calls': 1, 'labeled_component_fit_calls': 1}:
            raise ValueError('retained hybrid source does not prove genuine component fit counts')
        receipt.update(actual_composite_trials=1, actual_component_fit_calls=2,
                       additional_component_fit_calls_this_attempt=0 if recovered else 2)
    write(path, receipt)
    if (store.directory / f"{clone_version}.json").is_file():
        calibrated, _ = store.load_candidate(clone_version)
        if (calibrated.get("source_model_sha256") != metadata["sha256"] or calibrated.get("dataset_manifest_sha256") != dataset.sha256
                or calibrated.get("score_policy") != policy.wire()):
            raise ValueError("previous recalibration does not match its source/policy")
    else:
        def progress(value): write(path, {**receipt, "calibration_progress": value, "updated_at_utc": timestamp()})
        result = recalibrate(store, dataset, fold, version, clone_version, policy, directory / f"{prefix}-score-cache", progress=progress)
        calibrated = result["metadata"]
    result = {**receipt, "status": "FITTED_CALIBRATED", "model_version": clone_version, "model_sha256": calibrated["sha256"],
              "calibration_sha256": calibrated["calibration_sha256"], "score_policy": calibrated["score_policy"],
              "calibration_scope": calibrated["calibration_scope"], "calibration_cohort_windows": calibrated["calibration_cohort_windows"],
              "additional_fit_calls_in_recalibration": 0, "elapsed_seconds": time.monotonic() - before,
              "completed_at_utc": timestamp(), "quality_gate": "NOT_RUN"}
    write(path, result)
    return result


def search(directory, timeout, model_kind=IF_MODEL_KIND, *, coordinated=False,
           expected_sha256=None, expected_archive_sha256=None, max_new_runs=None):
    """Run the existing search, optionally yielding after bounded new completions.

    Retained complete receipts do not consume the limit. A stopped receipt is
    not the full campaign, and child memmaps close before coordination releases.
    """
    validate_new_run_limit(max_new_runs)
    options = {"max_new_runs": max_new_runs} if max_new_runs is not None else {}
    with coordinated_stage(directory, "campaign", enabled=coordinated) as coordinator_fd:
        return _search(directory, timeout, model_kind, expected_sha256=expected_sha256,
                       expected_archive_sha256=expected_archive_sha256, coordinator_fd=coordinator_fd, **options)


def _search(directory, timeout, model_kind, *, expected_sha256, expected_archive_sha256, coordinator_fd=None,
            max_new_runs=None):
    prefix = campaign_prefix(model_kind)
    dataset = (ShardedDataset(directory) if expected_sha256 is None and expected_archive_sha256 is None else
               open_owned_dataset(directory, expected_sha256=expected_sha256, expected_archive_sha256=expected_archive_sha256))
    if dataset.manifest["stage"] != "STRICT": raise ValueError("PILOT cannot be counted as the strict 360-fit campaign")
    for fold in (1, 2, 3): validate_fit_recipe(dataset, fold)
    identity = {"dataset_manifest_sha256": dataset.sha256, "code_fingerprint": fingerprint(model_kind)}
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): identity.update(model_kind=model_kind, recipe_version=1)
    if model_kind == HYBRID_MODEL_KIND:
        identity['labeled_training_manifest_sha256_by_fold'] = {
            str(fold): hybrid_fold_training(dataset, fold)[3] for fold in (1, 2, 3)}
    identity_path = directory / f"{prefix}-campaign.identity.json"
    with (directory / f"{prefix}-campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if identity_path.exists():
            if json.loads(identity_path.read_text()) != identity: raise ValueError("code/dataset changed; retained fits cannot be silently reused")
        else: write(identity_path, identity)
        runs = directory / f"{prefix}-runs"; runs.mkdir(mode=0o700, exist_ok=True)
        approved = campaign_runs(model_kind)
        labeled_bindings = {}
        def expected_run(run):
            return (run_identity(dataset, run) if max_new_runs is None else
                    bounded_run_identity(dataset, run, labeled_bindings))
        retained = set()
        if max_new_runs is not None:
            # Count only byte-verified complete receipts, including those after
            # the next unfinished run. Never hide a failed later receipt by
            # yielding early, or count an unvisited suffix as complete.
            for run in approved:
                path = runs / f"{run['run_id']}.json"
                if not path.exists(): continue
                previous = json.loads(path.read_text()); expected = expected_run(run)
                if any(previous.get(key) != value for key, value in expected.items()):
                    raise ValueError("retained fit receipt identity mismatch")
                if previous.get("status") == "FAILED":
                    raise ValueError("retained failed fit needs diagnosis, not an automatic retry")
                if previous.get("status") == "FITTED_CALIBRATED":
                    if model_kind == HYBRID_MODEL_KIND and (previous.get('actual_composite_trials') != 1
                            or previous.get('actual_component_fit_calls') != 2):
                        raise ValueError('completed hybrid trial lacks both measured fit components')
                    artifact = directory / f"{prefix}-models" / f"{previous['model_version']}.joblib"
                    if sha(artifact) != previous["model_sha256"]:
                        raise ValueError("completed fit/calibration artifact changed")
                    retained.add(run["run_id"])
        completed, new_completed = 0, 0
        for run in approved:
            path = runs / f"{run['run_id']}.json"
            previous = json.loads(path.read_text()) if path.exists() else None
            expected = expected_run(run)
            if previous is not None and any(previous.get(key) != value for key, value in expected.items()):
                raise ValueError("retained fit receipt identity mismatch")
            if previous is not None and previous.get("status") == "FAILED":
                raise ValueError("retained failed fit needs diagnosis, not an automatic retry")
            newly_completed = previous is None or previous.get("status") != "FITTED_CALIBRATED"
            if previous is None or previous.get("status") != "FITTED_CALIBRATED":
                with (runs / f"{run['run_id']}.log").open("a") as log:
                    command = [sys.executable, "-m", "app.strict_campaign", "_fit", "--dataset", str(directory), "--run-id", run["run_id"]]
                    if model_kind != IF_MODEL_KIND: command.extend(["--model-kind", model_kind])
                    if expected_sha256 is not None: command.extend(["--dataset-sha256", expected_sha256])
                    if expected_archive_sha256 is not None: command.extend(["--archive-sha256", expected_archive_sha256])
                    # Parent campaign coordination covers child memmaps. Do not
                    # pass --coordinated: reacquiring that flock would fail.
                    # An inherited description also keeps the lock held if the
                    # parent dies before its still-scoring child. No reacquire.
                    child_options = {"pass_fds": (coordinator_fd,)} if coordinator_fd is not None else {}
                    child = subprocess.Popen(command, stdout=log, stderr=log, **child_options)
                    write(directory / f"{prefix}-campaign.live.json", {**identity, "status": "RUNNING", "pid": child.pid,
                          "parent_pid": os.getpid(), "run_id": run["run_id"], "started_at_utc": timestamp()})
                    try: code = child.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        child.terminate()
                        try: child.wait(timeout=15)
                        except subprocess.TimeoutExpired: child.kill(); child.wait()
                        failure = json.loads(path.read_text()) if path.exists() else {**expected, "fit_completed": False}
                        write(path, {**failure, "status": "FAILED", "reason": "TIMEOUT"})
                        raise RuntimeError("fit/calibration timed out; failure and committed raw-score cache retained") from None
                    if code:
                        failure = json.loads(path.read_text()) if path.exists() else {**expected, "fit_completed": False}
                        write(path, {**failure, "status": "FAILED", "reason": "CHILD_EXIT"})
                        raise RuntimeError("fit/calibration failed; diagnose the retained log")
            receipt = json.loads(path.read_text())
            if receipt.get("status") != "FITTED_CALIBRATED": raise ValueError("managed fit did not finish its real calibration")
            if model_kind == HYBRID_MODEL_KIND and (receipt.get('actual_composite_trials') != 1
                    or receipt.get('actual_component_fit_calls') != 2):
                raise ValueError('completed hybrid trial lacks both measured fit components')
            artifact = directory / f"{prefix}-models" / f"{receipt['model_version']}.joblib"
            if sha(artifact) != receipt["model_sha256"]: raise ValueError("completed fit/calibration artifact changed")
            completed += 1
            if newly_completed: new_completed += 1
            retained.add(run["run_id"])
            actual_completed = len(retained) if max_new_runs is not None else completed
            write(directory / f"{prefix}-campaign.progress.json", {**identity, "status": "RUNNING", "actual_fits_completed": actual_completed,
                  "required_fits": 360, "last_run_id": run["run_id"], "quality_gate": "NOT_RUN", "updated_at_utc": timestamp(),
                  **({'actual_composite_trials': actual_completed, 'actual_component_fit_calls': actual_completed * 2, 'required_component_fit_calls': 720}
                     if model_kind == HYBRID_MODEL_KIND else {})})
            print(f"ACTUAL FIT+CALIBRATION {actual_completed}/360 {run['run_id']}; quality NOT_RUN", flush=True)
            if max_new_runs is not None and new_completed >= max_new_runs and len(retained) < 360:
                stopped = {**identity, "status": "STOPPED_AT_RUN_BOUNDARY", "actual_fits_completed": len(retained),
                    "required_fits": 360, "new_runs_completed": new_completed, "last_run_id": run["run_id"],
                    "selection_status": "NOT_STARTED", "quality_gate": "NOT_RUN", "holdout_scored": False,
                    "updated_at_utc": timestamp()}
                if model_kind == HYBRID_MODEL_KIND:
                    stopped.update(actual_composite_trials=len(retained), actual_component_fit_calls=len(retained) * 2,
                                   required_component_fit_calls=720, additional_fits_in_recalibration=0)
                write(directory / f"{prefix}-campaign.progress.json", stopped)
                write(directory / f"{prefix}-campaign.live.json", {**stopped, "parent_pid": os.getpid()})
                return stopped
        complete = {**identity, "status": "FIT_AND_CALIBRATION_COMPLETE", "actual_fits_completed": completed,
                    "required_fits": 360, "selection_status": "NOT_STARTED", "quality_gate": "NOT_RUN",
                    "holdout_scored": False, "completed_at_utc": timestamp()}
        if model_kind == HYBRID_MODEL_KIND:
            complete.update(actual_composite_trials=completed, actual_component_fit_calls=completed * 2,
                            required_component_fit_calls=720, additional_fits_in_recalibration=0)
        write(directory / f"{prefix}-campaign.progress.json", complete)
        write(directory / f"{prefix}-campaign.live.json", {**complete, "parent_pid": os.getpid()})
        if max_new_runs is not None: return complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("search", "_fit"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--model-kind", choices=MODEL_KINDS, default=IF_MODEL_KIND)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--coordinated", action="store_true")
    parser.add_argument("--max-new-runs", type=int)
    parser.add_argument("--dataset-sha256"); parser.add_argument("--archive-sha256")
    args = parser.parse_args()
    if not 60 <= args.timeout <= 7200: parser.error("managed fit timeout must be 60..7200 seconds")
    options = {"coordinated": args.coordinated, "expected_sha256": args.dataset_sha256,
               "expected_archive_sha256": args.archive_sha256}
    if args.command == "search":
        if args.max_new_runs is not None: options["max_new_runs"] = args.max_new_runs
        search(args.dataset.resolve(strict=True), args.timeout, args.model_kind, **options)
    else:
        if args.max_new_runs is not None: parser.error("--max-new-runs applies only to search")
        if not args.run_id: parser.error("approved run ID required")
        print(canonical(fit_one(args.dataset.resolve(strict=True), args.run_id, args.model_kind, **options)), flush=True)


if __name__ == "__main__": main()
