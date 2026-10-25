"""Complete validation campaign and freeze selection before any holdout scoring."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from app.calibration import recalibrate
from app.catalog import ShardedDataset, parse_json
from app.contract import (HYBRID_MODEL_KIND, IF_MODEL_KIND, MODEL_KINDS, SUPPORT_MODEL_KIND, campaign_runs,
                          model_recipe_binding, recipe_binding)
from app.model import ModelStore
from app.owned_dataset import open_owned_dataset
from app.pipeline_lock import coordinated_stage
from app.policy import ScorePolicy, canonical
from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
from app.strict_campaign import (bounded_run_identity, campaign_prefix, fingerprint, run_identity, sha,
                                 timestamp, validate_new_run_limit, write)
from app.validation import class_binding, config_document, rank_configurations, validate_candidate


def producer_class_binding(dataset, workspace):
    """Read the unchanged producer's manifest-pinned JVM snapshot, never rows."""
    if "compiled_feature_sha256" in dataset.manifest:
        return dataset.manifest["compiled_feature_sha256"], None
    expected = dataset.manifest.get("workspace_snapshot_sha256")
    if type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None:
        raise ValueError("original producer workspace snapshot SHA required")
    workspace = Path(workspace).absolute(); path = workspace / "snapshot.json"
    if ".." in workspace.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical owner-controlled producer workspace required")
    info = workspace.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("canonical owner-controlled producer workspace required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o022
                or not 0 < before.st_size <= 2 * 1024 * 1024):
            raise ValueError("bounded owner-controlled producer snapshot required")
        raw = source.read(2 * 1024 * 1024 + 1)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(raw) != before.st_size or signature(before) != signature(os.fstat(source.fileno()))
                or signature(before) != signature(path.lstat()) or hashlib.sha256(raw).hexdigest() != expected):
            raise ValueError("original producer workspace snapshot changed")
    snapshot = parse_json(raw)
    if (type(snapshot) is not dict or set(snapshot) != {"classes", "jars"}
            or type(snapshot["classes"]) is not dict or not 1 <= len(snapshot["classes"]) <= 4096
            or type(snapshot["jars"]) is not dict or not 1 <= len(snapshot["jars"]) <= 512):
        raise ValueError("bounded typed producer JVM snapshot required")
    for name, checksum in snapshot["classes"].items():
        if (type(name) is not str or not 1 <= len(name) <= 512
                or re.fullmatch(r"(?:[A-Za-z0-9_$]+/)*[A-Za-z0-9_$]+\.class", name) is None
                or type(checksum) is not str or re.fullmatch(r"[a-f0-9]{64}", checksum) is None):
            raise ValueError("typed relative producer class SHA required")
        member = workspace / "backend/target/classes/com/flarefitness/backend" / name
        if any(part.is_symlink() for part in (member, *member.parents)):
            raise ValueError("producer class symlink refused")
    for name, checksum in snapshot["jars"].items():
        if (type(name) is not str or not 1 <= len(name) <= 256 or re.fullmatch(r"[A-Za-z0-9_.-]+\.jar", name) is None
                or type(checksum) is not str or re.fullmatch(r"[a-f0-9]{64}", checksum) is None):
            raise ValueError("typed producer dependency SHA required")
    return snapshot["classes"], expected


def selection_identity(dataset, workspace, model_kind=IF_MODEL_KIND):
    if model_kind == HYBRID_MODEL_KIND and dataset.manifest["feature_schema_version"] != 4:
        raise ValueError("hybrid selection requires schema 4")
    compiled, snapshot_sha = producer_class_binding(dataset, workspace)
    classes = class_binding(workspace)
    if snapshot_sha is not None and any(compiled.get(name) != checksum for name, checksum in classes.items()):
        raise ValueError("production decision code differs from original producer snapshot")
    for name in ("service/siem/AccountRiskEngine.class", "service/siem/AccountBehaviorFeatures.class"):
        if compiled.get(name) != classes[name]:
            raise ValueError("production decision/feature code differs from frozen dataset")
    producer_binding = {}
    if dataset.manifest["feature_schema_version"] in (3, 4):
        directory = workspace / "backend/target/classes/com/flarefitness/backend"
        for name in ("ops/UebaFeatureExport.class", "service/siem/AccountBaselinePolicy.class",
                     "service/siem/AccountBehaviorFeatures.class", "service/siem/AccountRiskEngine.class",
                     "service/siem/SecurityEventNormalizer.class", "service/siem/ContextualBehaviorFeatures.class"):
            checksum = sha(directory / name)
            if compiled.get(name) != checksum:
                raise ValueError("contextual feature producer differs from frozen dataset")
            producer_binding[name] = checksum
        if dataset.manifest["feature_schema_version"] == 4:
            for name in ("service/siem/SessionEndpointBehaviorFeatures.class", "service/siem/EndpointCategory.class"):
                checksum = sha(directory / name)
                if compiled.get(name) != checksum:
                    raise ValueError("session/endpoint producer differs from frozen dataset")
                producer_binding[name] = checksum
    directory = Path(__file__).resolve().parent
    selection_sources = ("selection.py", "validation.py", "risk_replay.py")
    return {"dataset_manifest_sha256": dataset.sha256, "fit_code_fingerprint": fingerprint(model_kind),
            "selection_sources": {name: sha(directory / name) for name in selection_sources},
            **({"model_kind": model_kind, "recipe_version": 1} if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) else {}),
            **({"producer_workspace_snapshot_sha256": snapshot_sha} if snapshot_sha is not None else {}),
            "production_classes": classes, **({"feature_producers": producer_binding} if producer_binding else {})}


def validate_all(directory, workspace, model_kind=IF_MODEL_KIND, *, coordinated=False,
                 expected_sha256=None, expected_archive_sha256=None, max_new_runs=None):
    """Optionally validate bounded completed fits without emitting a partial ranking."""
    validate_new_run_limit(max_new_runs)
    options = {"max_new_runs": max_new_runs} if max_new_runs is not None else {}
    with coordinated_stage(directory, "selection", enabled=coordinated):
        return _validate_all(directory, workspace, model_kind, expected_sha256=expected_sha256,
                             expected_archive_sha256=expected_archive_sha256, **options)


def _validate_all(directory, workspace, model_kind, *, expected_sha256, expected_archive_sha256, max_new_runs=None):
    prefix = campaign_prefix(model_kind)
    dataset = (ShardedDataset(directory) if expected_sha256 is None and expected_archive_sha256 is None else
               open_owned_dataset(directory, expected_sha256=expected_sha256, expected_archive_sha256=expected_archive_sha256))
    if dataset.manifest["stage"] != "STRICT": raise ValueError("strict validation cannot use a pilot catalogue")
    expected = selection_identity(dataset, workspace, model_kind)
    fit_progress = json.loads((directory / f"{prefix}-campaign.progress.json").read_text())
    full_fits = fit_progress.get("actual_fits_completed") == 360 and fit_progress.get("status") == "FIT_AND_CALIBRATION_COMPLETE"
    bounded_fits = (max_new_runs is not None and fit_progress.get("status") in
                    ("RUNNING", "STOPPED_AT_RUN_BOUNDARY", "FIT_AND_CALIBRATION_COMPLETE")
                    and type(fit_progress.get("actual_fits_completed")) is int
                    and 0 <= fit_progress["actual_fits_completed"] <= 360)
    if (not (full_fits or bounded_fits) or fit_progress.get("code_fingerprint") != expected["fit_code_fingerprint"]
            or fit_progress.get("dataset_manifest_sha256") != dataset.sha256):
        raise ValueError("all 360 frozen fit/calibration runs are required")
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and (fit_progress.get("model_kind") != model_kind or fit_progress.get("recipe_version") != 1):
        raise ValueError(f"{'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} campaign kind/version identity required")
    store = ModelStore(directory / f"{prefix}-models")
    output = directory / f"{prefix}-validations"; output.mkdir(mode=0o700, exist_ok=True)
    approved = campaign_runs(model_kind)
    if max_new_runs is not None:
        for run in approved:
            fit_path = directory / f"{prefix}-runs" / f"{run['run_id']}.json"
            path = output / f"{run['run_id']}.json"
            if fit_path.exists() and json.loads(fit_path.read_text()).get("status") == "FAILED":
                raise ValueError("retained failed fit needs diagnosis, not validation")
            if path.exists() and json.loads(path.read_text()).get("status") == "FAILED":
                raise ValueError("retained failed validation needs diagnosis, not an automatic retry")
    completed, new_completed, labeled_bindings, last_new_run = [], 0, {}, None
    for run in approved:
        fit_path = directory / f"{prefix}-runs" / f"{run['run_id']}.json"
        path = output / f"{run['run_id']}.json"
        if max_new_runs is not None and not fit_path.exists():
            if path.exists(): raise ValueError("retained validation lacks its completed fit receipt")
            continue
        fit = json.loads(fit_path.read_text())
        if fit.get("status") == "FAILED":
            raise ValueError("retained failed fit needs diagnosis, not validation")
        if max_new_runs is not None and new_completed >= max_new_runs and not path.exists(): continue
        identity = (run_identity(dataset, run) if max_new_runs is None else
                    bounded_run_identity(dataset, run, labeled_bindings))
        if fit.get("status") != "FITTED_CALIBRATED" or any(fit.get(key) != value for key, value in identity.items()):
            raise ValueError("fit receipt does not prove its immutable identity")
        metadata, _ = store.load_candidate(fit["model_version"])
        if metadata["sha256"] != fit["model_sha256"] or metadata["calibration_sha256"] != fit["calibration_sha256"]:
            raise ValueError("fitted/calibrated candidate changed before validation")
        binding = model_recipe_binding(metadata)
        if binding["model_kind"] != model_kind or (model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and binding != recipe_binding(run["config"])):
            raise ValueError("fitted candidate model kind/recipe differs from campaign")
        if path.exists():
            result = json.loads(path.read_text())
            if result.get("status") == "FAILED":
                raise ValueError("retained failed validation needs diagnosis, not an automatic retry")
            if result.get("selection_identity") != expected or result.get("model_sha256") != metadata["sha256"]:
                raise ValueError("retained validation code/artifact identity changed")
        else:
            if max_new_runs is not None and new_completed >= max_new_runs: continue
            def progress(value):
                write(directory / f"{prefix}-validation.progress.json", {"status": "RUNNING", "completed_runs": len(completed),
                      "run_id": run["run_id"], "scoring_progress": value, "selection_identity": expected,
                      "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()})
            try:
                result = validate_candidate(dataset, store, fit["model_version"], run["fold"], directory / f"{prefix}-score-cache", workspace, progress=progress)
            except Exception as failure:
                if max_new_runs is not None:
                    write(path, {"status": "FAILED", "selection_identity": expected, "run_id": run["run_id"],
                                 "model_sha256": metadata["sha256"], "reason": "VALIDATION_FAILED",
                                 "failure_type": type(failure).__name__, "quality_gate": "NOT_RUN"})
                raise
            result.update(selection_identity=expected, run_id=run["run_id"], status="VALIDATED", completed_at_utc=timestamp())
            write(path, result)
            new_completed += 1
            last_new_run = run["run_id"]
        if result.get("status") != "VALIDATED" or result.get("evaluation_scope") != "VALIDATION":
            raise ValueError("validation did not complete; quality cannot be inferred")
        completed.append(result)
        write(directory / f"{prefix}-validation.progress.json", {"status": "RUNNING", "completed_runs": len(completed),
              "required_runs": 360, "selection_identity": expected, "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()})
        print(f"ACTUAL VALIDATION {len(completed)}/360; holdout unopened", flush=True)
    if max_new_runs is not None and (len(completed) != 360 or not full_fits):
        stopped = {"status": "STOPPED_AT_VALIDATION_BOUNDARY", "completed_runs": len(completed),
                   "validation_runs_completed": len(completed), "new_runs_completed": new_completed,
                   "last_run_id": last_new_run,
                   "required_runs": 360, "selection_identity": expected, "quality_gate": "NOT_RUN",
                   "holdout_scored": False, "data_provenance": "DEMO_ONLY", "updated_at_utc": timestamp()}
        write(directory / f"{prefix}-validation.progress.json", stopped)
        return stopped
    result = rank_configurations(completed, model_kind)
    result.update(selection_identity=expected, validation_runs_completed=len(completed), data_provenance="DEMO_ONLY")
    write(directory / f"{prefix}-ranking.json", result)
    write(directory / f"{prefix}-validation.progress.json", {"status": "COMPLETED", "completed_runs": len(completed),
          "required_runs": 360, "selection_identity": expected, "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()})
    return result


def choose(directory, workspace, model_kind=IF_MODEL_KIND, *, coordinated=False,
           expected_sha256=None, expected_archive_sha256=None, max_new_recalibrations=None):
    """Bounded recalibration writes progress separately from immutable selection."""
    validate_new_run_limit(max_new_recalibrations, "max_new_recalibrations")
    options = {"max_new_recalibrations": max_new_recalibrations} if max_new_recalibrations is not None else {}
    with coordinated_stage(directory, "selection", enabled=coordinated):
        return _choose(directory, workspace, model_kind, expected_sha256=expected_sha256,
                       expected_archive_sha256=expected_archive_sha256, **options)


def _choose(directory, workspace, model_kind, *, expected_sha256, expected_archive_sha256, max_new_recalibrations=None):
    prefix = campaign_prefix(model_kind)
    dataset = (ShardedDataset(directory) if expected_sha256 is None and expected_archive_sha256 is None else
               open_owned_dataset(directory, expected_sha256=expected_sha256, expected_archive_sha256=expected_archive_sha256))
    if dataset.manifest["stage"] != "STRICT": raise ValueError("pilot cannot become a frozen strict selection")
    expected = selection_identity(dataset, workspace, model_kind)
    path = directory / f"{prefix}-selection.json"
    if path.exists():
        previous = json.loads(path.read_text())
        if previous.get("selection_identity") != expected: raise ValueError("frozen selection cannot be retuned after code/data changes")
        if previous.get("status") == "SELECTED":
            metadata, payload = ModelStore(directory / f"{prefix}-models").load_candidate(previous["model_version"])
            if (metadata["sha256"] != previous["model_sha256"] or metadata["calibration_sha256"] != previous["calibration_sha256"]
                    or metadata["score_policy"]["policy_sha256"] != previous["policy_sha256"]):
                raise ValueError("frozen selected artifact changed")
            if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
                if (model_recipe_binding(previous) != model_recipe_binding(metadata)
                        or previous.get("model_config") != metadata["model_config"]
                        or previous.get("model_state_sha256") != state_sha256(payload)
                        or previous.get("model_state_format") != state_format(payload)
                        or previous.get("model_state_verifier_sha256") != verifier_sha256(model_kind)
                        or previous.get("scoring_implementation") != ModelStore.scoring_identity(payload["model"])):
                    raise ValueError(f"frozen selected {'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} recipe/state changed")
                if model_kind == HYBRID_MODEL_KIND and (metadata.get("fold") != 3 or metadata["model_config"]["random_state"] != 42):
                    raise ValueError("frozen hybrid representative must be fold 3 seed 42")
        return previous
    ranking = json.loads((directory / f"{prefix}-ranking.json").read_text())
    if ranking.get("selection_identity") != expected or ranking.get("validation_runs_completed") != 360:
        raise ValueError("complete immutable validation ranking required")
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and (ranking.get("model_kind") != model_kind or ranking.get("recipe_version") != 1):
        raise ValueError(f"{'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} ranking kind/version identity required")
    if model_kind == HYBRID_MODEL_KIND:
        fields = ("max_iter", "max_leaf_nodes", "l2_regularization")
        approved = {canonical({key: config_document(run["config"])[key] for key in fields})
                    for run in campaign_runs(model_kind)}
        configurations = ranking.get("configurations", [])
        if (len(configurations) != 24 or any(set(value["configuration"]) != set(fields) for value in configurations)
                or {canonical(value["configuration"]) for value in configurations} != approved):
            raise ValueError("all 24 distinct approved hybrid configurations required")
    store = ModelStore(directory / f"{prefix}-models")
    recalibrations = directory / f"{prefix}-top-recalibrations"; recalibrations.mkdir(mode=0o700, exist_ok=True)
    approved_runs = campaign_runs(model_kind)
    if max_new_recalibrations is not None:
        for run in approved_runs:
            fit_path = directory / f"{prefix}-runs" / f"{run['run_id']}.json"
            receipt_path = recalibrations / f"{run['run_id']}.json"
            if json.loads(fit_path.read_text()).get("status") == "FAILED":
                raise ValueError("retained failed fit needs diagnosis, not recalibration")
            if receipt_path.exists() and json.loads(receipt_path.read_text()).get("status") == "FAILED":
                raise ValueError("retained failed recalibration needs diagnosis, not an automatic retry")
    completed, selected, new_completed, whole_configurations = [], None, 0, 0
    labeled_bindings, last_new_run = {}, None
    complete_prefix, selection_ready = True, False
    # Three configurations x five seeds x three folds. Each recalibration reads
    # actual cached million-window scores; it never calls fit(). Further
    # ranked configurations are tried when these three cannot qualify.
    for number, configuration in enumerate(ranking["configurations"]):
        config = configuration["configuration"]; policy = ScorePolicy.from_wire(configuration["best_common_policy"]["policy"])
        configuration_completed, configuration_required = 0, 0
        for run in approved_runs:
            if any(config_document(run["config"])[key] != value for key, value in config.items()): continue
            configuration_required += 1
            receipt_path = recalibrations / f"{run['run_id']}.json"
            if (max_new_recalibrations is not None and new_completed >= max_new_recalibrations
                    and not receipt_path.exists()): continue
            fit = json.loads((directory / f"{prefix}-runs" / f"{run['run_id']}.json").read_text())
            if fit.get("status") == "FAILED":
                raise ValueError("retained failed fit needs diagnosis, not recalibration")
            if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and (model_recipe_binding(fit) != recipe_binding(run["config"])
                    or any(fit.get(key) != value for key, value in
                           (run_identity(dataset, run) if max_new_recalibrations is None else
                            bounded_run_identity(dataset, run, labeled_bindings)).items())):
                raise ValueError(f"{'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} recalibration source run identity changed")
            if model_kind == HYBRID_MODEL_KIND and (fit.get("status") != "FITTED_CALIBRATED"
                    or policy.document["feature_schema_version"] != 4):
                raise ValueError("completed hybrid fit and schema 4 recalibration policy required")
            version = prefix + "_top_" + hashlib.sha256((fit["source_model_version"] + dataset.sha256 + policy.sha256).encode()).hexdigest()[:24]
            if receipt_path.exists():
                receipt = json.loads(receipt_path.read_text())
                if receipt.get("status") == "FAILED":
                    raise ValueError("retained failed recalibration needs diagnosis, not an automatic retry")
                if receipt.get("selection_identity") != expected or receipt.get("policy_sha256") != policy.sha256:
                    raise ValueError("recalibration receipt identity changed")
            else:
                if max_new_recalibrations is not None and new_completed >= max_new_recalibrations: continue
                try:
                    actual = recalibrate(store, dataset, run["fold"], fit["source_model_version"], version, policy, directory / f"{prefix}-score-cache")
                except Exception as failure:
                    if max_new_recalibrations is not None:
                        write(receipt_path, {"status": "FAILED", "selection_identity": expected, "run_id": run["run_id"],
                                             "policy_sha256": policy.sha256, "reason": "RECALIBRATION_FAILED",
                                             "failure_type": type(failure).__name__, "quality_gate": "NOT_RUN"})
                    raise
                receipt = {"selection_identity": expected, "run_id": run["run_id"], "model_version": version,
                           "model_sha256": actual["metadata"]["sha256"], "calibration_sha256": actual["metadata"]["calibration_sha256"],
                           "policy_sha256": policy.sha256, "additional_fit_calls": actual["additional_fit_calls"],
                           "calibration_receipts": actual["calibration_receipts"], "completed_at_utc": timestamp()}
                if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): receipt.update(recipe_binding(run["config"]))
                if model_kind == HYBRID_MODEL_KIND:
                    receipt.update(fold=run["fold"], config=config_document(run["config"]),
                                   source_model_version=fit["source_model_version"], source_model_sha256=fit["source_model_sha256"],
                                   **{key: actual["metadata"][key] for key in
                                      ("model_state_sha256", "model_state_format", "model_state_verifier_sha256")})
                write(receipt_path, receipt)
                new_completed += 1
                last_new_run = run["run_id"]
            metadata, _ = store.load_candidate(receipt["model_version"])
            if (metadata["sha256"] != receipt["model_sha256"] or metadata["calibration_sha256"] != receipt["calibration_sha256"]
                    or receipt.get("additional_fit_calls") != 0): raise ValueError("recalibrated artifact/fit count mismatch")
            if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and (model_recipe_binding(receipt) != recipe_binding(run["config"])
                    or model_recipe_binding(metadata) != recipe_binding(run["config"])):
                raise ValueError(f"recalibrated {'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} recipe identity mismatch")
            if model_kind == HYBRID_MODEL_KIND:
                required = {"run_id": run["run_id"], "model_version": version, "fold": run["fold"],
                            "config": config_document(run["config"]), "source_model_version": fit["source_model_version"],
                            "source_model_sha256": fit["source_model_sha256"]}
                if (any(receipt.get(key) != value for key, value in required.items())
                        or metadata.get("model_config") != required["config"] or metadata.get("fold") != run["fold"]
                        or metadata.get("source_model_version") != fit["source_model_version"]
                        or metadata.get("source_model_sha256") != fit["source_model_sha256"]
                        or metadata.get("score_policy") != policy.wire()
                        or any(receipt.get(key) != metadata.get(key) for key in
                               ("model_state_sha256", "model_state_format", "model_state_verifier_sha256"))
                        or type(receipt.get("additional_fit_calls")) is not int):
                    raise ValueError("recalibrated hybrid source/configuration/policy/state identity mismatch")
            completed.append(receipt)
            configuration_completed += 1
            if selected is None and configuration["qualified"] and run["fold"] == 3 and run["config"].random_state == 42:
                selected = receipt
        whole = configuration_required == 15 and configuration_completed == configuration_required
        if whole: whole_configurations += 1
        complete_prefix = complete_prefix and whole
        write(directory / f"{prefix}-recalibration.progress.json", {"completed_recalibrations": len(completed), "minimum_required": 45,
              "additional_fit_calls": 0, "quality_gate": "NOT_RUN", "selection_identity": expected})
        if number >= 2 and selected is not None and (max_new_recalibrations is None or complete_prefix):
            selection_ready = True
            break
    if max_new_recalibrations is not None and not selection_ready and not complete_prefix:
        stopped = {"status": "STOPPED_AT_RECALIBRATION_BOUNDARY", "selection_identity": expected,
                   "dataset_sha256": dataset.sha256, "actual_fits_completed": 360, "validation_runs_completed": 360,
                   "completed_recalibrations": len(completed), "completed_configurations": whole_configurations,
                   "new_recalibrations_completed": new_completed, "minimum_required": 45,
                   "last_run_id": last_new_run,
                   "additional_fit_calls_in_recalibration": 0, "quality_gate": "NOT_RUN", "holdout_scored": False,
                   "data_provenance": "DEMO_ONLY", "updated_at_utc": timestamp()}
        if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): stopped.update(model_kind=model_kind, recipe_version=1)
        write(directory / f"{prefix}-selection.progress.json", stopped)
        return stopped
    if len(completed) < 45: raise ValueError("top three full configuration recalibrations required")
    result = {"status": "SELECTED" if selected is not None else "NO_QUALIFIED_CONFIG", "selection_identity": expected,
              "dataset_sha256": dataset.sha256, "actual_fits_completed": 360, "validation_runs_completed": 360,
              "completed_recalibrations": len(completed), "additional_fit_calls_in_recalibration": 0,
              "quality_gate": "NOT_RUN", "holdout_scored": False, "data_provenance": "DEMO_ONLY", "frozen_at_utc": timestamp()}
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): result.update(model_kind=model_kind, recipe_version=1)
    if selected is not None:
        result.update({key: selected[key] for key in ("model_version", "model_sha256", "calibration_sha256", "policy_sha256")})
        metadata, payload = store.load_candidate(selected["model_version"])
        result["policy"] = metadata["score_policy"]
        if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
            result.update(model_recipe_binding(metadata), model_config=metadata["model_config"],
                          model_state_sha256=state_sha256(payload), model_state_format=state_format(payload),
                          model_state_verifier_sha256=verifier_sha256(model_kind),
                          scoring_implementation=ModelStore.scoring_identity(payload["model"]))
    write(path, result)
    if max_new_recalibrations is not None:
        write(directory / f"{prefix}-selection.progress.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "choose"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--model-kind", choices=MODEL_KINDS, default=IF_MODEL_KIND)
    parser.add_argument("--coordinated", action="store_true")
    parser.add_argument("--max-new-runs", type=int)
    parser.add_argument("--max-new-recalibrations", type=int)
    parser.add_argument("--dataset-sha256"); parser.add_argument("--archive-sha256")
    args = parser.parse_args()
    options = {"coordinated": args.coordinated, "expected_sha256": args.dataset_sha256,
               "expected_archive_sha256": args.archive_sha256}
    consumer = validate_all if args.command == "validate" else choose
    if args.command == "validate":
        if args.max_new_recalibrations is not None: parser.error("--max-new-recalibrations applies only to choose")
        if args.max_new_runs is not None: options["max_new_runs"] = args.max_new_runs
    else:
        if args.max_new_runs is not None: parser.error("--max-new-runs applies only to validate")
        if args.max_new_recalibrations is not None: options["max_new_recalibrations"] = args.max_new_recalibrations
    result = consumer(args.dataset.resolve(strict=True), args.workspace.resolve(strict=True), args.model_kind, **options)
    print(canonical({key: value for key, value in result.items() if key != "configurations"}), flush=True)


if __name__ == "__main__": main()
