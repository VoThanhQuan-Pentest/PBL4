"""Operator packaging of immutable numeric shards and portable Java replay code.

No uploaded models, activation or secrets. STRICT packaging requires completed
independent selection; explicit preview packaging stays permanently PILOT.
"""

import argparse
from dataclasses import asdict
import fcntl
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import shutil
import uuid

from app.catalog import ShardedDataset, parse_json
from app.contract import (HYBRID_MODEL_KIND, IF_MODEL_KIND, MODEL_KINDS, SUPPORT_MODEL_KIND,
                          campaign_runs, model_recipe_binding, parse_training_config, recipe_binding, validate_version)
from app.holdout_provenance import (MARKER as HOLDOUT_AUDIT_FILE, MAX_AUDIT_BYTES as MAX_HOLDOUT_AUDIT_BYTES,
                                    holdout_audit_resources)
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from app.quality_proof import sha_file
from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
from app.owned_dataset import open_owned_dataset
from app.strict_campaign import campaign_prefix, fingerprint, hybrid_fold_training

MAX_PROOF_FILES = 1100
MAX_PROOF_BYTES = 2 * 1024 * 1024 * 1024
MAX_PROOF_MANIFEST_BYTES = 4 * 1024 * 1024


def bounded(path, limit=8 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit: raise ValueError("bounded regular package source required")
    return parse_json(path.read_bytes())


def proof_inventory(dataset, selected):
    """Hash bounded actual files; the inventory is evidence, not qualification."""
    from app.hybrid_strict_dataset import private_read
    runs = {run["run_id"] for run in campaign_runs(HYBRID_MODEL_KIND)}
    members = ["hybrid-campaign.progress.json", "hybrid-selection.json"]
    for name in ("hybrid-runs", "hybrid-validations", "hybrid-top-recalibrations"):
        directory = dataset.root / name
        if directory.is_symlink() or directory.resolve() != directory.absolute(): raise ValueError("canonical proof directory required")
        paths = sorted(islice(directory.glob("*.json"), 361))
        names = {path.stem for path in paths}
        if (not names <= runs or name != "hybrid-top-recalibrations" and names != runs
                or name == "hybrid-top-recalibrations" and not 45 <= len(names) <= 360):
            raise ValueError("complete bounded approved proof files required")
        members.extend(str(path.relative_to(dataset.root)) for path in paths)
    version = selected["model_version"]; validate_version(version)
    members.extend(f"hybrid-models/{version}.{extension}" for extension in ("json", "joblib"))
    if len(members) > MAX_PROOF_FILES: raise ValueError("proof inventory exceeds fixed file budget")
    files = {}; total = 0
    for name in members:
        path = dataset.root / name; limit = proof_file_limit(name)
        if (path.is_symlink() or path.resolve() != path.absolute() or not path.is_file()
                or not 0 < path.stat().st_size <= limit): raise ValueError("bounded canonical proof file required")
        total += path.stat().st_size
        if total > MAX_PROOF_BYTES: raise ValueError("proof bundle exceeds fixed byte budget")
        files[name] = sha_file(path)
    archive = {}
    for run_id in sorted(runs):
        fit = bounded(dataset.root / "hybrid-runs" / (run_id + ".json"), 1024 * 1024)
        archive[run_id] = {key: fit[key] for key in ("source_model_sha256", "model_sha256")}
    proof = {"format": "HYBRID_STRICT_PROOF_V1", "dataset_sha256": dataset.sha256,
            "selection_sha256": files["hybrid-selection.json"], "model_sha256": selected["model_sha256"],
            "calibration_sha256": selected["calibration_sha256"], "model_state_sha256": selected["model_state_sha256"],
            "files": files, "source_label_manifests": {
                str(fold): {"artifact_id": f"labels-fold{fold}", "manifest_sha256": hashlib.sha256(
                    private_read(dataset.root.parent / f"labels-fold{fold}", "manifest.private.json", 2 * 1024 * 1024)).hexdigest()}
                for fold in (1, 2, 3)}, "archive_model_sha256": archive}
    if len(canonical(proof).encode()) > MAX_PROOF_MANIFEST_BYTES: raise ValueError("bounded strict proof inventory required")
    return proof


def proof_file_limit(name):
    if name.endswith(".joblib"): return 128 * 1024 * 1024
    if name.startswith("hybrid-validations/"): return 4 * 1024 * 1024
    return 1024 * 1024


def copy_checked(source, target, checksum, limit, *, private=False):
    if source.is_symlink() or not source.is_file() or source.stat().st_size > limit or sha_file(source) != checksum:
        raise ValueError("immutable package input changed")
    if private and (source.resolve() != source.absolute() or source.stat().st_uid != os.geteuid()
                    or source.stat().st_mode & 0o777 != 0o600): raise ValueError("canonical owner-only immutable source required")
    if private:
        missing = []; parent = target.parent
        while not parent.exists(): missing.append(parent); parent = parent.parent
        if parent.is_symlink() or parent.resolve() != parent.absolute(): raise ValueError("canonical package parent required")
        for parent in reversed(missing): parent.mkdir(mode=0o700)
        incoming = os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb")
    else:
        target.parent.mkdir(mode=0o750, parents=True, exist_ok=True); incoming = source.open("rb")
    outgoing = (os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
                if private else target.open("xb"))
    with incoming, outgoing: shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    target.chmod(0o600 if private else 0o640)
    if sha_file(target) != checksum: raise ValueError("package copy checksum mismatch")


def hybrid_selection_proof(dataset, selected, metadata, payload):
    """Read complete campaign evidence, never fit, select or parse holdout rows."""
    if (dataset.manifest["stage"] != "STRICT" or dataset.manifest["feature_schema_version"] != 4
            or not isinstance(selected, dict) or selected.get("status") != "SELECTED"
            or selected.get("dataset_sha256") != dataset.sha256 or selected.get("model_kind") != HYBRID_MODEL_KIND
            or any(type(selected.get(key)) is not int or selected[key] != value for key, value in
                   {"actual_fits_completed": 360, "validation_runs_completed": 360,
                    "additional_fit_calls_in_recalibration": 0}.items())
            or type(selected.get("completed_recalibrations")) is not int or not 45 <= selected["completed_recalibrations"] <= 360):
        raise ValueError("complete selected strict schema4 hybrid receipt required")
    counts = metadata.get("actual_component_fit_counts")
    if (metadata.get("fold") != 3 or metadata.get("training_windows") != 50000
            or metadata.get("calibration_scope") != "STRICT"
            or not isinstance(counts, dict) or set(counts) != {"normal_component_fit_calls", "labeled_component_fit_calls"}
            or any(type(value) is not int or value != 1 for value in counts.values())):
        raise ValueError("selected original must preserve both measured component fits")
    progress = bounded(dataset.root / "hybrid-campaign.progress.json", 1024 * 1024)
    code = fingerprint(HYBRID_MODEL_KIND)
    identity = selected.get("selection_identity")
    if (not isinstance(progress, dict) or not isinstance(identity, dict)
            or progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE"
            or progress.get("code_fingerprint") != code or identity.get("fit_code_fingerprint") != code
            or identity.get("dataset_manifest_sha256") != dataset.sha256
            or progress.get("dataset_manifest_sha256") != dataset.sha256
            or progress.get("model_kind") != HYBRID_MODEL_KIND or identity.get("model_kind") != HYBRID_MODEL_KIND
            or any(type(progress.get(key)) is not int or progress[key] != value for key, value in
                   {"actual_fits_completed": 360, "actual_composite_trials": 360,
                    "actual_component_fit_calls": 720, "required_component_fit_calls": 720,
                    "additional_fits_in_recalibration": 0}.items())):
        raise ValueError("complete genuine hybrid 360/720 campaign proof required")
    folds = {fold: hybrid_fold_training(dataset, fold) for fold in (1, 2, 3)}
    hashes = {str(fold): value[3] for fold, value in folds.items()}
    if progress.get("labeled_training_manifest_sha256_by_fold") != hashes:
        raise ValueError("campaign independent labeled fold identities changed")
    runs = campaign_runs(HYBRID_MODEL_KIND); fits = {}; approved = {run["run_id"]: run for run in runs}
    for run in runs:
        fit = bounded(dataset.root / "hybrid-runs" / (run["run_id"] + ".json"), 1024 * 1024)
        fold = run["fold"]; manifest = folds[fold][2]
        expected = {"dataset_manifest_sha256": dataset.sha256, "code_fingerprint": code,
                    "run_id": run["run_id"], "fold": fold, "config": asdict(run["config"]),
                    "fit_split_sha256": dataset.split(f"fold{fold}-fit")["sha256"],
                    "normal_fit_split_sha256": dataset.split(f"fold{fold}-fit")["sha256"],
                    "labeled_training_artifact_id": f"labels-fold{fold}",
                    "labeled_training_manifest_sha256": hashes[str(fold)],
                    "labeled_training_split_sha256": hashlib.sha256(canonical(manifest["sections"]).encode()).hexdigest(),
                    "labeled_training_windows": 81500, "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000},
                    **recipe_binding(run["config"])}
        if (not isinstance(fit, dict) or any(fit.get(key) != value for key, value in expected.items())
                or fit.get("status") != "FITTED_CALIBRATED"
                or any(type(fit.get(key)) is not int or fit[key] != value for key, value in
                       {"actual_composite_trials": 1, "actual_component_fit_calls": 2,
                        "additional_fit_calls_in_recalibration": 0}.items())):
            raise ValueError("every approved hybrid trial requires measured two-component evidence")
        validate_version(fit["model_version"]); validate_version(fit["source_model_version"])
        for version, checksum in ((fit["model_version"], fit["model_sha256"]), (fit["source_model_version"], fit["source_model_sha256"])):
            artifact = dataset.root / "hybrid-models" / (version + ".joblib")
            if (artifact.is_symlink() or artifact.resolve() != artifact.absolute() or not artifact.is_file()
                    or not 0 < artifact.stat().st_size <= proof_file_limit(str(artifact)) or sha_file(artifact) != checksum):
                raise ValueError("hybrid fitted archive changed")
        validation = bounded(dataset.root / "hybrid-validations" / (run["run_id"] + ".json"), 4 * 1024 * 1024)
        if (not isinstance(validation, dict) or validation.get("status") != "VALIDATED"
                or validation.get("evaluation_scope") != "VALIDATION" or validation.get("run_id") != run["run_id"]
                or validation.get("selection_identity") != identity or validation.get("model_sha256") != fit["model_sha256"]
                or validation.get("calibration_sha256") != fit["calibration_sha256"]):
            raise ValueError("all independent frozen hybrid validation receipts required")
        fits[run["run_id"]] = fit
    directory = dataset.root / "hybrid-top-recalibrations"
    if directory.is_symlink() or directory.resolve() != directory.absolute(): raise ValueError("canonical recalibration receipts required")
    paths = sorted(islice(directory.glob("*.json"), 361))
    if not 45 <= len(paths) <= 360 or len(paths) != selected["completed_recalibrations"]:
        raise ValueError("at least 45 distinct zero-fit recalibrations required")
    groups = {}; representative = None
    for path in paths:
        receipt = bounded(path, 1024 * 1024); run = approved.get(path.stem)
        if run is None or not isinstance(receipt, dict): raise ValueError("unapproved recalibration receipt")
        fit = fits[path.stem]
        expected = {"selection_identity": identity, "run_id": path.stem, "fold": run["fold"],
                    "config": asdict(run["config"]), "source_model_version": fit["source_model_version"],
                    "source_model_sha256": fit["source_model_sha256"], **recipe_binding(run["config"])}
        if (any(receipt.get(key) != value for key, value in expected.items())
                or type(receipt.get("additional_fit_calls")) is not int or receipt["additional_fit_calls"] != 0):
            raise ValueError("zero additional fit and immutable recalibration source required")
        config = asdict(run["config"]); config.pop("random_state")
        groups.setdefault(canonical(config), set()).add((run["fold"], run["config"].random_state))
        if receipt.get("model_version") == selected["model_version"]: representative = receipt
    if len(groups) < 3 or any(len(values) != 15 for values in groups.values()):
        raise ValueError("three full configuration/seed/fold recalibrations required")
    labeled = folds[3][2]
    binding = {"labeled_training_artifact_id": "labels-fold3", "labeled_training_manifest_sha256": hashes["3"],
               "labeled_training_split_sha256": hashlib.sha256(canonical(labeled["sections"]).encode()).hexdigest(),
               "normal_fit_split_sha256": dataset.split("fold3-fit")["sha256"],
               "labeled_training_windows": 81500, "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000}}
    if (representative is None or representative["fold"] != 3 or representative["config"]["random_state"] != 42
            or representative["config"] != metadata["model_config"]
            or any(metadata.get(key) != value for key, value in binding.items())
            or any(selected.get(key) != value for key, value in {
                **model_recipe_binding(metadata), "model_config": metadata["model_config"],
                "model_state_sha256": state_sha256(payload), "model_state_format": state_format(payload),
                "model_state_verifier_sha256": verifier_sha256(HYBRID_MODEL_KIND),
                "scoring_implementation": ModelStore.scoring_identity(payload["model"])}.items())
            or any(representative.get(key) != metadata.get(key) for key in
                   ("model_state_sha256", "model_state_format", "model_state_verifier_sha256"))
            or representative.get("model_sha256") != metadata["sha256"]
            or representative.get("calibration_sha256") != metadata["calibration_sha256"]):
        raise ValueError("selected fold3 seed42 labeled/model numeric binding changed")
    proof = proof_inventory(dataset, selected)
    if any(proof["source_label_manifests"][str(fold)]["manifest_sha256"] != hashes[str(fold)] for fold in (1, 2, 3)):
        raise ValueError("source labels changed while constructing proof")
    return binding, proof


def hybrid_strict_proof(dataset, selected, metadata, payload):
    """Native source read-only proof constructor for pre-holdout consumers."""
    return hybrid_selection_proof(dataset, selected, metadata, payload)[1]


def recipe_entry(dataset, recipe_id, *, preview=False, model_kind=IF_MODEL_KIND):
    if not isinstance(recipe_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,96}", recipe_id): raise ValueError("bounded operator recipe ID required")
    prefix = campaign_prefix(model_kind)
    if preview:
        if dataset.manifest["stage"] != "PILOT": raise ValueError("preview cannot relabel strict data")
        if model_kind != IF_MODEL_KIND: raise ValueError("typed non-IF previews require independently installed labeled recipes")
        return {"recipe_id": recipe_id, "dataset_id": dataset.manifest["dataset_id"], "manifest_sha256": dataset.sha256,
                "mode": "PILOT", "fold": 1, "score_policy": ScorePolicy.strict().wire(),
                "config": {"n_estimators": 200, "max_samples": 128, "max_features": 1.0, "random_state": 42}}
    selected_path = dataset.root / (prefix + "-selection.json")
    selected = bounded(selected_path, 1024 * 1024)
    if model_kind == HYBRID_MODEL_KIND and (not isinstance(selected, dict) or any(type(selected.get(key)) is not int for key in
            ("actual_fits_completed", "validation_runs_completed", "completed_recalibrations", "additional_fit_calls_in_recalibration"))
            or selected.get("model_kind") != model_kind): raise ValueError("typed hybrid selection counts/kind required")
    if (not isinstance(selected, dict) or dataset.manifest["stage"] != "STRICT" or selected.get("status") != "SELECTED"
            or selected.get("actual_fits_completed") != 360 or selected.get("validation_runs_completed") != 360
            or selected.get("completed_recalibrations", 0) < 45 or selected.get("additional_fit_calls_in_recalibration") != 0
            or selected.get("dataset_sha256") != dataset.sha256): raise ValueError("complete immutable strict selection required")
    models = dataset.root / (prefix + "-models")
    if model_kind == HYBRID_MODEL_KIND and (models.is_symlink() or models.resolve() != models.absolute()):
        raise ValueError("canonical selected model directory required")
    metadata, payload = ModelStore(models).load_candidate(selected["model_version"])
    policy = ScorePolicy.from_wire(metadata["score_policy"])
    if (metadata.get("calibration_scope") != "STRICT" or metadata.get("dataset_manifest_sha256") != dataset.sha256
            or selected.get("model_sha256") != metadata["sha256"] or selected.get("calibration_sha256") != metadata["calibration_sha256"]
            or selected.get("policy") != policy.wire() or metadata.get("fold") != 3): raise ValueError("frozen selected artifact binding changed")
    config = metadata["model_config"]
    if model_recipe_binding(metadata)["model_kind"] != model_kind: raise ValueError("selected model kind differs")
    validated = parse_training_config(model_kind, config)
    if model_kind != IF_MODEL_KIND and model_recipe_binding(metadata) != recipe_binding(validated):
        raise ValueError("selected typed recipe binding differs")
    allowed = (asdict(validated) if model_kind == HYBRID_MODEL_KIND else
               {name: getattr(validated, name) for name in ("n_estimators", "max_samples", "max_features", "random_state")}
               if model_kind == IF_MODEL_KIND else validated.parameters())
    if validated.random_state != 42: raise ValueError("frozen representative seed required")
    extra = {}
    if model_kind == HYBRID_MODEL_KIND:
        extra, proof = hybrid_selection_proof(dataset, selected, metadata, payload)
        extra["strict_proof_sha256"] = hashlib.sha256(canonical(proof).encode()).hexdigest()
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND): extra.update(recipe_binding(validated))
    return {"recipe_id": recipe_id, "dataset_id": dataset.manifest["dataset_id"], "manifest_sha256": dataset.sha256,
            "mode": "STRICT", "fold": 3, "score_policy": policy.wire(), "config": allowed,
            "selection_sha256": sha_file(selected_path), "expected_model_sha256": metadata["sha256"],
            "expected_calibration_sha256": metadata["calibration_sha256"],
            "expected_model_state_sha256": state_sha256(payload), "model_state_format": state_format(payload),
            "model_state_verifier_sha256": verifier_sha256(model_kind), **extra}


def archive_package_files(dataset):
    """Authenticate archived storage bytes only; never decode or parse rows."""
    from app.archived_catalog import MAX_XZ_BYTES, SIDECAR, private_bytes
    from app.catalog import MAX_MANIFEST_BYTES, MAX_SHARD_BYTES
    raw = private_bytes(dataset.root, SIDECAR, MAX_MANIFEST_BYTES)
    if hashlib.sha256(raw).hexdigest() != dataset.archive_sha256:
        raise ValueError("archive sidecar changed before packaging")
    resources = [(SIDECAR, dataset.archive_sha256, MAX_MANIFEST_BYTES)]
    for relative, archived in dataset._archive_entries.items():
        encoded = private_bytes(dataset.root, archived["archive_path"], MAX_XZ_BYTES)
        if (len(encoded) != archived["archive_bytes"]
                or hashlib.sha256(encoded).hexdigest() != archived["archive_sha256"]):
            raise ValueError("archived package blob checksum/size changed")
        resources.append((archived["archive_path"], archived["archive_sha256"], MAX_XZ_BYTES))
        path = dataset.root / relative
        if path.exists() or path.is_symlink():
            original = private_bytes(dataset.root, relative, MAX_SHARD_BYTES)
            if (len(original) != archived["original_bytes"]
                    or hashlib.sha256(original).hexdigest() != archived["original_sha256"]):
                raise ValueError("present archived package original changed")
            resources.append((relative, archived["original_sha256"], MAX_SHARD_BYTES))
    return resources


def package_recipe(source, destination, recipe_id, *, preview=False, model_kind=IF_MODEL_KIND,
                   expected_sha256=None, expected_archive_sha256=None):
    if source.is_symlink() or destination.is_symlink(): raise ValueError("package roots cannot be symlinks")
    dataset = (ShardedDataset(source, expected_sha256=expected_sha256) if expected_archive_sha256 is None else
               open_owned_dataset(source, expected_sha256=expected_sha256, expected_archive_sha256=expected_archive_sha256))
    audits = holdout_audit_resources(dataset.root)
    if len(audits) == 2 and audits[0][1] != audits[1][1]:
        raise ValueError("conflicting protected holdout access audit markers")
    entry = recipe_entry(dataset, recipe_id, preview=preview, model_kind=model_kind)
    if audits: entry["holdout_access_audit_sha256"] = hashlib.sha256(audits[0][1]).hexdigest()
    archived = expected_archive_sha256 is not None
    resources = archive_package_files(dataset) if archived else None
    if archived: entry["archive_sha256"] = dataset.archive_sha256
    hybrid = model_kind == HYBRID_MODEL_KIND
    private = hybrid or archived
    if hybrid:
        # Reuse the final evidence guard before creating any package output.
        # A supplied inventory avoids its native constructor calling us again.
        from app.frozen_evaluation import verify_hybrid_strict_proof
        selected = bounded(dataset.root / "hybrid-selection.json", 1024 * 1024)
        metadata, payload = ModelStore(dataset.root / "hybrid-models").load_candidate(selected["model_version"])
        proof = proof_inventory(dataset, selected)
        if hashlib.sha256(canonical(proof).encode()).hexdigest() != entry["strict_proof_sha256"]:
            raise ValueError("campaign proof changed before pre-publication verification")
        verify_hybrid_strict_proof(dataset, selected, metadata, payload, proof=proof)
    destination.mkdir(mode=0o700 if private else 0o750, parents=True, exist_ok=True)
    if private and (destination.resolve() != destination.absolute() or destination.stat().st_uid != os.geteuid()
                    or destination.stat().st_mode & 0o777 != 0o700): raise ValueError("private owner-only hybrid catalogue required")
    target = destination / dataset.manifest["dataset_id"]
    if private and (destination / ".package.lock").is_symlink(): raise ValueError("canonical package lock required")
    with (destination / ".package.lock").open("a") as lock:
        if private: (destination / ".package.lock").chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        registry_path = destination / "catalog.json"
        if private and registry_path.exists() and (registry_path.stat().st_uid != os.geteuid()
                or registry_path.stat().st_mode & 0o777 != 0o600):
            raise ValueError("private owner-controlled package registry required")
        registry = bounded(registry_path, 1024 * 1024) if registry_path.exists() else {"entries": [], "strict_entries": []}
        if not isinstance(registry, dict): raise ValueError("typed catalogue registry required")
        entries = registry.setdefault("strict_entries", [])
        if not isinstance(entries, list) or len(entries) > 4: raise ValueError("bounded strict registry required")
        previous = next((value for value in entries if value.get("recipe_id") == recipe_id), None)
        if previous is not None:
            if previous != entry: raise ValueError("registered immutable recipe changed")
            if audits:
                installed_audits = holdout_audit_resources(target)
                root_audit = next((raw for path, raw in installed_audits if path == (target / HOLDOUT_AUDIT_FILE).absolute()), None)
                if root_audit != audits[0][1] or any(raw != audits[0][1] for _, raw in installed_audits):
                    raise ValueError("installed protected holdout access audit changed or missing")
            installed = (open_owned_dataset(target, expected_sha256=dataset.sha256, expected_archive_sha256=entry["archive_sha256"])
                         if archived else ShardedDataset(target, expected_sha256=dataset.sha256))
            if archived:
                archive_package_files(installed)
            else:
                for split in installed.manifest["splits"].values():
                    for descriptor in split["shards"]:
                        path = installed.root / descriptor["path"]
                        if path.is_symlink() or sha_file(path) != descriptor["sha256"]: raise ValueError("installed numeric shard changed")
            if hybrid:
                from app.hybrid_strict_dataset import load_hybrid_strict_fit
                proof = bounded(target / "hybrid-strict-proof.json", MAX_PROOF_MANIFEST_BYTES)
                if sha_file(target / "hybrid-strict-proof.json") != entry["strict_proof_sha256"]:
                    raise ValueError("installed strict proof inventory changed")
                for name, checksum in proof["files"].items():
                    path = target / name
                    if path.is_symlink() or path.resolve() != path.absolute() or sha_file(path) != checksum:
                        raise ValueError("installed campaign proof changed")
                for reference in proof["source_label_manifests"].values():
                    load_hybrid_strict_fit(destination / reference["artifact_id"], reference["manifest_sha256"])
            if holdout_audit_resources(dataset.root) != audits:
                raise ValueError("source protected holdout access audit changed during packaging")
            return entry
        if len(entries) >= 4 or target.exists() or any(value.get("dataset_id") == entry["dataset_id"] for value in entries):
            raise ValueError("existing dataset or registry capacity cannot be overwritten")
        pending = destination / (".pending-" + dataset.manifest["dataset_id"] + "-" + uuid.uuid4().hex)
        pending.mkdir(mode=0o700 if private else 0o750)
        copy_checked(dataset.root / "manifest.json", pending / "manifest.json", dataset.sha256, 8 * 1024 * 1024, private=private)
        if audits:
            copy_checked(audits[0][0], pending / HOLDOUT_AUDIT_FILE, entry["holdout_access_audit_sha256"],
                         MAX_HOLDOUT_AUDIT_BYTES, private=True)
        if entry["mode"] == "STRICT":
            name = campaign_prefix(model_kind) + "-selection.json"
            copy_checked(dataset.root / name, pending / name, entry["selection_sha256"], 1024 * 1024, private=private)
        if archived:
            for name, checksum, limit in resources:
                copy_checked(dataset.root / name, pending / name, checksum, limit, private=True)
            installed = open_owned_dataset(pending, expected_sha256=dataset.sha256,
                                           expected_archive_sha256=entry["archive_sha256"])
            archive_package_files(installed)
        else:
            for split in dataset.manifest["splits"].values():
                for descriptor in split["shards"]:
                    copy_checked(dataset.root / descriptor["path"], pending / descriptor["path"], descriptor["sha256"], 8 * 1024 * 1024, private=private)
        if hybrid:
            from app.hybrid_strict_dataset import load_hybrid_strict_fit
            selected = bounded(dataset.root / "hybrid-selection.json", 1024 * 1024)
            proof = proof_inventory(dataset, selected)
            if hashlib.sha256(canonical(proof).encode()).hexdigest() != entry["strict_proof_sha256"]:
                raise ValueError("campaign proof changed before packaging")
            for name, checksum in proof["files"].items():
                if name == "hybrid-selection.json": continue
                copy_checked(dataset.root / name, pending / name, checksum,
                             proof_file_limit(name), private=True)
            retained, retained_payload = ModelStore(pending / "hybrid-models").load_candidate(selected["model_version"])
            if (retained["sha256"] != entry["expected_model_sha256"]
                    or retained["calibration_sha256"] != entry["expected_calibration_sha256"]
                    or state_sha256(retained_payload) != entry["expected_model_state_sha256"]
                    or model_recipe_binding(retained) != model_recipe_binding(entry)
                    or retained["model_config"] != entry["config"] or retained["score_policy"] != entry["score_policy"]):
                raise ValueError("copied selected numeric candidate changed")
            (pending / "hybrid-strict-proof.json").write_text(canonical(proof)); (pending / "hybrid-strict-proof.json").chmod(0o600)
            staged_labels = []
            for reference in proof["source_label_manifests"].values():
                labeled_source = dataset.root.parent / reference["artifact_id"]
                _, _, labeled = load_hybrid_strict_fit(labeled_source, reference["manifest_sha256"])
                labeled_target = destination / reference["artifact_id"]
                if labeled_target.exists() or labeled_target.is_symlink(): raise ValueError("existing labeled artifact cannot be overwritten")
                labeled_pending = destination / (".pending-labels-" + uuid.uuid4().hex); labeled_pending.mkdir(mode=0o700)
                members = [("manifest.private.json", reference["manifest_sha256"]),
                           ("predeclared.private.json", labeled["predeclared_sha256"])]
                members.extend((shard["path"], shard["sha256"]) for section in labeled["sections"].values() for shard in section["shards"])
                for name, checksum in members:
                    copy_checked(labeled_source / name, labeled_pending / name, checksum, 8 * 1024 * 1024, private=True)
                load_hybrid_strict_fit(labeled_pending, reference["manifest_sha256"])
                staged_labels.append((labeled_pending, labeled_target))
            for labeled_pending, labeled_target in staged_labels: labeled_pending.rename(labeled_target)
        if holdout_audit_resources(dataset.root) != audits:
            raise ValueError("source protected holdout access audit changed during packaging")
        pending.rename(target)
        entries.append(entry); temporary = destination / ("catalog.json.tmp-" + uuid.uuid4().hex if private else "catalog.json.tmp")
        temporary.write_text(canonical(registry)); temporary.chmod(0o600 if private else 0o640); os.replace(temporary, registry_path)
    return entry


def package_java(source, destination, *, container_path="/run/ueba-risk"):
    if container_path != "/run/ueba-risk" or source.is_symlink() or destination.is_symlink(): raise ValueError("fixed private decision workspace required")
    snapshot = bounded(source / "snapshot.json")
    required = ("ops/UebaRiskReplay.class", "service/siem/AccountRiskEngine.class", "service/siem/UebaScorePolicy.class", "service/siem/AccountBehaviorFeatures.class")
    classes = source / "backend/target/classes"
    if any(not (classes / "com/flarefitness/backend" / name).is_file() for name in required): raise ValueError("production replay binary package is incomplete")
    if destination.exists():
        receipt = bounded(destination / "package.json")
        if receipt.get("source_snapshot_sha256") != sha_file(source / "snapshot.json"): raise ValueError("existing decision package differs")
        for relative, checksum in receipt["files"].items():
            if (destination / relative).is_symlink() or sha_file(destination / relative) != checksum: raise ValueError("installed decision package changed")
        return receipt
    destination.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    pending = destination.with_name(destination.name + ".pending-" + uuid.uuid4().hex); pending.mkdir(mode=0o750)
    files = {}
    for path in sorted(classes.rglob("*.class")):
        relative = Path("backend/target/classes") / path.relative_to(classes); checksum = sha_file(path)
        copy_checked(path, pending / relative, checksum, 8 * 1024 * 1024); files[str(relative)] = checksum
    for relative, checksum in snapshot["classes"].items():
        key = "backend/target/classes/com/flarefitness/backend/" + relative
        if files.get(key) != checksum: raise ValueError("decision feature code does not match frozen exporter")
    classpath = []
    for name, checksum in snapshot["jars"].items():
        if Path(name).name != name: raise ValueError("dependency package path is invalid")
        relative = "jars/" + name
        copy_checked(source / relative, pending / relative, checksum, 256 * 1024 * 1024)
        files[relative] = checksum; classpath.append(container_path + "/" + relative)
    classpath_path = pending / "backend/target/ueba-experiment.classpath"
    classpath_path.write_text(":".join(classpath)); classpath_path.chmod(0o640)
    files["backend/target/ueba-experiment.classpath"] = sha_file(classpath_path)
    receipt = {"source_snapshot_sha256": sha_file(source / "snapshot.json"), "files": files, "container_workspace": container_path}
    (pending / "package.json").write_text(canonical(receipt)); (pending / "package.json").chmod(0o640)
    pending.rename(destination); return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True); parser.add_argument("--recipe-id", required=True)
    parser.add_argument("--model-kind", choices=MODEL_KINDS, default=IF_MODEL_KIND)
    parser.add_argument("--expected-sha256"); parser.add_argument("--expected-archive-sha256")
    parser.add_argument("--java-source", type=Path); parser.add_argument("--java-destination", type=Path)
    args = parser.parse_args()
    entry = package_recipe(args.dataset, args.catalog, args.recipe_id, model_kind=args.model_kind,
                           expected_sha256=args.expected_sha256, expected_archive_sha256=args.expected_archive_sha256)
    if args.java_source is not None and args.java_destination is not None: package_java(args.java_source, args.java_destination)
    print(canonical({"recipe_id": entry["recipe_id"], "mode": entry["mode"], "primary_changed": False, "model_upload": False}))


if __name__ == "__main__": main()
