"""One frozen holdout evaluation: actual forest -> production Java -> scored episode journal.

An interrupted identical attempt may resume committed source shards, but an
artifact/policy/code change cannot reopen the attempt or inherit its quality.
PILOT/VALIDATION counter fixtures are never signed off as a frozen benchmark.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import numpy as np

from app.catalog import ShardedDataset, parse_json
from app.contract import (HYBRID_MODEL_KIND, IF_MODEL_KIND, MODEL_KINDS, SUPPORT_MODEL_KIND, feature_array,
                          campaign_runs, model_recipe_binding, parse_training_config, recipe_binding, validate_version)
from app.holdout_provenance import require_unblocked_holdout
from app.metric_journal import MetricJournal
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from app.quality_proof import audit_actual_rows, cluster_binding, math_binding, sha_file
from app.risk_replay import JavaRiskReplay
from app.selection import selection_identity
from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
from app.strict_campaign import campaign_prefix, fingerprint, hybrid_fold_training, timestamp, write
from app.strict_metrics import FAMILIES, SCOPES, confidence_for, strict_gate
from app.validation import config_document, point_qualified

HYBRID_PROOF_FORMAT = "HYBRID_STRICT_PROOF_V1"
HYBRID_PROOF_FILE = "hybrid-strict-proof.json"


def _hybrid_read(path, maximum, *, document=True):
    """Bounded owner-private readback; never accept paths from a public body."""
    if path.resolve() != path.absolute(): raise ValueError("canonical hybrid proof file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= maximum):
            raise ValueError("bounded protected hybrid proof file required")
        digest = hashlib.sha256(); body = bytearray() if document else None; total = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > maximum: raise ValueError("hybrid proof size changed during read")
            digest.update(block)
            if body is not None: body.extend(block)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (total != before.st_size or signature(before) != signature(os.fstat(stream.fileno()))
                or signature(before) != signature(path.lstat())):
            raise ValueError("hybrid proof changed during read")
        return digest.hexdigest(), parse_json(bytes(body)) if document else None


def verify_hybrid_strict_proof(dataset, selected, metadata, payload, *, source=False, proof=None):
    """Read complete protected proofs before holdout transport, not summary claims.

    Packaging verified all archived model bytes at its source. Their retained
    hashes are archival bindings, not a claim that this reader reloaded360 models.
    Only the selected original binary must remain installed for exact readback.
    """
    try:
        return _verify_hybrid_strict_proof(dataset, selected, metadata, payload, source=source, proof=proof)
    except (KeyError, TypeError, AttributeError, OSError):
        raise ValueError("complete protected hybrid strict proof unavailable") from None


def _verify_hybrid_strict_proof(dataset, selected, metadata, payload, *, source, proof):
    if dataset.manifest["stage"] != "STRICT" or dataset.manifest["feature_schema_version"] != 4:
        raise ValueError("full strict schema 4 hybrid source required")
    if (selected.get("status") != "SELECTED" or selected.get("dataset_sha256") != dataset.sha256
            or any(type(selected.get(key)) is not int or selected[key] != value for key, value in {
                "actual_fits_completed": 360, "validation_runs_completed": 360, "additional_fit_calls_in_recalibration": 0}.items())
            or type(selected.get("completed_recalibrations")) is not int or not 45 <= selected["completed_recalibrations"] <= 360):
        raise ValueError("complete typed frozen hybrid selection required")
    root = dataset.root
    for directory in (root, root.parent, root / "hybrid-models", root / "hybrid-runs",
                      root / "hybrid-validations", root / "hybrid-top-recalibrations"):
        info = directory.stat()
        if directory.resolve() != directory.absolute() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("protected owner-controlled hybrid proof directories required")
    proof_path = root / HYBRID_PROOF_FILE
    if proof_path.is_symlink(): raise ValueError("hybrid proof inventory cannot be a symlink")
    if proof is not None:
        encoded = canonical(proof).encode()
        if len(encoded) > 4 * 1024 * 1024: raise ValueError("bounded hybrid proof inventory required")
        proof_sha = hashlib.sha256(encoded).hexdigest()
    elif source:
        from app.package_catalog import hybrid_strict_proof
        proof = hybrid_strict_proof(dataset, selected, metadata, payload)
        proof_sha = hashlib.sha256(canonical(proof).encode()).hexdigest()
        if proof_path.exists():
            stored_sha, stored = _hybrid_read(proof_path, 4 * 1024 * 1024)
            if stored != proof or stored_sha != proof_sha: raise ValueError("native hybrid proof differs from actual retained source")
    else:
        proof_sha, proof = _hybrid_read(proof_path, 4 * 1024 * 1024)
    required = {"format", "dataset_sha256", "selection_sha256", "model_sha256", "calibration_sha256",
                "model_state_sha256", "files", "source_label_manifests", "archive_model_sha256"}
    if (type(proof) is not dict or set(proof) != required or proof["format"] != HYBRID_PROOF_FORMAT
            or any(proof.get(key) != value for key, value in {
                "dataset_sha256": dataset.sha256, "model_sha256": selected["model_sha256"],
                "calibration_sha256": selected["calibration_sha256"], "model_state_sha256": selected["model_state_sha256"]}.items())
            or type(proof["files"]) is not dict or not 769 <= len(proof["files"]) <= 1084
            or type(proof["source_label_manifests"]) is not dict or set(proof["source_label_manifests"]) != {"1", "2", "3"}):
        raise ValueError("complete immutable hybrid proof inventory required")
    runs = campaign_runs(HYBRID_MODEL_KIND); approved = {run["run_id"]: run for run in runs}
    validate_version(selected["model_version"])
    base = {"hybrid-selection.json", "hybrid-campaign.progress.json",
            f"hybrid-models/{selected['model_version']}.json", f"hybrid-models/{selected['model_version']}.joblib"}
    base.update(f"hybrid-runs/{run_id}.json" for run_id in approved)
    base.update(f"hybrid-validations/{run_id}.json" for run_id in approved)
    recal_paths = set(proof["files"]) - base
    if (not base <= set(proof["files"]) or not 45 <= len(recal_paths) <= 360
            or len(recal_paths) != selected["completed_recalibrations"]
            or any(not path.startswith("hybrid-top-recalibrations/") or Path(path).stem not in approved
                   or path != f"hybrid-top-recalibrations/{Path(path).stem}.json" for path in recal_paths)
            or type(proof["archive_model_sha256"]) is not dict or set(proof["archive_model_sha256"]) != set(approved)
            or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in proof["files"].values())):
        raise ValueError("all360 fit/validation and distinct45 recalibration proof files required")
    budget = {"bytes": 0}
    def read(relative, *, binary=False):
        maximum = 128 * 1024 * 1024 if binary else 4 * 1024 * 1024 if relative.startswith("hybrid-validations/") else 1024 * 1024
        checksum, record = _hybrid_read(root / relative, maximum, document=not binary)
        if checksum != proof["files"][relative]: raise ValueError("retained hybrid proof file hash changed")
        budget["bytes"] += (root / relative).stat().st_size
        if budget["bytes"] > 2 * 1024**3: raise ValueError("aggregate hybrid proof byte budget exceeded")
        return checksum, record
    selection_sha, actual_selected = read("hybrid-selection.json")
    if actual_selected != selected or proof["selection_sha256"] != selection_sha:
        raise ValueError("hybrid proof selection binding changed")
    _, progress = read("hybrid-campaign.progress.json")
    code = fingerprint(HYBRID_MODEL_KIND); identity = selected["selection_identity"]
    if (progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or progress.get("model_kind") != HYBRID_MODEL_KIND
            or progress.get("code_fingerprint") != code or identity.get("fit_code_fingerprint") != code
            or progress.get("dataset_manifest_sha256") != dataset.sha256
            or any(type(progress.get(key)) is not int or progress[key] != value for key, value in {
                "actual_fits_completed": 360, "actual_composite_trials": 360, "actual_component_fit_calls": 720,
                "required_component_fit_calls": 720, "additional_fits_in_recalibration": 0}.items())):
        raise ValueError("genuine complete hybrid360/720 campaign required")
    folds = {}
    for fold in (1, 2, 3):
        declared = proof["source_label_manifests"][str(fold)]
        if type(declared) is not dict or set(declared) != {"artifact_id", "manifest_sha256"} or declared["artifact_id"] != f"labels-fold{fold}":
            raise ValueError("approved matching-fold protected labeled source IDs required")
        _, _, manifest, label_sha = hybrid_fold_training(dataset, fold)
        if declared["manifest_sha256"] != label_sha or progress["labeled_training_manifest_sha256_by_fold"][str(fold)] != label_sha:
            raise ValueError("actual independent labeled source hash changed")
        folds[fold] = (manifest, label_sha)
    original_path = f"hybrid-models/{selected['model_version']}"
    read(original_path + ".json"); binary_sha, _ = read(original_path + ".joblib", binary=True)
    if binary_sha != selected["model_sha256"]: raise ValueError("selected original hybrid binary changed")
    original, original_payload = ModelStore(root / "hybrid-models").load_candidate(selected["model_version"])
    config = parse_training_config(HYBRID_MODEL_KIND, selected["model_config"])
    implementation = ModelStore.scoring_identity(payload["model"])
    if (config.random_state != 42 or original.get("fold") != 3 or metadata.get("fold") != 3
            or any(candidate.get("catalogue_mode", "STRICT") != "STRICT"
                   or candidate.get("scope", "FULL_STRICT_SOURCE") != "FULL_STRICT_SOURCE" for candidate in (original, metadata))
            or any(type(candidate.get("actual_component_fit_counts")) is not dict
                   or any(type(value) is not int for value in candidate["actual_component_fit_counts"].values())
                   for candidate in (original, metadata))
            or model_recipe_binding(original) != recipe_binding(config) or model_recipe_binding(metadata) != recipe_binding(config)
            or any(original.get(key) != value for key, value in {
                "sha256": selected["model_sha256"], "dataset_manifest_sha256": dataset.sha256,
                "calibration_sha256": selected["calibration_sha256"], "model_config": config_document(config),
                "score_policy": selected["policy"], "calibration_scope": "STRICT"}.items())
            or any(selected.get(key) != value for key, value in {
                "model_state_sha256": state_sha256(original_payload), "model_state_format": state_format(HYBRID_MODEL_KIND),
                "model_state_verifier_sha256": verifier_sha256(HYBRID_MODEL_KIND), "scoring_implementation": implementation}.items())
            or state_sha256(payload) != selected["model_state_sha256"]
            or metadata.get("scoring_implementation") != implementation or original.get("scoring_implementation") != implementation):
        raise ValueError("selected original fold3 seed42 hybrid state/source changed")
    fits = {}; selected_cases = 0
    from app.policy import DETECTION_GRID
    from itertools import product
    policy_grid = {ScorePolicy.strict(ready, cold, rule, schema=4).sha256
                   for ready, cold, rule in product(DETECTION_GRID, DETECTION_GRID, (45, 60, 70))}
    chosen_policy = ScorePolicy.from_wire(selected["policy"])
    for run_id, run in approved.items():
        fold = run["fold"]; manifest, label_sha = folds[fold]; fit_sha = dataset.split(f"fold{fold}-fit")["sha256"]
        expected = {"run_id": run_id, "fold": fold, "config": config_document(run["config"]),
                    "dataset_manifest_sha256": dataset.sha256, "code_fingerprint": code,
                    "fit_split_sha256": fit_sha, "normal_fit_split_sha256": fit_sha,
                    "labeled_training_artifact_id": f"labels-fold{fold}", "labeled_training_manifest_sha256": label_sha,
                    "labeled_training_split_sha256": hashlib.sha256(canonical(manifest["sections"]).encode()).hexdigest(),
                    "labeled_training_windows": 81500, "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000},
                    **recipe_binding(run["config"])}
        _, fit = read(f"hybrid-runs/{run_id}.json")
        archive = proof["archive_model_sha256"][run_id]
        if (any(fit.get(key) != value for key, value in expected.items()) or fit.get("status") != "FITTED_CALIBRATED"
                or type(archive) is not dict or archive != {key: fit[key] for key in ("source_model_sha256", "model_sha256")}
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in archive.values())
                or any(type(fit.get(key)) is not int or fit[key] != value for key, value in {
                    "actual_composite_trials": 1, "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0}.items())):
            raise ValueError("each approved genuine hybrid trial must retain both component proofs")
        fits[run_id] = fit
        _, validation = read(f"hybrid-validations/{run_id}.json")
        expected_validation = {"run_id": run_id, "fold": fold, "config": expected["config"], "status": "VALIDATED",
            "evaluation_scope": "VALIDATION", "selection_identity": identity, "model_sha256": fit["model_sha256"],
            "calibration_sha256": fit["calibration_sha256"], "dataset_manifest_sha256": dataset.sha256,
            "validation_split_sha256": dataset.split(f"fold{fold}-validation")["sha256"], **recipe_binding(run["config"])}
        cases = validation["policies"]
        if (any(validation.get(key) != value for key, value in expected_validation.items()) or len(cases) != 192
                or {ScorePolicy.from_wire(case["policy"]).sha256 for case in cases} != policy_grid
                or any(set(case["scopes"]) != {"MODEL_ONLY", "SIEM_FINAL"}
                       or any(scope.get("normal_samples") != 1000000 or scope.get("positive_samples") != 1000
                              or set(scope.get("families", {})) != set(FAMILIES)
                              or any(group.get("positive_samples") != 200 for group in scope["families"].values())
                              for scope in case["scopes"].values()) for case in cases)):
            raise ValueError("all360 real hybrid validation identities and original192 policies required")
        if all(expected["config"][key] == selected["model_config"][key] for key in ("max_iter", "max_leaf_nodes", "l2_regularization")):
            case = next(case for case in cases if case["policy"]["policy_sha256"] == chosen_policy.sha256)
            if not point_qualified(case["scopes"], chosen_policy): raise ValueError("selected hybrid policy failed an independent seed/fold slice")
            selected_cases += 1
    if selected_cases != 15: raise ValueError("all15 independent selected hybrid policy cases required")
    groups = {}; representative = None
    for relative in sorted(recal_paths):
        _, receipt = read(relative); run_id = Path(relative).stem; run = approved[run_id]; fit = fits[run_id]
        expected = {"run_id": run_id, "fold": run["fold"], "config": config_document(run["config"]),
                    "selection_identity": identity, "source_model_version": fit["source_model_version"],
                    "source_model_sha256": fit["source_model_sha256"], **recipe_binding(run["config"])}
        if (any(receipt.get(key) != value for key, value in expected.items())
                or type(receipt.get("additional_fit_calls")) is not int or receipt["additional_fit_calls"] != 0):
            raise ValueError("all distinct hybrid top recalibrations must prove zero additional fits")
        configuration = config_document(run["config"]); configuration.pop("random_state")
        groups.setdefault(canonical(configuration), set()).add((run["fold"], run["config"].random_state))
        if receipt.get("model_version") == selected["model_version"]: representative = receipt
    if len(groups) < 3 or any(len(group) != 15 for group in groups.values()) or representative is None:
        raise ValueError("three full distinct configuration/seed/fold recalibrations required")
    label_manifest, label_sha = folds[3]
    source_binding = {"labeled_training_artifact_id": "labels-fold3", "labeled_training_manifest_sha256": label_sha,
        "labeled_training_split_sha256": hashlib.sha256(canonical(label_manifest["sections"]).encode()).hexdigest(),
        "normal_fit_split_sha256": dataset.split("fold3-fit")["sha256"], "labeled_training_windows": 81500,
        "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000}, "training_windows": 50000,
        "actual_component_fit_counts": {"normal_component_fit_calls": 1, "labeled_component_fit_calls": 1},
        "labeled_training_scope": "CALLER_VERIFIED_SEPARATE_CHRONOLOGICAL_TRAINING_ONLY",
        "normal_training_scope": "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED", "data_provenance": "DEMO_ONLY"}
    if (representative["fold"] != 3 or representative["config"] != selected["model_config"]
            or representative["policy_sha256"] != chosen_policy.sha256
            or any(representative.get(key) != selected.get(key) for key in ("model_sha256", "calibration_sha256", "model_state_sha256",
                                                                         "model_state_format", "model_state_verifier_sha256"))
            or any(candidate.get(key) != value for candidate in (original, metadata) for key, value in source_binding.items())
            or any(candidate.get("confirmed_attack_target_available") is not False for candidate in (original, metadata))):
        raise ValueError("selected hybrid representative source/policy/numeric proof changed")
    return {"format": HYBRID_PROOF_FORMAT, "proof_sha256": proof_sha, "selection_sha256": selection_sha,
            "actual_composite_trials": 360, "actual_component_fit_calls": 720, "validation_runs": 360,
            "zero_fit_recalibrations": len(recal_paths), "source_label_manifests": proof["source_label_manifests"]}


def model_binding(metadata, policy):
    return {"model_version": metadata["model_version"], "model_sha256": metadata["sha256"],
            "feature_schema_version": metadata["feature_schema_version"], "calibration_sha256": metadata["calibration_sha256"],
            "policy_sha256": policy.sha256, "dataset_sha256": metadata["dataset_manifest_sha256"]}


def actual_scores(payload, policy, rows):
    """Use the serving scorer with actual calibrated cohorts; no label enters inference."""
    schema = policy.document["feature_schema_version"]
    vectors = feature_array([row["features"] for row in rows], 5000, schema)
    cohorts = ["COLD" if row["cohort"] == "COLD" else "READY" for row in rows]
    return ModelStore.score_payload(payload, vectors, "offline_frozen_candidate", schema, policy=policy, cohorts=cohorts)["results"]


def score_shards(dataset, split, payload, policy, replay, journal, *, progress=None):
    """Internal bounded transport; qualification/population checks are in evaluate()."""
    if split == "holdout": require_unblocked_holdout(dataset)
    for descriptor, rows in dataset.iter_shards(split):
        if journal.completed_source_shard(descriptor["id"], descriptor["sha256"], len(rows)): continue
        actual = replay.score(rows, actual_scores(payload, policy, rows))
        checksum = hashlib.sha256(canonical(actual).encode()).hexdigest()
        journal.ingest(descriptor["id"], actual, checksum, source_sha256=descriptor["sha256"])
        if progress: progress(journal.progress())


def compute_scope(journal, scope, policy, directory, version):
    count = journal.db.execute("SELECT count(*) FROM counts WHERE scope=? AND kind='cluster'", (scope,)).fetchone()[0]
    if count < 2: raise ValueError("actual account/day bootstrap clusters required")
    path = directory / f".{version}-{scope.lower()}-clusters.i64"
    if path.is_symlink(): raise ValueError("private cluster matrix cannot be a symlink")
    # This is a derived cache, not scored evidence. Rebuilding cannot add rows
    # or modify the frozen journal; bounded memmap avoids a giant Python list.
    if getattr(journal, "storage_guard", False):
        from app.storage_budget import require_headroom
        require_headroom(directory, count * 4 * 8)
    with path.open("wb") as stream: stream.truncate(count * 4 * 8)
    path.chmod(0o600)
    matrix = np.memmap(path, dtype="<i8", mode="r+", shape=(count, 4))
    try:
        written = 0
        for _, row in journal.groups(scope, "cluster"):
            matrix[written] = [row.tp, row.fn, row.fp, row.tn]; written += 1
        if written != count: raise ValueError("cluster population changed during finalization")
        matrix.flush()
        counts = journal.counter(scope)
        confidence = confidence_for(counts, policy, matrix)
        confidence.update(cluster_counter_sha256=cluster_binding(journal.db, scope)["cluster_counter_sha256"])
        result = strict_gate(counts, policy, dict(journal.groups(scope, "family")), dict(journal.groups(scope, "cohort")), confidence, scope=scope)
        return result
    finally: matrix._mmap.close()


def evaluate(directory, workspace, model_kind=IF_MODEL_KIND, *, progress=None,
             expected_sha256=None, expected_archive_sha256=None, coordinated=False):
    """Evaluate only under explicit offline archive/coordinator opt-in.

    The stage lock covers the entire consumer lifetime, including all source
    reads, Java replay and memmaps. Defaults preserve the ordinary catalogue.
    """
    from app.pipeline_lock import coordinated_stage
    with coordinated_stage(directory, "evaluation", enabled=coordinated):
        return _evaluate(directory, workspace, model_kind, progress=progress,
                         expected_sha256=expected_sha256,
                         expected_archive_sha256=expected_archive_sha256)


def _evaluate(directory, workspace, model_kind=IF_MODEL_KIND, *, progress=None,
              expected_sha256=None, expected_archive_sha256=None):
    prefix = campaign_prefix(model_kind)
    if expected_sha256 is None and expected_archive_sha256 is None:
        dataset = ShardedDataset(directory)
    else:
        from app.owned_dataset import open_owned_dataset
        dataset = open_owned_dataset(directory, expected_sha256=expected_sha256,
                                     expected_archive_sha256=expected_archive_sha256)
    if dataset.manifest["stage"] != "STRICT": raise ValueError("pilot cannot be a frozen strict holdout")
    require_unblocked_holdout(dataset)
    selected_path = directory / f"{prefix}-selection.json"
    if not selected_path.is_file() or selected_path.stat().st_size > 1024 * 1024: raise ValueError("bounded frozen selection required")
    selected = json.loads(selected_path.read_text())
    if (selected.get("status") != "SELECTED" or selected.get("actual_fits_completed") != 360
            or selected.get("validation_runs_completed") != 360 or selected.get("completed_recalibrations", 0) < 45
            or selected.get("additional_fit_calls_in_recalibration") != 0
            or selected.get("selection_identity") != selection_identity(dataset, workspace, model_kind)):
        raise ValueError("complete frozen independent selection required before holdout")
    store = ModelStore(directory / f"{prefix}-models")
    metadata, payload = store.load_candidate(selected["model_version"])
    policy = ScorePolicy.from_wire(metadata["score_policy"])
    binding = model_binding(metadata, policy)
    if (not policy.strict_gate or metadata.get("calibration_scope") != "STRICT"
            or binding["feature_schema_version"] != dataset.manifest["feature_schema_version"]
            or binding["feature_schema_version"] != policy.document["feature_schema_version"]
            or any(selected.get(key) != value for key, value in binding.items() if key != "feature_schema_version")
            or selected.get("policy") != policy.wire()): raise ValueError("selected candidate binding changed")
    typed_binding = model_recipe_binding(metadata)
    if typed_binding["model_kind"] != model_kind or model_recipe_binding(selected) != typed_binding:
        raise ValueError("selected candidate model kind/recipe changed")
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
        config = parse_training_config(model_kind, metadata["model_config"])
        implementation = ModelStore.scoring_identity(payload["model"])
        if (recipe_binding(config) != typed_binding or selected.get("model_config") != config_document(config)
                or selected.get("model_state_sha256") != state_sha256(payload)
                or selected.get("model_state_format") != state_format(model_kind)
                or state_format(payload) != state_format(model_kind)
                or selected.get("model_state_verifier_sha256") != verifier_sha256(model_kind)
                or selected.get("scoring_implementation") != implementation
                or metadata.get("scoring_implementation") != implementation):
            raise ValueError(f"selected {'hybrid' if model_kind == HYBRID_MODEL_KIND else 'support'} state/scoring implementation changed")
    hybrid_proof = verify_hybrid_strict_proof(dataset, selected, metadata, payload, source=True) if model_kind == HYBRID_MODEL_KIND else None
    holdout = dataset.split("holdout")
    if holdout["normal"] != 10000000 or holdout["positive"] != 10000:
        raise ValueError("actual declared strict holdout population required")
    identity = {**binding, "holdout_split_sha256": holdout["sha256"], "selection_file_sha256": sha_file(selected_path),
                "quality_math_binding": math_binding(), "production_classes": selected["selection_identity"]["production_classes"],
                "scorer_sha256": sha_file(Path(__file__)), "data_provenance": "DEMO_ONLY"}
    if model_kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
        identity.update(typed_binding, model_state_sha256=selected["model_state_sha256"],
                        model_state_format=state_format(model_kind), model_state_verifier_sha256=verifier_sha256(model_kind),
                        scoring_implementation=implementation)
    if hybrid_proof is not None: identity["hybrid_strict_proof"] = hybrid_proof
    return evaluate_bound(dataset, store, metadata, payload, policy, identity, workspace, progress=progress,
                          progress_file=directory / f"{prefix}-holdout.progress.json", result_file=directory / f"{prefix}-holdout-result.json")


def evaluate_bound(dataset, store, metadata, payload, policy, identity, workspace, *, progress=None, progress_file=None, result_file=None,
                   require_storage_guard=False):
    """Same actual scorer/journal/gate for offline and ID-only worker jobs.

    A read-only operator catalogue never receives output files; worker evidence
    is kept in its private model directory. Neither caller can shrink the gate.
    """
    if type(require_storage_guard) is not bool: raise ValueError("explicit evaluation storage guard required")
    storage_guard = require_storage_guard or getattr(dataset, "archive_sha256", None) is not None
    require_unblocked_holdout(dataset)
    binding = model_binding(metadata, policy)
    if model_recipe_binding(metadata)["model_kind"] == HYBRID_MODEL_KIND:
        proof = identity.get("hybrid_strict_proof")
        if (type(proof) is not dict or proof.get("format") != HYBRID_PROOF_FORMAT
                or proof.get("actual_composite_trials") != 360 or proof.get("actual_component_fit_calls") != 720
                or proof.get("validation_runs") != 360 or proof.get("zero_fit_recalibrations", 0) < 45):
            raise ValueError("complete verified hybrid proof required before holdout scoring")
    holdout = dataset.split("holdout")
    if (dataset.manifest["stage"] != "STRICT" or not policy.strict_gate or metadata.get("calibration_scope") != "STRICT"
            or binding["feature_schema_version"] != dataset.manifest["feature_schema_version"]
            or binding["feature_schema_version"] != policy.document["feature_schema_version"]
            or metadata.get("dataset_manifest_sha256") != dataset.sha256
            or holdout["normal"] != 10000000 or holdout["positive"] != 10000
            or any(identity.get(key) != value for key, value in binding.items())):
        raise ValueError("full immutable strict candidate/holdout identity required")
    version = metadata["model_version"]
    evidence = store.directory / f"{version}.evaluation.json"
    identity_path = store.directory / f"{version}.evaluation-identity.json"
    journal_path = store.directory / f"{version}.metrics.sqlite"
    with (store.directory / f".{version}.evaluation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if identity_path.exists():
            if json.loads(identity_path.read_text()) != identity: raise ValueError("frozen evaluation identity changed; cannot reopen holdout")
        else: write(identity_path, identity)
        if evidence.exists():
            previous = json.loads(evidence.read_text())
            if previous.get("status") == "SUCCEEDED":
                if previous.get("evaluation_identity") != identity or previous.get("scored_journal_sha256") != sha_file(journal_path):
                    raise ValueError("retained frozen evaluation evidence changed")
                return previous  # A failed quality gate is retained, not silently retuned.
        write(evidence, {**binding, "status": "RUNNING", "quality_gate": "NOT_RUN", "evaluation_identity": identity,
                        "evaluation_scope": "FROZEN_HOLDOUT", "data_provenance": "DEMO_ONLY"})
        journal = MetricJournal(journal_path, policy=policy, model_sha256=metadata["sha256"],
                                calibration_sha256=metadata["calibration_sha256"], dataset_sha256=dataset.sha256,
                                storage_guard=storage_guard)
        try:
            with JavaRiskReplay(workspace, policy, expected_classes=identity["production_classes"]) as replay:
                def advanced(current):
                    if progress: progress(current)
                    if progress_file is not None:
                        write(progress_file, {**binding, "status": "RUNNING", **current,
                              "quality_gate": "NOT_RUN", "updated_at_utc": timestamp()})
                score_shards(dataset, "holdout", payload, policy, replay, journal, progress=advanced)
            if (journal.progress()["episodes"] != holdout["records"]
                    or journal.db.execute("SELECT count(*) FROM source_shards").fetchone()[0] != len(holdout["shards"])):
                raise ValueError("not all declared holdout source shards were actually scored")
            actual_population = audit_actual_rows(journal.db)
            scopes = {scope: compute_scope(journal, scope, policy, store.directory, version) for scope in SCOPES}
            result = {**binding, "status": "SUCCEEDED", "quality_gate": "PASS" if all(value["quality_gate"] == "PASS" for value in scopes.values()) else "FAIL",
                      "evaluation_scope": "FROZEN_HOLDOUT", "data_provenance": "DEMO_ONLY", "evaluation_identity": identity,
                      "quality_math_binding": identity["quality_math_binding"], "scopes": scopes,
                      "actual_scored_episodes": actual_population, "raw_episode_audit_completed": True,
                      "scored_journal_file": journal_path.name, "completed_at_utc": timestamp()}
        finally: journal.close()
        result["scored_journal_sha256"] = sha_file(journal_path)
        write(evidence, result)
        if result_file is not None: write(result_file, result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--model-kind", choices=MODEL_KINDS, default=IF_MODEL_KIND)
    parser.add_argument("--dataset-sha256")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--coordinated", action="store_true")
    args = parser.parse_args()
    result = evaluate(args.dataset.resolve(strict=True), args.workspace.resolve(strict=True), args.model_kind,
                      expected_sha256=args.dataset_sha256, expected_archive_sha256=args.archive_sha256,
                      coordinated=args.coordinated)
    print(canonical({key: value for key, value in result.items() if key != "scopes"}), flush=True)


if __name__ == "__main__": main()
