"""Operator-installed scalar recipes over existing read-only sharded datasets.

Public clients can select IDs only. They cannot select files, features, labels,
model uploads, policies or hyperparameters. PILOT entries are explicitly preview
recipes and produce permanently non-activatable PILOT_ONLY calibrations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING

from app.calibration import recalibrate
from app.catalog import ShardedDataset, parse_json
from app.contract import (HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, SupportTrainingConfig, TrainingConfig,
                          campaign_runs, model_recipe_binding, parse_training_config, recipe_binding, validate_version)
from app.model import ModelStore
from app.policy import ScorePolicy
from app.semantic_model import FORMAT
from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
from app.strict_campaign import HybridFitCounter, campaign_prefix, fingerprint, hybrid_fold_training, write
from app.policy import canonical

if TYPE_CHECKING:
    from app.hybrid_incident import HybridResearchConfig


@dataclass(frozen=True)
class Recipe:
    recipe_id: str
    dataset: ShardedDataset
    config: TrainingConfig | SupportTrainingConfig | HybridResearchConfig
    policy: ScorePolicy
    fold: int
    mode: str
    expected_model_sha256: str | None = None
    expected_calibration_sha256: str | None = None
    expected_model_state_sha256: str | None = None
    model_state_verifier_sha256: str | None = None
    model_kind: str = IF_MODEL_KIND
    recipe_version: int = 1
    recipe_sha256: str | None = None
    model_state_format: str = FORMAT
    labeled_training_artifact_id: str | None = None
    labeled_training_manifest_sha256: str | None = None
    strict_proof_sha256: str | None = None
    holdout_access_audit_sha256: str | None = None


def hybrid_strict_header(recipe):
    """Bounded protected queue admission, not numeric/campaign qualification."""
    from app.frozen_evaluation import HYBRID_PROOF_FILE, HYBRID_PROOF_FORMAT, _hybrid_read
    if (recipe.mode != "STRICT" or recipe.fold != 3 or recipe.config.random_state != 42
            or not isinstance(recipe.strict_proof_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", recipe.strict_proof_sha256)
            or recipe.labeled_training_artifact_id != "labels-fold3"
            or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in (
                recipe.expected_model_sha256, recipe.expected_calibration_sha256, recipe.expected_model_state_sha256,
                recipe.model_state_verifier_sha256, recipe.labeled_training_manifest_sha256))):
        raise ValueError("registered complete hybrid STRICT proof pin/fold required")
    root = recipe.dataset.root
    for directory in (root.parent, root, root / "hybrid-models", root / "hybrid-runs",
                      root / "hybrid-validations", root / "hybrid-top-recalibrations"):
        info = directory.stat()
        if directory.resolve() != directory.absolute() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("protected hybrid proof directories required")
    manifest_sha, manifest = _hybrid_read(root / "manifest.json", 8 * 1024 * 1024)
    if manifest_sha != recipe.dataset.sha256 or manifest != recipe.dataset.manifest:
        raise ValueError("protected strict dataset manifest changed")
    selection_sha, selected = _hybrid_read(root / "hybrid-selection.json", 1024 * 1024)
    if type(selected) is not dict: raise ValueError("typed frozen hybrid selection required")
    if (model_recipe_binding(selected) != recipe_binding(recipe.config)
            or parse_training_config(HYBRID_MODEL_KIND, selected.get("model_config")) != recipe.config
            or selected.get("model_config") != asdict(recipe.config) or selected.get("policy") != recipe.policy.wire()
            or any(selected.get(key) != value for key, value in {
                "model_sha256": recipe.expected_model_sha256,
                "calibration_sha256": recipe.expected_calibration_sha256,
                "model_state_sha256": recipe.expected_model_state_sha256,
                "model_state_format": recipe.model_state_format,
                "model_state_verifier_sha256": recipe.model_state_verifier_sha256}.items())):
        raise ValueError("registered hybrid selected configuration/state/policy changed")
    if (selected.get("status") != "SELECTED" or selected.get("dataset_sha256") != recipe.dataset.sha256
            or any(type(selected.get(key)) is not int or selected[key] != value for key, value in {
                "actual_fits_completed": 360, "validation_runs_completed": 360, "additional_fit_calls_in_recalibration": 0}.items())
            or type(selected.get("completed_recalibrations")) is not int or not 45 <= selected["completed_recalibrations"] <= 360):
        raise ValueError("complete typed hybrid selection header required")
    proof_sha, proof = _hybrid_read(root / HYBRID_PROOF_FILE, 4 * 1024 * 1024)
    required = {"format", "dataset_sha256", "selection_sha256", "model_sha256", "calibration_sha256",
                "model_state_sha256", "files", "source_label_manifests", "archive_model_sha256"}
    if (proof_sha != recipe.strict_proof_sha256 or type(proof) is not dict or set(proof) != required
            or proof.get("format") != HYBRID_PROOF_FORMAT or any(proof.get(key) != value for key, value in {
                "dataset_sha256": recipe.dataset.sha256, "selection_sha256": selection_sha,
                "model_sha256": recipe.expected_model_sha256, "calibration_sha256": recipe.expected_calibration_sha256,
                "model_state_sha256": recipe.expected_model_state_sha256}.items())
            or type(proof["source_label_manifests"]) is not dict or set(proof["source_label_manifests"]) != {"1", "2", "3"}):
        raise ValueError("registered hybrid proof/labeled source checksum changed")
    runs = {run["run_id"] for run in campaign_runs(HYBRID_MODEL_KIND)}
    validate_version(selected["model_version"])
    original_path = f"hybrid-models/{selected['model_version']}"
    base = {"hybrid-selection.json", "hybrid-campaign.progress.json", original_path + ".json", original_path + ".joblib"}
    base.update(f"hybrid-runs/{run_id}.json" for run_id in runs)
    base.update(f"hybrid-validations/{run_id}.json" for run_id in runs)
    files = proof["files"]
    if type(files) is not dict: raise ValueError("complete hybrid proof inventory header required")
    recal = set(files) - base
    if (not base <= set(files) or len(recal) != selected["completed_recalibrations"]
            or files.get(original_path + ".joblib") != recipe.expected_model_sha256
            or any(path != f"hybrid-top-recalibrations/{Path(path).stem}.json" or Path(path).stem not in runs for path in recal)
            or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in files.values())
            or type(proof["archive_model_sha256"]) is not dict or set(proof["archive_model_sha256"]) != runs
            or any(type(value) is not dict or set(value) != {"source_model_sha256", "model_sha256"}
                   or any(not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum) for checksum in value.values())
                   for value in proof["archive_model_sha256"].values())):
        raise ValueError("complete360 trial/validation and45 recalibration proof headers required")
    progress_sha, progress = _hybrid_read(root / "hybrid-campaign.progress.json", 1024 * 1024)
    code = fingerprint(HYBRID_MODEL_KIND)
    if (type(progress) is not dict or progress_sha != files["hybrid-campaign.progress.json"] or selection_sha != files["hybrid-selection.json"]
            or progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or progress.get("model_kind") != HYBRID_MODEL_KIND
            or progress.get("dataset_manifest_sha256") != recipe.dataset.sha256 or progress.get("code_fingerprint") != code
            or type(selected.get("selection_identity")) is not dict or selected["selection_identity"].get("fit_code_fingerprint") != code
            or type(progress.get("labeled_training_manifest_sha256_by_fold")) is not dict
            or set(progress["labeled_training_manifest_sha256_by_fold"]) != {"1", "2", "3"}
            or any(type(progress.get(key)) is not int or progress[key] != value for key, value in {
                "actual_fits_completed": 360, "actual_composite_trials": 360, "actual_component_fit_calls": 720,
                "required_component_fit_calls": 720, "additional_fits_in_recalibration": 0}.items())):
        raise ValueError("genuine complete hybrid360/720 campaign header required")
    for fold in (1, 2, 3):
        reference = proof["source_label_manifests"][str(fold)]
        if (type(reference) is not dict or set(reference) != {"artifact_id", "manifest_sha256"}
                or reference["artifact_id"] != f"labels-fold{fold}" or not isinstance(reference["manifest_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", reference["manifest_sha256"])):
            raise ValueError("protected matching-fold strict labeled manifest references required")
        directory = root.parent / reference["artifact_id"]; info = directory.stat()
        if directory.resolve() != directory.absolute() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("protected strict labeled directories required")
        label_sha, label = _hybrid_read(directory / "manifest.private.json", 2 * 1024 * 1024)
        if (type(label) is not dict or label_sha != reference["manifest_sha256"] or label.get("format") != "HYBRID_STRICT_LABELED_SOURCE_V1"
                or label.get("stage") != "STRICT_SOURCE" or label.get("scope") != "FULL_STRICT_SOURCE"
                or type(label.get("fold")) is not int or label["fold"] != fold
                or label.get("quality_gate") != "NOT_EVALUATED"
                or any(type(label.get(key)) is not int or label[key] != 0 for key in ("fit_or_score_calls", "holdout_numeric_records_read"))
                or label.get("standard_manifest_sha256") != recipe.dataset.sha256
                or label.get("standard_fit") != recipe.dataset.split(f"fold{fold}-fit")
                or type(label.get("sections")) is not dict or set(label["sections"]) != {"normal", "supplement"}
                or progress.get("labeled_training_manifest_sha256_by_fold", {}).get(str(fold)) != label_sha):
            raise ValueError("protected strict labeled manifest header changed")
    if proof["source_label_manifests"]["3"]["manifest_sha256"] != recipe.labeled_training_manifest_sha256:
        raise ValueError("registered hybrid proof/labeled source checksum changed")
    metadata_sha, original = _hybrid_read(root / (original_path + ".json"), 1024 * 1024)
    if type(original) is not dict: raise ValueError("typed selected original hybrid metadata header required")
    counts = original.get("actual_component_fit_counts")
    classes = original.get("labeled_class_windows")
    if (metadata_sha != files[original_path + ".json"] or model_recipe_binding(original) != recipe_binding(recipe.config)
            or parse_training_config(HYBRID_MODEL_KIND, original.get("model_config")) != recipe.config
            or type(original.get("fold")) is not int or type(counts) is not dict
            or set(counts) != {"normal_component_fit_calls", "labeled_component_fit_calls"}
            or any(type(value) is not int or value != 1 for value in counts.values())
            or type(classes) is not dict or set(classes) != {"0", "1", "2"}
            or any(type(classes.get(key)) is not int or classes[key] != value for key, value in {"0": 71500, "1": 8000, "2": 2000}.items())
            or type(original.get("training_windows")) is not int or original["training_windows"] != 50000
            or type(original.get("labeled_training_windows")) is not int or original["labeled_training_windows"] != 81500
            or original.get("confirmed_attack_target_available") is not False
            or original.get("scope", "FULL_STRICT_SOURCE") != "FULL_STRICT_SOURCE"
            or original.get("catalogue_mode", "STRICT") != "STRICT"
            or any(original.get(key) != value for key, value in {
                "model_config": asdict(recipe.config), "score_policy": recipe.policy.wire(), "fold": 3,
                "sha256": recipe.expected_model_sha256, "calibration_sha256": recipe.expected_calibration_sha256,
                "dataset_manifest_sha256": recipe.dataset.sha256, "calibration_scope": "STRICT", "data_provenance": "DEMO_ONLY",
                "normal_fit_split_sha256": recipe.dataset.split("fold3-fit")["sha256"],
                "labeled_training_split_sha256": hashlib.sha256(canonical(label["sections"]).encode()).hexdigest(),
                "labeled_training_artifact_id": recipe.labeled_training_artifact_id,
                "labeled_training_manifest_sha256": recipe.labeled_training_manifest_sha256}.items())):
        raise ValueError("selected original hybrid private metadata header changed")
    return selected


def verify_registered_hybrid(recipe, metadata=None, payload=None):
    """Full async proof verification before fitting or holdout numeric reads."""
    from app.frozen_evaluation import verify_hybrid_strict_proof
    selected = hybrid_strict_header(recipe)
    if metadata is None:
        metadata, payload = ModelStore(recipe.dataset.root / "hybrid-models").load_candidate(selected["model_version"])
    verified = verify_hybrid_strict_proof(recipe.dataset, selected, metadata, payload)
    if (verified.get("proof_sha256") != recipe.strict_proof_sha256
            or verified.get("source_label_manifests", {}).get("3") != {
                "artifact_id": recipe.labeled_training_artifact_id,
                "manifest_sha256": recipe.labeled_training_manifest_sha256}):
        raise ValueError("registered hybrid proof/labeled source checksum changed")
    return verified


def hybrid_training(dataset, fold, artifact_id, manifest_sha256):
    """Protected ID-only labeled source; never relax ordinary normal FIT."""
    from app.hybrid_bulk_dataset import load_hybrid_bulk_fit
    if (fold != 1 or dataset.manifest["stage"] != "PILOT" or dataset.manifest["feature_schema_version"] != 4
            or not isinstance(artifact_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", artifact_id)
            or not isinstance(manifest_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_sha256)):
        raise ValueError("hybrid PILOT requires fixed-fold protected labeled artifact ID/hash")
    root = dataset.root.parent
    directory = root / artifact_id
    try:
        for path in (root, dataset.root, directory):
            if (path.resolve(strict=True) != path or path.stat().st_uid != os.geteuid()
                    or stat.S_IMODE(path.stat().st_mode) != 0o700):
                raise ValueError("private canonical owner-controlled hybrid catalogue folders required")
        for path in (root / "catalog.json", dataset.root / "manifest.json", directory / "manifest.private.json"):
            if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid()
                    or stat.S_IMODE(path.stat().st_mode) != 0o600):
                raise ValueError("private owner-controlled hybrid catalogue files required")
    except OSError:
        raise ValueError("private installed hybrid catalogue unavailable") from None
    normal, supervised, manifest = load_hybrid_bulk_fit(directory, manifest_sha256)
    fit = dataset.split("fold1-fit")
    if (manifest.get("artifact_id") != artifact_id or manifest["training_sections"]["NORMAL_COMPONENT"] != fit
            or len(normal) != 50000 or len(supervised) != 81500
            or normal != [row for _, rows in dataset.iter_shards("fold1-fit") for row in rows]):
        raise ValueError("hybrid normal component must equal actual complete registered normal FIT")
    return normal, supervised, manifest


def hybrid_fingerprint(recipe):
    from app.hybrid_incident import HybridIncidentScorer
    return {"scoring_implementation": ModelStore.scoring_identity(HybridIncidentScorer(recipe.config)),
            "operator_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "labeled_training_artifact_id": recipe.labeled_training_artifact_id,
            "labeled_training_manifest_sha256": recipe.labeled_training_manifest_sha256}


class OperatorCatalog:
    def __init__(self, root): self.root = Path(root).absolute()

    def recipe(self, recipe_id):
        if not isinstance(recipe_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,96}", recipe_id):
            raise ValueError("invalid operator recipe ID")
        registry = self.root / "catalog.json"
        if self.root.is_symlink() or registry.is_symlink() or not registry.is_file() or registry.stat().st_size > 1024 * 1024:
            raise ValueError("bounded operator catalogue unavailable")
        document = parse_json(registry.read_bytes())
        entries = document.get("strict_entries", []) if isinstance(document, dict) else None
        if not isinstance(entries, list) or len(entries) > 4: raise ValueError("bounded registered recipe list required")
        ids = set(); chosen = None
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("recipe_id"), str) or not re.fullmatch(r"[a-z0-9_-]{8,96}", entry["recipe_id"]):
                raise ValueError("invalid registered recipe")
            if entry["recipe_id"] in ids: raise ValueError("duplicate registered recipe ID")
            ids.add(entry["recipe_id"])
            if entry["recipe_id"] == recipe_id: chosen = entry
        if chosen is None: raise ValueError("recipe is not registered by the operator")
        name = chosen.get("dataset_id")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", name): raise ValueError("invalid registered dataset ID")
        directory = self.root / name
        if directory.is_symlink() or directory.resolve().parent != self.root.resolve(): raise ValueError("dataset escapes operator catalogue")
        if not isinstance(chosen.get("manifest_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", chosen["manifest_sha256"]):
            raise ValueError("registered manifest checksum required")
        if "archive_sha256" in chosen:
            from app.archived_catalog import ArchivedShardedDataset, owned_root
            from app.frozen_evaluation import _hybrid_read
            if not isinstance(chosen["archive_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", chosen["archive_sha256"]):
                raise ValueError("registered explicit archive checksum required")
            owned_root(self.root)
            _, protected_registry = _hybrid_read(registry, 1024 * 1024)
            if protected_registry != document: raise ValueError("protected archived registry changed during admission")
            dataset = ArchivedShardedDataset(directory, expected_sha256=chosen["manifest_sha256"],
                                              expected_archive_sha256=chosen["archive_sha256"])
        else:
            dataset = ShardedDataset(directory, expected_sha256=chosen["manifest_sha256"])
        mode = chosen.get("mode", "STRICT")
        if mode not in ("STRICT", "PILOT") or dataset.manifest["stage"] != mode:
            raise ValueError("recipe scope differs from actual catalogue stage")
        fold = chosen.get("fold")
        if type(fold) is not int or fold not in (1, 2, 3): raise ValueError("approved recipe fold required")
        config = chosen.get("config")
        if not isinstance(config, dict): raise ValueError("approved server-side recipe configuration required")
        binding = model_recipe_binding(chosen)
        recipe = parse_training_config(binding["model_kind"], config)
        if binding["recipe_sha256"] is not None and binding != recipe_binding(recipe):
            raise ValueError("registered recipe hash/configuration mismatch")
        if binding["model_kind"] == SUPPORT_MODEL_KIND and dataset.manifest["feature_schema_version"] != 4:
            raise ValueError("support recipe requires schema 4")
        labeled_id = chosen.get("labeled_training_artifact_id")
        labeled_sha = chosen.get("labeled_training_manifest_sha256")
        if binding["model_kind"] == HYBRID_MODEL_KIND:
            if mode == "PILOT": hybrid_training(dataset, fold, labeled_id, labeled_sha)
            else:
                if (fold != 3 or recipe.random_state != 42 or labeled_id != "labels-fold3"
                        or not isinstance(labeled_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", labeled_sha)
                        or not isinstance(chosen.get("strict_proof_sha256"), str)
                        or not re.fullmatch(r"[a-f0-9]{64}", chosen["strict_proof_sha256"])):
                    raise ValueError("registered complete hybrid STRICT proof pin/fold required")
                from app.frozen_evaluation import _hybrid_read
                _, protected_registry = _hybrid_read(registry, 1024 * 1024)
                if protected_registry != document: raise ValueError("protected hybrid registry changed during admission")
        elif labeled_id is not None or labeled_sha is not None:
            raise ValueError("labeled training references are reserved for hybrid recipes")
        numeric_format = state_format(binding["model_kind"])
        if binding["model_kind"] == HYBRID_MODEL_KIND and chosen.get("model_state_format", numeric_format) != numeric_format:
            raise ValueError("hybrid registered numeric format mismatch")
        policy = ScorePolicy.from_wire(chosen.get("score_policy"))
        if not policy.strict_gate or policy.document["feature_schema_version"] != dataset.manifest["feature_schema_version"]:
            raise ValueError("strict score policy must match the registered feature schema")
        if mode == "STRICT":
            selection_file = directory / (campaign_prefix(binding["model_kind"]) + "-selection.json")
            if selection_file.is_symlink() or not selection_file.is_file() or selection_file.stat().st_size > 1024 * 1024:
                raise ValueError("bounded completed selection required")
            data = selection_file.read_bytes()
            if hashlib.sha256(data).hexdigest() != chosen.get("selection_sha256"): raise ValueError("registered selection checksum mismatch")
            selected = parse_json(data)
            if (selected.get("status") != "SELECTED" or selected.get("actual_fits_completed") != 360
                    or selected.get("validation_runs_completed") != 360 or selected.get("completed_recalibrations", 0) < 45
                    or selected.get("dataset_sha256") != dataset.sha256 or selected.get("policy") != policy.wire()
                    or chosen.get("expected_model_sha256") != selected.get("model_sha256")
                    or chosen.get("expected_calibration_sha256") != selected.get("calibration_sha256")
                    or model_recipe_binding(selected) != binding):
                raise ValueError("registered candidate does not match frozen independent selection")
            if fold != 3 or recipe.random_state != 42: raise ValueError("frozen representative fold/seed required")
            if (not isinstance(chosen.get("expected_model_state_sha256"), str)
                    or not re.fullmatch(r"[a-f0-9]{64}", chosen["expected_model_state_sha256"])
                    or chosen.get("model_state_format") != numeric_format
                    or chosen.get("model_state_verifier_sha256") != verifier_sha256(binding["model_kind"])):
                raise ValueError("registered exact numeric-model identity/verifier required")
            if binding["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
                if binding["model_kind"] == HYBRID_MODEL_KIND:
                    from app.hybrid_incident import HybridIncidentScorer
                    implementation = ModelStore.scoring_identity(HybridIncidentScorer(recipe))
                    configuration = asdict(recipe)
                else:
                    from app.normal_support import NormalSupportScorer
                    implementation = ModelStore.scoring_identity(NormalSupportScorer(**recipe.parameters()))
                    configuration = recipe.parameters()
                if (selected.get("model_config") != configuration
                        or selected.get("model_state_sha256") != chosen["expected_model_state_sha256"]
                        or selected.get("model_state_format") != numeric_format
                        or selected.get("model_state_verifier_sha256") != verifier_sha256(binding["model_kind"])
                        or selected.get("scoring_implementation") != implementation):
                    raise ValueError("selected typed recipe/state/implementation binding differs")
        result = Recipe(recipe_id, dataset, recipe, policy, fold, mode,
                      chosen.get("expected_model_sha256"), chosen.get("expected_calibration_sha256"),
                      chosen.get("expected_model_state_sha256"), chosen.get("model_state_verifier_sha256"),
                      binding["model_kind"], binding["recipe_version"], binding["recipe_sha256"], numeric_format,
                      labeled_id, labeled_sha, chosen.get("strict_proof_sha256"), chosen.get("holdout_access_audit_sha256"))
        if binding["model_kind"] == HYBRID_MODEL_KIND and mode == "STRICT": hybrid_strict_header(result)
        return result


def train_recipe(store: ModelStore, recipe: Recipe, version: str, cache: Path, *, progress=None):
    """Real worker-owned fitting/calibration with an ID-only caller contract."""
    validate_version(version)
    dataset, fold = recipe.dataset, recipe.fold
    schema = dataset.manifest["feature_schema_version"]
    if not recipe.policy.strict_gate or recipe.policy.document["feature_schema_version"] != schema:
        raise ValueError("recipe policy and dataset feature schema differ")
    source_identity = version + dataset.sha256 + recipe.policy.sha256
    if recipe.model_kind == SUPPORT_MODEL_KIND:
        source_identity += canonical({**recipe_binding(recipe.config), "code_fingerprint": fingerprint(recipe.model_kind)})
    if recipe.model_kind == HYBRID_MODEL_KIND:
        if recipe.mode == "STRICT":
            strict_proof = verify_registered_hybrid(recipe)
            normal, supervised, labeled_manifest, labeled_sha = hybrid_fold_training(dataset, fold)
            if labeled_sha != recipe.labeled_training_manifest_sha256:
                raise ValueError("registered strict labeled training source changed")
            hybrid_code = fingerprint(HYBRID_MODEL_KIND)
            source_identity += recipe.strict_proof_sha256
        else:
            normal, supervised, labeled_manifest = hybrid_training(dataset, fold, recipe.labeled_training_artifact_id,
                                                                   recipe.labeled_training_manifest_sha256)
            hybrid_code = hybrid_fingerprint(recipe)
        source_identity += canonical({**recipe_binding(recipe.config), "code_fingerprint": hybrid_code})
    source_version = "recipe_fit_" + hashlib.sha256(source_identity.encode()).hexdigest()[:24]
    fit = dataset.split(f"fold{fold}-fit")
    if fit["positive"] or fit["cohorts"] != {"READY": fit["records"]} or not 500 <= fit["records"] <= 50000:
        raise ValueError("bounded all-normal actual fitting rows required")
    if recipe.mode == "STRICT" and fit["records"] != 50000: raise ValueError("full frozen fitting population required")
    expected = {"dataset_manifest_sha256": dataset.sha256, "fit_split_sha256": fit["sha256"], "fold": fold,
                "recipe_id": recipe.recipe_id, "model_config": asdict(recipe.config) if recipe.model_kind == HYBRID_MODEL_KIND else recipe.config.parameters()}
    if recipe.recipe_sha256 is not None:
        declared = {"model_kind": recipe.model_kind, "recipe_version": recipe.recipe_version, "recipe_sha256": recipe.recipe_sha256}
        if declared != recipe_binding(recipe.config): raise ValueError("typed operator recipe differs from its configuration")
        expected.update(declared)
    elif recipe.model_kind != IF_MODEL_KIND:
        raise ValueError("support operator recipe requires complete typed identity")
    if recipe.model_kind == SUPPORT_MODEL_KIND: expected["code_fingerprint"] = fingerprint(recipe.model_kind)
    if recipe.model_kind == HYBRID_MODEL_KIND:
        expected.update(code_fingerprint=hybrid_code,
                        labeled_training_artifact_id=recipe.labeled_training_artifact_id,
                        labeled_training_manifest_sha256=recipe.labeled_training_manifest_sha256,
                        labeled_training_windows=81500, labeled_class_windows={"0": 71500, "1": 8000, "2": 2000})
        if recipe.mode == "STRICT":
            expected.update(strict_proof_sha256=recipe.strict_proof_sha256, hybrid_strict_proof=strict_proof,
                            scope="FULL_STRICT_SOURCE", normal_fit_split_sha256=fit["sha256"],
                            labeled_training_split_sha256=hashlib.sha256(canonical(labeled_manifest["sections"]).encode()).hexdigest())
    if (store.directory / f"{source_version}.json").exists():
        metadata, _ = store.load_candidate(source_version)
        if any(metadata.get(key) != value for key, value in expected.items()): raise ValueError("interrupted recipe fitting identity changed")
        if recipe.model_kind == HYBRID_MODEL_KIND and recipe.mode == "STRICT" and metadata.get("actual_component_fit_counts") != {
                "normal_component_fit_calls": 1, "labeled_component_fit_calls": 1}:
            raise ValueError("retained strict hybrid must prove both genuine component fits")
    else:
        features = [row["features"] for _, rows in dataset.iter_shards(f"fold{fold}-fit") for row in rows]
        initial = []
        for _, rows in dataset.iter_shards(f"fold{fold}-calibration-ready"):
            initial.extend(row["features"] for row in rows[:5000 - len(initial)])
            if len(initial) == 5000: break
        if len(features) != fit["records"]: raise ValueError("fitted rows differ from declared immutable population")
        labeled = {}
        if recipe.model_kind == HYBRID_MODEL_KIND:
            from app.hybrid_dataset import training_targets
            labeled = {"labeled_samples": [row["features"] for row in supervised],
                       "labeled_targets": training_targets(supervised)}
        if recipe.model_kind == HYBRID_MODEL_KIND and recipe.mode == "STRICT":
            with HybridFitCounter() as actual:
                metadata = store.train(source_version, features, initial, schema_version=schema, config=recipe.config, policy=recipe.policy, **labeled)
            if actual.counts != {"normal_component_fit_calls": 1, "labeled_component_fit_calls": 1}:
                raise ValueError("strict hybrid requires both genuine component fits")
            metadata.update(actual_component_fit_counts=actual.counts)
        else:
            metadata = store.train(source_version, features, initial, schema_version=schema, config=recipe.config, policy=recipe.policy, **labeled)
        metadata.update(expected); write(store.directory / f"{source_version}.json", metadata)
    result = recalibrate(store, dataset, fold, source_version, version, recipe.policy, cache, progress=progress)
    metadata = result["metadata"]
    _, payload = store.load_candidate(version)  # Always verifies actual binary file SHA first.
    numeric_sha = state_sha256(payload)
    numeric_format = state_format(payload)
    if numeric_format != recipe.model_state_format: raise ValueError("operator recipe numeric state format mismatch")
    if recipe.mode == "STRICT" and (numeric_sha != recipe.expected_model_state_sha256
            or recipe.model_state_verifier_sha256 != verifier_sha256(recipe.model_kind)
            or metadata["calibration_sha256"] != recipe.expected_calibration_sha256):
        raise ValueError("actual worker fit/calibration differs from the independently frozen selected artifact")
    metadata.update(recipe_id=recipe.recipe_id, catalogue_mode=recipe.mode,
                    model_state_sha256=numeric_sha, model_state_format=numeric_format,
                    model_state_verifier_sha256=verifier_sha256(recipe.model_kind))
    if recipe.mode == "STRICT": metadata["selected_reference_model_sha256"] = recipe.expected_model_sha256
    if recipe.model_kind == HYBRID_MODEL_KIND and recipe.mode == "STRICT": verify_registered_hybrid(recipe, metadata, payload)
    write(store.directory / f"{version}.json", metadata)
    return metadata
