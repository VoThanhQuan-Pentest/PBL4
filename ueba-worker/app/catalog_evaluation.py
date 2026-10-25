"""ID-only strict worker evaluation over operator-installed read-only shards."""

from pathlib import Path

from app.catalog import parse_json
from app.contract import HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, model_recipe_binding, recipe_binding
from app.frozen_evaluation import evaluate_bound, model_binding, verify_hybrid_strict_proof
from app.holdout_provenance import require_unblocked_holdout
from app.policy import ScorePolicy
from app.quality_proof import math_binding, sha_file
from app.selection import selection_identity
from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
from app.strict_campaign import campaign_prefix
from app.validation import config_document


def evaluate_recipe(store, recipe, version, workspace, *, progress=None):
    if recipe.mode != "STRICT" or recipe.dataset.manifest["stage"] != "STRICT":
        raise ValueError("preview recipes cannot consume or pass the strict holdout")
    require_unblocked_holdout(recipe.dataset, expected_audit_sha256=getattr(recipe, "holdout_access_audit_sha256", None))
    kind = recipe.model_kind
    selected_path = recipe.dataset.root / (campaign_prefix(kind) + "-selection.json")
    if selected_path.is_symlink() or not selected_path.is_file() or selected_path.stat().st_size > 1024 * 1024:
        raise ValueError("bounded registered frozen selection required")
    selected = parse_json(selected_path.read_bytes())
    if (selected.get("status") != "SELECTED" or selected.get("actual_fits_completed") != 360
            or selected.get("validation_runs_completed") != 360 or selected.get("completed_recalibrations", 0) < 45
            or selected.get("additional_fit_calls_in_recalibration") != 0
            or selected.get("selection_identity") != selection_identity(recipe.dataset, workspace, kind)):
        raise ValueError("worker recipe does not match the complete frozen selection/code")
    metadata, payload = store.load_candidate(version)
    policy = ScorePolicy.from_wire(metadata["score_policy"])
    binding = {"model_kind": kind, "recipe_version": recipe.recipe_version, "recipe_sha256": recipe.recipe_sha256}
    selected_binding, actual_binding = model_recipe_binding(selected), model_recipe_binding(metadata)
    if (selected_binding != binding or actual_binding != binding
            or (kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and binding != recipe_binding(recipe.config))
            or (kind == IF_MODEL_KIND and recipe.recipe_sha256 is not None and binding != recipe_binding(recipe.config))):
        raise ValueError("worker recipe model kind/version/configuration identity mismatch")
    numeric_format, verifier = state_format(kind), verifier_sha256(kind)
    if (metadata.get("recipe_id") != recipe.recipe_id or metadata.get("catalogue_mode") != "STRICT"
            or metadata.get("calibration_scope") != "STRICT" or metadata.get("dataset_manifest_sha256") != recipe.dataset.sha256
            or metadata.get("model_config") != config_document(recipe.config) or policy.wire() != recipe.policy.wire()
            or selected.get("policy") != recipe.policy.wire()
            or selected.get("model_sha256") != recipe.expected_model_sha256
            or metadata.get("selected_reference_model_sha256") != recipe.expected_model_sha256
            or metadata.get("model_state_format") != numeric_format or state_format(payload) != numeric_format
            or recipe.model_state_format != numeric_format or metadata.get("model_state_verifier_sha256") != verifier
            or recipe.model_state_verifier_sha256 != verifier
            or metadata.get("model_state_sha256") != recipe.expected_model_state_sha256
            or state_sha256(payload) != recipe.expected_model_state_sha256
            or selected.get("calibration_sha256") != metadata["calibration_sha256"]
            or metadata["calibration_sha256"] != recipe.expected_calibration_sha256):
        raise ValueError("actual worker candidate differs from independently selected model/calibration/policy")
    if kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
        from app.model import ModelStore
        implementation = ModelStore.scoring_identity(payload["model"])
        if (selected.get("model_config") != config_document(recipe.config)
                or selected.get("model_state_sha256") != recipe.expected_model_state_sha256
                or selected.get("model_state_format") != numeric_format
                or selected.get("model_state_verifier_sha256") != verifier
                or selected.get("scoring_implementation") != implementation
                or metadata.get("scoring_implementation") != implementation):
            raise ValueError(f"selected {'hybrid' if kind == HYBRID_MODEL_KIND else 'support'} numeric state/scoring implementation changed")
    hybrid_proof = None
    if kind == HYBRID_MODEL_KIND:
        import re
        if (not isinstance(getattr(recipe, "strict_proof_sha256", None), str)
                or not re.fullmatch(r"[a-f0-9]{64}", recipe.strict_proof_sha256)
                or metadata.get("strict_proof_sha256") != recipe.strict_proof_sha256):
            raise ValueError("registered hybrid strict proof pin changed or unavailable")
        if (recipe.fold != 3 or recipe.config.random_state != 42 or metadata.get("fold") != 3
                or recipe.labeled_training_artifact_id != metadata.get("labeled_training_artifact_id")
                or recipe.labeled_training_manifest_sha256 != metadata.get("labeled_training_manifest_sha256")):
            raise ValueError("registered hybrid representative/labeled source changed")
        hybrid_proof = verify_hybrid_strict_proof(recipe.dataset, selected, metadata, payload)
        if hybrid_proof.get("proof_sha256") != recipe.strict_proof_sha256:
            raise ValueError("registered hybrid strict proof checksum changed")
    binding = model_binding(metadata, policy)
    identity = {**binding, "holdout_split_sha256": recipe.dataset.split("holdout")["sha256"],
                "selection_file_sha256": sha_file(selected_path), "quality_math_binding": math_binding(),
                "production_classes": selected["selection_identity"]["production_classes"],
                "scorer_sha256": sha_file(Path(__file__).with_name("frozen_evaluation.py")),
                "catalogue_scorer_sha256": sha_file(Path(__file__)), "recipe_id": recipe.recipe_id, "data_provenance": "DEMO_ONLY",
                "model_state_sha256": recipe.expected_model_state_sha256, "model_state_format": numeric_format,
                "model_state_verifier_sha256": verifier,
                **({**actual_binding, "scoring_implementation": implementation} if kind in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) else {}),
                "selected_reference_model_sha256": recipe.expected_model_sha256}
    if hybrid_proof is not None: identity["hybrid_strict_proof"] = hybrid_proof
    return evaluate_bound(recipe.dataset, store, metadata, payload, policy, identity, workspace, progress=progress)
