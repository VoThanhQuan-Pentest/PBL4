"""Independent post-selection holdout recovery; the old holdout stays blocked.

A receipt is an immutable binding, not a quality result or an exposure override.
Only designated original TRAIN/VAL resources may support the selected model.
New causal cases cannot be allocated until a complete selection is frozen.
"""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

from app.catalog import MAX_MANIFEST_BYTES, MAX_SHARD_BYTES, ShardedDataset, parse_json, utc, validate_rows
from app.contract import FEATURE_NAMES_V4, HYBRID_MODEL_KIND, validate_version
from app.holdout_provenance import holdout_audit_resources, require_unblocked_holdout
from app.policy import ScorePolicy, canonical

RECEIPT_FORMAT = "FRESH_HOLDOUT_FROZEN_SELECTION_V1"
PROTOCOL_FORMAT = "FRESH_HOLDOUT_RECOVERY_PROTOCOL_V1"
MANIFEST_FORMAT = "FRESH_HOLDOUT_RECOVERY_MANIFEST_V1"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
DEPENDENCIES = {"numpy": "2.5.3", "scipy": "1.18.1", "scikit-learn": "1.9.1", "joblib": "1.6.0"}
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
COHORTS = ("READY", "UNSEEN_READY", "COLD")
TRAIN_VAL_SPLITS = tuple(f"fold{fold}-{role}" for fold in (1, 2, 3)
                        for role in ("fit", "calibration-ready", "calibration-cold", "validation"))
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 128 * 1024 * 1024
PROJECT_ROOT_ENV = "UEBA_RECOVERY_PROJECT_ROOT"
AUTHORITY_DIRECTORY = "observability/runtime/fresh-holdout-recovery-authority"


def digest_document(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _sha(value):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("checksum-bound recovery identity required")
    return value


def _identifier(value, *, fresh=False):
    if (type(value) is not str or re.fullmatch(r"[a-z0-9_-]{8,32}", value) is None
            or fresh and (not value.startswith("fresh-holdout-") or "pilot" in value)):
        raise ValueError("distinct fresh holdout dataset identity required")
    return value


def checked_path(value):
    path = Path(value).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical nonsymlink recovery path required")
    return path


def private_directory(value):
    path = checked_path(value)
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("private owner-controlled recovery directory required")
    return path


def require_separate_location(value, source, *, file=False):
    retained = checked_path(source).parent
    target = checked_path(value).parent if file else checked_path(value)
    if target == retained or retained in target.parents or target in retained.parents:
        raise ValueError("recovery receipt/output must not overlap the complete retained original source or labels")
    return target


def project_root():
    """Explicit project mount; a flat /code/app checkpoint is not the project."""
    value = os.environ.get(PROJECT_ROOT_ENV)
    if type(value) is not str or not Path(value).is_absolute():
        raise ValueError("explicit absolute recovery project root required")
    path = checked_path(value); info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("owner-controlled explicit recovery project root required")
    return path


def code_sha256(value, *, empty=False):
    """Stable bounded code read; source checkout group modes are not changed."""
    path = checked_path(value)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not (0 if empty else 1) <= before.st_size <= 1024 * 1024):
            raise ValueError("bounded owner-controlled frozen code required")
        raw = stream.read(1024 * 1024 + 1)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != before.st_size or signature(before) != signature(os.fstat(stream.fileno()))
                or signature(before) != signature(path.lstat())):
            raise ValueError("frozen recovery code changed during read")
    return hashlib.sha256(raw).hexdigest()


def private_read(value, maximum, *, document=True, maximum_links=1):
    """Bounded fail-closed metadata/binary read with inode-stability checks."""
    path = checked_path(value)
    initial = path.lstat()
    signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.geteuid()
            or stat.S_IMODE(initial.st_mode) != 0o600 or not 1 <= initial.st_nlink <= maximum_links
            or not 0 < initial.st_size <= maximum):
        raise ValueError("bounded private recovery file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256(); body = bytearray() if document else None; count = 0
    with os.fdopen(descriptor, "rb") as stream:
        if signature(initial) != signature(os.fstat(stream.fileno())):
            raise ValueError("recovery file changed before read")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            count += len(block)
            if count > maximum: raise ValueError("recovery file exceeds its bound")
            digest.update(block)
            if document: body.extend(block)
        if (count != initial.st_size or signature(initial) != signature(os.fstat(stream.fileno()))
                or signature(initial) != signature(path.lstat())):
            raise ValueError("recovery file changed during read")
    return digest.hexdigest(), parse_json(bytes(body)) if document else None


def write_new(value, document):
    path = checked_path(value); private_directory(path.parent)
    raw = canonical(document).encode()
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES: raise ValueError("bounded recovery document required")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fsync_directory(path.parent)
    return hashlib.sha256(raw).hexdigest()


def fsync_directory(value):
    path = checked_path(value)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def recovery_code_binding():
    root = project_root()
    module_sha = code_sha256(Path(__file__).absolute())
    if module_sha != code_sha256(root / "ueba-worker/app/fresh_holdout_recovery.py"):
        raise ValueError("active frozen recovery module differs from pinned project copy")
    return {"ueba-worker/app/fresh_holdout_recovery.py": module_sha,
        "observability/scripts/generate-ueba-fresh-holdout.py": code_sha256(root / "observability/scripts/generate-ueba-fresh-holdout.py")}


def evaluation_code_binding():
    """Freeze every active app source and the complete unchanged CI machinery."""
    app = checked_path(Path(__file__).absolute().parent)
    entries = list(app.iterdir())
    if (not 1 <= len(entries) <= 256
            or any(not path.is_file() or re.fullmatch(r"[a-z_][a-z0-9_]*\.py", path.name) is None for path in entries)):
        raise ValueError("flat bounded frozen app inventory required; unpinned folders/bytecode refused")
    inventory = {path.name: code_sha256(path, empty=path.name == "__init__.py") for path in sorted(entries)}
    required = {"__init__.py", "fresh_holdout_recovery.py", "frozen_evaluation.py", "quality_proof.py", "strict_metrics.py",
                "policy.py", "metric_journal.py", "selection.py", "strict_campaign.py", "contract.py", "catalog.py"}
    if not required <= set(inventory): raise ValueError("complete frozen scorer/math/journal app inventory required")
    math_binding = {"sources": {name: inventory[name] for name in ("quality_proof.py", "strict_metrics.py", "policy.py", "metric_journal.py")},
                    "dependencies": {name: importlib.metadata.version(name) for name in ("numpy", "scipy")}}
    return {"app_source_sha256": inventory, "app_inventory_sha256": digest_document(inventory),
            "scorer_sha256": inventory["frozen_evaluation.py"], "quality_math_binding": math_binding,
            "metric_journal_sha256": inventory["metric_journal.py"]}


def authority_key(receipt):
    selected = receipt["selection"]
    return digest_document([receipt["source"]["manifest_sha256"], receipt["selection_sha256"],
                            selected["model_sha256"], selected["policy_sha256"]])


def _authority_claim(receipt, receipt_path):
    return {"format": "FRESH_HOLDOUT_RECOVERY_AUTHORITY_V1", "authority_key": authority_key(receipt),
        "recovery_project_root": receipt["recovery_project_root"], "canonical_receipt_path": str(checked_path(receipt_path)),
        "original_training_manifest_sha256": receipt["source"]["manifest_sha256"],
        "selection_sha256": receipt["selection_sha256"], "model_sha256": receipt["selection"]["model_sha256"],
        "policy_sha256": receipt["selection"]["policy_sha256"]}


def claim_recovery_authority(receipt, receipt_path):
    root = project_root()
    if receipt["recovery_project_root"] != str(root): raise ValueError("recovery project root changed")
    authority = root / AUTHORITY_DIRECTORY
    parent = checked_path(authority.parent); info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("owned recovery authority parent required")
    authority.mkdir(mode=0o700, exist_ok=True); private_directory(authority)
    fsync_directory(authority.parent)
    claim = _authority_claim(receipt, receipt_path)
    # A partial claim is deliberately fail-closed, never permission to re-freeze.
    checksum = write_new(authority / (claim["authority_key"] + ".private.json"), claim)
    return {"authority_key": claim["authority_key"], "canonical_receipt_path": claim["canonical_receipt_path"], "claim_sha256": checksum}


def verify_recovery_authority(receipt, receipt_path):
    root = project_root(); authority = receipt["recovery_authority"]
    if (receipt["recovery_project_root"] != str(root)
            or authority["canonical_receipt_path"] != str(checked_path(receipt_path))
            or authority["authority_key"] != authority_key(receipt)):
        raise ValueError("only the authoritative frozen receipt path may allocate or evaluate; copied/renamed receipt refused")
    directory = private_directory(root / AUTHORITY_DIRECTORY)
    checksum, claim = private_read(directory / (authority["authority_key"] + ".private.json"), MAX_RECEIPT_BYTES)
    if checksum != authority["claim_sha256"] or claim != _authority_claim(receipt, receipt_path):
        raise ValueError("canonical frozen selection authority claim changed")
    return authority


def require_execution_environment():
    if (os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE or not Path("/.dockerenv").is_file()
            or os.geteuid() != 1000):
        raise ValueError("pinned UID1000 Docker-only recovery execution required")
    if {name: importlib.metadata.version(name) for name in DEPENDENCIES} != DEPENDENCIES:
        raise ValueError("exact frozen recovery dependencies required")
    project_root()


def validate_frozen_receipt(receipt):
    try:
        return _validate_frozen_receipt(receipt)
    except (KeyError, TypeError, AttributeError):
        raise ValueError("malformed frozen recovery receipt") from None


def _validate_frozen_receipt(receipt):
    required = {"format", "status", "recorded_at_utc", "source", "selection_sha256", "selection",
                "hybrid_proof", "recovery_code_sha256", "recovery_project_root", "recovery_authority", "evaluation_code_binding", "execution_image_id", "dependencies",
                "lifecycle_provenance_sha256", "new_holdout_generated", "old_holdout_scored",
                "quality_gate", "data_provenance"}
    if (type(receipt) is not dict or set(receipt) != required or receipt["format"] != RECEIPT_FORMAT
            or receipt["status"] != "FROZEN_BEFORE_FRESH_HOLDOUT" or receipt["quality_gate"] != "NOT_RUN"
            or receipt["data_provenance"] != "DEMO_ONLY" or receipt["new_holdout_generated"] is not False
            or receipt["old_holdout_scored"] is not False or receipt["execution_image_id"] != IMAGE
            or receipt["dependencies"] != DEPENDENCIES):
        raise ValueError("immutable complete pre-generation frozen selection receipt required")
    _sha(receipt["selection_sha256"])
    selected = receipt["selection"]
    if (type(selected) is not dict or selected.get("status") != "SELECTED"
            or selected.get("model_kind") != HYBRID_MODEL_KIND
            or type(selected.get("recipe_version")) is not int or selected["recipe_version"] != 1
            or selected.get("holdout_scored") is not False or selected.get("quality_gate") != "NOT_RUN"
            or selected.get("data_provenance") != "DEMO_ONLY"
            or any(type(selected.get(key)) is not int or selected[key] != expected for key, expected in {
                "actual_fits_completed": 360, "validation_runs_completed": 360,
                "additional_fit_calls_in_recalibration": 0}.items())
            or type(selected.get("completed_recalibrations")) is not int
            or not 45 <= selected["completed_recalibrations"] <= 360):
        raise ValueError("all360 fit/validation and45..360 zero-fit recalibrations required")
    if digest_document(selected) != receipt["selection_sha256"]:
        raise ValueError("exact immutable canonical frozen selection bytes required")
    validate_version(selected["model_version"])
    for key in ("model_sha256", "model_state_sha256", "model_state_verifier_sha256", "calibration_sha256",
                "policy_sha256", "recipe_sha256", "dataset_sha256"):
        _sha(selected.get(key))
    if (selected.get("model_state_format") != "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1"
            or type(selected.get("model_config")) is not dict or selected["model_config"].get("random_state") != 42
            or type(selected.get("scoring_implementation")) is not dict or not selected["scoring_implementation"]):
        raise ValueError("original representative numeric state/scoring implementation required")
    policy = ScorePolicy.from_wire(selected["policy"])
    if (not policy.strict_gate or policy.document["feature_schema_version"] != 4
            or policy.sha256 != selected["policy_sha256"]):
        raise ValueError("unchanged strict schema4 policy required")
    source = receipt["source"]
    fields = {"dataset_id", "manifest_sha256", "blocked_holdout_split_sha256", "blocked_audit_sha256",
              "train_validation_split_sha256", "label_manifest_sha256", "generation_source_binding",
              "workspace_snapshot_sha256", "generation_identity_sha256"}
    if type(source) is not dict or set(source) != fields:
        raise ValueError("original TRAIN/VAL source and blocked holdout bindings required")
    _identifier(source["dataset_id"])
    for key in ("manifest_sha256", "blocked_holdout_split_sha256", "workspace_snapshot_sha256", "generation_identity_sha256"):
        _sha(source[key])
    if (type(source["blocked_audit_sha256"]) is not dict or not 1 <= len(source["blocked_audit_sha256"]) <= 2
            or not set(source["blocked_audit_sha256"]) <= {"root", "parent"}
            or type(source["train_validation_split_sha256"]) is not dict
            or set(source["train_validation_split_sha256"]) != set(TRAIN_VAL_SPLITS)
            or type(source["label_manifest_sha256"]) is not dict
            or set(source["label_manifest_sha256"]) != {"1", "2", "3"}):
        raise ValueError("all original TRAIN/VAL, labels and BLOCKED audits required")
    for mapping in (source["blocked_audit_sha256"], source["train_validation_split_sha256"], source["label_manifest_sha256"]):
        for checksum in mapping.values(): _sha(checksum)
    generator_binding = source["generation_source_binding"]
    if (type(generator_binding) is not dict or set(generator_binding) != {"source_sha256", "sha256"}
            or type(generator_binding["source_sha256"]) is not dict or not generator_binding["source_sha256"]
            or generator_binding["sha256"] != digest_document(generator_binding["source_sha256"])):
        raise ValueError("original frozen generation source SHA inventory required")
    for checksum in generator_binding["source_sha256"].values(): _sha(checksum)
    identity = selected.get("selection_identity")
    if (type(identity) is not dict or identity.get("dataset_manifest_sha256") != source["manifest_sha256"]
            or selected["dataset_sha256"] != source["manifest_sha256"]
            or identity.get("producer_workspace_snapshot_sha256") != source["workspace_snapshot_sha256"]
            or type(identity.get("production_classes")) is not dict or not identity["production_classes"]
            or type(identity.get("feature_producers")) is not dict or not identity["feature_producers"]
            or type(identity.get("fit_code_fingerprint")) is not dict
            or identity["fit_code_fingerprint"].get("dependencies") != DEPENDENCIES
            or type(identity.get("selection_sources")) is not dict or not identity["selection_sources"]):
        raise ValueError("frozen model/source/code/JVM selection identity required")
    for mapping in (identity["production_classes"], identity["feature_producers"],
                    identity["selection_sources"], identity["fit_code_fingerprint"].get("sources", {})):
        if not mapping: raise ValueError("complete frozen code/JVM SHA inventory required")
        for checksum in mapping.values(): _sha(checksum)
    proof = receipt["hybrid_proof"]
    if (type(proof) is not dict or proof.get("format") != "HYBRID_STRICT_PROOF_V1"
            or proof.get("selection_sha256") != receipt["selection_sha256"]
            or any(type(proof.get(key)) is not int or proof[key] != expected for key, expected in {
                "actual_composite_trials": 360, "actual_component_fit_calls": 720, "validation_runs": 360}.items())
            or type(proof.get("zero_fit_recalibrations")) is not int
            or proof["zero_fit_recalibrations"] != selected["completed_recalibrations"]
            or {fold: value["manifest_sha256"] for fold, value in proof.get("source_label_manifests", {}).items()}
                != source["label_manifest_sha256"]):
        raise ValueError("verified complete360/720/360 native strict proof required")
    _sha(proof.get("proof_sha256"))
    if (type(receipt["recovery_code_sha256"]) is not dict
            or set(receipt["recovery_code_sha256"]) != {"ueba-worker/app/fresh_holdout_recovery.py",
                "observability/scripts/generate-ueba-fresh-holdout.py"}
            or type(receipt["lifecycle_provenance_sha256"]) is not dict
            or not set(receipt["lifecycle_provenance_sha256"]) <= {"approval", "checkpoint"}):
        raise ValueError("separate recovery code and bounded optional lifecycle SHA bindings required")
    for mapping in (receipt["recovery_code_sha256"], receipt["lifecycle_provenance_sha256"]):
        for checksum in mapping.values(): _sha(checksum)
    root = receipt["recovery_project_root"]; authority = receipt["recovery_authority"]
    if (type(root) is not str or not Path(root).is_absolute() or ".." in Path(root).parts
            or type(authority) is not dict or set(authority) != {"authority_key", "canonical_receipt_path", "claim_sha256"}
            or type(authority["canonical_receipt_path"]) is not str or not Path(authority["canonical_receipt_path"]).is_absolute()
            or ".." in Path(authority["canonical_receipt_path"]).parts or authority["authority_key"] != authority_key(receipt)):
        raise ValueError("fixed recovery project root and one canonical receipt authority required")
    _sha(authority["claim_sha256"])
    evaluation = receipt["evaluation_code_binding"]
    if (type(evaluation) is not dict or set(evaluation) != {"app_source_sha256", "app_inventory_sha256", "scorer_sha256", "quality_math_binding", "metric_journal_sha256"}
            or type(evaluation["app_source_sha256"]) is not dict or not 11 <= len(evaluation["app_source_sha256"]) <= 256
            or evaluation["app_inventory_sha256"] != digest_document(evaluation["app_source_sha256"])
            or evaluation["scorer_sha256"] != evaluation["app_source_sha256"].get("frozen_evaluation.py")
            or evaluation["metric_journal_sha256"] != evaluation["app_source_sha256"].get("metric_journal.py")
            or evaluation["app_source_sha256"].get("fresh_holdout_recovery.py") != receipt["recovery_code_sha256"]["ueba-worker/app/fresh_holdout_recovery.py"]
            or evaluation["quality_math_binding"] != {"sources": {name: evaluation["app_source_sha256"].get(name)
                for name in ("quality_proof.py", "strict_metrics.py", "policy.py", "metric_journal.py")},
                "dependencies": {name: DEPENDENCIES[name] for name in ("numpy", "scipy")}}):
        raise ValueError("pre-generation full scorer/math/journal inventory required")
    for name, checksum in evaluation["app_source_sha256"].items():
        if type(name) is not str or re.fullmatch(r"[a-z_][a-z0-9_]*\.py", name) is None:
            raise ValueError("bounded flat evaluation source names required")
        _sha(checksum)
    times = []
    for value in (receipt["recorded_at_utc"], selected.get("frozen_at_utc")):
        if type(value) is not str or not 1 <= len(value) <= 64:
            raise ValueError("pre-generation frozen selection timestamps required")
        try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError: raise ValueError("UTC frozen selection timestamp required") from None
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("UTC frozen selection timestamp required")
        times.append(parsed)
    if times[0] < times[1]: raise ValueError("selection must be frozen before its recovery receipt")
    return receipt


def load_frozen_receipt(path, expected_sha256):
    _sha(expected_sha256)
    checksum, receipt = private_read(path, MAX_RECEIPT_BYTES)
    if checksum != expected_sha256: raise ValueError("frozen recovery receipt SHA mismatch")
    try: validate_frozen_receipt(receipt)
    except (KeyError, TypeError, AttributeError):
        raise ValueError("malformed frozen recovery receipt") from None
    verify_recovery_authority(receipt, path)
    return receipt


def collect_frozen_binding(source, workspace):
    """Full existing proof readback; never transport the blocked old holdout."""
    from app.frozen_evaluation import verify_hybrid_strict_proof
    from app.hybrid_strict_dataset import validate_standard_manifest
    from app.model import ModelStore
    from app.selection import selection_identity
    source = private_directory(source); workspace = checked_path(workspace)
    dataset = ShardedDataset(source)
    validate_standard_manifest(dataset.manifest, dataset.manifest["dataset_id"])
    audits = holdout_audit_resources(source)
    if not audits: raise ValueError("recovery requires retained original BLOCKED holdout audit")
    audit_shas = {}
    for path, raw in audits:
        if parse_json(raw)["dataset_id"] != dataset.manifest["dataset_id"]:
            raise ValueError("blocked audit differs from original source")
        audit_shas["root" if path.parent == source else "parent"] = hashlib.sha256(raw).hexdigest()
    selection_sha, selected = private_read(source / "hybrid-selection.json", MAX_RECEIPT_BYTES)
    if selected.get("selection_identity") != selection_identity(dataset, workspace, HYBRID_MODEL_KIND):
        raise ValueError("selected original TRAIN/VAL identity changed")
    store = ModelStore(source / "hybrid-models")
    # Verify the private selected binary before the normal model-store readback.
    checksum, _ = private_read(store.directory / (selected["model_version"] + ".joblib"), MAX_MODEL_BYTES, document=False)
    if checksum != selected.get("model_sha256"): raise ValueError("selected original binary changed")
    metadata, payload = store.load_candidate(selected["model_version"])
    proof = verify_hybrid_strict_proof(dataset, selected, metadata, payload, source=True)
    binding = {"dataset_id": dataset.manifest["dataset_id"], "manifest_sha256": dataset.sha256,
        "blocked_holdout_split_sha256": dataset.split("holdout")["sha256"], "blocked_audit_sha256": audit_shas,
        "train_validation_split_sha256": {name: dataset.split(name)["sha256"] for name in TRAIN_VAL_SPLITS},
        "label_manifest_sha256": {fold: value["manifest_sha256"] for fold, value in proof["source_label_manifests"].items()},
        "generation_source_binding": dataset.manifest["source_binding"],
        "workspace_snapshot_sha256": dataset.manifest["workspace_snapshot_sha256"],
        "generation_identity_sha256": dataset.manifest["generation_identity_sha256"]}
    return {"source": binding, "selection_sha256": selection_sha, "selection": selected, "hybrid_proof": proof}


def freeze_selection(source, workspace, output, *, lifecycle_provenance_sha256=None):
    """Create a separate receipt; do not modify source, model, labels or audit."""
    require_execution_environment()
    output = checked_path(output); require_separate_location(output, source, file=True)
    private_directory(output.parent)
    if output.exists(): raise ValueError("new authoritative frozen receipt path required")
    receipt = {"format": RECEIPT_FORMAT, "status": "FROZEN_BEFORE_FRESH_HOLDOUT",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(), **collect_frozen_binding(source, workspace),
        "recovery_code_sha256": recovery_code_binding(), "recovery_project_root": str(project_root()),
        "evaluation_code_binding": evaluation_code_binding(), "execution_image_id": IMAGE, "dependencies": DEPENDENCIES,
        "lifecycle_provenance_sha256": lifecycle_provenance_sha256 or {}, "new_holdout_generated": False,
        "old_holdout_scored": False, "quality_gate": "NOT_RUN", "data_provenance": "DEMO_ONLY"}
    claim = _authority_claim(receipt, output)
    receipt["recovery_authority"] = {"authority_key": claim["authority_key"],
        "canonical_receipt_path": claim["canonical_receipt_path"], "claim_sha256": digest_document(claim)}
    validate_frozen_receipt(receipt)
    if claim_recovery_authority(receipt, output) != receipt["recovery_authority"]:
        raise ValueError("authoritative recovery claim readback changed")
    checksum = write_new(output, receipt)
    if load_frozen_receipt(output, checksum) != receipt: raise ValueError("frozen receipt readback changed")
    return checksum, receipt


def verify_frozen_receipt(receipt, source, workspace, *, receipt_path=None):
    validate_frozen_receipt(receipt)
    verify_recovery_authority(receipt, receipt_path or receipt["recovery_authority"]["canonical_receipt_path"])
    if receipt["recovery_code_sha256"] != recovery_code_binding():
        raise ValueError("frozen recovery adapter code changed")
    if receipt["evaluation_code_binding"] != evaluation_code_binding():
        raise ValueError("pre-generation frozen scorer/math/journal app inventory changed")
    binding = collect_frozen_binding(source, workspace)
    if any(receipt[key] != value for key, value in binding.items()):
        raise ValueError("original source/selection/model/policy/code/JVM changed after freeze")
    return receipt


def fresh_protocol(receipt, receipt_sha256, dataset_id, entropy_hex, *, scoped_test=False):
    """Allocate cases only from a valid frozen receipt and new post-freeze entropy."""
    validate_frozen_receipt(receipt); _sha(receipt_sha256)
    if digest_document(receipt) != receipt_sha256:
        raise ValueError("canonical frozen receipt SHA required before allocating cases")
    _identifier(dataset_id, fresh=True)
    if dataset_id == receipt["source"]["dataset_id"]: raise ValueError("old dataset cannot become the fresh holdout")
    _sha(entropy_hex)
    normal, positive = (100, 50) if scoped_test else (10000000, 10000)
    namespace = "recovery-" + digest_document([receipt_sha256, dataset_id, entropy_hex])[:48]
    return {"format": PROTOCOL_FORMAT, "dataset_id": dataset_id,
        "scope": "SCOPED_TEST" if scoped_test else "FULL_FRESH_HOLDOUT", "frozen_selection_receipt_sha256": receipt_sha256,
        "original_training_manifest_sha256": receipt["source"]["manifest_sha256"],
        "postfreeze_entropy_hex": entropy_hex, "seed_namespace": namespace,
        "holdout": {"start_day": 85, "days": 14, "normal": normal, "positive": positive,
            "positive_per_family": positive // 5, "cohort_ratio": [70, 20, 10]},
        "cohort_identity_protocol": "READY_ORIGINAL_FOLD3_PROFILE_AND_SUBJECT_FRESH_CASE_SEED;UNSEEN_READY_AND_COLD_FRESH_SUBJECTS",
        "context_windows": {"READY": 48, "UNSEEN_READY": 48, "COLD": 3},
        "old_numeric_corpus_read": False, "old_holdout_acceptance_allowed": False,
        "fit_or_score_calls": 0, "quality_gate": "NOT_EVALUATED", "data_provenance": "DEMO_ONLY"}


def recovery_writer():
    """Load only the receipt-bound local recovery adapter, never a caller path."""
    writer_path = project_root() / "observability/scripts/generate-ueba-fresh-holdout.py"
    specification = importlib.util.spec_from_file_location("verified_fresh_holdout_recovery_writer", writer_path)
    writer = importlib.util.module_from_spec(specification); sys.modules[specification.name] = writer
    specification.loader.exec_module(writer)
    return writer


class FreshHoldoutDataset:
    """Validated transport adapter: original training SHA, fresh holdout identity.

    No old split can be transported through this adapter. The model's original
    TRAIN/VAL binding is deliberately not rewritten or presented as a new fit.
    Only the independent holdout manifest supplies numeric rows.
    """
    def __init__(self, source, fresh_root, workspace, receipt_path, *, receipt_sha256, manifest_sha256):
        _sha(manifest_sha256)
        receipt = load_frozen_receipt(receipt_path, receipt_sha256)
        require_separate_location(receipt_path, source, file=True)
        verify_frozen_receipt(receipt, source, workspace, receipt_path=receipt_path)
        root = private_directory(fresh_root); require_unblocked_holdout(root)
        require_separate_location(root, source)
        actual_sha, manifest = private_read(root / "manifest.json", MAX_MANIFEST_BYTES)
        if actual_sha != manifest_sha256: raise ValueError("fresh holdout manifest SHA mismatch")
        declaration_sha, declaration = private_read(root / "predeclared.private.json", MAX_RECEIPT_BYTES)
        allocation_path = checked_path(receipt_path).with_name(Path(receipt_path).name + ".allocation.private.json")
        allocation_sha, allocation = private_read(allocation_path, MAX_RECEIPT_BYTES)
        try:
            protocol = declaration["protocol"]
            expected = fresh_protocol(receipt, receipt_sha256, manifest["dataset_id"], protocol["postfreeze_entropy_hex"])
            fields = {"format", "dataset_id", "stage", "scope", "quality_gate", "data_provenance",
                "feature_schema_version", "telemetry_contract_version", "feature_names", "frozen_selection_receipt_sha256",
                "original_training_manifest_sha256", "allocation_sha256", "predeclared_sha256", "protocol_sha256", "producer_identity",
                "splits", "fit_or_score_calls", "old_holdout_numeric_records_read", "old_holdout_acceptance_allowed"}
            if (type(manifest) is not dict or set(manifest) != fields or manifest["format"] != MANIFEST_FORMAT
                    or manifest["stage"] != "STRICT_FRESH_HOLDOUT" or manifest["scope"] != "FULL_FRESH_HOLDOUT"
                    or manifest["quality_gate"] != "NOT_EVALUATED" or manifest["data_provenance"] != "DEMO_ONLY"
                    or type(manifest["feature_schema_version"]) is not int or manifest["feature_schema_version"] != 4
                    or type(manifest["telemetry_contract_version"]) is not int or manifest["telemetry_contract_version"] != 3
                    or manifest["feature_names"] != list(FEATURE_NAMES_V4)
                    or manifest["frozen_selection_receipt_sha256"] != receipt_sha256
                    or manifest["original_training_manifest_sha256"] != receipt["source"]["manifest_sha256"]
                    or manifest["predeclared_sha256"] != declaration_sha
                    or manifest["allocation_sha256"] != allocation_sha or declaration["allocation_sha256"] != allocation_sha
                    or allocation != {"format": "FRESH_HOLDOUT_ALLOCATION_V1", "frozen_selection_receipt_sha256": receipt_sha256,
                        "recovery_authority": receipt["recovery_authority"],
                        "output_root": str(root), "protocol": expected}
                    or manifest["protocol_sha256"] != digest_document(expected) or protocol != expected
                    or declaration["protocol_sha256"] != manifest["protocol_sha256"]
                    or declaration["frozen_selection_receipt_sha256"] != receipt_sha256
                    or any(type(declaration[key]) is not int or declaration[key] != 0 for key in
                           ("new_frames_before_declaration", "fit_or_score_calls", "old_holdout_numeric_records_read"))
                    or manifest["producer_identity"] != declaration["producer_identity"]
                    or manifest["producer_identity"]["standard_producer"] != receipt["source"]["generation_source_binding"]
                    or manifest["producer_identity"]["workspace_snapshot_sha256"] != receipt["source"]["workspace_snapshot_sha256"]
                    or manifest["producer_identity"]["execution_image_id"] != IMAGE
                    or manifest["producer_identity"]["recovery_code_sha256"] != receipt["recovery_code_sha256"]
                    or manifest["producer_identity"]["recovery_project_root"] != receipt["recovery_project_root"]
                    or type(manifest["splits"]) is not dict or set(manifest["splits"]) != {"holdout"}
                    or any(type(manifest[key]) is not int or manifest[key] != 0 for key in
                           ("fit_or_score_calls", "old_holdout_numeric_records_read"))
                    or manifest["old_holdout_acceptance_allowed"] is not False):
                raise ValueError("full independent post-freeze holdout declaration required")
            holdout = manifest["splits"]["holdout"]
            ShardedDataset._check_split(holdout, set(), set())
            if (holdout["normal"] != 10000000 or holdout["positive"] != 10000
                    or holdout["families"] != {"normal": 10000000, **{family: 2000 for family in FAMILIES}}
                    or holdout["cohorts"] != {"READY": 7007000, "UNSEEN_READY": 2002000, "COLD": 1001000}):
                raise ValueError("unchanged full strict fresh holdout populations required")
            from datetime import timedelta
            anchor = datetime(2026, 4, 1, tzinfo=timezone.utc)
            if not anchor + timedelta(days=84) <= utc(holdout["from"]) <= utc(holdout["to"]) < anchor + timedelta(days=98):
                raise ValueError("unchanged day85..98 temporal holdout required")
        except (KeyError, TypeError, AttributeError):
            raise ValueError("malformed standalone fresh holdout manifest") from None
        # The manifest is not a substitute for all committed producer receipts.
        writer = recovery_writer()
        producer = writer.frozen_producer(receipt)
        actual_producer_identity, _, _ = writer.bind_producer(producer, receipt, workspace)
        if actual_producer_identity != manifest["producer_identity"]:
            raise ValueError("fresh producer/code/JVM differs from frozen generation")
        actual_holdout = writer.verify_completed_generation(producer, root, protocol, declaration_sha, declaration["batch_accounts"])
        if actual_holdout != holdout:
            raise ValueError("fresh manifest differs from all actual committed producer receipts")
        original = ShardedDataset(source)
        if original.sha256 != receipt["source"]["manifest_sha256"]:
            raise ValueError("original training source manifest changed")
        self.root = root
        self.sha256 = original.sha256
        self.manifest = {**original.manifest, "splits": {"holdout": holdout}}
        self.fresh_manifest = manifest
        self.fresh_manifest_sha256 = manifest_sha256
        self.receipt = receipt
        self.receipt_sha256 = receipt_sha256
        self.recovery_identity = {"format": MANIFEST_FORMAT, "frozen_selection_receipt_sha256": receipt_sha256,
            "recovery_project_root": receipt["recovery_project_root"], "recovery_authority": receipt["recovery_authority"],
            "evaluation_code_binding": receipt["evaluation_code_binding"],
            "fresh_holdout_dataset_id": manifest["dataset_id"], "fresh_holdout_manifest_sha256": manifest_sha256,
            "holdout_split_sha256": holdout["sha256"], "original_training_manifest_sha256": self.sha256,
            "allocation_sha256": allocation_sha, "predeclared_sha256": declaration_sha, "protocol_sha256": manifest["protocol_sha256"],
            "producer_identity": manifest["producer_identity"]}

    def split(self, name):
        if name != "holdout": raise ValueError("fresh recovery adapter transports only its independent holdout")
        return self.fresh_manifest["splits"][name]

    def iter_shards(self, name):
        require_unblocked_holdout(self.root)
        for descriptor in self.split(name)["shards"]:
            checksum, rows = private_read(self.root / descriptor["path"], MAX_SHARD_BYTES, maximum_links=2)
            stats = validate_rows(rows, 4)
            if checksum != descriptor["sha256"] or any(descriptor[key] != value for key, value in stats.items()):
                raise ValueError("fresh causal shard checksum/population changed")
            yield descriptor, rows


def evaluate_fresh(source, fresh_root, workspace, receipt_path, *, receipt_sha256, manifest_sha256, progress=None):
    """Reuse unchanged scorer, Java, journal, both scopes and all strict CI gates."""
    require_execution_environment()
    from app.frozen_evaluation import evaluate_bound, model_binding
    from app.model import ModelStore
    dataset = FreshHoldoutDataset(source, fresh_root, workspace, receipt_path,
                                  receipt_sha256=receipt_sha256, manifest_sha256=manifest_sha256)
    selected = dataset.receipt["selection"]
    original_store = ModelStore(checked_path(source) / "hybrid-models")
    metadata, payload = original_store.load_candidate(selected["model_version"])
    policy = ScorePolicy.from_wire(selected["policy"])
    binding = model_binding(metadata, policy)
    if any(selected.get(key) != value for key, value in binding.items() if key != "feature_schema_version"):
        raise ValueError("frozen recovered selected model binding changed")
    # Its independently pinned fresh identity makes resuming the same attempt
    # possible, but an old attempt or changed model/policy cannot be inherited.
    identity = {**binding, "selection_file_sha256": dataset.receipt["selection_sha256"],
        "quality_math_binding": dataset.receipt["evaluation_code_binding"]["quality_math_binding"],
        "production_classes": selected["selection_identity"]["production_classes"],
        "scorer_sha256": dataset.receipt["evaluation_code_binding"]["scorer_sha256"],
        "data_provenance": "DEMO_ONLY", "hybrid_strict_proof": dataset.receipt["hybrid_proof"],
        "model_kind": selected["model_kind"], "recipe_version": selected["recipe_version"], "recipe_sha256": selected["recipe_sha256"],
        "model_state_sha256": selected["model_state_sha256"], "model_state_format": selected["model_state_format"],
        "model_state_verifier_sha256": selected["model_state_verifier_sha256"],
        "scoring_implementation": selected["scoring_implementation"], **dataset.recovery_identity}
    evidence_directory = dataset.root / "evidence"
    evidence_directory.mkdir(mode=0o700, exist_ok=True)
    store = SimpleNamespace(directory=private_directory(evidence_directory))
    return evaluate_bound(dataset, store, metadata, payload, policy, identity, workspace, progress=progress,
        progress_file=dataset.root / "fresh-holdout.progress.json", result_file=dataset.root / "fresh-holdout-result.json",
        require_storage_guard=True)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fresh-holdout", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--allow-evaluation", action="store_true", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_fresh(args.source, args.fresh_holdout, args.workspace, args.receipt,
                                receipt_sha256=args.receipt_sha256, manifest_sha256=args.manifest_sha256)
        print(canonical({key: result[key] for key in ("status", "quality_gate", "evaluation_scope", "data_provenance")}), flush=True)
    except Exception as error:
        raise SystemExit("Fresh holdout evaluation refused: " + type(error).__name__ + "; private evidence retained") from None


if __name__ == "__main__": main()
