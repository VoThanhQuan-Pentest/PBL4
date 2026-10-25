#!/usr/bin/env python3
"""Continue one frozen local campaign after its exact live fit container exits.

No AWS, primary-model activation or external traffic. Observation failures do
not restart containers; every stage remains inspectable by its actual Docker ID.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "sha256:a8c57b76489a9c297bec061984a00db807acbfc2031028ae6f3c522c9d665544"
STAGES = {"validation": ["-m", "app.selection", "validate"],
          "selection": ["-m", "app.selection", "choose"],
          "holdout": ["-m", "app.frozen_evaluation"]}
RUNTIME = ROOT / "observability/runtime"
HYBRID_KIND = "normal_plus_incident_research"
SHA = re.compile(r"[a-f0-9]{64}")
SOURCE_ROOT = re.compile(r"hybrid-strict-source-[A-Za-z0-9_-]{8,128}")
RESERVE_BYTES = 5_000_000_000
MODEL_PUBLICATION_CAP = 128 * 1024 ** 2
FIT_SOURCES = ("strict_campaign.py", "calibration.py", "model.py", "catalog.py", "contract.py", "policy.py",
               "hybrid_incident.py", "hybrid_semantic.py", "normal_support.py", "model_state_dispatch.py",
               "hybrid_strict_dataset.py", "pipeline_lock.py", "owned_dataset.py", "archived_catalog.py", "storage_budget.py")
ONE_UNIT_APPROVAL_FIELDS = {"approval_schema_version", "scope", "source_standard", "continuation_identity_sha256",
                            "stage", "unit_id", "expected_before", "execution_approved", "retirement_approved", "user_approval_reference"}
COUNT_FIELDS = {"actual_fits_completed", "validation_runs_completed", "completed_recalibrations"}


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def checked_directory(path, *, private=True):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical owned continuation directory required")
    value = path.stat(follow_symlinks=False)
    mode_ok = stat.S_IMODE(value.st_mode) == 0o700 if private else not value.st_mode & 0o022
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or not mode_ok:
        raise ValueError("owner-controlled continuation directory required")
    return path


def checked_bytes(path, maximum, *, private=True, empty=False):
    """Stable no-follow bounded reads; preflight never opens numeric resources."""
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical owned continuation file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        mode_ok = stat.S_IMODE(before.st_mode) == 0o600 if private else not before.st_mode & 0o022
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not mode_ok or not (0 if empty else 1) <= before.st_size <= maximum):
            raise ValueError("bounded owner-controlled continuation file required")
        body = stream.read(maximum + 1)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(body) != before.st_size or signature(before) != signature(os.fstat(stream.fileno()))
                or signature(before) != signature(path.lstat())):
            raise ValueError("continuation file changed during preflight")
    return body


def pinned_document(path, expected_sha, maximum=8 * 1024 * 1024):
    if type(expected_sha) is not str or SHA.fullmatch(expected_sha) is None:
        raise ValueError("explicit trusted continuation metadata SHA required")
    raw = checked_bytes(path, maximum)
    if hashlib.sha256(raw).hexdigest() != expected_sha: raise ValueError("continuation metadata SHA mismatch")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result: raise ValueError("duplicate continuation metadata field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite continuation metadata")))


def hybrid_code_identity(code, image):
    """The caller pins this canonical inventory SHA, never an auto-adopted hash."""
    if type(image) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise ValueError("explicit immutable HYBRID image ID required")
    code = checked_directory(code, private=False); app = checked_directory(code / "app", private=False)
    entries = list(app.iterdir())
    if len(entries) > 256 or any(path.is_dir() or not re.fullmatch(r"[a-z_][a-z0-9_]*\.py", path.name) for path in entries):
        raise ValueError("flat frozen Python sources only; bytecode or unpinned members refused")
    required = {"__init__.py", "strict_campaign.py", "selection.py", "frozen_evaluation.py", "storage_budget.py"}
    if not required <= {path.name for path in entries}: raise ValueError("complete frozen HYBRID entry points required")
    sources = {path.name: hashlib.sha256(checked_bytes(path, 1024 * 1024, private=False, empty=path.name == "__init__.py")).hexdigest()
               for path in sorted(entries)}
    value = {"image_id": image, "python_sources": sources}
    return value, hashlib.sha256(canonical(value).encode()).hexdigest()


def hybrid_child_identity(value, *, container_id, image, identity_sha):
    if (type(container_id) is not str or SHA.fullmatch(container_id) is None or value.get("Id") != container_id
            or value.get("Image") != image or value.get("Config", {}).get("Labels", {}).get("flare.strict.identity") != identity_sha):
        raise ValueError("exact HYBRID child/image/continuation identity required")


def hybrid_terminal_ready(value, *, container_id, image, identity_sha):
    """A known child handle cannot be replaced after observation failure/timeout."""
    hybrid_child_identity(value, container_id=container_id, image=image, identity_sha=identity_sha)
    state = value.get("State", {})
    if state.get("Status") in ("running", "created"): return False
    if state.get("Status") != "exited" or type(state.get("ExitCode")) is not int or state["ExitCode"] != 0 or state.get("OOMKilled"):
        raise ValueError("HYBRID child failed; preserve exact handle/logs and never automatically restart")
    return True


class HybridPlan:
    """Source-only read-only extension of this continuation's frozen workflow.

    A source checkpoint is not selected-model proof. Even a pinned lifecycle
    checkpoint cannot execute or authorize retirement through this plan builder.
    """
    def __init__(self, dataset, *, dataset_sha, archive_sha, marker_sha, terminal_sha,
                 code, code_sha, workspace, workspace_sha, image,
                 lifecycle_approval=None, lifecycle_approval_sha=None):
        self.dataset = checked_directory(dataset)
        source = checked_directory(self.dataset.parent); run = checked_directory(source.parent)
        if (self.dataset.name != "standard" or source.name != "source" or run.parent != RUNTIME.absolute()
                or SOURCE_ROOT.fullmatch(run.name) is None):
            raise ValueError("exact NEW HYBRID source/standard layout required")
        self.code = checked_directory(code, private=False); self.workspace = checked_directory(workspace, private=False)
        inventory, actual_code_sha = hybrid_code_identity(self.code, image)
        if type(code_sha) is not str or SHA.fullmatch(code_sha) is None or actual_code_sha != code_sha:
            raise ValueError("explicit frozen HYBRID code inventory SHA mismatch")
        self.image = image
        self.lifecycle_approval = lifecycle_approval
        marker = pinned_document(source / "predeclared.private.json", marker_sha, 2 * 1024 * 1024)
        terminal = pinned_document(source / "state.private.json", terminal_sha, 2 * 1024 * 1024)
        if str(ROOT / "ueba-worker") not in sys.path: sys.path.insert(0, str(ROOT / "ueba-worker"))
        from app.archived_catalog import ArchivedShardedDataset
        from app.hybrid_strict_dataset import validate_standard_manifest
        from app.hybrid_strict_protocol import protocol_sha256, source_protocol
        from app.storage_budget import require_headroom
        self.require_headroom = require_headroom
        protocol = marker.get("protocol")
        if (type(protocol) is not dict or protocol != source_protocol(protocol.get("dataset_id"))
                or marker.get("scope") != "FULL_STRICT_SOURCE" or marker.get("protocol_sha256") != protocol_sha256(protocol)
                or type(marker.get("source_identity")) is not dict or not marker["source_identity"]
                or terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE" or terminal.get("stage") != "STRICT_SOURCE"
                or terminal.get("scope") != "FULL_STRICT_SOURCE" or terminal.get("quality_gate") != "NOT_EVALUATED"
                or terminal.get("folds_completed") != [1, 2, 3] or any(type(fold) is not int for fold in terminal["folds_completed"])
                or terminal.get("source_identity_before") != marker["source_identity"]
                or terminal.get("source_identity_after") != marker["source_identity"]
                or any(type(record.get(key)) is not int or record[key] != 0 for record, key in (
                    (marker, "fit_or_score_calls"), (marker, "holdout_numeric_records_read"),
                    (terminal, "fit_or_score_calls"), (terminal, "holdout_numeric_records_read"),
                    (terminal, "downstream_holdout_numeric_records_read")))):
            raise ValueError("pinned completed independent FULL HYBRID source metadata required")
        self.catalog = ArchivedShardedDataset(self.dataset, expected_sha256=dataset_sha, expected_archive_sha256=archive_sha)
        validate_standard_manifest(self.catalog.manifest, protocol["dataset_id"])
        generation = pinned_document(self.dataset / "generation.identity.json", self.catalog.manifest.get("generation_identity_sha256"))
        progress_path = self.dataset / "generation.progress.json"
        progress_sha = hashlib.sha256(checked_bytes(progress_path, 2 * 1024 * 1024)).hexdigest()
        progress = pinned_document(progress_path, progress_sha, 2 * 1024 * 1024)
        if (generation.get("stage") != "STRICT" or generation.get("dataset_id") != protocol["dataset_id"]
                or not self.catalog.manifest.get("source_binding") or generation.get("source_binding") != self.catalog.manifest["source_binding"]
                or generation.get("old_numeric_corpus_read") is not False or generation.get("authentic_capture") is not False
                or progress.get("status") != "COMPLETED" or progress.get("stage") != "STRICT"
                or progress.get("dataset_id") != protocol["dataset_id"] or progress.get("manifest_sha256") != dataset_sha
                or progress.get("published_manifest") is False
                or any(type(record.get("fit_or_score_calls")) is not int or record["fit_or_score_calls"] != 0 for record in (generation, progress))):
            raise ValueError("matching completed fresh standard producer metadata required")
        label_shas = {}
        for fold in (1, 2, 3):
            label_root = checked_directory(source / f"labels-fold{fold}")
            label_path = label_root / "manifest.private.json"
            label_sha = hashlib.sha256(checked_bytes(label_path, 2 * 1024 * 1024)).hexdigest()
            label = pinned_document(label_path, label_sha, 2 * 1024 * 1024)
            if (label.get("scope") != "FULL_STRICT_SOURCE" or label.get("stage") != "STRICT_SOURCE"
                    or label.get("quality_gate") != "NOT_EVALUATED" or type(label.get("fold")) is not int or label["fold"] != fold
                    or label.get("standard_manifest_sha256") != dataset_sha or label.get("standard_fit") != self.catalog.split(f"fold{fold}-fit")
                    or label.get("source_identity_before") != marker["source_identity"]
                    or label.get("source_identity_after") != marker["source_identity"]
                    or any(type(label.get(key)) is not int or label[key] != 0 for key in ("fit_or_score_calls", "holdout_numeric_records_read"))):
                raise ValueError("all three complete matching-fold label metadata bindings required")
            label_shas[str(fold)] = label_sha
        snapshot = pinned_document(self.workspace / "snapshot.json", workspace_sha)
        source_classes = marker["source_identity"].get("java", {}).get("classes")
        compiled_classes = self.catalog.manifest.get("compiled_feature_sha256")
        if (self.catalog.manifest.get("workspace_snapshot_sha256") != workspace_sha
                or type(snapshot.get("classes")) is not dict or not snapshot["classes"] or snapshot["classes"] != source_classes
                or "compiled_feature_sha256" in self.catalog.manifest and snapshot["classes"] != compiled_classes):
            raise ValueError("pinned frozen JVM class inventory differs from source")
        for name, sha in snapshot["classes"].items():
            if (type(name) is not str or Path(name).is_absolute() or ".." in Path(name).parts
                    or not name.endswith(".class") or type(sha) is not str or SHA.fullmatch(sha) is None
                    or hashlib.sha256(checked_bytes(self.workspace / "backend/target/classes/com/flarefitness/backend" / name,
                                                   8 * 1024 * 1024, private=False)).hexdigest() != sha):
                raise ValueError("frozen production JVM class changed")
        if type(snapshot.get("jars")) is not dict or not snapshot["jars"]: raise ValueError("pinned frozen JVM dependencies required")
        for name, sha in snapshot["jars"].items():
            if (type(name) is not str or Path(name).name != name or not name.endswith(".jar")
                    or hashlib.sha256(checked_bytes(self.workspace / "jars" / name, 512 * 1024 * 1024, private=False)).hexdigest() != sha):
                raise ValueError("frozen JVM dependency changed")
        if (lifecycle_approval is None) != (lifecycle_approval_sha is None): raise ValueError("lifecycle checkpoint requires path and trusted SHA together")
        if lifecycle_approval is not None: pinned_document(lifecycle_approval, lifecycle_approval_sha, 2 * 1024 * 1024)
        self.protocol = protocol
        self.java_classes = snapshot["classes"]
        self.identity = {"model_kind": HYBRID_KIND, "dataset_sha256": dataset_sha, "archive_sha256": archive_sha,
                         "dataset_directory": str(self.dataset), "code_directory": str(self.code), "workspace_directory": str(self.workspace),
                         "source_marker_sha256": marker_sha, "source_terminal_sha256": terminal_sha,
                         "code_inventory_sha256": code_sha, "java_snapshot_sha256": workspace_sha,
                         "labeled_manifest_sha256_by_fold": label_shas, **inventory,
                         "continuation_script_sha256": hashlib.sha256(checked_bytes(Path(__file__), 1024 * 1024, private=False)).hexdigest(),
                         "lifecycle_approval_sha256": lifecycle_approval_sha}
        self.identity_sha = hashlib.sha256(canonical(self.identity).encode()).hexdigest()

    @property
    def identity_sha256(self): return self.identity_sha

    def recheck(self):
        current = HybridPlan(self.dataset, dataset_sha=self.identity["dataset_sha256"], archive_sha=self.identity["archive_sha256"],
                             marker_sha=self.identity["source_marker_sha256"], terminal_sha=self.identity["source_terminal_sha256"],
                             code=self.code, code_sha=self.identity["code_inventory_sha256"], workspace=self.workspace,
                             workspace_sha=self.identity["java_snapshot_sha256"], image=self.image,
                             lifecycle_approval=self.lifecycle_approval, lifecycle_approval_sha=self.identity["lifecycle_approval_sha256"])
        if current.identity != self.identity or current.identity_sha256 != self.identity_sha256:
            raise ValueError("frozen HYBRID continuation identity drifted")

    def command(self, stage, unit=1):
        if type(unit) is not int or not 1 <= unit <= 360: raise ValueError("fixed bounded HYBRID unit required")
        commands = {"fit": ["-m", "app.strict_campaign", "search", "--max-new-runs", "1"],
                    "validation": ["-m", "app.selection", "validate", "--max-new-runs", "1"],
                    "ranking": ["-m", "app.selection", "validate"],
                    "recalibration": ["-m", "app.selection", "choose", "--max-new-recalibrations", "1"],
                    "holdout": ["-m", "app.frozen_evaluation"]}
        if stage not in commands: raise ValueError("known HYBRID continuation stage required")
        name = f"flare-hybrid-{stage}-{self.identity_sha[:16]}-{unit:03d}"
        command = ["docker", "run", "-d", "--name", name, "--network", "none", "--user", "1000:1000",
            "--memory", "2g", "--cpus", "2", "--pids-limit", "128", "--entrypoint", "python",
            "--label", "flare.strict.identity=" + self.identity_sha,
            "-v", str(self.code) + ":/code:ro", "-v", str(self.dataset.parent) + ":/source:rw",
            "-v", str(self.workspace) + ":/workspace:ro", "-v", str(self.workspace) + ":" + str(self.workspace) + ":ro",
            "-w", "/code", "-e", "PYTHONPATH=/code", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PYTHONPYCACHEPREFIX=/tmp/ueba-hybrid-bytecode", "-e", "OPENBLAS_NUM_THREADS=1", "-e", "OMP_NUM_THREADS=1",
            self.image, "-B", *commands[stage], "--dataset", "/source/standard", "--model-kind", HYBRID_KIND,
            "--dataset-sha256", self.identity["dataset_sha256"], "--archive-sha256", self.identity["archive_sha256"], "--coordinated"]
        if stage != "fit": command.extend(["--workspace", "/workspace"])
        return command

    def unit_budgets(self):
        # Journals are conservative allowances, not proven future compression or
        # SQLite growth bounds. Admission must check each allocation again.
        hot_journal_allowance = 3 * 1024 ** 3
        budgets = {"fit": 2 * MODEL_PUBLICATION_CAP + 2_000_000 * (37 * 8 + 8) + hot_journal_allowance,
                   "validation": 1_001_000 * (37 * 8 + 8 + 3) + hot_journal_allowance,
                   "recalibration": MODEL_PUBLICATION_CAP + 2_000_000 * (37 * 8 + 8) + hot_journal_allowance,
                   "holdout": 10 * 1024 ** 3 + 2 * 10_010_000 * 4 * 8}
        budgets["ranking"] = 32 * 1024 ** 2
        return budgets

    def preflight(self):
        budgets = self.unit_budgets()
        try:
            headroom = self.require_headroom(self.dataset, budgets["fit"])
            next_unit_admissible = True
        except ValueError:
            headroom = {"planned_bytes": budgets["fit"], "reserve_bytes": RESERVE_BYTES}
            next_unit_admissible = False
        return {"status": "HYBRID_PREFLIGHT_ONLY", "scope": "SOURCE_METADATA_AND_EXECUTION_BINDINGS_ONLY",
                "identity": self.identity, "identity_sha256": self.identity_sha,
                "source_status": "COMPLETE_UNQUALIFIED_SOURCE", "full_source_metadata_admissible": True,
                "selected_model_proof": "NOT_CHECKED_NOT_A_SOURCE_PROOF", "execution_admitted": False,
                "lifecycle_admitted": False, "lifecycle_checkpoint_is_retirement_authority": False,
                "commands": {stage: self.command(stage) for stage in ("fit", "validation", "ranking", "recalibration", "holdout")},
                "schedule": ["360_BOUNDED_FIT_THEN_VALIDATION_PAIRS", "FULL360_RETAINED_RECEIPT_RANKING",
                             "45_TO360_BOUNDED_ZERO_FIT_TOP_RECALIBRATIONS", "QUALIFIED_FROZEN_HOLDOUT_ONLY"],
                "storage": {"reserve_bytes": RESERVE_BYTES, "next_fit_unit_admissible": next_unit_admissible,
                            "next_unit_headroom": headroom, "next_unit_allowance_bytes": budgets,
                            "source_boot_model_class": {"initial_calibration_records": 5000, "publication_cap_bytes": MODEL_PUBLICATION_CAP},
                            "full_calibrated_model_class": {"READY_records": 1_000_000, "COLD_records": 1_000_000,
                                                          "publication_cap_bytes": MODEL_PUBLICATION_CAP},
                            "retained_model_publications_minimum": 765, "retained_model_publications_maximum": 1080,
                            "maximum_model_publication_cap_total_bytes": 1080 * MODEL_PUBLICATION_CAP,
                            "full_campaign_capacity_guaranteed": False, "compression_forecast_is_formal_bound": False},
                "requirements": ["PIN_EXACT_SOURCE_AND_CACHE_RETIREMENT_APPROVALS_BEFORE_ANY_UNLINK",
                    "RELEASE_ALL_STAGE_CONSUMERS_BEFORE_ARCHIVE_RESTORE_OR_RETIRE",
                    "RESTORE_SCORE_AND_DEPENDENT_VECTOR_INTEGRITY_RULE_CACHES_BEFORE_REUSE",
                    "VERIFY_CLOSED_GENERATION_BYTES_AND_ARCHIVE_BEFORE_RE_RETIREMENT",
                    "RECHECK_DECIMAL5GB_RESERVE_BEFORE_EACH_BOUNDED_ALLOCATION_OR_UNIT",
                    "RETAIN_FIT_LABELS_MANIFESTS_MODELS_RECEIPTS_ARCHIVES_AND_FINAL_SCORED_JOURNAL",
                    "REQUIRE_EXACT_SUCCESSFUL_DOCKER_ID_AND_MATCHING_RECEIPT_BEFORE_ADVANCING",
                    "NEVER_RESTART_OR_ADOPT_FAILED_CHILDREN_OR_RECEIPTS",
                    "REQUEST_STORAGE_IF_ACTUAL_RETAINED_BYTES_EXCEED_AVAILABLE_HEADROOM"],
                "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "files_deleted": 0, "aws_changed": False}


def private_receipt(path, maximum=4 * 1024 * 1024):
    if path.is_symlink(): raise ValueError("private regular one-unit receipt required")
    if not path.exists(): return None
    if path.lstat().st_nlink != 1: raise ValueError("single-link one-unit receipt required")
    sha = hashlib.sha256(checked_bytes(path, maximum)).hexdigest()
    value = pinned_document(path, sha, maximum)
    if type(value) is not dict: raise ValueError("one-unit receipt object required")
    return value


def fit_fingerprint(plan):
    value = private_receipt(plan.dataset / "hybrid-campaign.identity.json")
    if value is None: return None
    if not set(FIT_SOURCES) <= set(plan.identity["python_sources"]): raise ValueError("complete frozen HYBRID fitting sources required")
    expected = {name: plan.identity["python_sources"][name] for name in FIT_SOURCES}
    fingerprint = value.get("code_fingerprint", {})
    dependencies = fingerprint.get("dependencies", {})
    if (value.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"] or value.get("model_kind") != HYBRID_KIND
            or value.get("recipe_version") != 1 or value.get("labeled_training_manifest_sha256_by_fold") != plan.identity["labeled_manifest_sha256_by_fold"]
            or fingerprint.get("sources") != expected or set(dependencies) != {"scikit-learn", "numpy", "scipy", "joblib"}
            or any(type(version) is not str or not 1 <= len(version) <= 100 for version in dependencies.values())):
        raise ValueError("retained HYBRID campaign source/code identity changed")
    return fingerprint


def selection_binding(plan, identity, fingerprint):
    if (type(identity) is not dict or fingerprint is None or identity.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
            or identity.get("fit_code_fingerprint") != fingerprint or identity.get("model_kind") != HYBRID_KIND or identity.get("recipe_version") != 1
            or identity.get("selection_sources") != {name: plan.identity["python_sources"].get(name) for name in ("selection.py", "validation.py", "risk_replay.py")}
            or not identity.get("production_classes")
            or any(plan.java_classes.get(name) != sha for group in ("production_classes", "feature_producers")
                   for name, sha in identity.get(group, {}).items())):
        raise ValueError("retained HYBRID selection/code/JVM identity changed")


def hybrid_records(plan):
    """Read only known private terminal metadata; never fit, load pickle, or score."""
    fingerprint = fit_fingerprint(plan)
    fits, validations, recalibrations = {}, {}, {}
    for run in plan.protocol["campaign"]:
        run_id = run["run_id"]; fold = run["fold"]
        fit = private_receipt(plan.dataset / "hybrid-runs" / (run_id + ".json"))
        validation = private_receipt(plan.dataset / "hybrid-validations" / (run_id + ".json"))
        recalibration = private_receipt(plan.dataset / "hybrid-top-recalibrations" / (run_id + ".json"))
        if fit is not None:
            expected = {"status": "FITTED_CALIBRATED", "run_id": run_id, "fold": fold, "config": run["config"],
                "dataset_manifest_sha256": plan.identity["dataset_sha256"], "code_fingerprint": fingerprint,
                "model_kind": HYBRID_KIND, "recipe_version": 1, "recipe_sha256": run["recipe_sha256"],
                "labeled_training_manifest_sha256": plan.identity["labeled_manifest_sha256_by_fold"][str(fold)],
                "normal_fit_split_sha256": plan.catalog.split(f"fold{fold}-fit")["sha256"],
                "fit_split_sha256": plan.catalog.split(f"fold{fold}-fit")["sha256"],
                "training_windows": 50000, "calibration_scope": "STRICT", "quality_gate": "NOT_RUN",
                "actual_composite_trials": 1, "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0}
            if fingerprint is None or any(fit.get(key) != value for key, value in expected.items()):
                raise ValueError("failed/incomplete or changed retained HYBRID fit receipt")
            if any(type(fit.get(key)) is not int for key in ("actual_composite_trials", "actual_component_fit_calls", "additional_fit_calls_in_recalibration")):
                raise ValueError("typed actual HYBRID fit counts required")
            fits[run_id] = fit
        if validation is not None:
            if (fit is None or validation.get("status") != "VALIDATED" or validation.get("evaluation_scope") != "VALIDATION"
                    or validation.get("run_id") != run_id or validation.get("model_sha256") != fit.get("model_sha256")
                    or validation.get("calibration_sha256") != fit.get("calibration_sha256")
                    or validation.get("fold") != fold or validation.get("config") != run["config"]
                    or validation.get("validation_split_sha256") != plan.catalog.split(f"fold{fold}-validation")["sha256"]
                    or validation.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"]
                    or validation.get("model_kind") != HYBRID_KIND or validation.get("recipe_sha256") != run["recipe_sha256"]):
                raise ValueError("failed/incomplete or changed retained HYBRID validation receipt")
            selection_binding(plan, validation.get("selection_identity"), fingerprint)
            validations[run_id] = validation
        if recalibration is not None:
            if (fit is None or recalibration.get("status") == "FAILED" or recalibration.get("run_id") != run_id
                    or type(recalibration.get("additional_fit_calls")) is not int or recalibration["additional_fit_calls"] != 0
                    or recalibration.get("config") != run["config"] or recalibration.get("fold") != fold
                    or recalibration.get("source_model_version") != fit.get("source_model_version")
                    or recalibration.get("source_model_sha256") != fit.get("source_model_sha256")
                    or recalibration.get("model_kind") != HYBRID_KIND or recalibration.get("recipe_sha256") != run["recipe_sha256"]
                    or type(recalibration.get("policy_sha256")) is not str or SHA.fullmatch(recalibration["policy_sha256"]) is None):
                raise ValueError("failed/incomplete or changed retained zero-fit HYBRID recalibration receipt")
            selection_binding(plan, recalibration.get("selection_identity"), fingerprint)
            recalibrations[run_id] = recalibration
    return {"fingerprint": fingerprint, "fits": fits, "validations": validations, "recalibrations": recalibrations,
            "counts": {"actual_fits_completed": len(fits), "validation_runs_completed": len(validations), "completed_recalibrations": len(recalibrations)}}


def hybrid_selected(plan, selected, records):
    if (not selected or selected.get("status") != "SELECTED" or selected.get("model_kind") != HYBRID_KIND
            or selected.get("recipe_version") != 1 or selected.get("dataset_sha256") != plan.identity["dataset_sha256"]
            or any(type(selected.get(key)) is not int or selected[key] != records["counts"][key] for key in COUNT_FIELDS)
            or records["counts"]["actual_fits_completed"] != 360 or records["counts"]["validation_runs_completed"] != 360
            or not 45 <= records["counts"]["completed_recalibrations"] <= 360
            or type(selected.get("additional_fit_calls_in_recalibration")) is not int or selected["additional_fit_calls_in_recalibration"] != 0
            or selected.get("holdout_scored") is not False or not selected.get("model_version")):
        raise ValueError("qualified complete immutable HYBRID selection required; holdout remains closed")
    selection_binding(plan, selected.get("selection_identity"), records["fingerprint"])
    groups = {}
    for receipt in records["recalibrations"].values():
        config = dict(receipt["config"]); seed = config.pop("random_state")
        group = groups.setdefault(canonical(config), {"members": set(), "policies": set()})
        group["members"].add((receipt["fold"], seed)); group["policies"].add(receipt.get("policy_sha256"))
    if (len(records["recalibrations"]) != records["counts"]["completed_recalibrations"] or len(groups) < 3
            or any(len(group["members"]) != 15 or len(group["policies"]) != 1 for group in groups.values())):
        raise ValueError("three whole distinct zero-fit HYBRID configuration proofs required")
    representatives = [receipt for receipt in records["recalibrations"].values() if receipt.get("model_version") == selected["model_version"]]
    if (len(representatives) != 1 or representatives[0].get("fold") != 3 or representatives[0]["config"].get("random_state") != 42
            or any(representatives[0].get(key) != selected.get(key) for key in ("model_sha256", "calibration_sha256", "policy_sha256", "model_state_sha256"))):
        raise ValueError("unchanged fold3/seed42 selected HYBRID representative required")


def require_unblocked_holdout(dataset):
    """Use the shared metadata-only provenance gate before any holdout child."""
    if str(ROOT / "ueba-worker") not in sys.path: sys.path.insert(0, str(ROOT / "ueba-worker"))
    from app.holdout_provenance import require_unblocked_holdout as require
    require(dataset)


def next_hybrid_unit(plan):
    records = hybrid_records(plan)
    for run in plan.protocol["campaign"]:
        run_id = run["run_id"]
        if run_id not in records["fits"]: return {"stage": "fit", "unit_id": run_id, "before": records["counts"]}
        if run_id not in records["validations"]: return {"stage": "validation", "unit_id": run_id, "before": records["counts"]}
    ranking = private_receipt(plan.dataset / "hybrid-ranking.json")
    if ranking is None: return {"stage": "ranking", "unit_id": "FULL360_RANKING", "before": records["counts"]}
    if type(ranking.get("validation_runs_completed")) is not int or ranking["validation_runs_completed"] != 360:
        raise ValueError("full immutable HYBRID ranking required")
    selection_binding(plan, ranking.get("selection_identity"), records["fingerprint"])
    fields = ("max_iter", "max_leaf_nodes", "l2_regularization")
    approved = {canonical({key: run["config"][key] for key in fields}) for run in plan.protocol["campaign"]}
    configurations = ranking.get("configurations", [])
    if (len(configurations) != 24 or {canonical(value.get("configuration", {})) for value in configurations} != approved):
        raise ValueError("all24 distinct approved HYBRID ranking configurations required")
    selected = private_receipt(plan.dataset / "hybrid-selection.json")
    if selected is not None:
        hybrid_selected(plan, selected, records)
        require_unblocked_holdout(plan.dataset)
        if private_receipt(plan.dataset / "hybrid-holdout-result.json") is not None:
            raise ValueError("retained holdout is terminal or incomplete; never reopen automatically")
        if private_receipt(plan.dataset / "hybrid-models" / (selected["model_version"] + ".evaluation.json")) is not None:
            raise ValueError("orphan completed/running evaluation evidence needs diagnosis; never reopen automatically")
        return {"stage": "holdout", "unit_id": selected["model_version"], "before": records["counts"]}
    for configuration in configurations:
        config = configuration["configuration"]
        for run in plan.protocol["campaign"]:
            if any(run["config"][key] != value for key, value in config.items()): continue
            if run["run_id"] not in records["recalibrations"]:
                return {"stage": "recalibration", "unit_id": run["run_id"], "before": records["counts"]}
    raise ValueError("no new approved recalibration remains; incomplete selection needs diagnosis")


def campaign_run_approval(plan, path, sha):
    if Path(path).lstat().st_nlink != 1: raise ValueError("single-link private campaign-run approval required")
    approval = pinned_document(path, sha, 2 * 1024 * 1024)
    if (type(approval) is not dict or set(approval) != ONE_UNIT_APPROVAL_FIELDS
            or type(approval["approval_schema_version"]) is not int or approval["approval_schema_version"] != 1
            or approval["scope"] != "NEW_HYBRID_STRICT_ONE_UNIT_ONLY" or approval["source_standard"] != str(plan.dataset)
            or approval["continuation_identity_sha256"] != plan.identity_sha256
            or approval["stage"] not in ("fit", "validation", "ranking", "recalibration", "holdout")
            or type(approval["unit_id"]) is not str or not 1 <= len(approval["unit_id"]) <= 128
            or approval["execution_approved"] is not True or approval["retirement_approved"] is not False
            or type(approval["user_approval_reference"]) is not str or not 1 <= len(approval["user_approval_reference"]) <= 2000
            or type(approval["expected_before"]) is not dict or set(approval["expected_before"]) != COUNT_FIELDS
            or any(type(count) is not int or not 0 <= count <= 360 for count in approval["expected_before"].values())):
        raise ValueError("exact explicit one-unit campaign-run approval required; no retirement authority")
    return approval


def write_unit_state(path, value):
    checked_directory(path.parent)
    if path.exists() or path.is_symlink(): private_receipt(path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".one-unit-", dir=path.parent)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical(value).encode()); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary_name, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def verify_hybrid_unit_result(plan, unit):
    records = hybrid_records(plan); stage = unit["stage"]; before = unit["before"]
    expected = dict(before)
    counter = {"fit": "actual_fits_completed", "validation": "validation_runs_completed", "recalibration": "completed_recalibrations"}.get(stage)
    if counter is not None: expected[counter] += 1
    if records["counts"] != expected: raise ValueError("one-unit actual receipt counts differ from approved boundary")
    if stage in ("fit", "validation", "recalibration"):
        group = {"fit": "fits", "validation": "validations", "recalibration": "recalibrations"}[stage]
        receipt = records[group].get(unit["unit_id"])
        if receipt is None: raise ValueError("approved exact HYBRID unit has no complete receipt")
        progress_name = {"fit": "hybrid-campaign.progress.json", "validation": "hybrid-validation.progress.json", "recalibration": "hybrid-selection.progress.json"}[stage]
        progress = private_receipt(plan.dataset / progress_name)
        statuses = {"fit": ("STOPPED_AT_RUN_BOUNDARY", "FIT_AND_CALIBRATION_COMPLETE"),
                    "validation": ("STOPPED_AT_VALIDATION_BOUNDARY", "COMPLETED"),
                    "recalibration": ("STOPPED_AT_RECALIBRATION_BOUNDARY", "SELECTED", "NO_QUALIFIED_CONFIG")}[stage]
        if not progress or progress.get("status") not in statuses: raise ValueError("exact complete stopped/terminal stage progress required")
        if progress.get("quality_gate") != "NOT_RUN": raise ValueError("pre-holdout stage cannot claim model quality")
        if stage == "fit":
            if progress.get("dataset_manifest_sha256") != plan.identity["dataset_sha256"] or progress.get("code_fingerprint") != records["fingerprint"]:
                raise ValueError("fit progress source/code binding changed")
        else:
            selection_binding(plan, progress.get("selection_identity"), records["fingerprint"])
        progress_counter = "completed_runs" if stage == "validation" else counter
        if type(progress.get(progress_counter)) is not int or progress[progress_counter] != expected[counter]:
            raise ValueError("stage progress does not prove the approved actual count")
        if progress.get("status", "").startswith("STOPPED_") and progress.get("last_run_id") != unit["unit_id"]:
            raise ValueError("stage stopped at a different approved run")
        if stage != "validation":
            publications = [("model_version", "model_sha256")]
            if stage == "fit": publications.append(("source_model_version", "source_model_sha256"))
            for version_key, sha_key in publications:
                version, sha = receipt.get(version_key), receipt.get(sha_key)
                if (type(version) is not str or re.fullmatch(r"[a-z0-9_-]{8,128}", version) is None
                        or type(sha) is not str or SHA.fullmatch(sha) is None
                        or hashlib.sha256(checked_bytes(plan.dataset / "hybrid-models" / (version + ".joblib"), MODEL_PUBLICATION_CAP)).hexdigest() != sha):
                    raise ValueError("actual newly published HYBRID model bytes changed")
        return {"counts": expected, "unit_receipt_sha256": hashlib.sha256(canonical(receipt).encode()).hexdigest(), "quality_gate": "NOT_RUN"}
    if stage == "ranking":
        next_hybrid_unit(plan)  # Validates the complete ranking without scoring.
        receipt = private_receipt(plan.dataset / "hybrid-ranking.json")
    else:
        selected = private_receipt(plan.dataset / "hybrid-selection.json"); hybrid_selected(plan, selected, records)
        receipt = private_receipt(plan.dataset / "hybrid-holdout-result.json")
        proof = (receipt or {}).get("evaluation_identity", {}).get("hybrid_strict_proof", {})
        if (not receipt or receipt.get("status") != "SUCCEEDED" or receipt.get("evaluation_scope") != "FROZEN_HOLDOUT"
                or type(receipt.get("actual_scored_episodes")) is not int or receipt["actual_scored_episodes"] != 10_010_000
                or receipt.get("dataset_sha256") != plan.identity["dataset_sha256"] or receipt.get("model_version") != unit["unit_id"]
                or receipt.get("quality_gate") not in ("PASS", "FAIL") or proof.get("actual_composite_trials") != 360
                or proof.get("actual_component_fit_calls") != 720 or proof.get("validation_runs") != 360
                or type(proof.get("zero_fit_recalibrations")) is not int or proof["zero_fit_recalibrations"] < 45):
            raise ValueError("complete native HYBRID proof and actual full holdout result required")
    if receipt is None: raise ValueError("complete actual terminal stage receipt required")
    return {"counts": expected, "unit_receipt_sha256": hashlib.sha256(canonical(receipt).encode()).hexdigest(), "quality_gate": receipt.get("quality_gate", "NOT_RUN")}


def execute_hybrid_one_unit(plan, approval_path, approval_sha):
    """Exactly one approved child; no automatic loop, restart, cache or deletion."""
    plan.recheck()
    approval = campaign_run_approval(plan, approval_path, approval_sha)
    ledger = plan.dataset / "hybrid-one-unit"
    if not ledger.exists(): ledger.mkdir(mode=0o700)
    checked_directory(ledger)
    lock_path = ledger / "coordinator.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > 1024 * 1024): raise ValueError("private single-link continuation lock required")
        def verify_lock():
            try: current = lock_path.lstat()
            except OSError: raise ValueError("held continuation lock pathname/inode unavailable") from None
            if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1 or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                    or (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (info.st_dev, info.st_ino)):
                raise ValueError("held continuation lock pathname/inode changed")
        verify_lock()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_lock()
        path = ledger / (approval_sha + ".private.json")
        entries = list(ledger.iterdir())
        if len(entries) > 1083: raise ValueError("bounded one-unit state ledger required")
        for item in entries:
            if item == lock_path or item == path: continue
            if not re.fullmatch(r"[a-f0-9]{64}\.private\.json", item.name): raise ValueError("unknown one-unit ledger member refused")
            prior = private_receipt(item)
            if prior.get("status") != "SUCCEEDED": raise ValueError("another failed/unobserved one-unit handle needs diagnosis; never restart")
        state = private_receipt(path)
        if state is not None:
            if (state.get("identity_sha256") != plan.identity_sha256 or state.get("approval_sha256") != approval_sha
                    or state.get("stage") != approval["stage"] or state.get("unit_id") != approval["unit_id"]
                    or state.get("before") != approval["expected_before"]): raise ValueError("retained one-unit state identity changed")
            if state.get("status") == "FAILED": raise ValueError("failed one-unit handle needs diagnosis, never restart")
            if state.get("status") == "SUCCEEDED": raise ValueError("this approved unit already completed; a new exact boundary approval is required")
            unit = {"stage": state["stage"], "unit_id": state["unit_id"], "before": state["before"]}
            if unit["stage"] == "holdout": require_unblocked_holdout(plan.dataset)
        else:
            unit = next_hybrid_unit(plan)
            if unit != {"stage": approval["stage"], "unit_id": approval["unit_id"], "before": approval["expected_before"]}:
                raise ValueError("approval differs from exact next actual receipt boundary")
            plan.require_headroom(plan.dataset, plan.unit_budgets()[unit["stage"]])
            ordinal = unit["before"].get({"fit": "actual_fits_completed", "validation": "validation_runs_completed", "recalibration": "completed_recalibrations"}.get(unit["stage"]), 0) + 1
            command = plan.command(unit["stage"], ordinal); name = command[command.index("--name") + 1]
            inventory = subprocess.run(["docker", "container", "ls", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"], capture_output=True, text=True, timeout=15)
            if inventory.returncode or inventory.stdout.strip(): raise ValueError("unavailable inventory or unrecorded child; duplicate dispatch refused")
            state = {"status": "DISPATCH_INTENT", "identity_sha256": plan.identity_sha256, "approval_sha256": approval_sha,
                     "stage": unit["stage"], "unit_id": unit["unit_id"], "before": unit["before"], "container_name": name,
                     "container_id": None, "quality_gate": "NOT_RUN", "retirement_authority": False, "aws_changed": False}
            write_unit_state(path, state)  # Durable intent before potentially ambiguous dispatch.
            try:
                verify_lock()
                launched = subprocess.run(command, capture_output=True, text=True, timeout=15)
                if launched.returncode or SHA.fullmatch(launched.stdout.strip()) is None: raise RuntimeError("ambiguous Docker dispatch")
                state.update(status="DISPATCHED", container_id=launched.stdout.strip())
                write_unit_state(path, state)  # Exact Docker ID is durable before any wait.
            except (RuntimeError, subprocess.TimeoutExpired, OSError):
                state.update(status="DISPATCH_UNKNOWN"); write_unit_state(path, state); return state
        while True:
            handle = state.get("container_id") or state["container_name"]
            try:
                observed = subprocess.run(["docker", "inspect", "--type", "container", handle], capture_output=True, text=True, timeout=15)
                if observed.returncode: raise RuntimeError("Docker observation unavailable")
                value = json.loads(observed.stdout)[0]
            except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError, IndexError, TypeError):
                state.update(status="OBSERVATION_UNAVAILABLE"); write_unit_state(path, state); return state
            try:
                verify_lock()
                if not state.get("container_id"):
                    candidate = value.get("Id")
                    hybrid_child_identity(value, container_id=candidate, image=plan.image, identity_sha=plan.identity_sha256)
                    state["container_id"] = candidate; write_unit_state(path, state)
                if not hybrid_terminal_ready(value, container_id=state["container_id"], image=plan.image, identity_sha=plan.identity_sha256):
                    state.update(status="RUNNING"); write_unit_state(path, state); time.sleep(30); continue
                plan.recheck()
                result = verify_hybrid_unit_result(plan, unit)
                if state.get("status") == "SUCCEEDED" and state.get("result") != result: raise ValueError("retained completed unit proof changed")
                state.update(status="SUCCEEDED", result=result, quality_gate=result["quality_gate"])
                write_unit_state(path, state)
                return state
            except ValueError as failure:
                state.update(status="FAILED", failure_type=type(failure).__name__, failure_reason=str(failure))
                write_unit_state(path, state)
                raise
    finally:
        os.close(descriptor)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bounded regular pipeline metadata required")
    return json.loads(path.read_text())


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, allow_nan=False)); temporary.chmod(0o600)
    temporary.replace(path)


def fit_ready(state, progress, identity):
    if state["Status"] == "running": return False
    if state["Status"] != "exited" or state["ExitCode"] != 0 or state.get("OOMKilled"):
        raise ValueError("fit container did not finish successfully; no automatic restart")
    if (progress.get("status") != "FIT_AND_CALIBRATION_COMPLETE" or progress.get("actual_fits_completed") != 360
            or progress.get("required_fits") != 360 or progress.get("quality_gate") != "NOT_RUN"
            or any(progress.get(key) != identity[key] for key in ("dataset_manifest_sha256", "code_fingerprint"))):
        raise ValueError("terminal fit container has no matching complete 360-fit receipt")
    return True


def may_open_holdout(selection, dataset_sha):
    if (selection.get("status") != "SELECTED" or selection.get("actual_fits_completed") != 360
            or selection.get("validation_runs_completed") != 360 or selection.get("completed_recalibrations", 0) < 45
            or selection.get("additional_fit_calls_in_recalibration") != 0 or selection.get("dataset_sha256") != dataset_sha
            or selection.get("holdout_scored") is not False):
        return False
    return True


class Runner:
    def __init__(self, dataset, fit_id, image=DEFAULT_IMAGE):
        self.dataset = dataset.resolve(strict=True)
        if self.dataset.parent != (ROOT / "observability/runtime/ueba-experiments").resolve() or dataset.is_symlink():
            raise ValueError("existing owned local experiment directory required")
        if not re.fullmatch(r"[a-z0-9_-]{8,64}", self.dataset.name) or not re.fullmatch(r"[a-f0-9]{64}", fit_id):
            raise ValueError("exact experiment and fit container identities required")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image): raise ValueError("immutable local benchmark image ID required")
        self.fit_id, self.image = fit_id, image
        self.code = self.dataset / "training-code-snapshot"
        self.workspace = self.dataset / "frozen-exporter"
        self.fit_identity = read(self.dataset / "strict-campaign.identity.json")
        manifest = read(self.dataset / "manifest.json")
        if manifest.get("stage") != "STRICT" or digest(self.dataset / "manifest.json") != self.fit_identity["dataset_manifest_sha256"]:
            raise ValueError("frozen strict dataset identity mismatch")
        for name, sha in self.fit_identity["code_fingerprint"]["sources"].items():
            if digest(self.code / "app" / name) != sha: raise ValueError("frozen fitting source changed")
        snapshot = read(self.workspace / "snapshot.json")
        if snapshot["classes"] != manifest["compiled_feature_sha256"]: raise ValueError("frozen production class manifest mismatch")
        for name, sha in snapshot["classes"].items():
            if digest(self.workspace / "backend/target/classes/com/flarefitness/backend" / name) != sha:
                raise ValueError("frozen production feature/decision binary changed")
        for name, sha in snapshot["jars"].items():
            if Path(name).name != name or digest(self.workspace / "jars" / name) != sha: raise ValueError("frozen JVM dependency changed")
        self.identity = {"fit_container_id": fit_id, "image_id": image, "dataset_sha256": self.fit_identity["dataset_manifest_sha256"],
                         "java_snapshot_sha256": digest(self.workspace / "snapshot.json"),
                         "python_sources": {path.name: digest(path) for path in sorted((self.code / "app").glob("*.py"))}}
        self.identity_sha = hashlib.sha256(json.dumps(self.identity, sort_keys=True).encode()).hexdigest()
        self.file = self.dataset / "strict-pipeline.progress.json"
        self.state = {"status": "RUNNING", "stage": "WAITING_FIT", "identity": self.identity, "identity_sha256": self.identity_sha,
                      "operator_process_pid": os.getpid(), "containers": {}, "quality_gate": "NOT_RUN", "aws_primary_changed": False}

    def docker(self, *args):
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=15)
        if result.returncode: raise RuntimeError("Docker observation/dispatch failed; do not infer container termination")
        return result.stdout.strip()

    def inspect(self, container): return json.loads(self.docker("inspect", container))[0]

    def update(self, **values):
        self.state.update(values, updated_at_utc=datetime.now(timezone.utc).isoformat())
        write(self.file, self.state)

    def observe(self, container):
        # A transient observation failure preserves the same handle. It never
        # authorizes a second container or silently treats the first as dead.
        while True:
            try: return self.inspect(container)
            except (RuntimeError, subprocess.TimeoutExpired):
                self.update(observation_error="DOCKER_OBSERVATION_UNAVAILABLE", observed_container_id=container)
                time.sleep(30)

    def wait_fitting(self):
        while True:
            value = self.observe(self.fit_id)
            if value["Image"] != self.image: raise ValueError("live fitting image differs from pinned benchmark")
            progress = read(self.dataset / "strict-campaign.progress.json")
            self.update(stage="WAITING_FIT", fit_status=value["State"]["Status"], actual_fits_completed=progress.get("actual_fits_completed"))
            if fit_ready(value["State"], progress, self.fit_identity): return
            time.sleep(45)

    def stage(self, name):
        if name == "holdout": require_unblocked_holdout(self.dataset)
        container_name = "flare-strict-" + name + "-" + self.dataset.name[-24:]
        self.update(stage=name.upper())
        existing = subprocess.run(["docker", "container", "ls", "-a", "--filter", "name=^/" + container_name + "$", "--format", "{{.ID}}"],
                                  capture_output=True, text=True, timeout=15)
        if existing.returncode: raise RuntimeError("Docker inventory unavailable; do not create a duplicate stage")
        if existing.stdout.strip():
            value = self.observe(existing.stdout.strip())
            if value["Image"] != self.image or value["Config"].get("Labels", {}).get("flare.strict.identity") != self.identity_sha:
                raise ValueError("existing stage container has a different frozen identity")
            container_id = value["Id"]
        else:
            mounts = ["-v", str(self.code) + ":/code:ro", "-v", str(self.dataset) + ":/experiment:rw",
                      "-v", str(self.workspace) + ":/workspace:ro", "-v", str(self.workspace) + ":" + str(self.workspace) + ":ro"]
            container_id = self.docker("run", "-d", "--name", container_name, "--network", "none", "--user", "1000:1000",
                  "--memory", "1g", "--cpus", "1", "--pids-limit", "128", "--label", "flare.strict.identity=" + self.identity_sha,
                  *mounts, "-w", "/code", "-e", "PYTHONPATH=/code", "-e", "OPENBLAS_NUM_THREADS=1", "-e", "OMP_NUM_THREADS=1",
                  self.image, *STAGES[name], "--dataset", "/experiment", "--workspace", "/workspace")
        self.state["containers"][name] = container_id
        self.update(stage=name.upper(), observed_container_id=container_id)
        while True:
            value = self.observe(container_id)
            self.update(container_status=value["State"]["Status"], observed_container_id=container_id)
            if value["State"]["Status"] == "exited":
                if value["State"]["ExitCode"] != 0 or value["State"].get("OOMKilled"):
                    raise ValueError("stage failed; retain exact container/logs and do not automatically restart")
                return
            if value["State"]["Status"] not in ("running", "created"): raise ValueError("stage is no longer eligible")
            time.sleep(45)

    def run(self):
        lock = (self.dataset / "strict-pipeline.lock").open("a"); os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.file.exists():
                previous = read(self.file)
                if previous.get("identity") != self.identity: raise ValueError("pipeline identity changed")
                self.state["containers"] = previous.get("containers", {})
            self.update(); self.wait_fitting(); self.stage("validation"); self.stage("selection")
            selected = read(self.dataset / "strict-selection.json")
            if not may_open_holdout(selected, self.identity["dataset_sha256"]):
                self.update(status="NO_QUALIFIED_SELECTION", quality_gate="NOT_RUN", holdout_started=False); return
            self.stage("holdout")
            result = read(self.dataset / "strict-holdout-result.json")
            if result.get("status") != "SUCCEEDED" or result.get("actual_scored_episodes") != 10010000:
                raise ValueError("holdout container has no complete actual-scoring result")
            self.update(status="BENCHMARK_COMPLETE", quality_gate=result["quality_gate"], model_version=result["model_version"],
                        holdout_started=True, data_provenance="DEMO_ONLY", aws_primary_changed=False)
        except Exception as failure:
            self.update(status="FAILED", failure_type=type(failure).__name__, failure_reason=str(failure)); raise
        finally: lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--fit-container-id")
    parser.add_argument("--mode", choices=("legacy", "hybrid-source"), default="legacy")
    parser.add_argument("--preflight", "--dry-run", dest="preflight", action="store_true")
    parser.add_argument("--execute-one-unit", action="store_true")
    parser.add_argument("--campaign-run-approval", type=Path); parser.add_argument("--campaign-run-approval-sha256")
    parser.add_argument("--dataset-sha256"); parser.add_argument("--archive-sha256")
    parser.add_argument("--source-marker-sha256"); parser.add_argument("--source-terminal-sha256")
    parser.add_argument("--code", type=Path); parser.add_argument("--code-sha256")
    parser.add_argument("--workspace", type=Path); parser.add_argument("--workspace-sha256")
    parser.add_argument("--image-id")
    parser.add_argument("--lifecycle-approval", type=Path); parser.add_argument("--lifecycle-approval-sha256")
    args = parser.parse_args()
    if args.mode == "hybrid-source":
        if not args.preflight and not args.execute_one_unit: parser.error("HYBRID execution blocked: use --preflight or an explicitly approved --execute-one-unit")
        if args.preflight and args.execute_one_unit: parser.error("preflight and one-unit execution are separate requests")
        if args.execute_one_unit and (args.campaign_run_approval is None or args.campaign_run_approval_sha256 is None):
            parser.error("one-unit execution requires an explicit private campaign-run approval and trusted SHA")
        if not args.execute_one_unit and (args.campaign_run_approval is not None or args.campaign_run_approval_sha256 is not None):
            parser.error("campaign-run approval is only consumed by --execute-one-unit")
        if args.fit_container_id is not None: parser.error("HYBRID source preflight does not adopt a legacy fit container")
        required = ("dataset_sha256", "archive_sha256", "source_marker_sha256", "source_terminal_sha256",
                    "code", "code_sha256", "workspace", "workspace_sha256", "image_id")
        if any(getattr(args, name) is None for name in required): parser.error("explicit HYBRID source/archive/code/JVM/image checkpoints required")
        plan = HybridPlan(args.dataset, dataset_sha=args.dataset_sha256, archive_sha=args.archive_sha256,
                          marker_sha=args.source_marker_sha256, terminal_sha=args.source_terminal_sha256,
                          code=args.code, code_sha=args.code_sha256, workspace=args.workspace,
                          workspace_sha=args.workspace_sha256, image=args.image_id,
                          lifecycle_approval=args.lifecycle_approval, lifecycle_approval_sha=args.lifecycle_approval_sha256)
        result = (execute_hybrid_one_unit(plan, args.campaign_run_approval, args.campaign_run_approval_sha256)
                  if args.execute_one_unit else plan.preflight())
        print(canonical(result))
        return
    if args.preflight or args.execute_one_unit or any(getattr(args, name) is not None for name in (
            "dataset_sha256", "archive_sha256", "source_marker_sha256", "source_terminal_sha256", "code", "code_sha256",
            "workspace", "workspace_sha256", "image_id", "lifecycle_approval", "lifecycle_approval_sha256",
            "campaign_run_approval", "campaign_run_approval_sha256")):
        parser.error("HYBRID checkpoint/preflight options require --mode hybrid-source")
    if args.fit_container_id is None: parser.error("--fit-container-id is required for the legacy continuation")
    Runner(args.dataset, args.fit_container_id).run()


if __name__ == "__main__": main()
