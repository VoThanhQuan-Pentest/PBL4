#!/usr/bin/env python3
"""Prepare/verify exact NEW strict-source retirement metadata, never retire.

Only manifest, archive-sidecar, producer/label and committed-batch metadata is
read. Original/XZ/label payloads remain unopened. No job or deletion path exists.
Production preparation runs inside a pinned, explicitly labelled metadata-only
Docker observer; actual inventory is checked while all five source locks hold.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("strict_lifecycle_retirement", ROOT / "observability/scripts/retire-ueba-strict-source-shards.py")
R = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(R)
S = R.S
C = R.C
from app.pipeline_lock import coordinated_stage

MAX_CONTAINERS = 1024
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
OBSERVER_LABEL = "flare.strict.lifecycle-observer"


def docker_json(arguments):
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=30)
    if result.returncode or not result.stdout or len(result.stdout.encode()) > MAX_INVENTORY_BYTES:
        raise ValueError("bounded actual Docker inventory unavailable")
    return S.parse_json(result.stdout.encode())


def source_reference(value, source):
    """A bind exposing an ancestor/descendant of this exact source is relevant."""
    if type(value) is not str or not value.startswith("/"): return False
    path = Path(value)
    if ".." in path.parts: raise ValueError("noncanonical Docker source reference refused")
    try: path = path.resolve()
    except (OSError, RuntimeError):
        raise ValueError("canonical actual Docker source reference unavailable") from None
    return path.is_relative_to(source.parent) or source.parent.is_relative_to(path)


def actual_consumers(source, identity_sha, image, observer_container_id):
    """No caller-supplied consumer list or silent failed inspection is accepted."""
    if (type(observer_container_id) is not str or S.SHA.fullmatch(observer_container_id) is None
            or image != R.IMAGE or os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != image
            or not Path("/.dockerenv").is_file()):
        raise ValueError("explicit pinned metadata-only Docker observer required")
    shim_sha = os.environ.get("UEBA_LIFECYCLE_DOCKER_SHIM_SHA256")
    proxy_sha = os.environ.get("UEBA_LIFECYCLE_DOCKER_PROXY_SHA256")
    shim = shutil.which("docker")
    if (any(type(value) is not str or S.SHA.fullmatch(value) is None for value in (shim_sha, proxy_sha))
            or os.environ.get("UEBA_LIFECYCLE_DOCKER_SOURCE_SHA256") != S.sha256(str(source).encode())
            or shim is None or S.sha256(C.checked_bytes(shim, 1024 * 1024, private=False)) != shim_sha):
        raise ValueError("exact pinned source-bound metadata-only Docker shim/proxy required")
    result = subprocess.run(["docker", "container", "ls", "--all", "--quiet", "--no-trunc"],
                            capture_output=True, text=True, timeout=30)
    if result.returncode or len(result.stdout.encode()) > MAX_CONTAINERS * 65:
        raise ValueError("actual Docker container inventory unavailable")
    ids = result.stdout.splitlines()
    if (not 1 <= len(ids) <= MAX_CONTAINERS or len(set(ids)) != len(ids)
            or any(S.SHA.fullmatch(value) is None for value in ids) or observer_container_id not in ids):
        raise ValueError("exact bounded Docker inventory including observer required")
    consumers = []; observer_seen = False
    for identifier in ids:
        values = docker_json(["inspect", "--type", "container", identifier])
        if type(values) is not list or len(values) != 1 or type(values[0]) is not dict:
            raise ValueError("exact inspected Docker container required")
        value = values[0]; state = value.get("State"); config = value.get("Config"); mounts = value.get("Mounts")
        if (value.get("Id") != identifier or type(state) is not dict or type(config) is not dict
                or type(mounts) is not list or type(state.get("Running")) is not bool
                or state.get("Status") not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
                or type(config.get("Labels")) not in (dict, type(None))):
            raise ValueError("complete exact Docker runtime metadata required")
        active = state["Running"] or state["Status"] not in {"exited", "dead"}
        labels = config.get("Labels") or {}
        if identifier == observer_container_id:
            if (value.get("Image") != image or state["Status"] != "running" or state["Running"] is not True
                    or labels.get(OBSERVER_LABEL) != "metadata-only"
                    or config.get("Hostname") != identifier[:12] or os.uname().nodename != identifier[:12]):
                raise ValueError("actual self observer identity/image/metadata-only label mismatch")
            observer_seen = True
            continue
        relevant = labels.get("flare.strict.identity") == identity_sha
        for mount in mounts:
            if type(mount) is not dict or type(mount.get("Source")) is not str:
                raise ValueError("complete actual Docker mount inventory required")
            relevant = relevant or source_reference(mount["Source"], source)
        for key in ("Cmd", "Entrypoint", "Env"):
            arguments = config.get(key)
            if arguments is not None and (type(arguments) is not list or any(type(item) is not str for item in arguments)):
                raise ValueError("complete actual Docker command inventory required")
            relevant = relevant or any(str(source.parent) in item or str(source) in item for item in arguments or [])
        if active and relevant: consumers.append(identifier)
    if not observer_seen: raise ValueError("actual metadata-only observer absent")
    return sorted(consumers)


def stage_lock_check(descriptor, path):
    held = os.fstat(descriptor); identity = (held.st_dev, held.st_ino)
    def check():
        try:
            for value in (os.fstat(descriptor), path.lstat()):
                if (not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600
                        or value.st_uid != os.geteuid() or value.st_nlink != 1
                        or not 0 <= value.st_size <= S.MAX_METADATA or (value.st_dev, value.st_ino) != identity
                        or any(part.is_symlink() for part in (path, *path.parents))):
                    raise ValueError("unchanged private single-link held stage lock required")
        except OSError:
            raise ValueError("unchanged private single-link held stage lock required") from None
    check()
    return check


def alias_signature(path):
    """Stat only: checks plain originals without opening their numeric bytes."""
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("plain original alias symlinks refused")
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_uid != os.geteuid() or not 0 < value.st_size <= S.MAX_SHARD_BYTES):
        raise ValueError("private plain original alias required")
    return S._signature(value)


def target_batch(descriptors, start=0, count=None):
    """Select an explicit stable range of manifest-declared non-FIT targets.

    Selection never depends on which files happen to be missing. Each batch
    receives its own exact approval/checkpoint; the retirement tool still
    checks all metadata in that transaction before every alias deletion.
    """
    eligible = sorted(path for path, (split, _) in descriptors.items() if not split.endswith("-fit"))
    if (type(start) is not int or start < 0 or start >= len(eligible)
            or count is None and start != 0
            or count is not None and (type(count) is not int or not 1 <= count <= 256)):
        raise ValueError("explicit bounded non-FIT manifest target range required")
    return set(eligible if count is None else eligible[start:start + count])


def build_targets(plan, source_pins, *, target_start=0, target_count=None):
    dataset = plan.catalog; source = plan.dataset; snapshots = {}; aliases = {}
    def record(path, sha, maximum=S.MAX_METADATA):
        if type(sha) is not str or S.SHA.fullmatch(sha) is None:
            raise ValueError("explicit archive-bound metadata SHA required")
        value, snapshot = S.metadata(path, maximum, sha); snapshots[path] = (snapshot, maximum); return value
    for path, key, maximum in ((source / "manifest.json", "dataset_manifest_sha256", S.MAX_MANIFEST_BYTES),
            (source / "verification/manifest.json", "dataset_manifest_sha256", S.MAX_MANIFEST_BYTES),
            (source / S.SIDECAR, "archive_sidecar_sha256", S.MAX_MANIFEST_BYTES),
            (source.parent / "predeclared.private.json", "source_marker_sha256", S.MAX_METADATA),
            (source.parent / "state.private.json", "source_terminal_sha256", S.MAX_METADATA)):
        record(path, source_pins[key], maximum)
    result = record(source / S.RESULT, source_pins["archive_result_sha256"])
    expected = {"status": "COMPLETED", "scope": "STORAGE_ONLY", **{key: source_pins[key] for key in R.SOURCE_PINS if key != "archive_result_sha256"},
        "original_files_deleted_or_renamed": 0, "numeric_rows_parsed": 0, "holdout_numeric_records_read": 0, "fit_calls": 0, "score_calls": 0,
        "original_manifest_bytes_unchanged": True, "original_hardlink_topology_unchanged": True}
    if (type(result) is not dict or any(result.get(key) != value for key, value in expected.items())
            or any(type(result.get(key)) is not int for key in ("original_files_deleted_or_renamed", "numeric_rows_parsed", "holdout_numeric_records_read", "fit_calls", "score_calls"))
            or any(type(result.get(key)) is not bool for key in ("original_manifest_bytes_unchanged", "original_hardlink_topology_unchanged"))):
        raise ValueError("exact completed opaque archive result required")
    generation = record(source / "generation.identity.json", result.get("source_generation_identity_sha256"))
    progress = record(source / "generation.progress.json", result.get("source_generation_progress_sha256"))
    if (result.get("source_generation_identity_sha256") != dataset.manifest.get("generation_identity_sha256")
            or generation.get("source_binding") != dataset.manifest.get("source_binding")
            or progress.get("manifest_sha256") != source_pins["dataset_manifest_sha256"]):
        raise ValueError("completed archive producer metadata differs from exact manifest")
    descriptors = {item["path"]: (split, item) for split, value in dataset.manifest["splits"].items() for item in value["shards"]}
    if not 1 <= len(descriptors) <= S.MAX_SHARDS: raise ValueError("bounded complete declared source descriptors required")
    selected = target_batch(descriptors, target_start, target_count)
    targets = []
    for projection, (split, descriptor) in sorted(descriptors.items()):
        # FIT is always retained and checked. Nonselected non-FIT aliases may
        # belong to a separately approved earlier batch; they are not adopted,
        # skipped based on absence, deleted, or claimed intact by this batch.
        if not split.endswith("-fit") and projection not in selected:
            continue
        entry = dataset._archive_entries[projection]
        identifier = descriptor["id"]
        # Non-FIT identifiers use the exact existing retirement role grammar.
        if split.endswith("-fit"):
            match = R.SHARD_ID.fullmatch(identifier.replace("-fit-", "-validation-", 1))
        else:
            match = R.SHARD_ID.fullmatch(identifier)
        if match is None: raise ValueError("exact committed source alias descriptor required")
        group = {"projection": projection, "batch_alias": f"batches/{match['batch']}/{identifier}.json",
                 "verification_alias": f"verification/shards/{identifier}.json", "sha256": descriptor["sha256"], "bytes": entry["original_bytes"]}
        signatures = [alias_signature(source / group[key]) for key in ("projection", "batch_alias", "verification_alias")]
        if (any(value != signatures[0] for value in signatures) or signatures[0][2] != group["bytes"]
                or signatures[0][-1] < 3 or not split.endswith("-fit") and signatures[0][-1] != 3):
            raise ValueError("exact intact original three-alias group required")
        aliases.update({source / group[key]: signature for key, signature in zip(("projection", "batch_alias", "verification_alias"), signatures)})
        if not split.endswith("-fit"):
            _, _, _, receipt_snapshot = R.group_binding(source, group, dataset, descriptors)
            snapshots[receipt_snapshot[0]] = (receipt_snapshot[1], S.MAX_METADATA)
            targets.append(group)
    if not targets: raise ValueError("explicit complete non-FIT target set required")
    return targets, snapshots, aliases


def fresh_destination(path, source):
    path = Path(path).absolute(); C.checked_directory(path.parent)
    if (".." in path.parts or path.exists() or path.is_symlink() or path.is_relative_to(source)
            or any(path.is_relative_to(source.parent / f"labels-fold{fold}") for fold in (1, 2, 3))):
        raise ValueError("fresh separate private metadata destination required")
    return path


def prepare(*, dataset, dataset_sha, archive_sha, archive_result_sha, marker_sha, terminal_sha,
            code, code_sha, workspace, workspace_sha, image, user_approval_reference, observer_container_id,
            observer_code_sha, approval_path, checkpoint_path, write=False, approval_sha=None, checkpoint_sha=None,
            target_start=0, target_count=None):
    """Default verifies only; write=True creates two fresh metadata artifacts."""
    if (type(write) is not bool or image != R.IMAGE or type(user_approval_reference) is not str
            or not 1 <= len(user_approval_reference) <= 2000 or not user_approval_reference.strip()
            or type(archive_result_sha) is not str or S.SHA.fullmatch(archive_result_sha) is None):
        raise ValueError("explicit pinned NEW source metadata preparation inputs required")
    def check_observer_code():
        if (type(observer_code_sha) is not str or S.SHA.fullmatch(observer_code_sha) is None
                or S.sha256(C.checked_bytes(__file__, 1024 * 1024, private=False)) != observer_code_sha):
            raise ValueError("exact pinned lifecycle observer code required")
    check_observer_code()
    source = S.source_path(dataset)
    pins = dict(zip(R.SOURCE_PINS, (dataset_sha, archive_sha, archive_result_sha, marker_sha, terminal_sha)))
    if any(type(value) is not str or S.SHA.fullmatch(value) is None for value in pins.values()):
        raise ValueError("all five trusted source metadata SHA pins required")
    if write and (approval_sha is not None or checkpoint_sha is not None):
        raise ValueError("fresh prepare never adopts existing approval/checkpoint pins")
    if not write and ((approval_sha is None) != (checkpoint_sha is None)):
        raise ValueError("existing approval and checkpoint require both trusted hashes")
    with ExitStack() as stack:
        lock_checks = [S.lock_existing(stack, path) for path in R.lock_paths(source)[:2]]
        for stage in ("campaign", "selection", "evaluation"):
            descriptor = stack.enter_context(coordinated_stage(source, stage, enabled=True))
            lock_checks.append(stage_lock_check(descriptor, source.parent / (stage + ".lock")))
        plan = C.HybridPlan(source, dataset_sha=dataset_sha, archive_sha=archive_sha, marker_sha=marker_sha, terminal_sha=terminal_sha,
            code=code, code_sha=code_sha, workspace=workspace, workspace_sha=workspace_sha, image=image)
        targets, snapshots, aliases = build_targets(plan, pins, target_start=target_start, target_count=target_count)
        approval = {"approval_schema_version": 1, "scope": "NEW_STRICT_SOURCE_SHARDS_ONLY", "source_standard": str(source),
            **pins, "targets": targets, "retirement_approved": True, "user_approval_reference": user_approval_reference}
        approval_raw = S.canonical(approval).encode(); expected_approval_sha = S.sha256(approval_raw)
        if len(approval_raw) > R.MAX_APPROVAL_BYTES: raise ValueError("bounded retirement approval required")
        commands = {name: plan.command(stage) for name, stage in (("campaign", "fit"), ("selection", "validation"), ("evaluation", "holdout"))}
        checkpoint = {"checkpoint_schema_version": 1, "scope": "NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR", "status": "QUIESCENT",
            "source_standard": str(source), "retirement_approval_sha256": expected_approval_sha, **pins,
            "continuation_identity_sha256": plan.identity_sha256, "identity": plan.identity, "commands": commands,
            "lock_paths": [str(path) for path in R.lock_paths(source)], "active_consumers": None,
            "code_sha256": {name: S.sha256(C.checked_bytes(R.ROOT / name, 1024 * 1024, private=False)) for name in R.CODE_FILES}}
        def recheck():
            check_observer_code()
            for check in lock_checks: check()
            plan.recheck(); R.unchanged(snapshots)
            if any(alias_signature(path) != value for path, value in aliases.items()):
                raise ValueError("original aliases changed during metadata preparation")
            consumers = actual_consumers(source, plan.identity_sha256, image, observer_container_id)
            if consumers: raise ValueError("active Docker consumer references exact NEW source")
            for check in lock_checks: check()
            return consumers
        checkpoint["active_consumers"] = recheck()
        checkpoint_raw = S.canonical(checkpoint).encode(); expected_checkpoint_sha = S.sha256(checkpoint_raw)
        if len(checkpoint_raw) > S.MAX_METADATA: raise ValueError("bounded coordinator checkpoint required")
        if write:
            approval_path = fresh_destination(approval_path, source); checkpoint_path = fresh_destination(checkpoint_path, source)
            if approval_path == checkpoint_path: raise ValueError("separate approval and checkpoint destinations required")
            S.write_new(approval_path, approval_raw)
            R.load_approval(approval_path, expected_approval_sha)
            recheck()
            S.write_new(checkpoint_path, checkpoint_raw)
        elif approval_sha is None:
            return {"status": "VERIFIED_METADATA_ONLY", "source_standard": str(source), "targets": len(targets),
                "original_aliases": 3 * len(targets), "continuation_identity_sha256": plan.identity_sha256,
                "approval_sha256": expected_approval_sha, "checkpoint_sha256": expected_checkpoint_sha,
                "observer_code_sha256": observer_code_sha,
                "metadata_artifacts_written": 0, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0,
                "files_deleted": 0, "execution_started": False, "aws_changed": False}
        else:
            approval_path = Path(approval_path).absolute(); checkpoint_path = Path(checkpoint_path).absolute()
            if approval_sha != expected_approval_sha or checkpoint_sha != expected_checkpoint_sha:
                raise ValueError("existing exact lifecycle metadata differs from recomputed pins/targets/commands")
            if R.load_approval(approval_path, approval_sha) != approval:
                raise ValueError("existing source approval differs from exact complete targets")
        checkpoint_snapshot, check_code = R.coordinator_admission(source, approval, expected_approval_sha, checkpoint_path,
            expected_checkpoint_sha, lock_checks=lock_checks)
        snapshots[checkpoint_snapshot[0]] = (checkpoint_snapshot[1], S.MAX_METADATA)
        snapshots[approval_path] = (S.metadata(approval_path, R.MAX_APPROVAL_BYTES, expected_approval_sha)[1], R.MAX_APPROVAL_BYTES)
        recheck(); check_code(); R.unchanged(snapshots)
        return {"status": "PREPARED_METADATA_ONLY" if write else "VERIFIED_LIFECYCLE_METADATA_ONLY",
            "source_standard": str(source), "targets": len(targets), "original_aliases": 3 * len(targets),
            "approval_path": str(approval_path), "approval_sha256": expected_approval_sha,
            "checkpoint_path": str(checkpoint_path), "checkpoint_sha256": expected_checkpoint_sha,
            "continuation_identity_sha256": plan.identity_sha256, "metadata_artifacts_written": 2 if write else 0,
            "observer_code_sha256": observer_code_sha,
            "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "files_deleted": 0,
            "execution_started": False, "aws_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("dataset", "code", "workspace", "approval-path", "checkpoint-path"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("dataset-sha256", "archive-sha256", "archive-result-sha256", "source-marker-sha256", "source-terminal-sha256",
                 "code-sha256", "workspace-sha256", "image-id", "user-approval-reference", "observer-container-id", "observer-code-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--prepare", action="store_true", help="Create fresh private metadata only; never retire or dispatch")
    parser.add_argument("--approval-sha256"); parser.add_argument("--checkpoint-sha256")
    parser.add_argument("--target-start", type=int, default=0, help="Zero-based index in sorted non-FIT manifest projections")
    parser.add_argument("--target-count", type=int, help="Explicit batch size 1..256; omitted means the unchanged complete target set")
    args = parser.parse_args()
    try:
        result = prepare(dataset=args.dataset, dataset_sha=args.dataset_sha256, archive_sha=args.archive_sha256,
            archive_result_sha=args.archive_result_sha256, marker_sha=args.source_marker_sha256, terminal_sha=args.source_terminal_sha256,
            code=args.code, code_sha=args.code_sha256, workspace=args.workspace, workspace_sha=args.workspace_sha256,
            image=args.image_id, user_approval_reference=args.user_approval_reference, observer_container_id=args.observer_container_id,
            observer_code_sha=args.observer_code_sha256,
            approval_path=args.approval_path, checkpoint_path=args.checkpoint_path, write=args.prepare,
            approval_sha=args.approval_sha256, checkpoint_sha=args.checkpoint_sha256,
            target_start=args.target_start, target_count=args.target_count)
        print(S.canonical(result))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise SystemExit("NEW strict lifecycle metadata refused; no payload read, deletion or dispatch; any partial NEW metadata retained") from None


if __name__ == "__main__":
    main()
