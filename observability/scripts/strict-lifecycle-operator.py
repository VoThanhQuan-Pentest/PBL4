#!/usr/bin/env python3
"""Record one already completed strict-source retirement batch.

The retirement worker performs the source operations. This host-side tool
rechecks the same approval/checkpoint through the restricted observer before
advancing the private resume cursor. It never deletes source files itself.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime"
STATE = RUNTIME / "private-backups/hybrid-source-batches-20261011-LttE0nBT/lifecycle-resume.private.json"
OUT = STATE.parent
SOURCE = RUNTIME / "hybrid-strict-source-20261004-pdSIQYiW/source/standard"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
RESERVE = 5_000_000_000
SHA = re.compile(r"[a-f0-9]{64}")
BATCH = re.compile(r"batch_([0-9]{4})")
STATE_KEYS = {
    "schema_version", "scope", "source_standard", "campaign_bindings_file",
    "observer_container_id", "proxy_socket_directory", "observer_code_sha256",
    "retirement_code_sha256", "archive_result_sha256", "image_id", "scratch_directory",
    "required_non_fit_manifest_targets", "next_target_start", "fit_source_retained",
    "archives_models_labels_metadata_retained", "old_holdout_acceptance_allowed",
    "unit_025_approval_prepared_not_launched", "aws_changed", "resume_rule",
}
BATCH_KEYS = {"target_start", "target_count", "approval_sha256", "checkpoint_sha256",
              "container_id", "status", "original_aliases_deleted", "original_bytes_retired",
              "numeric_rows_parsed"}
BATCH_OPTIONAL = {"execution_kind"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def parse_document(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate lifecycle metadata field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite lifecycle metadata")))


def read_private(path, maximum=16 * 1024 * 1024):
    path = Path(path).absolute()
    if ".." in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("canonical private lifecycle metadata required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise ValueError("bounded owner-controlled lifecycle file required")
        raw = stream.read(maximum + 1)
        if (len(raw) != before.st_size or signature(before) != signature(os.fstat(stream.fileno()))
                or signature(before) != signature(path.lstat())):
            raise ValueError("lifecycle file changed during read")
    return parse_document(raw)


def read_manifest_pair():
    path = SOURCE / "manifest.json"
    mirror = SOURCE / "verification/manifest.json"
    signatures = []
    for item in (path, mirror):
        value = item.lstat()
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 2
                or not 1 <= value.st_size <= 8 * 1024 * 1024):
            raise ValueError("complete two-link protected manifest pair required")
        signatures.append((value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns))
    if signatures[0][:3] != signatures[1][:3]:
        raise ValueError("manifest hardlink pair identity differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(8 * 1024 * 1024 + 1)
        if (len(raw) != signatures[0][2]
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != signatures[0]):
            raise ValueError("manifest changed during bounded read")
        for item in (path, mirror):
            current = item.lstat()
            if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != signatures[0]:
                raise ValueError("manifest hardlink changed during bounded read")
    return parse_document(raw)


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def next_batch(state):
    if type(state) is not dict or state.get("schema_version") != 1 or state.get("scope") != "NEW_STRICT_SOURCE_BYTE_PRESERVING_BATCH_RETIREMENT":
        raise ValueError("known byte-preserving strict-source lifecycle state required")
    batches = {}
    for key, value in state.items():
        match = BATCH.fullmatch(key)
        if match:
            if (type(value) is not dict or not BATCH_KEYS <= set(value)
                    or set(value) - BATCH_KEYS - BATCH_OPTIONAL):
                raise ValueError("complete committed batch receipt required")
            batches[int(match.group(1))] = value
        elif key not in STATE_KEYS:
            raise ValueError("unknown lifecycle state member refused")
    if (any(type(state.get(key)) is not int or state[key] < 0 for key in
            ("required_non_fit_manifest_targets", "next_target_start"))
            or type(state.get("fit_source_retained")) is not bool or state["fit_source_retained"] is not True
            or type(state.get("archives_models_labels_metadata_retained")) is not bool
            or state["archives_models_labels_metadata_retained"] is not True
            or type(state.get("old_holdout_acceptance_allowed")) is not bool
            or state["old_holdout_acceptance_allowed"] is not False
            or type(state.get("aws_changed")) is not bool or state["aws_changed"] is not False):
        raise ValueError("retained FIT/archives/holdout exclusion/lab-only invariants required")
    ordered = sorted(batches)
    if ordered != list(range(len(ordered))):
        raise ValueError("retirement batch sequence contains a gap")
    cursor = 0
    for index in ordered:
        item = batches[index]
        if (item["target_start"] != cursor or type(item["target_count"]) is not int
                or not 1 <= item["target_count"] <= 256 or item["status"] != "SUCCEEDED"
                or item["original_aliases_deleted"] != item["target_count"] * 3
                or item["numeric_rows_parsed"] != 0
                or item.get("execution_kind", "PINNED_BATCH_CONTAINER") not in
                    {"PINNED_BATCH_CONTAINER", "DOCKER_EXEC_IN_METADATA_OBSERVER"}
                or type(item["original_bytes_retired"]) is not int or item["original_bytes_retired"] <= 0
                or any(type(item[key]) is not str or SHA.fullmatch(item[key]) is None
                       for key in ("approval_sha256", "checkpoint_sha256", "container_id"))):
            raise ValueError("prior batch does not prove one complete byte-preserving range")
        cursor += item["target_count"]
    if cursor != state["next_target_start"]:
        raise ValueError("resume cursor differs from committed batch ranges")
    required = state["required_non_fit_manifest_targets"]
    if not 0 <= cursor < required:
        raise ValueError("no remaining bounded retirement batch")
    return len(ordered), cursor, min(256, required - cursor)


def observer_identity(container_id):
    if type(container_id) is not str or SHA.fullmatch(container_id) is None:
        raise ValueError("exact observer container identity required")
    template = "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{index .Config.Labels \"flare.strict.lifecycle-observer\"}}|{{json .Mounts}}"
    result = subprocess.run(["docker", "inspect", "--type", "container", "--format", template, container_id],
                            capture_output=True, text=True, timeout=15)
    if result.returncode or not result.stdout or len(result.stdout) > 64 * 1024:
        raise ValueError("exact observer runtime metadata unavailable")
    fields = result.stdout.strip().split("|", 7)
    if len(fields) != 8 or fields[:7] != [container_id, IMAGE, "running", "1000:1000", "none", "true", "metadata-only"]:
        raise ValueError("pinned running isolated metadata observer required")
    mounts = json.loads(fields[7])
    if type(mounts) is not list:
        raise ValueError("complete observer bind inventory required")
    writable = {mount.get("Source") for mount in mounts if type(mount) is dict and mount.get("RW") is True}
    required = {
        str(RUNTIME / "hybrid-strict-source-20261004-pdSIQYiW/source"),
        str(OUT),
        str(RUNTIME / "private-backups/source-retirement-scratch-20261011-NK71bhgY"),
    }
    bind_writable = {mount.get("Source") for mount in mounts
                     if type(mount) is dict and mount.get("Type") == "bind" and mount.get("RW") is True}
    if bind_writable != required:
        raise ValueError("observer write mounts exceed or omit the approved source/output/scratch roots")
    return container_id


def expected_targets(approval, start, count):
    manifest = read_manifest_pair()
    described = sorted(
        "shards/" + shard["id"] + ".json"
        for split, section in manifest["splits"].items()
        if not split.endswith("-fit")
        for shard in section["shards"]
    )
    targets = approval.get("targets")
    if (type(targets) is not list or len(targets) != count
            or [item.get("projection") for item in targets if type(item) is dict] != described[start:start + count]):
        raise ValueError("retirement approval is not the next exact manifest range")
    return targets


def verify_in_observer(observer, approval_path, approval_sha, checkpoint_path, checkpoint_sha):
    command = ["docker", "exec", "--env", "TMPDIR=" + str(RUNTIME / "private-backups/source-retirement-scratch-20261011-NK71bhgY"),
        "--user", "1000:1000", observer, "python3", "-B", str(ROOT / "observability/scripts/retire-ueba-strict-source-shards.py"),
        "--approval", str(approval_path), "--approval-sha256", approval_sha,
        "--verify-only", "--resume", "--coordinator-checkpoint", str(checkpoint_path),
        "--coordinator-checkpoint-sha256", checkpoint_sha]
    result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if result.returncode or not result.stdout:
        raise ValueError("exact source retirement receipt verification failed")
    value = json.loads(result.stdout)
    if (type(value) is not dict or value.get("status") != "VERIFIED_ONLY"
            or value.get("groups_verified") <= 0 or value.get("original_aliases_deleted") != 0
            or value.get("numeric_rows_parsed") != 0):
        raise ValueError("worker did not verify completed retirement receipts without deletion")
    return value


def atomic_write(path, value, prior_sha):
    path = Path(path).absolute()
    parent = path.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or path.is_symlink()):
        raise ValueError("private lifecycle state path required")
    if sha_file(path) != prior_sha:
        raise ValueError("lifecycle resume state changed while the batch was being verified")
    raw = canonical(value).encode()
    fd, temporary = tempfile.mkstemp(prefix=".lifecycle-resume-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def record_batch(approval_path, approval_sha, checkpoint_path, checkpoint_sha, observer, socket_dir):
    lock_path = STATE.with_suffix(".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        held = os.fstat(descriptor)
        if (not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid()
                or stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1):
            raise ValueError("private lifecycle coordinator lock required")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prior_state_sha = sha_file(STATE)
        state = read_private(STATE)
        if sha_file(STATE) != prior_state_sha:
            raise ValueError("lifecycle resume state changed during read")
        index, start, count = next_batch(state)
        if observer_identity(observer) != observer:
            raise ValueError("observer identity changed")
        socket_path = Path(socket_dir).absolute()
        if (socket_path.is_symlink() or any(part.is_symlink() for part in socket_path.parents)
                or not socket_path.is_dir() or socket_path.stat().st_uid != os.geteuid()
                or stat.S_IMODE(socket_path.stat().st_mode) != 0o700):
            raise ValueError("private observer socket directory required")
        socket_file = socket_path / "metadata.sock"
        socket_info = socket_file.lstat()
        if (not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != os.geteuid()
                or stat.S_IMODE(socket_info.st_mode) != 0o600):
            raise ValueError("pinned private metadata proxy socket required")
        for path, sha in ((approval_path, approval_sha), (checkpoint_path, checkpoint_sha)):
            if not isinstance(sha, str) or not SHA.fullmatch(sha) or sha_file(path) != sha:
                raise ValueError("retirement approval/checkpoint checksum mismatch")
        approval = read_private(approval_path, 8 * 1024 * 1024)
        checkpoint = read_private(checkpoint_path, 2 * 1024 * 1024)
        source_pins = {
            "dataset_manifest_sha256": sha_file(SOURCE / "manifest.json"),
            "archive_sidecar_sha256": sha_file(SOURCE / "archives.private.json"),
            "archive_result_sha256": state["archive_result_sha256"],
            "source_marker_sha256": sha_file(SOURCE.parent / "predeclared.private.json"),
            "source_terminal_sha256": sha_file(SOURCE.parent / "state.private.json"),
        }
        if (approval.get("scope") != "NEW_STRICT_SOURCE_SHARDS_ONLY"
                or approval.get("source_standard") != str(SOURCE)
                or approval.get("retirement_approved") is not True
                or any(approval.get(key) != value for key, value in source_pins.items())
                or checkpoint.get("scope") != "NEW_STRICT_SOURCE_RETIREMENT_COORDINATOR"
                or checkpoint.get("status") != "QUIESCENT"
                or checkpoint.get("source_standard") != str(SOURCE)
                or checkpoint.get("retirement_approval_sha256") != approval_sha
                or any(checkpoint.get(key) != value for key, value in source_pins.items())):
            raise ValueError("matching approved source and quiescent checkpoint required")
        targets = expected_targets(approval, start, count)
        verification = verify_in_observer(observer, approval_path, approval_sha, checkpoint_path, checkpoint_sha)
        if verification["groups_verified"] != count:
            raise ValueError("completed receipt count differs from approved manifest range")
        entry = {"target_start": start, "target_count": count, "approval_sha256": approval_sha,
            "checkpoint_sha256": checkpoint_sha, "container_id": observer, "status": "SUCCEEDED",
            "original_aliases_deleted": 3 * count, "original_bytes_retired": sum(item["bytes"] for item in targets),
            "numeric_rows_parsed": 0, "execution_kind": "DOCKER_EXEC_IN_METADATA_OBSERVER"}
        if f"batch_{index:04d}" in state:
            raise ValueError("batch state already exists; refusing overwrite")
        state[f"batch_{index:04d}"] = entry
        state["next_target_start"] = start + count
        state["observer_container_id"] = observer
        state["proxy_socket_directory"] = str(socket_path)
        atomic_write(STATE, state, prior_state_sha)
        return {"batch_index": index, "target_start": start, "target_count": count,
                "groups_verified": verification["groups_verified"], "original_aliases_deleted": entry["original_aliases_deleted"],
                "original_bytes_retired": entry["original_bytes_retired"], "next_target_start": state["next_target_start"],
                "quality_gate": "NOT_RUN", "aws_changed": False}
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--observer-container-id", required=True)
    parser.add_argument("--socket-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(canonical(record_batch(args.approval, args.approval_sha256, args.checkpoint,
                                    args.checkpoint_sha256, args.observer_container_id,
                                    args.socket_directory)), flush=True)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("lifecycle batch receipt refused; retained lifecycle state unchanged") from None


if __name__ == "__main__":
    main()
