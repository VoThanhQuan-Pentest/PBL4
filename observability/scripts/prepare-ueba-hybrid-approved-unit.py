#!/usr/bin/env python3
"""Prepare one private operator approval from an exact completed HYBRID boundary.

Only frozen code/JVM inventories and bounded private metadata are read. This
tool does not dispatch Docker, fit, score, archive, retire, activate, or contact
AWS. A completed unqualified source and retained counts are not qualification.
The existing continuation remains responsible for checking and executing one
separately requested approved unit; this tool never starts it.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
MAX_APPROVAL_BYTES = 2 * 1024 * 1024
MAX_LEDGER_ENTRIES = 1083


def continuation():
    """Reuse the trusted existing continuation, never import checkpoint code."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "hybrid_approved_unit_continuation", ROOT / "observability/scripts/continue-ueba-strict.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def existing_boundary_lock(helper, plan):
    """Observe the existing coordinator lock without creating source files."""
    ledger = plan.dataset / "hybrid-one-unit"
    if ledger.is_symlink():
        raise ValueError("private one-unit ledger symlink refused")
    if not ledger.exists():
        def verify_absent():
            if ledger.exists() or ledger.is_symlink():
                raise ValueError("one-unit ledger appeared during approval preparation")
        yield verify_absent
        verify_absent()
        return
    helper.checked_directory(ledger)
    directory = ledger.lstat()
    lock = ledger / "coordinator.lock"
    descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 1024 * 1024):
            raise ValueError("private single-link continuation lock required")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def verify():
            helper.checked_directory(ledger)
            current = ledger.lstat()
            if (directory.st_dev, directory.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("one-unit ledger changed during approval preparation")
            if signature(info) != signature(lock.lstat()):
                raise ValueError("continuation lock changed during approval preparation")
        verify()
        yield verify
        verify()
    finally:
        os.close(descriptor)


def retained_boundary(helper, plan):
    """Use the runner's actual metadata boundary; refuse unsafe old handles."""
    unit = helper.next_hybrid_unit(plan)
    ledger = plan.dataset / "hybrid-one-unit"
    if ledger.is_symlink():
        raise ValueError("private one-unit ledger symlink refused")
    if ledger.exists():
        helper.checked_directory(ledger)
        entries = list(ledger.iterdir())
        if len(entries) > MAX_LEDGER_ENTRIES:
            raise ValueError("bounded one-unit state ledger required")
        for path in entries:
            if path.name == "coordinator.lock":
                continue
            if re.fullmatch(r"[a-f0-9]{64}\.private\.json", path.name) is None:
                raise ValueError("unknown one-unit ledger member refused")
            state = helper.private_receipt(path, MAX_APPROVAL_BYTES)
            if (type(state) is not dict or state.get("status") != "SUCCEEDED"
                    or state.get("identity_sha256") != plan.identity_sha256
                    or state.get("approval_sha256") != path.name.removesuffix(".private.json")):
                raise ValueError("failed/live or foreign one-unit approval boundary refused")
    return unit


def approval_destination(helper, plan, output):
    """Keep operator artifacts outside the immutable source metadata subtree."""
    output = Path(output).absolute()
    parent = helper.checked_directory(output.parent)
    if ".." in output.parts or output.exists() or output.is_symlink():
        raise ValueError("fresh exact private approval destination required")
    if output.is_relative_to(plan.dataset.parent):
        raise ValueError("operator approval must remain outside the source subtree")
    return output, parent


def write_new_approval(helper, plan, output, approval):
    """Exclusive no-follow publication; an existing destination is never changed."""
    output, parent = approval_destination(helper, plan, output)
    raw = helper.canonical(approval).encode()
    if not 1 <= len(raw) <= MAX_APPROVAL_BYTES:
        raise ValueError("bounded one-unit approval required")
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(parent_descriptor)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o700
                or (before.st_dev, before.st_ino) != (parent.lstat().st_dev, parent.lstat().st_ino)):
            raise ValueError("stable private approval parent required")
        descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "wb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError("new private single-link approval required")
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if (before.st_dev, before.st_ino) != (parent.lstat().st_dev, parent.lstat().st_ino):
            raise ValueError("approval parent changed during publication")
        sha = hashlib.sha256(raw).hexdigest()
        if helper.campaign_run_approval(plan, output, sha) != approval:
            raise ValueError("one-unit approval readback differs")
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return sha


def prepare(output, *, dataset, dataset_sha, archive_sha, marker_sha, terminal_sha,
            code, code_sha, workspace, workspace_sha, image, user_approval_reference,
            helper=None):
    if (type(user_approval_reference) is not str
            or not 1 <= len(user_approval_reference) <= 2000
            or not user_approval_reference.strip()):
        raise ValueError("nonblank explicit user approval reference required")
    helper = continuation() if helper is None else helper
    # Construction rejects live/incomplete/tampered source before any write.
    plan = helper.HybridPlan(dataset, dataset_sha=dataset_sha, archive_sha=archive_sha,
        marker_sha=marker_sha, terminal_sha=terminal_sha, code=code, code_sha=code_sha,
        workspace=workspace, workspace_sha=workspace_sha, image=image)
    output, _ = approval_destination(helper, plan, output)
    with existing_boundary_lock(helper, plan) as verify_lock:
        unit = retained_boundary(helper, plan)
        approval = {"approval_schema_version": 1, "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
            "source_standard": str(plan.dataset), "continuation_identity_sha256": plan.identity_sha256,
            "stage": unit["stage"], "unit_id": unit["unit_id"], "expected_before": unit["before"],
            "execution_approved": True, "retirement_approved": False,
            "user_approval_reference": user_approval_reference}
        plan.recheck()
        if retained_boundary(helper, plan) != unit:
            raise ValueError("actual one-unit receipt boundary changed before approval")
        verify_lock()
        sha = write_new_approval(helper, plan, output, approval)
    return {"status": "PREPARED_ONE_UNIT_APPROVAL", "approval_path": str(output),
        "approval_sha256": sha, "continuation_identity_sha256": plan.identity_sha256,
        "stage": unit["stage"], "unit_id": unit["unit_id"], "expected_before": unit["before"],
        "quality_gate": "NOT_RUN", "execution_started": False, "retirement_approved": False,
        "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "aws_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--source-marker-sha256", required=True)
    parser.add_argument("--source-terminal-sha256", required=True)
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--code-sha256", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--workspace-sha256", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--user-approval-reference", required=True)
    args = parser.parse_args()
    try:
        helper = continuation()
        result = prepare(args.output, dataset=args.dataset, dataset_sha=args.dataset_sha256,
            archive_sha=args.archive_sha256, marker_sha=args.source_marker_sha256,
            terminal_sha=args.source_terminal_sha256, code=args.code, code_sha=args.code_sha256,
            workspace=args.workspace, workspace_sha=args.workspace_sha256, image=args.image_id,
            user_approval_reference=args.user_approval_reference, helper=helper)
        print(helper.canonical(result))
    except (OSError, ValueError, TypeError, KeyError) as failure:
        raise SystemExit("HYBRID one-unit approval refused/failed: " + type(failure).__name__
                         + "; existing source and approvals unchanged; any new partial approval retained") from None


if __name__ == "__main__":
    main()
