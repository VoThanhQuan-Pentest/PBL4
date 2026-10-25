#!/usr/bin/env python3
"""Safe, one-unit operator for the retained schema-4 strict campaign.

This module only prepares metadata approvals or delegates one already approved
unit to continue-ueba-strict.py. It never opens raw records, launches AWS work,
or continues into the previously blocked holdout.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime"
DATASET = RUNTIME / "hybrid-strict-source-20261004-pdSIQYiW/source/standard"
CODE = RUNTIME / "private-backups/hybrid-execution-code-20261005-j2smoa4k"
WORKSPACE = RUNTIME / "private-backups/hybrid-execution-java-20261005-d_gl_k__"
STATE = RUNTIME / "private-backups/hybrid-one-unit-approvals-20261011-oJ0txg4X"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
PINS = {
    "dataset_sha": "d372eda63ef1b8bae9d17331fa4abf978db8f69b60eb192c9a009ed41aa2afd1",
    "archive_sha": "0ae0525908507b56f7500a841609d1a01e9326da85a9c36aa729132311ac7267",
    "marker_sha": "3e20e41a14d1379e3515919484f89fdd5f5d0ff3819a7bdd70c0b709914f6e6b",
    "terminal_sha": "a2c773f79c121123f2a794e5b329cf70280b82bd53595011140b4cc7b2f6cf8a",
    "code_sha": "cb1aff3368e33177e633163741ad91bc09624b3f84b5b890d7d8ab79a670c103",
    "workspace_sha": "64e5aee49d6f716a66e2f700e3888e9fe0e53e6123ad11e3a1713fd57f83f8d2",
}
SHA = re.compile(r"[a-f0-9]{64}")
APPROVAL_FIELDS = {
    "approval_schema_version", "scope", "source_standard", "continuation_identity_sha256",
    "stage", "unit_id", "expected_before", "execution_approved", "retirement_approved",
    "user_approval_reference",
}
COUNTS = {"actual_fits_completed", "validation_runs_completed", "completed_recalibrations"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def private_directory(path, *, create=False):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private operator directory required")
    if not path.exists() and create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("operator directory must be owned and mode 0700")
    return path


def continuation_module():
    path = ROOT / "observability/scripts/continue-ueba-strict.py"
    spec = importlib.util.spec_from_file_location("pinned_strict_continuation", path)
    if spec is None or spec.loader is None:
        raise ValueError("strict continuation module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def campaign_plan():
    module = continuation_module()
    plan = module.HybridPlan(
        DATASET, dataset_sha=PINS["dataset_sha"], archive_sha=PINS["archive_sha"],
        marker_sha=PINS["marker_sha"], terminal_sha=PINS["terminal_sha"],
        code=CODE, code_sha=PINS["code_sha"], workspace=WORKSPACE,
        workspace_sha=PINS["workspace_sha"], image=IMAGE,
    )
    return module, plan


def next_unit_without_legacy_holdout(module, plan):
    """Return None once selection exists; never call the old-holdout branch."""
    selected = module.private_receipt(plan.dataset / "hybrid-selection.json")
    if selected is not None:
        records = module.hybrid_records(plan)
        module.hybrid_selected(plan, selected, records)
        return None, records, selected
    progress = module.private_receipt(plan.dataset / "hybrid-selection.progress.json")
    if progress is not None and progress.get("status") == "NO_QUALIFIED_CONFIG":
        return None, module.hybrid_records(plan), progress
    records = module.hybrid_records(plan)
    return module.next_hybrid_unit(plan), records, None


def safe_status(module, plan):
    unit, records, selected_or_progress = next_unit_without_legacy_holdout(module, plan)
    if unit is None:
        state = "SELECTED_STOP_BEFORE_OLD_HOLDOUT" if selected_or_progress and selected_or_progress.get("status") == "SELECTED" else "NO_QUALIFIED_CONFIG"
        return {"stage": state, "status": state, **records["counts"], "quality_gate": "NOT_RUN",
                "holdout_scored": False, "aws_changed": False}
    return {"stage": unit["stage"], "status": "READY_FOR_EXPLICIT_ONE_UNIT_APPROVAL", **unit["before"],
            "unit_id": unit["unit_id"], "quality_gate": "NOT_RUN", "holdout_scored": False,
            "aws_changed": False}


def write_approval(module, plan, state_directory, reference):
    state_directory = private_directory(state_directory, create=True)
    if type(reference) is not str or not reference.strip() or len(reference) > 2000:
        raise ValueError("bounded user authorization reference required")
    unit, records, selected_or_progress = next_unit_without_legacy_holdout(module, plan)
    if unit is None:
        raise ValueError("campaign is terminal before legacy holdout; no approval was created")
    if unit["stage"] not in {"fit", "validation", "ranking", "recalibration"}:
        raise ValueError("only pre-holdout strict campaign stages are permitted")
    plan.recheck()
    plan.require_headroom(plan.dataset, plan.unit_budgets()[unit["stage"]])
    approval = {
        "approval_schema_version": 1,
        "scope": "NEW_HYBRID_STRICT_ONE_UNIT_ONLY",
        "source_standard": str(plan.dataset),
        "continuation_identity_sha256": plan.identity_sha256,
        "stage": unit["stage"],
        "unit_id": unit["unit_id"],
        "expected_before": unit["before"],
        "execution_approved": True,
        "retirement_approved": False,
        "user_approval_reference": reference.strip(),
    }
    if set(approval) != APPROVAL_FIELDS or set(approval["expected_before"]) != COUNTS:
        raise ValueError("internal one-unit approval schema mismatch")
    encoded = canonical(approval).encode()
    approval_sha = hashlib.sha256(encoded).hexdigest()
    path = state_directory / f"operator-{approval_sha}.private.json"
    reused = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if module.checked_bytes(path, 2 * 1024 * 1024) != encoded:
            raise ValueError("existing approval differs from the exact campaign boundary") from None
        reused = True
    else:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    return {"stage": unit["stage"], "unit_id": unit["unit_id"], "approval_path": str(path),
            "approval_sha256": approval_sha, "counts_before": records["counts"],
            "approval_reused": reused, "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}


def validate_approval(module, plan, path, expected_sha):
    if not isinstance(expected_sha, str) or SHA.fullmatch(expected_sha) is None:
        raise ValueError("trusted approval checksum required")
    raw = module.checked_bytes(path, 2 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("approval checksum mismatch")
    approval = json.loads(raw)
    if (type(approval) is not dict or set(approval) != APPROVAL_FIELDS
            or approval.get("scope") != "NEW_HYBRID_STRICT_ONE_UNIT_ONLY"
            or approval.get("source_standard") != str(plan.dataset)
            or approval.get("continuation_identity_sha256") != plan.identity_sha256
            or approval.get("stage") not in {"fit", "validation", "ranking", "recalibration"}
            or approval.get("execution_approved") is not True
            or approval.get("retirement_approved") is not False):
        raise ValueError("approval is not valid for this frozen pre-holdout campaign")
    return approval


def execute(module, plan, approval_path, approval_sha):
    approval = validate_approval(module, plan, approval_path, approval_sha)
    state = safe_status(module, plan)
    if (state.get("unit_id") != approval["unit_id"] or state.get("stage") != approval["stage"]
            or {key: state[key] for key in COUNTS} != approval["expected_before"]):
        raise ValueError("approval is stale; prepare a new one-unit approval")
    return module.execute_hybrid_one_unit(plan, Path(approval_path), approval_sha)


def resume_interrupted_unit(module, plan, state_directory):
    """Resume one exact durable child; never redispatch or adopt its output by status alone."""
    ledger = Path(plan.dataset) / "hybrid-one-unit"
    if not ledger.exists() and not ledger.is_symlink():
        return None
    module.checked_directory(ledger)
    state_directory = private_directory(state_directory)
    entries = list(ledger.iterdir())
    if len(entries) > 1083:
        raise ValueError("bounded one-unit ledger required")
    pending = []
    for path in entries:
        if path.name == "coordinator.lock":
            continue
        match = re.fullmatch(r"([a-f0-9]{64})\.private\.json", path.name)
        if match is None:
            raise ValueError("unknown one-unit ledger member requires inspection")
        state = module.private_receipt(path)
        if state.get("status") == "SUCCEEDED":
            continue
        if state.get("status") == "FAILED":
            raise ValueError("failed exact child requires diagnosis; automatic restart is forbidden")
        if state.get("status") not in {"DISPATCH_INTENT", "DISPATCHED", "DISPATCH_UNKNOWN",
                                        "OBSERVATION_UNAVAILABLE", "RUNNING"}:
            raise ValueError("unknown one-unit state requires inspection")
        expected_fields = {"status", "identity_sha256", "approval_sha256", "stage", "unit_id", "before",
                           "container_name", "container_id", "quality_gate", "retirement_authority", "aws_changed"}
        if (set(state) != expected_fields or state.get("identity_sha256") != plan.identity_sha256
                or state.get("approval_sha256") != match.group(1)
                or state.get("stage") not in {"fit", "validation", "ranking", "recalibration"}
                or state.get("quality_gate") != "NOT_RUN" or state.get("retirement_authority") is not False
                or state.get("aws_changed") is not False or not isinstance(state.get("before"), dict)
                or set(state["before"]) != COUNTS
                or any(type(value) is not int or not 0 <= value <= 360 for value in state["before"].values())):
            raise ValueError("incomplete or misbound pre-holdout child state requires inspection")
        approval_sha = match.group(1)
        approval_path = state_directory / f"operator-{approval_sha}.private.json"
        approval = module.campaign_run_approval(plan, approval_path, approval_sha)
        if (approval.get("stage") != state["stage"] or approval.get("unit_id") != state["unit_id"]
                or approval.get("expected_before") != state["before"]):
            raise ValueError("interrupted child no longer matches its exact user approval")
        ordinal_field = {"fit": "actual_fits_completed", "validation": "validation_runs_completed",
                         "recalibration": "completed_recalibrations"}.get(state["stage"])
        ordinal = state["before"][ordinal_field] + 1 if ordinal_field else 1
        command = plan.command(state["stage"], ordinal)
        expected_name = command[command.index("--name") + 1]
        if state.get("container_name") != expected_name:
            raise ValueError("interrupted container name differs from the frozen one-unit command")
        pending.append((approval_path, approval_sha))
    if len(pending) > 1:
        raise ValueError("multiple interrupted children require individual diagnosis")
    if not pending:
        return None
    approval_path, approval_sha = pending[0]
    # The continuation reopens only this original approval/handle. Its durable
    # state and exact Docker ID/name are checked before a result can be accepted.
    return module.execute_hybrid_one_unit(plan, approval_path, approval_sha)


def run_until_selection(module, plan, state_directory, reference, maximum_units):
    if type(maximum_units) is not int or not 1 <= maximum_units <= 1081:
        raise ValueError("bounded pre-holdout unit limit required")
    completed = 0
    last_wait_state = None
    while completed < maximum_units:
        recovered = resume_interrupted_unit(module, plan, state_directory)
        if recovered is not None:
            if recovered.get("status") == "SUCCEEDED":
                completed += 1
                last_wait_state = None
                print(canonical({"event": "unit-reconciled", "units_completed_this_run": completed,
                    "stage": recovered["stage"], "unit_id": recovered["unit_id"],
                    "counts": (recovered.get("result") or {}).get("counts"),
                    "quality_gate": recovered.get("quality_gate", "NOT_RUN"),
                    "holdout_scored": False, "aws_changed": False}), flush=True)
                continue
            if recovered.get("status") not in {"DISPATCH_UNKNOWN", "DISPATCHED", "RUNNING", "OBSERVATION_UNAVAILABLE"}:
                raise ValueError("interrupted one-unit handle returned an unknown durable state")
            wait_state = (recovered.get("status"), recovered.get("container_id"), recovered.get("container_name"))
            if wait_state != last_wait_state:
                print(canonical({"event": "resuming-existing-unit", "stage": recovered.get("stage"),
                    "unit_id": recovered.get("unit_id"), "state": recovered.get("status"),
                    "container_id": recovered.get("container_id"), "aws_changed": False}), flush=True)
                last_wait_state = wait_state
            time.sleep(30)
            continue
        status = safe_status(module, plan)
        if status["stage"] in {"SELECTED_STOP_BEFORE_OLD_HOLDOUT", "NO_QUALIFIED_CONFIG"}:
            return {**status, "units_completed_this_run": completed}
        approval = write_approval(module, plan, state_directory, reference)
        result = execute(module, plan, approval["approval_path"], approval["approval_sha256"])
        if result.get("status") == "SUCCEEDED":
            completed += 1
            last_wait_state = None
            proof = result.get("result") or {}
            print(canonical({"event": "unit-completed", "units_completed_this_run": completed,
                "stage": result["stage"], "unit_id": result["unit_id"],
                "counts": proof.get("counts"), "quality_gate": result.get("quality_gate", "NOT_RUN"),
                "holdout_scored": False, "aws_changed": False}), flush=True)
            continue
        if result.get("status") not in {"DISPATCH_UNKNOWN", "DISPATCHED", "RUNNING", "OBSERVATION_UNAVAILABLE"}:
            raise ValueError("one-unit runner returned an unknown durable state")
        wait_state = (result.get("status"), result.get("container_id"), result.get("container_name"))
        if wait_state != last_wait_state:
            print(canonical({"event": "resuming-same-unit", "stage": result.get("stage"),
                "unit_id": result.get("unit_id"), "state": result.get("status"),
                "container_id": result.get("container_id"), "aws_changed": False}), flush=True)
            last_wait_state = wait_state
        time.sleep(30)
    current = safe_status(module, plan)
    return {"status": "MAXIMUM_PREHOLDOUT_UNITS_REACHED", "stage": current["stage"],
            "units_completed_this_run": completed, "counts": {key: current[key] for key in COUNTS},
            "quality_gate": "NOT_RUN", "holdout_scored": False, "aws_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "prepare-approval", "execute-one-unit", "run-until-selection"))
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--approval-sha256")
    parser.add_argument("--reference", default="User authorized implementation of the strict completion plan")
    parser.add_argument("--maximum-units", type=int, default=1081)
    args = parser.parse_args()
    try:
        module, plan = campaign_plan()
        if args.action == "status":
            result = safe_status(module, plan)
        elif args.action == "prepare-approval":
            if args.approval is not None or args.approval_sha256 is not None:
                raise ValueError("approval input is invalid while preparing a new approval")
            result = write_approval(module, plan, STATE, args.reference)
        elif args.action == "execute-one-unit":
            if args.approval is None or args.approval_sha256 is None:
                raise ValueError("one-unit execution requires the exact prepared approval and checksum")
            result = execute(module, plan, args.approval, args.approval_sha256)
        else:
            if args.approval is not None or args.approval_sha256 is not None:
                raise ValueError("long campaign runner creates one-unit approvals from the current boundary")
            result = run_until_selection(module, plan, STATE, args.reference, args.maximum_units)
        print(canonical(result), flush=True)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("strict operator refused the requested action; private metadata retained") from None


if __name__ == "__main__":
    main()
