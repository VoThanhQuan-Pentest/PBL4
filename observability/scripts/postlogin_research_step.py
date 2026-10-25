#!/usr/bin/env python3
"""Run one bounded, private, resumable research job under the approved ledger.

This is an operator CLI, not an API accepting remote commands. Input hashes bind
receipts to code/data. GNU timeout bounds the job even if this supervisor dies.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish


def utc():
    return datetime.now(timezone.utc)


def process_start(pid):
    try:
        # The comm field may contain spaces/parentheses; fields after its final ')'
        # start at stat field 3. Field 22 is the kernel start tick.
        return Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def recover_active(state, now=None):
    active = state.get("active_unit")
    if not active:
        return
    now = now or utc()
    pid = active.get("pid")
    if pid and process_start(pid) == active.get("process_start"):
        raise RuntimeError("LIVE_JOB_MUST_BE_OBSERVED_NOT_RESTARTED")
    # Covers a supervisor dying between spawn and persisting the child PID.
    if now < datetime.fromisoformat(active["deadline_utc"]) + timedelta(seconds=10):
        raise RuntimeError("WAIT_FOR_INDEPENDENT_JOB_DEADLINE_BEFORE_RECOVERY")
    state["elapsed_seconds"] += active["cap_seconds"]
    group = active["group"]
    state["group_seconds"][group] = state["group_seconds"].get(group, 0) + active["cap_seconds"]
    state["recovered_interrupted_units"] += 1
    state["active_unit"] = None


def binding(argv, inputs):
    return {"argv": argv, "inputs_sha256": {str(p.resolve()): digest(p) for p in inputs}}


def run(output, unit, group, maximum_seconds, argv, inputs):
    output = private_directory(output)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", unit) or not argv or maximum_seconds < 1:
        raise ValueError("bounded named unit and explicit command required")
    if group not in ("setup", "pilot", "otp", "strict", "verification"):
        raise ValueError("unknown job group")
    with (output / "research-step.lock").open("a+") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = output / "budget.private.json"
        state = json.loads(state_path.read_text())
        recover_active(state)
        publish(state_path, state)
        expected = binding(argv, inputs)
        marker = output / (unit + ".commit.private.json")
        if marker.exists():
            proof = json.loads(marker.read_text())
            receipt = output / (unit + ".receipt.private.json")
            if proof["receipt"] != receipt.name or digest(receipt) != proof["receipt_sha256"]:
                raise ValueError("committed job receipt changed")
            previous = json.loads(receipt.read_text())
            if previous["binding"] != expected:
                raise ValueError("job code/data/command changed; use a new explicit unit")
            print(canonical({"unit": unit, "reused": True, "receipt": proof, "status": previous["status"]}))
            return previous["exit_code"]
        hold = output / "operator-hold.private.json"
        if hold.exists() and json.loads(hold.read_text()).get("hold_new_units"):
            raise RuntimeError("STOP_OPERATOR_HOLD")
        if shutil.disk_usage(output).free < state["disk_reserve_bytes"]:
            raise RuntimeError("STOP_DISK_RESERVE")
        remaining = state["cap_seconds"] - state["elapsed_seconds"]
        if state.get("reserve_checkpoint_for_all_groups", False):
            remaining -= state["checkpoint_reserve_seconds"]
        if group == "pilot":
            remaining = min(remaining, state["pilot_cap_seconds"] - state["group_seconds"].get("pilot", 0))
        if group == "strict":
            remaining -= state["otp_reserve_seconds"]
            if not state.get("reserve_checkpoint_for_all_groups", False):
                remaining -= state["checkpoint_reserve_seconds"]
        seconds = min(maximum_seconds, math.floor(remaining))
        if seconds < 1:
            raise RuntimeError("STOP_BUDGET")
        deadline = utc() + timedelta(seconds=seconds)
        state["active_unit"] = {"id": unit, "group": group, "cap_seconds": seconds,
                                "deadline_utc": deadline.isoformat(), "pid": None}
        publish(state_path, state)
        log_path = output / (unit + ".log.private.txt")
        started = time.monotonic()
        with log_path.open("wb") as log:
            os.chmod(log.name, 0o600)
            child = subprocess.Popen(["timeout", "--signal=TERM", "--kill-after=5s", str(seconds), *argv],
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            state["active_unit"].update(pid=child.pid, process_start=process_start(child.pid))
            publish(state_path, state)
            try:
                code = child.wait(timeout=seconds + 10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                code = 124
        elapsed = time.monotonic() - started
        state["elapsed_seconds"] += elapsed
        state["group_seconds"][group] = state["group_seconds"].get(group, 0) + elapsed
        state["active_unit"] = None
        publish(state_path, state)
        inputs_unchanged = binding(argv, inputs) == expected
        if not inputs_unchanged and code == 0:
            code = 65
        document = {"unit": unit, "group": group, "binding": expected, "exit_code": code,
                    "status": "INPUT_CHANGED_DURING_JOB" if not inputs_unchanged else
                    "COMMAND_PASS" if code == 0 else "STOP_TIMEOUT" if code == 124 else "COMMAND_FAIL",
                    "inputs_unchanged_at_completion": inputs_unchanged,
                    "elapsed_seconds": elapsed, "maximum_seconds": seconds,
                    "cumulative_job_seconds": state["elapsed_seconds"], "log_sha256": digest(log_path),
                    "log": log_path.name, "finished_at_utc": utc().isoformat()}
        proof = commit(output, document, phase=unit)
        operator = json.loads((output / "operator-state.private.json").read_text())
        operator.update(last_verified_commit=proof, active_handle=None,
                        cumulative_job_seconds=state["elapsed_seconds"], status=document["status"])
        publish(output / "operator-state.private.json", operator)
        print(canonical({"unit": unit, "status": document["status"], "elapsed_seconds": elapsed, "receipt": proof}))
        return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--maximum-seconds", type=int, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    raise SystemExit(run(args.output, args.unit, args.group, args.maximum_seconds, command, args.input))
