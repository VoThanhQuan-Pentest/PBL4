#!/usr/bin/env python3
"""Host admission and independent Docker/OS watchdog for the bounded pilot."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish


def command(args, *, timeout=20):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode: raise RuntimeError("command failed: " + " ".join(args[:3]) + ": " + result.stderr[-500:])
    return result.stdout.strip()


def inspect_container(container):
    raw = command(["docker", "inspect", "--format", "{{json .HostConfig}}", container])
    config = json.loads(raw)
    if (config["NetworkMode"] != "none" or config["Memory"] != 2 * 1024**3
            or config["NanoCpus"] != 2_000_000_000 or not config["ReadonlyRootfs"]
            or config["PidsLimit"] != 128):
        raise ValueError("actual container resource/isolation policy mismatch")
    return {key: config[key] for key in ("NetworkMode", "Memory", "NanoCpus", "ReadonlyRootfs", "PidsLimit")}


def reject_terminal_round(output):
    marker = output / "pilot-result.commit.private.json"
    if marker.exists():
        proof = json.loads(marker.read_text())
        if (proof.get("receipt") != "pilot-result.receipt.private.json"
                or digest(output / proof["receipt"]) != proof.get("receipt_sha256")):
            raise ValueError("terminal pilot receipt integrity failed")
        status = json.loads((output / proof["receipt"]).read_text())["status"]
        raise ValueError("pilot round is terminal (" + status + "); no automatic new trials")


def check_quota(quota, *, now=None):
    threshold = quota.get("stop_new_units_used_percent", 80)
    used = quota["used_percent_5h"]
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
           for value in (threshold, used)) or not 0 < threshold <= 100 or not 0 <= used <= 100:
        raise ValueError("valid quota percentage and stop threshold required")
    observed = datetime.fromisoformat(quota["observed_at_utc"].replace("Z", "+00:00"))
    age = ((now or datetime.now(timezone.utc)) - observed).total_seconds()
    if used >= threshold or not 0 <= age <= 300:
        raise ValueError("fresh live quota below reserve threshold required")


def preflight(repo, output, mode):
    output = private_directory(output)
    if mode == "pilot": reject_terminal_round(output)
    protocol = json.loads((output / "pilot.protocol.private.json").read_text())
    state = json.loads((output / "operator-state.private.json").read_text())
    original = json.loads((output / "p0.receipt.private.json").read_text())
    r2 = Path(original["r2"])
    if digest(r2 / "parallel-campaign.identity.private.json") != original["r2_identity_sha256"]:
        raise ValueError("historical R2 identity changed")
    historical = json.loads((r2 / "parallel-campaign.identity.private.json").read_text())["continuation_identity"]
    for name, expected in historical["python_sources"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts or digest(r2 / "code/app" / name) != expected:
            raise ValueError("frozen Python source changed")
    code = output / "pilot-code"
    for name, expected in protocol["code_sha256"].items():
        if digest(code / name) != expected: raise ValueError("pilot code snapshot changed")
    if digest(output / "pilot.source.identity.private.json") != protocol["source_binding_sha256"]:
        raise ValueError("source identity changed")
    source = json.loads((output / "pilot.source.identity.private.json").read_text())
    if source["original_generator_sha256"] != digest(r2 / "code/app/schema4_episodes.py"):
        raise ValueError("frozen causal generator changed")
    overlay = json.loads((output / "java-overlay-stream/identity.private.json").read_text())
    base = Path(overlay["base_workspace"])
    if digest(base / "snapshot.json") != historical["java_snapshot_sha256"]:
        raise ValueError("JVM snapshot changed")
    inventory = json.loads((base / "snapshot.json").read_text())
    for kind, entries in inventory.items():
        directory = base / ("backend/target/classes/com/flarefitness/backend" if kind == "classes" else "jars")
        for name, expected in entries.items():
            if Path(name).is_absolute() or ".." in Path(name).parts or digest(directory / name) != expected:
                raise ValueError("JVM inventory bytes changed")
    for name, expected in overlay["overlay_classes_sha256"].items():
        if digest(output / "java-overlay-stream/classes" / name) != expected: raise ValueError("Java overlay changed")
    image = protocol["image_id"]
    if (image != historical["image_id"] or command(["docker", "image", "inspect", image, "--format", "{{.Id}} {{.Os}}/{{.Architecture}}"])
            != image + " linux/amd64"):
        raise ValueError("actual pinned image/architecture required")
    if shutil.disk_usage(output).free < 5_000_000_000 + 2 * 1024**3:
        raise ValueError("insufficient reserve and output headroom")
    check_quota(state["quota"])
    if mode == "pilot":
        hold = json.loads((output / "operator-hold.private.json").read_text())
        if hold.get("hold_new_units"): raise ValueError("operator hold remains active")
        admission = json.loads((output / "pilot-admission.private.json").read_text())
        fixture_receipt = Path(admission["fixture_receipt"])
        if (not fixture_receipt.resolve().is_relative_to(output) or fixture_receipt.name != "pipeline-integration.receipt.private.json"):
            raise ValueError("owned fixture receipt required")
        if (admission["pilot_protocol_sha256"] != digest(output / "pilot.protocol.private.json")
                or digest(Path(admission["fixture_receipt"])) != admission["fixture_receipt_sha256"]):
            raise ValueError("verified pipeline admission required")
    budget = json.loads((output / "pilot-budget.private.json").read_text())
    if budget["cap_seconds"] != 7200 or budget["composite_invocations"] >= 7:
        raise ValueError("cumulative pilot budget exhausted or changed")
    writer_fd = os.open(output / "pilot.writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try: fcntl.flock(writer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(writer_fd)
    return protocol, r2, base, {"frozen_python_pins": len(historical["python_sources"]),
        "jvm_classes": len(inventory["classes"]), "jars": len(inventory["jars"]),
        "image_id": image, "free_bytes": shutil.disk_usage(output).free,
        "pilot_protocol_sha256": digest(output / "pilot.protocol.private.json")}


def run(repo, output, mode, maximum_new_fits):
    output = private_directory(output); started = time.monotonic()
    lock_fd = os.open(output / "pilot.launcher.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    container = "flare-ueba-postlogin-" + ("pipeline-fixture-r2" if mode == "fixture" else "pilot-r2")
    if command(["docker", "ps", "-a", "--filter", "name=^/" + container + "$", "--format", "{{.ID}} {{.Status}}"]):
        raise ValueError("existing handle must be observed, never replaced")
    protocol, r2, base, checks = preflight(repo, output, mode)
    code = output / "pilot-code"
    if mode == "fixture":
        source = repo / "observability/scripts/verify-ueba-postlogin-pipeline.py"
        shutil.copyfile(source, code / source.name); (code / source.name).chmod(0o600)
        fixture = private_directory(output / ("pipeline-fixture-" + str(time.time_ns())), create=True)
        shutil.copytree(output / "pilot-replay-java", fixture / "pilot-replay-java")
        seconds = 180
        python_args = ["-B", "/research/verify-ueba-postlogin-pipeline.py", "--output", str(output), "--fixture", str(fixture)]
    else:
        budget = json.loads((output / "pilot-budget.private.json").read_text())
        seconds = math.floor(budget["cap_seconds"] - budget["elapsed_seconds"] - 10)
        if seconds < 1: raise ValueError("no remaining job budget")
        python_args = ["-B", "/research/run-ueba-postlogin-pilot.py", "--output", str(output),
                       "--model-kind", "normal_plus_incident_research", "--maximum-new-fits", str(maximum_new_fits)]
    args = ["docker", "run", "-d", "--init", "--name", container, "--network", "none", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "128", "--user", f"{os.geteuid()}:{os.getegid()}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=134217728",
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "OMP_NUM_THREADS=2", "--env", "OPENBLAS_NUM_THREADS=2",
            "--env", "MKL_NUM_THREADS=2", "--env", "PYTHONPATH=" + str(r2 / "code")]
    for source, destination, readonly in ((r2 / "code", r2 / "code", True), (base, base, True),
                                         (output, output, False), (code, code, True), (code, Path("/research"), True)):
        args.extend(["--mount", f"type=bind,src={source},dst={destination}" + (",readonly" if readonly else "")])
    args += ["--entrypoint", "/usr/bin/timeout", protocol["image_id"], "--signal=TERM", "--kill-after=10s", str(seconds), "python", *python_args]
    container_id = command(args)
    try:
        actual = inspect_container(container_id)
    except Exception:
        subprocess.run(["docker", "stop", "--time", "1", container_id], capture_output=True, timeout=15)
        raise
    tag = mode + "-" + str(time.time_ns())
    launch = {"status": "RUNNING", "mode": mode, "container_id": container_id, "name": container,
              "watchdog_seconds": seconds, "resource_policy_actual": actual, "preflight": checks,
              "launcher_sha256": digest(__file__), "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "holdout_scored": False, "aws_changed": False, "auto_containment": False}
    if mode == "fixture": launch["fixture_runner_sha256"] = digest(code / "verify-ueba-postlogin-pipeline.py")
    publish(output / (tag + ".launch.private.json"), launch, maximum=16 * 1024)
    state = json.loads((output / "operator-state.private.json").read_text())
    state.update(status="RUNNING_" + mode.upper(), active_handle={"kind": "docker", "name": container,
                 "id": container_id, "launch_receipt": tag + ".launch.private.json"})
    publish(output / "operator-state.private.json", state)
    print(canonical({"status": "RUNNING", "container": container_id, "name": container, "mode": mode}), flush=True)
    try:
        exit_code = int(command(["docker", "wait", container_id], timeout=seconds + 40))
    except subprocess.TimeoutExpired:
        # The independent OS timeout remains authoritative; never start a second writer.
        raise RuntimeError("observation timed out; inspect the same container")
    log = output / (tag + ".log")
    with log.open("wb") as stream:
        subprocess.run(["docker", "logs", container_id], stdout=stream, stderr=subprocess.STDOUT, check=False)
        stream.flush(); os.fsync(stream.fileno())
    log.chmod(0o600)
    execution = json.loads(command(["docker", "inspect", "--format", "{{json .State}}", container_id]))
    receipt = {**launch, "status": "COMPLETED" if exit_code == 0 else "FAILED", "exit_code": exit_code,
               "oom_killed": execution["OOMKilled"], "elapsed_seconds": round(time.monotonic() - started, 3),
               "log": log.name, "log_sha256": digest(log)}
    if mode == "fixture" and exit_code == 0:
        fixture_receipt = fixture / "pipeline-integration.receipt.private.json"
        proof = json.loads(fixture_receipt.read_text())
        if proof["additional_fit_calls"] != 0 or proof["status"] != "PIPELINE_INTEGRATION_FIXTURE_PASS":
            raise ValueError("fixture failed its no-fit contract")
        receipt.update(fixture_receipt=str(fixture_receipt), fixture_receipt_sha256=digest(fixture_receipt))
    commit(output, receipt, phase=tag)
    if mode == "fixture":
        budget = json.loads((output / "pilot-budget.private.json").read_text())
        budget["elapsed_seconds"] += receipt["elapsed_seconds"]
        publish(output / "pilot-budget.private.json", budget)
    state = json.loads((output / "operator-state.private.json").read_text())
    state.update(active_handle=None, last_execution_receipt=tag + ".receipt.private.json")
    if exit_code: state.update(status="FAILED_" + mode.upper(), next_action="Read bounded log tail and preserve all committed units before any recovery")
    elif mode == "fixture": state.update(status="PIPELINE_FIXTURE_PASS", next_action="Recheck quota, verify admission and run at most one real pilot fit")
    publish(output / "operator-state.private.json", state)
    command(["docker", "rm", container_id])
    print(canonical({"status": receipt["status"], "exit_code": exit_code, "receipt": tag + ".receipt.private.json"}), flush=True)
    os.close(lock_fd)
    if exit_code: raise SystemExit(exit_code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["fixture", "pilot"], required=True)
    parser.add_argument("--maximum-new-fits", type=int, choices=range(1, 8), default=1)
    args = parser.parse_args(); run(args.repo.absolute(), args.output.absolute(), args.mode, args.maximum_new_fits)
