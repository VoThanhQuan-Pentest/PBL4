#!/usr/bin/env python3
"""One allowlisted offline source worker with kernel CPU/memory caps and its own deadline."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from ueba_research_artifacts import commit, private_directory, publish

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"


def command(args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def run(source, frozen, output, mode, fold, seconds, attempt, comparison_source=None):
    name = f"flare-risk-source-{mode}-f{fold}-v2-a{attempt}"
    if command(["docker", "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"]):
        raise RuntimeError("EXISTING_WORKER_MUST_BE_OBSERVED_NOT_RESTARTED")
    if (command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Os}}/{{.Architecture}}"])
            != IMAGE + " linux/amd64"):
        raise ValueError("pinned worker image changed")
    base = Path(json.loads((source / "java-overlay-stream/identity.private.json").read_text())["base_workspace"])
    mounts = [(source, True), (frozen, True), (base, True), (Path(__file__).parent, True), (output, False)]
    if mode in ("ratio-check", "ratio-pilot", "boundary-check", "boundary-pilot", "calibration-diagnosis", "projection-check", "projection-pilot", "consensus-pilot", "replication-check", "replication-pilot"):
        if comparison_source is None:
            raise ValueError("ratio research requires its immutable prior comparison source")
        mounts.append((comparison_source, True))
    mounts += [(ROOT / "backend/src/main/java/com/flarefitness/backend" / suffix, True) for suffix in (
        "ops/PostLoginFeatureExport.java", "service/siem/PostLoginRiskContextFeatures.java")]
    args = ["docker", "create", "--init", "--name", name, "--network", "none", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "128", "--user", f"{os.geteuid()}:{os.getegid()}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=134217728",
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "OMP_NUM_THREADS=2",
            "--env", "OPENBLAS_NUM_THREADS=2", "--env", "PYTHONPATH=" + str(frozen)]
    for path, readonly in mounts:
        args += ["--mount", f"type=bind,src={path},dst={path}" + (",readonly" if readonly else "")]
    program = {"recovery": "postlogin_risk_recovery.py", "pilot": "postlogin_risk_pilot.py",
               "resume-check": "postlogin_risk_resume_check.py", "pilot-check": "postlogin_risk_pilot_check.py",
               "ratio-check": "postlogin_risk_ratio_pilot.py", "ratio-pilot": "postlogin_risk_ratio_pilot.py",
               "boundary-check": "postlogin_risk_boundary_pilot.py", "boundary-pilot": "postlogin_risk_boundary_pilot.py",
               "calibration-diagnosis": "postlogin_risk_calibration_diagnosis.py",
               "projection-check": "postlogin_risk_projection_pilot.py", "projection-pilot": "postlogin_risk_projection_pilot.py",
               "consensus-pilot": "postlogin_risk_consensus_pilot.py",
               "replication-check": "postlogin_risk_replication.py", "replication-pilot": "postlogin_risk_replication.py"}.get(mode, "postlogin_risk_source.py")
    args += ["--entrypoint", "/usr/bin/timeout", IMAGE, "--signal=TERM", "--kill-after=5s", str(seconds),
             "python", "-B", str(Path(__file__).with_name(program)),
             "--source", str(source), "--frozen-code", str(frozen), "--output", str(output),
             "--fold", str(fold), "--maximum-seconds", str(max(1, seconds - 10))]
    if mode in ("benchmark", "generate"):
        args += ["--mode", mode]
    if mode in ("ratio-check", "ratio-pilot", "boundary-check", "boundary-pilot", "calibration-diagnosis", "projection-check", "projection-pilot", "consensus-pilot", "replication-check", "replication-pilot"):
        args += ["--comparison-source", str(comparison_source), "--mode", mode]
    container = command(args)
    try:
        config = json.loads(command(["docker", "inspect", container, "--format", "{{json .HostConfig}} "]))
        if (config["Memory"] != 2 * 1024**3 or config["NanoCpus"] != 2_000_000_000
                or config["NetworkMode"] != "none" or not config["ReadonlyRootfs"] or config["PidsLimit"] != 128):
            raise ValueError("worker resource isolation differs from approved caps")
        operator_path = output / "operator-state.private.json"
        operator = json.loads(operator_path.read_text())
        operator.update(status="SOURCE_WORKER_" + mode.upper() + "_STARTING",
                        active_handle={"kind": "docker", "id": container, "name": name})
        publish(operator_path, operator)
        started = subprocess.run(["docker", "start", "-a", container], timeout=seconds + 30)
        state = json.loads(command(["docker", "inspect", container, "--format", "{{json .State}} "]))
        commit(output, {"container": name, "image_id": IMAGE, "mode": mode, "fold": fold,
                       "maximum_seconds": seconds, "cpu_maximum": 2, "memory_maximum_bytes": config["Memory"],
                       "network": config["NetworkMode"], "exit_code": state["ExitCode"],
                       "oom_killed": state["OOMKilled"], "started_at": state["StartedAt"], "finished_at": state["FinishedAt"]},
               phase=f"worker-{mode}-f{fold}-a{attempt}")
        return state["ExitCode"] if not state["OOMKilled"] else 137
    finally:
        if command(["docker", "inspect", container, "--format", "{{.State.Running}} "]) == "true":
            subprocess.run(["docker", "stop", "--time", "1", container], check=True, timeout=15)
        subprocess.run(["docker", "rm", container], check=True, timeout=15)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--mode", choices=("benchmark", "generate", "recovery", "pilot", "resume-check", "pilot-check", "ratio-check", "ratio-pilot", "boundary-check", "boundary-pilot", "calibration-diagnosis", "projection-check", "projection-pilot", "consensus-pilot", "replication-check", "replication-pilot"), required=True)
    p.add_argument("--comparison-source", type=Path)
    p.add_argument("--fold", type=int, choices=(1, 2, 3), default=1)
    p.add_argument("--maximum-seconds", type=int, required=True)
    p.add_argument("--attempt", type=int, default=1)
    a = p.parse_args()
    if not 30 <= a.maximum_seconds <= 7200 or not 1 <= a.attempt <= 9:
        raise ValueError("bounded worker deadline and attempt required")
    raise SystemExit(run(private_directory(a.source), a.frozen_code.resolve(), private_directory(a.output),
                         a.mode, a.fold, a.maximum_seconds, a.attempt,
                         a.comparison_source.resolve() if a.comparison_source else None))
