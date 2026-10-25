#!/usr/bin/env python3
"""Actual SIGKILL/resume through the production raw-to-Java source batch path.

Fixtures stay in a separate directory and can never satisfy full split counts.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from postlogin_risk_probe import frozen_generator
from postlogin_risk_rolling import java_classpath
from postlogin_risk_data import Sampler
from postlogin_risk_source import source_batch, resource_limits
from ueba_research_artifacts import commit, digest, private_directory


def child(source, frozen, output, directory, interrupt):
    data = frozen_generator(source, frozen)
    cp = java_classpath(source, output)
    sampler = Sampler(data, 1, "fit")
    for offset in (0, 32):
        binding = {"scope": "RECOVERY_FIXTURE_NEVER_TRAINING", "offset": offset, "count": 32}
        source_batch(directory, f"fixture-batch-{offset:02d}", binding, sampler, cp)
        if interrupt:
            os.kill(os.getpid(), signal.SIGKILL)


def run(source, frozen, output):
    if not resource_limits()["verified"]:
        raise RuntimeError("capped offline worker required")
    fixture = output / "source-recovery-fixture-v1"
    fixture.mkdir(mode=0o700)
    baseline, recovered = fixture / "uninterrupted", fixture / "interrupted"
    baseline.mkdir(mode=0o700); recovered.mkdir(mode=0o700)
    common = [sys.executable, "-B", str(Path(__file__)), "--source", str(source), "--frozen-code", str(frozen),
              "--output", str(output), "--maximum-seconds", "120"]
    interrupted = subprocess.run([*common, "--child-directory", str(recovered), "--interrupt"], timeout=60)
    if interrupted.returncode != -signal.SIGKILL:
        raise ValueError("fixture must demonstrate a real SIGKILL after the first durable batch")
    first = recovered / "fixture-batch-00.receipt.private.json"
    retained = digest(first)
    subprocess.run([*common, "--child-directory", str(recovered)], check=True, timeout=90)
    subprocess.run([*common, "--child-directory", str(baseline)], check=True, timeout=90)
    if digest(first) != retained:
        raise ValueError("recovery rewrote a committed source batch")
    for offset in (0, 32):
        name = f"fixture-batch-{offset:02d}.receipt.private.json"
        if digest(baseline / name) != digest(recovered / name):
            raise ValueError("resumed production source differs from uninterrupted source")
    result = {"status": "SOURCE_SIGKILL_RECOVERY_PASS", "actual_sigkill_exit_code": interrupted.returncode,
              "retained_first_batch_sha256": retained, "resumed_rows": 64,
              "uninterrupted_rows": 64, "old_batch_unchanged": True, "byte_parity": True,
              "production_path": "postlogin_risk_source.source_batch", "new_fits": 0,
              "fixture_not_training_data": True, "holdout_scored": False}
    proof = commit(output, result, phase="source-sigkill-recovery")
    print(json.dumps({"status": result["status"], "receipt": proof}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--maximum-seconds", type=int, required=True)
    p.add_argument("--fold", type=int, default=1)
    p.add_argument("--child-directory", type=Path)
    p.add_argument("--interrupt", action="store_true")
    a = p.parse_args()
    source, output = private_directory(a.source), private_directory(a.output)
    if a.child_directory:
        child(source, a.frozen_code.resolve(), output, private_directory(a.child_directory), a.interrupt)
    else:
        run(source, a.frozen_code.resolve(), output)
