#!/usr/bin/env python3
"""Read-only one-hour HTTP/container stability gate for a disposable CI project.

This is application/pipeline stability evidence, not fixed-model qualification.
The surrounding runtime workflow verifies ELK ingestion and restart recovery.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
GIB = 1024 ** 3
STATE_FORMAT = ('{"id":"{{.Id}}","running":{{.State.Running}},'
                '"oom":{{.State.OOMKilled}},"restarts":{{.RestartCount}},'
                '"health":"{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"}')


def validate_states(states, baseline=None):
    if len(states) < 10 or len({row["id"] for row in states}) != len(states):
        raise RuntimeError("Incomplete isolated stack")
    for row in states:
        if not row["running"] or row["oom"] or row["health"] not in {"healthy", "none"}:
            raise RuntimeError("Container unhealthy, stopped or OOM-killed")
    if baseline is not None and sorted(states, key=lambda row: row["id"]) != baseline:
        raise RuntimeError("Container state or restart count changed during observation")
    return sorted(states, key=lambda row: row["id"])


def read_json(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("HTTP response exceeded the bounded probe size")
    return json.loads(body)


def observe(seconds, probe, *, clock=time.monotonic, sleep=time.sleep, progress=lambda _: None):
    started = clock()
    result = {"status": "RUNNING", "cycles": 0, "http_evaluations": 0,
              "continuous_seconds": 0, "minimum_available_bytes": None, "minimum_free_bytes": None,
              "model_training_requested": False, "fixed_model_qualified": False}
    while True:
        memory, disk = probe()
        result["cycles"] += 1
        result["http_evaluations"] += 4
        result["continuous_seconds"] = clock() - started
        for key, value in [("minimum_available_bytes", memory), ("minimum_free_bytes", disk)]:
            result[key] = value if result[key] is None else min(result[key], value)
        progress(result)
        if result["continuous_seconds"] >= seconds:
            return result
        sleep(min(60, seconds - result["continuous_seconds"]))


def main(output, seconds):
    project = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if os.environ.get("GITHUB_ACTIONS") != "true" or not re.fullmatch(r"pbl4-observability-runtime-\d+-\d+", project):
        raise RuntimeError("Only the disposable GitHub runtime project is allowed")
    runtime = (ROOT / "observability/runtime").resolve()
    if output.is_symlink() or not output.resolve().is_relative_to(runtime) or output.exists():
        raise RuntimeError("A new receipt inside the CI runtime directory is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    identifiers = subprocess.check_output(["docker", "ps", "-q", "--filter",
        "label=com.docker.compose.project=" + project], text=True, timeout=15).split()
    if len(identifiers) < 10:
        raise RuntimeError("Expected the complete isolated runtime stack")

    def states():
        rows = subprocess.check_output(["docker", "inspect", "--format", STATE_FORMAT, *identifiers],
                                       text=True, timeout=15)
        return [json.loads(row) for row in rows.splitlines()]

    baseline = validate_states(states())
    port = int(os.environ.get("LOCAL_LAB_WEB_PORT", "8088"))
    if not 1 <= port <= 65535:
        raise RuntimeError("Invalid loopback port")

    def probe():
        validate_states(states(), baseline)
        memory = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                          if line.startswith("MemAvailable:"))) * 1024
        disk = shutil.disk_usage(ROOT).free
        if memory < 3 * GIB or disk < 30 * GIB:
            raise RuntimeError("Resource reserve below 3 GiB RAM or 30 GiB disk")
        gateway = read_json(f"http://127.0.0.1:{port}/healthz")
        if gateway.get("status") != "UP" or gateway.get("redis_state") != "UP":
            raise RuntimeError("Gateway or Redis unavailable")
        for url in [f"http://127.0.0.1:{port}/api/health", "http://127.0.0.1:8089/api/health"]:
            if read_json(url).get("status") != "UP":
                raise RuntimeError("Application or recovery API unavailable")
        if not isinstance(read_json(f"http://127.0.0.1:{port}/api/products"), (dict, list)):
            raise RuntimeError("Catalogue returned invalid JSON")
        return memory, disk

    def publish(result):
        pending = output.with_suffix(".pending")
        with pending.open("x") as handle:
            json.dump(result, handle, indent=2)
        pending.replace(output)

    try:
        result = observe(seconds, probe, progress=publish)
        if result["cycles"] < 30:
            raise RuntimeError("Fewer than 30 complete HTTP cycles")
        result["status"] = "CI_RUNTIME_ONE_HOUR_PASS"
        publish(result)
        print(json.dumps(result))
    except Exception as error:
        publish({"status": "FAILED", "error_type": type(error).__name__, "reason": str(error),
                 "fixed_model_qualified": False})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=3600)
    args = parser.parse_args()
    if not 3600 <= args.seconds <= 7200:
        parser.error("Stability evidence requires 3600–7200 continuous seconds")
    main(args.output, args.seconds)
