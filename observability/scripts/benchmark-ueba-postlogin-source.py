#!/usr/bin/env python3
"""P3 source preflight: representative standard/labeled measurements, zero fits."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import resource
import signal
import subprocess
import time

import postlogin_pilot_data as data
from ueba_research_artifacts import canonical, commit, digest, private_directory, publish


def measured_specs():
    calibration = list(data.specifications(1, "calibration"))
    validation = list(data.specifications(1, "validation"))
    fitting = list(data.specifications(1, "fit"))
    standard = [calibration[i * 313 % 5000] for i in range(16)]
    standard += [calibration[5000 + i * 313 % 5000] for i in range(16)]
    standard += [validation[14000 + i * 251 % 4000] for i in range(16)]
    labeled = [fitting[i * 83 % 3000] for i in range(36)]
    labeled += [fitting[3000 + i * 79 % 800] for i in range(10)]
    labeled += [fitting[3800], fitting[3999]]
    return [("standard", spec) for spec in standard] + [("labeled", spec) for spec in labeled]


def classpath(output):
    overlay = output / "java-overlay-stream"
    identity = json.loads((overlay / "identity.private.json").read_text())
    for relative, expected in identity["overlay_classes_sha256"].items():
        if digest(overlay / "classes" / relative) != expected: raise ValueError("Java overlay changed")
    checker = Path(__file__).with_name("audit-ueba-postlogin-representation.py")
    spec = importlib.util.spec_from_file_location("pilot_workspace", checker)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    base, _ = module.pinned_workspace(identity["base_workspace"], identity["base_workspace_snapshot_sha256"])
    return str(overlay / "classes") + ":" + base


def run(output):
    started = time.monotonic(); output = private_directory(output)
    def expired(*_): raise TimeoutError("P3 source benchmark exceeded the 180-second predeclared cap")
    signal.signal(signal.SIGALRM, expired); signal.alarm(180)
    specs = measured_specs()
    protocol = {"phase": "P3_SOURCE_BENCHMARK", "maximum_rows": 96, "maximum_wall_seconds": 180,
        "maximum_frame_bytes": 2 * 1024**2, "runner_sha256": digest(__file__),
        "data_source_sha256": digest(Path(data.__file__)), "source_protocol": data.protocol(),
        "overlay_identity_sha256": digest(output / "java-overlay-stream/identity.private.json"),
        "scope": "Separate representative standard and labeled batches; not quality, qualification, or a fitted-unit benchmark.",
        "fit_calls": 0, "holdout_access": False}
    protocol_path = output / "p3-source-benchmark.protocol.private.json"
    if protocol_path.exists() and json.loads(protocol_path.read_text()) != protocol: raise ValueError("benchmark protocol changed")
    publish(protocol_path, protocol, maximum=32 * 1024)
    samples = []; timing = Counter(); sizes = Counter(); seen = Counter()
    log_path = output / "p3-source-benchmark.java.log"
    with log_path.open("ab") as log:
        log_path.chmod(0o600)
        java = subprocess.Popen(["java", "-Xmx256m", "-cp", classpath(output),
            "com.flarefitness.backend.ops.PostLoginFeatureExport", "--demo-only"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        try:
            for kind, specification in specs:
                row_start = time.monotonic()
                frame, metadata = data.build(specification)
                for baseline in frame["baseline_frames"]:
                    warmup = (canonical({"baseline_frame": baseline}) + "\n").encode()
                    if len(warmup) > protocol["maximum_frame_bytes"]: raise ValueError("warmup frame byte bound exceeded")
                    java.stdin.write(warmup); java.stdin.flush()
                    acknowledgement = java.stdout.readline(32 * 1024)
                    if not acknowledgement or json.loads(acknowledgement).get("warmup_frame_id") != baseline["frame_id"]:
                        raise ValueError("baseline stream correspondence failed")
                    sizes[kind + "/" + metadata["cohort"]] += len(warmup)
                frame["baseline_frames"] = []
                raw = (canonical(frame) + "\n").encode()
                if len(raw) > protocol["maximum_frame_bytes"]: raise ValueError("source frame exceeds actual producer byte bound")
                java.stdin.write(raw); java.stdin.flush()
                line = java.stdout.readline(32 * 1024)
                if not line or len(line) >= 32 * 1024: raise ValueError("Java exporter refused representative source")
                numeric = json.loads(line)
                if (numeric["frame_id"] != metadata["frame_id"] or numeric["representation_version"] != "postlogin-before-action-v1"
                        or numeric["baseline_established"] != (metadata["cohort"] != "COLD")
                        or len(numeric["baseline_features"]) != 37 or len(numeric["postlogin_features"]) != 20
                        or numeric["postlogin_features"][2] != 1):
                    raise ValueError("source/Java representation, cohort or session coverage parity failed")
                key = kind + "/" + metadata["cohort"]
                timing[key] += time.monotonic() - row_start; seen[key] += 1; sizes[key] += len(raw)
                samples.append({**metadata, "baseline_features": numeric["baseline_features"], "postlogin_features": numeric["postlogin_features"]})
            java.stdin.close()
            if java.stdout.read(1) or java.wait(timeout=15): raise ValueError("Java source benchmark did not terminate cleanly")
        finally:
            if java.poll() is None:
                java.kill(); java.wait(timeout=10)
    publish(output / "p3-source-benchmark.numeric.private.json", {"rows": samples}, maximum=512 * 1024)
    # A conservative generation projection only; actual fitting/validation still
    # needs its own timing and must fit the remaining shared two-hour budget.
    ready = timing["standard/READY"] / seen["standard/READY"]
    unseen = timing["standard/UNSEEN_READY"] / seen["standard/UNSEEN_READY"]
    cold = timing["standard/COLD"] / seen["standard/COLD"]
    labeled = timing["labeled/READY"] / seen["labeled/READY"]
    projection = 1.5 * (23700 * max(ready, labeled) + 4200 * unseen + 7100 * cold)
    receipt = {"phase": "P3_SOURCE_BENCHMARK", "status": "SOURCE_PREFLIGHT_PASS",
        "protocol_sha256": digest(protocol_path), "rows": len(samples), "rows_per_kind_cohort": dict(seen),
        "generation_and_java_seconds_per_kind_cohort": dict(timing), "raw_bytes_per_kind_cohort": dict(sizes),
        "projected_one_fold_generation_seconds_with_50_percent_margin": round(projection, 3),
        "generation_projection_only_not_fitted_unit_eta": True, "actual_fitted_unit_measured": False,
        "additional_fit_calls": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False,
        "elapsed_seconds": round(time.monotonic() - started, 3), "peak_rss_kib_self": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "peak_rss_kib_child": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
    if projection >= 7200: receipt["status"] = "STOP_BUDGET"
    proof = commit(output, receipt, phase="p3-source-benchmark")
    state = json.loads((output / "operator-state.private.json").read_text())
    state.update(phase="P3_PREPARATION", status=receipt["status"], last_verified_commit=proof, active_handle=None,
        pilot_job_wall_seconds_used=receipt["elapsed_seconds"], next_action="Check cumulative budget and publication/recovery fixture before any fit")
    publish(output / "operator-state.private.json", state)
    print(canonical({key: receipt[key] for key in ("status", "rows", "elapsed_seconds", "projected_one_fold_generation_seconds_with_50_percent_margin", "additional_fit_calls")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.absolute())
