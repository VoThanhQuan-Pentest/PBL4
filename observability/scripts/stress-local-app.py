#!/usr/bin/env python3
"""Real benign local application ramp/soak with trace conservation in ELK.

Refuses AWS/non-loopback origins and anything except the existing owned local
gateway. No auth guessing, attack payloads, provider calls or primary promotion.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROJECT = "flare-local-elk"
CONTAINERS = {name: PROJECT + "-" + name + "-1" for name in ("gateway", "app", "nginx", "ueba-worker", "filebeat", "logstash", "elasticsearch")}
DEFAULT_STAGES = (("RAMP_1", 1, 300), ("RAMP_5", 5, 300), ("RAMP_10", 10, 300), ("RAMP_25", 25, 300), ("SOAK", 10, 3600))
PATHS = ("/api/health", "/api/products", "/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def docker(*args, data=None, timeout=15):
    result = subprocess.run(["docker", *args], input=data, capture_output=True, text=True, timeout=timeout)
    if result.returncode: raise RuntimeError("owned Docker operation failed")
    return result.stdout.strip()


def inspect(name): return json.loads(docker("inspect", name))[0]


def verify_target(origin, gateway):
    value = urllib.parse.urlsplit(origin)
    if (value.scheme != "http" or value.hostname != "127.0.0.1" or value.username or value.password or value.path not in ("", "/")
            or value.query or value.fragment or value.port is None): raise ValueError("explicit local-only test origin required")
    if gateway["Config"].get("Labels", {}).get("com.docker.compose.project") != PROJECT or not gateway["State"]["Running"]:
        raise ValueError("owned local gateway is not running")
    ports = gateway["HostConfig"].get("PortBindings", {}).get("8082/tcp", [])
    if not any(row.get("HostIp") == "127.0.0.1" and row.get("HostPort") == str(value.port) for row in ports):
        raise ValueError("target is not the inspected local gateway socket")
    return origin.rstrip("/")


def probe(origin, number, run_id):
    started = time.monotonic()
    request = urllib.request.Request(origin + PATHS[number % len(PATHS)], headers={"User-Agent": "Flare-Owned-Local-Load/1.0", "X-Flare-Lab-Run": run_id})
    status, trace, error = 0, "", None
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=5) as response:
            status = response.status; trace = response.headers.get("X-Request-ID", ""); response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as failure:
        status = failure.code; trace = failure.headers.get("X-Request-ID", "")
    except (urllib.error.URLError, TimeoutError, OSError): error = "TRANSPORT"
    return {"number": number, "status": status, "trace_id": trace, "latency_seconds": time.monotonic() - started, "error": error}


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def assess_service_stability(before, after, *, collector_recovery_exercised):
    unexpected_restarts, oom_killed, unavailable = [], [], []
    for name, current in after.items():
        previous = before[name]
        restart_delta = current["restart_count"] - previous["restart_count"]
        expected_filebeat_restart = (name == CONTAINERS["filebeat"]
                                     and collector_recovery_exercised and restart_delta == 1)
        if restart_delta != 0 and not expected_filebeat_restart:
            unexpected_restarts.append(name)
        if current["oom_killed"]:
            oom_killed.append(name)
        if not current["running"] or (current["health"] is not None and current["health"] != "healthy"):
            unavailable.append(name)
    return {"passed": not unexpected_restarts and not oom_killed and not unavailable,
            "unexpected_restarts": unexpected_restarts,
            "oom_killed_containers": oom_killed,
            "unavailable_containers": unavailable}


def primary_version():
    value = docker("exec", CONTAINERS["ueba-worker"], "python", "-c",
                   "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8091/health',timeout=3))['model_version'])")
    return value


def elastic_counts(traces):
    query = {"size": 0, "query": {"terms": {"trace.id": traces}}, "aggs": {"traces": {"terms": {"field": "trace.id", "size": len(traces)}}}}
    # Credentials are expanded only inside the existing Elasticsearch container,
    # never in host argv, evidence, command output or a URL.
    program = 'password=$(cat /run/flare-secrets/elasticsearch.password); curl --fail --silent --show-error --max-time 8 --cacert /usr/share/elasticsearch/config/certs/ca.crt --user "elastic:${password}" -H "Content-Type: application/json" --data-binary @- https://localhost:9200/logs-nginx.access-lab/_search'
    result = json.loads(docker("exec", "-i", CONTAINERS["elasticsearch"], "bash", "-ceu", program, data=json.dumps(query), timeout=12))
    return {row["key"]: row["doc_count"] for row in result["aggregations"]["traces"]["buckets"]}


def write(path, value):
    temporary = path.with_suffix(".tmp"); temporary.write_text(json.dumps(value, sort_keys=True, allow_nan=False)); temporary.chmod(0o600); temporary.replace(path)


def run(origin, directory, *, stages=DEFAULT_STAGES, recover_filebeat=False):
    if directory.exists() or directory.is_symlink(): raise ValueError("new private owned load-run directory required")
    origin = verify_target(origin, inspect(CONTAINERS["gateway"]))
    container_info = {}
    for name in CONTAINERS.values():
        info = inspect(name)
        if not info["State"]["Running"] or info["Config"].get("Labels", {}).get("com.docker.compose.project") != PROJECT:
            raise ValueError("the full existing local stack must be running")
        container_info[name] = info
    directory.mkdir(mode=0o700, parents=True)
    run_id = uuid.uuid4().hex; before = primary_version(); accepted, latencies, phases = [], [], []
    statuses = {}; failures = 0; total = 0; recovered = False; resources = []; phase = None
    full = stages == DEFAULT_STAGES
    state = {"status": "RUNNING", "run_id": run_id, "target": origin, "operator_process_pid": os.getpid(), "full_plan": full,
             "primary_before": before, "data_provenance": "DEMO_ONLY", "evaluation_scope": "LOCAL_APPLICATION_LOAD", "quality_gate": "NOT_APPLICABLE"}
    images = {name: info["Image"] for name, info in container_info.items()}
    service_state_before = {name: {"running": info["State"]["Running"],
                                   "restart_count": info["RestartCount"],
                                   "oom_killed": info["State"]["OOMKilled"],
                                   "health": info["State"].get("Health", {}).get("Status")}
                            for name, info in container_info.items()}
    write(directory / "progress.json", state | {"image_ids": images, "service_state_before": service_state_before})
    journal = directory / "requests.jsonl"
    try:
        with journal.open("x") as output, ThreadPoolExecutor(max_workers=32) as pool:
            journal.chmod(0o600)
            for phase, rate, seconds in stages:
                phase_start = time.monotonic(); pending = set(); phase_sent = 0; phase_latencies = []; phase_failures = 0; next_tick = phase_start
                while time.monotonic() - phase_start < seconds or pending:
                    now = time.monotonic()
                    if now - phase_start < seconds and now >= next_tick and len(pending) < 32:
                        pending.add(pool.submit(probe, origin, total, run_id)); total += 1; phase_sent += 1; next_tick += 1 / rate
                    for future in tuple(pending):
                        if not future.done(): continue
                        row = future.result(); pending.remove(future); output.write(json.dumps(row | {"phase": phase}, sort_keys=True) + "\n")
                        statuses[str(row["status"])] = statuses.get(str(row["status"]), 0) + 1
                        latencies.append(row["latency_seconds"]); phase_latencies.append(row["latency_seconds"])
                        if row["status"] == 200:
                            if not re.fullmatch(r"[a-f0-9]{32}", row["trace_id"]): raise ValueError("successful request has no server-owned trace")
                            accepted.append(row["trace_id"])
                        if row["status"] not in (200, 429) or row["error"]: failures += 1; phase_failures += 1
                    if now - phase_start > seconds + 10: raise RuntimeError("request backlog exceeded bounded drain time")
                    if now % 30 < 0.1:
                        output.flush(); write(directory / "progress.json", state | {"image_ids": images,
                              "service_state_before": service_state_before, "phase": phase,
                              "sent": total, "received": sum(statuses.values()),
                              "unexpected_failures": failures})
                    time.sleep(0.01)
                phases.append({"phase": phase, "target_rps": rate, "elapsed_seconds": time.monotonic() - phase_start, "requests": phase_sent,
                               "actual_rps": phase_sent / max(time.monotonic() - phase_start, 0.001),
                               "p95_seconds": percentile(phase_latencies, 0.95), "unexpected_failures": phase_failures})
                resources.append({"phase": phase, "stats": docker("stats", "--no-stream", "--format", "{{json .}}", *CONTAINERS.values(), timeout=20)})
                if phase == "RAMP_25" and recover_filebeat:
                    # Controlled local buffering check; the finally clause always
                    # restores the exact owned collector, never another service.
                    docker("stop", "--time", "3", CONTAINERS["filebeat"])
                    try:
                        for number in range(10):
                            row = probe(origin, total + number, run_id); output.write(json.dumps(row | {"phase": "COLLECTOR_BUFFER"}) + "\n")
                            if row["status"] != 200 or not re.fullmatch(r"[a-f0-9]{32}", row["trace_id"]): raise ValueError("buffer probe failed")
                            accepted.append(row["trace_id"])
                            statuses["200"] = statuses.get("200", 0) + 1; latencies.append(row["latency_seconds"])
                    finally: docker("start", CONTAINERS["filebeat"])
                    total += 10; recovered = True
        if len(set(accepted)) != len(accepted): raise ValueError("server trace collision or duplicate acknowledgement")
        counts = {}; deadline = time.monotonic() + 90
        for start in range(0, len(accepted), 1000):
            group = accepted[start:start + 1000]
            while True:
                observed = elastic_counts(group)
                if all(observed.get(trace) == 1 for trace in group): counts.update(observed); break
                if time.monotonic() >= deadline: raise ValueError("missing or duplicate acknowledged access traces in ELK")
                time.sleep(1)
        after = primary_version()
        final_info = {name: inspect(name) for name in CONTAINERS.values()}
        service_state_after = {name: {"running": info["State"]["Running"],
                                      "restart_count": info["RestartCount"],
                                      "oom_killed": info["State"]["OOMKilled"],
                                      "health": info["State"].get("Health", {}).get("Status")}
                               for name, info in final_info.items()}
        stability = assess_service_stability(service_state_before, service_state_after,
                                             collector_recovery_exercised=recovered)
        service_stability_pass = stability["passed"]
        pass_load = (full and failures / max(total, 1) < 0.01 and after == before and service_stability_pass
                     and sum(statuses.values()) == total
                     and all(row["p95_seconds"] is not None and row["p95_seconds"] <= 1
                             and row["actual_rps"] >= 0.9 * row["target_rps"] for row in phases))
        result = state | {"status": "COMPLETED", "load_gate": "PASS" if pass_load else "FAIL" if full else "SMOKE_ONLY",
                          "total_requests": total, "status_counts": statuses, "unexpected_failures": failures, "phases": phases, "resources": resources,
                          "acknowledged_successful_traces": len(accepted), "actual_unique_elk_documents": len(counts), "missing_or_duplicate_traces": 0,
                          "collector_recovery_exercised": recovered, "primary_after": after, "primary_changed": after != before,
                          "service_state_before": service_state_before, "service_state_after": service_state_after,
                          "service_stability_gate": "PASS" if service_stability_pass else "FAIL",
                          "unexpected_restarts": stability["unexpected_restarts"],
                          "oom_killed_containers": stability["oom_killed_containers"],
                          "unavailable_containers": stability["unavailable_containers"],
                          "request_journal_sha256": hashlib.sha256(journal.read_bytes()).hexdigest(), "image_ids": images,
                          "completed_at_utc": datetime.now(timezone.utc).isoformat()}
        write(directory / "result.json", result); write(directory / "progress.json", result); return result
    except KeyboardInterrupt:
        write(directory / "progress.json", state | {"status": "INTERRUPTED", "phase": phase,
              "image_ids": images, "service_state_before": service_state_before,
              "sent": total, "received": sum(statuses.values()), "unexpected_failures": failures,
              "error_type": "KeyboardInterrupt", "reason": "Operator interrupted the owned local load run.",
              "collector_recovery_exercised": recovered,
              "interrupted_at_utc": datetime.now(timezone.utc).isoformat()})
        raise
    except Exception as failure:
        write(directory / "progress.json", state | {"status": "FAILED", "image_ids": images,
              "service_state_before": service_state_before, "phase": phase,
              "sent": total, "received": sum(statuses.values()),
              "unexpected_failures": failures, "error_type": type(failure).__name__,
              "reason": str(failure)}); raise


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", type=Path, required=True); parser.add_argument("--recover-filebeat", action="store_true"); parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(); stages = (("SMOKE", 1, 5),) if args.smoke else DEFAULT_STAGES
    result = run(args.target, args.output_dir, stages=stages, recover_filebeat=args.recover_filebeat)
    print(json.dumps({name: result[name] for name in ("status", "load_gate", "total_requests", "missing_or_duplicate_traces", "primary_changed")}))


if __name__ == "__main__": main()
