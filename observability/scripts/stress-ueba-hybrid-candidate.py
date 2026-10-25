#!/usr/bin/env python3
"""Owned isolated candidate-only performance load; repeated rows are NOT quality samples."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
CANDIDATE = "bulk_hybrid_calibrated_42"
KIND = "normal_plus_incident_research"
FORMAT = "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1"
LABEL = "flare.ueba.candidate-stress.run"
DRIVER_LABEL = "flare.ueba.candidate-stress.driver"
STAGES = (("RAMP_1", 1, 30), ("RAMP_5", 5, 30), ("RAMP_10", 10, 30), ("RAMP_25", 25, 30), ("SOAK_5", 5, 300))
BATCH_SIZE = 10
CLIENTS = 8
BOOTSTRAP = '''import resource
from fastapi import Depends
from sklearn.ensemble import HistGradientBoostingClassifier
from app.normal_support import NormalSupportScorer
from app.hybrid_incident import HybridIncidentScorer
from app.model import ModelStore
counts = {"fits": 0, "activation": 0, "recalibration": 0}
def denied(kind):
    def reject(*args, **kwargs):
        counts[kind] += 1
        raise RuntimeError("owned stress forbids mutation")
    return reject
for cls in (HistGradientBoostingClassifier, NormalSupportScorer, HybridIncidentScorer):
    cls.fit = denied("fits")
ModelStore.train = denied("fits")
ModelStore.activate = denied("activation")
ModelStore.recalibrated_candidate = denied("recalibration")
from app.main import app, store, require_token
from contextlib import asynccontextmanager
@asynccontextmanager
async def candidate_only_lifespan(_app):
    yield
app.router.lifespan_context = candidate_only_lifespan
@app.get("/owned/stress-profile", dependencies=[Depends(require_token)])
def profile():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return dict(counts, active_version=store().active_version,
                cpu_seconds=usage.ru_utime + usage.ru_stime, peak_rss_kib=usage.ru_maxrss)
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8091, log_level="warning")
'''
BOOTSTRAP_UDS = BOOTSTRAP.replace(
    'uvicorn.run(app, host="0.0.0.0", port=8091, log_level="warning")',
    'uvicorn.run(app, uds="/socket/worker.sock", log_level="warning")')
DRIVER = r'''import concurrent.futures
import http.client
import json
import math
import os
from pathlib import Path
import socket
import time
import urllib.parse

ROOT = Path("/owned")
SOCKET = "/socket/worker.sock"
config = json.loads((ROOT / "stress-input.json").read_text())
token = (ROOT / "token").read_text()
candidate = config["candidate_version"]
metadata = config["metadata"]
rows = config["rows"]
stages = config["stages"]
batch_size = config["batch_size"]
clients = config["client_workers"]
policy = json.loads(metadata["score_policy"]["policy_document_json"])

class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)

def call(path, payload=None, timeout=15):
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    connection = UnixConnection("localhost", timeout=timeout)
    headers = {"X-UEBA-Token": token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request("GET" if body is None else "POST", path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read(2 * 1024 * 1024 + 1)
    connection.close()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("bounded candidate response required")
    try:
        return response.status, json.loads(raw)
    except ValueError:
        raise ValueError("candidate response must be JSON") from None

def validate(value, payload):
    if (type(value) is not dict or value.get("available") is not True or value.get("model_version") != candidate
            or value.get("feature_schema_version") != 4 or value.get("feature_names") != metadata["feature_names"]
            or value.get("calibration_sha256") != metadata["calibration_sha256"]
            or value.get("score_policy") != metadata["score_policy"]
            or type(value.get("results")) is not list or len(value["results"]) != len(payload["vectors"])):
        raise ValueError("candidate response identity/shape mismatch")
    for row, cohort in zip(value["results"], payload["cohorts"]):
        raw, percentile = row.get("raw_anomaly_score"), row.get("normal_percentile")
        if (type(raw) not in (int, float) or type(percentile) not in (int, float)
                or not math.isfinite(raw) or not math.isfinite(percentile) or not 0 <= percentile <= 100
                or row.get("scoring_cohort") != cohort):
            raise ValueError("candidate score/cohort is invalid")
        detected = policy["detection_percentile_micro"][cohort] / 1000000
        warning = policy["warning_percentile_micro"] / 1000000
        level = "VERY_UNUSUAL" if percentile >= detected else "UNUSUAL" if percentile >= warning else "NORMAL_RANGE"
        if row.get("level") != level:
            raise ValueError("candidate policy level mismatch")

def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None

def summarize(rows):
    latencies = [row["latency_seconds"] for row in rows]
    statuses = {}
    for row in rows:
        key = str(row["status"])
        statuses[key] = statuses.get(key, 0) + 1
    return {"requests": len(rows), "status_counts": statuses,
            "errors": sum(row["error"] is not None for row in rows),
            "requested_rows": sum(row["requested_rows"] for row in rows),
            "validated_rows": sum(row["validated_rows"] for row in rows),
            "p50_seconds": percentile(latencies, .5), "p95_seconds": percentile(latencies, .95),
            "p99_seconds": percentile(latencies, .99)}

def probe(payload, timeout=15):
    start = time.monotonic(); status = 0; error = None
    try:
        status, value = call("/internal/v1/score-candidate", payload, timeout)
        if status != 200:
            error = "HTTP"
        else:
            validate(value, payload)
    except (OSError, TimeoutError, socket.timeout):
        error = "TRANSPORT"
    except (ValueError, KeyError, TypeError):
        error = "RESPONSE_CONTRACT"
    return {"status": status, "error": error, "latency_seconds": time.monotonic() - start,
            "requested_rows": len(payload["vectors"]),
            "validated_rows": len(payload["vectors"]) if status == 200 and error is None else 0}

def write_new(path, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def main():
    deadline = time.monotonic() + 60
    while True:
        try:
            _, health = call("/health", timeout=2)
            if health.get("model_available") is not False:
                raise ValueError("stress runner refuses an active model")
            break
        except (OSError, TimeoutError, socket.timeout):
            if time.monotonic() >= deadline:
                raise RuntimeError("owned candidate worker did not become ready")
            time.sleep(.25)
    _, initial_profile = call("/owned/stress-profile")
    cold = next(row for row in rows if row[1] == "COLD")
    warm_rows = rows[:batch_size - 1] + [cold]
    warm_payload = {"model_version": candidate, "feature_schema_version": 4,
                    "feature_names": metadata["feature_names"],
                    "vectors": [row[0] for row in warm_rows], "cohorts": [row[1] for row in warm_rows]}
    warm = probe(warm_payload, timeout=120)
    write_new(ROOT / "cold-load.json", warm)
    if warm["status"] != 200 or warm["error"] is not None:
        raise RuntimeError("separate candidate cold-load failed")
    journal_path = ROOT / "requests.jsonl"
    fd = os.open(journal_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    completed = []; phases = []; ordinal = 0
    with os.fdopen(fd, "w") as journal, concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
        for phase, rate, seconds in stages:
            start = time.monotonic(); next_tick = start; pending = set(); phase_rows = []; missed = 0; peak = 0
            while time.monotonic() - start < seconds or pending:
                now = time.monotonic()
                if now - start < seconds and now >= next_tick:
                    if len(pending) < clients:
                        batch = [rows[(ordinal * batch_size + i) % len(rows)] for i in range(batch_size)]
                        payload = {"model_version": candidate, "feature_schema_version": 4,
                                   "feature_names": metadata["feature_names"],
                                   "vectors": [row[0] for row in batch], "cohorts": [row[1] for row in batch]}
                        pending.add(pool.submit(probe, payload)); ordinal += 1
                        peak = max(peak, len(pending))
                    else:
                        missed += 1
                    next_tick = now + 1 / rate
                for future in tuple(pending):
                    if future.done():
                        row = future.result(); pending.remove(future); completed.append(row); phase_rows.append(row)
                        journal.write(json.dumps(row | {"phase": phase}, sort_keys=True) + "\n")
                if now - start > seconds + 20:
                    raise RuntimeError("bounded request drain exceeded")
                time.sleep(.005)
            elapsed = time.monotonic() - start
            result = summarize(phase_rows) | {"phase": phase, "target_rps": rate,
                     "elapsed_seconds": elapsed, "actual_rps": len(phase_rows) / elapsed,
                     "missed_scheduling_ticks": missed, "peak_inflight": peak}
            phases.append(result); journal.flush(); write_new(ROOT / (phase + ".json"), result)
    _, final_profile = call("/owned/stress-profile")
    _, final_health = call("/health")
    if (final_health.get("model_available") is not False or final_profile.get("active_version") is not None
            or any(final_profile.get(key) != 0 for key in ("fits", "activation", "recalibration"))):
        raise ValueError("candidate-only no-mutation profile violated")
    totals = summarize(completed)
    stress_gate = "PASS" if (totals["requests"] > 0 and totals["errors"] == 0
                              and totals["validated_rows"] == totals["requested_rows"]
                              and all(phase["errors"] == 0 for phase in phases)) else "FAIL"
    result = totals | {"status": "COMPLETED", "stress_gate": stress_gate, "phases": phases,
             "profile_before": initial_profile, "profile_after": final_profile,
             "cold_load_warmup": warm, "quality_gate": "NOT_APPLICABLE",
             "independent_quality_samples": 0, "network_mode": "none_unix_socket_only"}
    write_new(ROOT / "result.json", result)
    print(json.dumps({key: result[key] for key in ("status", "requests", "validated_rows", "errors", "p95_seconds")}))

try:
    main()
except BaseException as failure:
    try:
        write_new(ROOT / "failure.json", {"status": "FAILED", "exception_type": type(failure).__name__,
                   "reason": str(failure), "quality_gate": "NOT_APPLICABLE"})
    except BaseException:
        pass
    raise
'''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ResponseContract(ValueError):
    def __init__(self, status):
        super().__init__("bounded JSON candidate response required")
        self.status = status


def docker(*args, timeout=20):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("owned Docker operation failed")
    return result.stdout.strip()


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_write(path, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False) if not isinstance(value, str) else value
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(raw)


def sources(model_dir, catalog):
    if model_dir.is_symlink() or catalog.is_symlink():
        raise ValueError("regular private source directories required")
    model_dir, catalog = model_dir.resolve(strict=True), catalog.resolve(strict=True)
    metadata_file = model_dir / (CANDIDATE + ".json")
    model_file = model_dir / (CANDIDATE + ".joblib")
    for path in (metadata_file, model_file, catalog / "manifest.json"):
        if path.is_symlink() or not path.is_file():
            raise ValueError("regular read-only source artifacts required")
    if metadata_file.stat().st_size > 2 * 1024 * 1024 or (catalog / "manifest.json").stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bounded source metadata required")
    metadata = json.loads(metadata_file.read_text())
    if (metadata.get("model_kind") != KIND or metadata.get("model_state_format") != FORMAT
            or metadata.get("feature_schema_version") != 4 or metadata.get("calibration_scope") != "PILOT_ONLY"
            or metadata.get("data_provenance") != "DEMO_ONLY" or checksum(model_file) != metadata.get("sha256")):
        raise ValueError("verified saved PILOT candidate required")
    for key in ("sha256", "calibration_sha256", "model_state_sha256"):
        if not isinstance(metadata.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", metadata[key]):
            raise ValueError("candidate numeric/binary/calibration identities required")
    if any((model_dir / name).exists() for name in ("active.json", "primary.json")):
        raise ValueError("candidate source must have no active selector")
    manifest = json.loads((catalog / "manifest.json").read_text())
    if manifest.get("stage") != "PILOT" or manifest.get("feature_names") != metadata.get("feature_names"):
        raise ValueError("actual normalized schema-4 PILOT source required")
    rows, source_hashes = [], {}
    for descriptor in manifest["splits"]["fold1-validation"]["shards"]:
        relative = descriptor.get("path", "")
        if not re.fullmatch(r"shards/[a-z0-9_-]+\.json", relative):
            raise ValueError("bounded catalog shard path required")
        path = catalog / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024 or checksum(path) != descriptor.get("sha256"):
            raise ValueError("validation source checksum mismatch")
        source_hashes[str(path)] = descriptor["sha256"]
        batch = json.loads(path.read_text())
        if len(batch) != descriptor["records"] or len(batch) > 5000:
            raise ValueError("bounded actual source shard required")
        for row in batch:
            values = row.get("features")
            if (type(values) is not list or len(values) != 37 or any(type(v) not in (int, float) or not math.isfinite(v) for v in values)
                    or row.get("cohort") not in ("READY", "UNSEEN_READY", "COLD")):
                raise ValueError("normalized numeric source/cohort required")
            # Labels, family and identity deliberately do not enter this pool or request.
            rows.append((values, "COLD" if row["cohort"] == "COLD" else "READY"))
    if len(rows) != 21000:
        raise ValueError("the frozen 21000-row validation source is required")
    source_hashes.update({str(metadata_file): checksum(metadata_file), str(model_file): checksum(model_file),
                          str(catalog / "manifest.json"): checksum(catalog / "manifest.json")})
    for name in ("model.py", "main.py", "contract.py", "normal_support.py", "hybrid_incident.py", "hybrid_semantic.py", "semantic_model.py", "candidate_cache.py"):
        path = ROOT / "ueba-worker/app" / name
        if path.exists(): source_hashes[str(path)] = checksum(path)
    return metadata, rows, source_hashes


def _regular_private(path, *, owner=1000, group=1000, mode=0o640, maximum=8 * 1024 * 1024):
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("candidate package paths cannot contain symlinks")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_gid != group
            or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
            or not 0 < info.st_size <= maximum):
        raise ValueError("bounded owner-controlled candidate artifact required")
    return path


def _strict_package(package_dir, package_sha256):
    package_dir = Path(package_dir).absolute()
    if any(parent.is_symlink() for parent in (package_dir, *package_dir.parents)):
        raise ValueError("candidate package paths cannot contain symlinks")
    info = package_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
            or stat.S_IMODE(info.st_mode) != 0o750):
        raise ValueError("qualified candidate must be the sealed owner-only package directory")
    manifest_path = _regular_private(package_dir / "candidate-package.json", maximum=2 * 1024 * 1024)
    if checksum(manifest_path) != package_sha256:
        raise ValueError("qualified candidate package manifest pin mismatch")
    package = json.loads(manifest_path.read_text())
    version = package.get("model_version") if type(package) is dict else None
    package_fields = {"format", "schema_version", "status", "model_version", "data_provenance", "quality_gate",
        "feature_schema_version", "recipe_id", "original_dataset_id", "original_training_manifest_sha256",
        "selection_receipt_sha256", "fresh_holdout_dataset_id", "fresh_holdout_manifest_sha256",
        "holdout_split_sha256", "model_sha256", "model_state_sha256", "calibration_sha256", "policy_sha256",
        "artifact_sha256", "selection_proof", "strict_reference"}
    if (not isinstance(version, str) or not re.fullmatch(r"[a-z0-9_-]{8,64}", version)
            or set(package) != package_fields
            or package.get("format") != "UEBA_QUALIFIED_ADOPTION_PACKAGE_V1"
            or package.get("schema_version") != 1 or package.get("status") != "READY"
            or package.get("data_provenance") != "DEMO_ONLY" or package.get("quality_gate") != "PASS"
            or package.get("feature_schema_version") != 4):
        raise ValueError("strict DEMO_ONLY quality-passing candidate package required")
    artifacts = package.get("artifact_sha256")
    if (type(artifacts) is not dict or set(artifacts) != {"joblib", "metadata", "evaluation", "evaluation_identity", "metrics"}
            or any(type(value) is not str or not re.fullmatch(r"[a-f0-9]{64}", value) for value in artifacts.values())):
        raise ValueError("complete strict candidate artifact digest inventory required")
    names = {"joblib": f"{version}.joblib", "metadata": f"{version}.json",
             "evaluation": f"{version}.evaluation.json", "evaluation_identity": f"{version}.evaluation-identity.json",
             "metrics": f"{version}.metrics.sqlite"}
    if {item.name for item in package_dir.iterdir()} != {"candidate-package.json", *names.values()}:
        raise ValueError("qualified package has an unexpected or missing artifact")
    limits = {"joblib": 128 * 1024 * 1024, "metadata": 8 * 1024 * 1024,
              "evaluation": 8 * 1024 * 1024, "evaluation_identity": 8 * 1024 * 1024,
              "metrics": 8 * 1024 ** 3}
    checked = {}
    for kind, name in names.items():
        path = package_dir / name
        if kind == "metrics":
            path = _regular_private(path, maximum=limits[kind])
            # The potentially multi-gigabyte journal is bound by the pinned package
            # manifest and is not mounted into or read by the scoring worker.
            continue
        path = _regular_private(path, maximum=limits[kind])
        if checksum(path) != artifacts[kind]:
            raise ValueError("qualified candidate artifact checksum mismatch")
        checked[kind] = path
    model_bytes = checked["joblib"]
    metadata = json.loads(checked["metadata"].read_text())
    strict_reference = package.get("strict_reference")
    proof = package.get("selection_proof")
    if (metadata.get("model_version") != version or metadata.get("model_kind") != KIND
            or metadata.get("model_state_format") != FORMAT or metadata.get("feature_schema_version") != 4
            or metadata.get("calibration_scope") != "STRICT" or metadata.get("data_provenance") != "DEMO_ONLY"
            or metadata.get("sha256") != artifacts["joblib"] or checksum(model_bytes) != metadata.get("sha256")
            or package.get("model_sha256") != metadata.get("sha256")
            or package.get("calibration_sha256") != metadata.get("calibration_sha256")
            or package.get("model_state_sha256") != metadata.get("model_state_sha256")
            or type(metadata.get("feature_names")) is not list or len(metadata["feature_names"]) != 37
            or not isinstance(strict_reference, dict)
            or strict_reference.get("manifest_sha256") != package.get("original_training_manifest_sha256")
            or not isinstance(proof, dict) or proof.get("holdout_scored") is not False
            or proof.get("actual_composite_trials") != 360 or proof.get("actual_component_fit_calls") != 720
            or proof.get("validation_runs") != 360 or not 45 <= proof.get("zero_fit_recalibrations", 0) <= 360):
        raise ValueError("qualified package is not bound to its strict schema-4 measured candidate")
    evaluation = json.loads(checked["evaluation"].read_text())
    evaluation_identity = json.loads(checked["evaluation_identity"].read_text())
    if (evaluation.get("status") != "SUCCEEDED" or evaluation.get("quality_gate") != "PASS"
            or evaluation.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or evaluation.get("actual_scored_episodes") != 10_010_000
            or evaluation.get("model_version") != version
            or evaluation.get("model_sha256") != metadata["sha256"]
            or evaluation.get("evaluation_identity") != evaluation_identity
            or evaluation_identity.get("fresh_holdout_manifest_sha256") != package.get("fresh_holdout_manifest_sha256")
            or evaluation_identity.get("holdout_split_sha256") != package.get("holdout_split_sha256")
            or evaluation_identity.get("frozen_selection_receipt_sha256") != package.get("selection_receipt_sha256")
            or evaluation_identity.get("original_training_manifest_sha256") != package.get("original_training_manifest_sha256")):
        raise ValueError("verified full strict fresh-holdout evaluation is required")
    scopes = evaluation.get("scopes")
    if not isinstance(scopes, dict) or set(scopes) != {"MODEL_ONLY", "SIEM_FINAL"}:
        raise ValueError("both strict evaluation scopes must pass")
    for scope in scopes.values():
        tp, fn, fp, tn = (scope.get(key) for key in ("tp", "fn", "fp", "tn"))
        if (scope.get("quality_gate") != "PASS" or any(type(value) is not int or value < 0 for value in (tp, fn, fp, tn))
                or tp + fn != 10_000 or fp + tn != 10_000_000
                or (tp + tn) / 10_010_000 <= .98
                or tp / (tp + fn) <= .99 or fp / (fp + tn) >= .001
                or tp / max(1, tp + fp) < .998):
            raise ValueError("strict holdout point estimates fail a predeclared acceptance threshold")
    return package_dir, version, metadata, manifest_path, checked, package


def _campaign_code(campaign_root, catalog_root, dataset_sha256, archive_sha256):
    campaign_root, catalog_root = Path(campaign_root).absolute(), Path(catalog_root).absolute()
    if any(parent.is_symlink() for parent in (campaign_root, *campaign_root.parents)):
        raise ValueError("strict campaign root cannot contain symlinks")
    identity_path = campaign_root / "parallel-campaign.identity.private.json"
    if identity_path.is_symlink() or not identity_path.is_file() or identity_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("bounded immutable strict campaign identity required")
    identity = json.loads(identity_path.read_text())
    continuation = identity.get("continuation_identity") if type(identity) is dict else None
    replay = dict(identity) if type(identity) is dict else {}
    campaign_id = replay.get("campaign_id"); replay["campaign_id"] = None
    campaign_digest = hashlib.sha256(json.dumps(replay, sort_keys=True, separators=(",", ":"),
                                                 allow_nan=False).encode()).hexdigest()[:24]
    continuation_digest = hashlib.sha256(json.dumps(continuation, sort_keys=True, separators=(",", ":"),
                                                      allow_nan=False).encode()).hexdigest() if type(continuation) is dict else None
    code_root = campaign_root / "code"
    if (type(identity) is not dict or identity.get("campaign_type") != "HYBRID_STRICT_PARALLEL"
            or identity.get("data_provenance") != "DEMO_ONLY" or identity.get("quality_gate") != "NOT_RUN"
            or identity.get("holdout_scored") is not False or identity.get("aws_changed") is not False
            or campaign_id != campaign_digest or continuation_digest != identity.get("continuation_identity_sha256")
            or type(continuation) is not dict or continuation.get("model_kind") != KIND
            or continuation.get("dataset_directory") != str(catalog_root)
            or continuation.get("dataset_sha256") != dataset_sha256 or continuation.get("archive_sha256") != archive_sha256
            or continuation.get("code_directory") != str(code_root)
            or not isinstance(continuation.get("python_sources"), dict)):
        raise ValueError("campaign, dataset and archive pins do not match the completed strict source identity")
    app_dir = code_root / "app"
    inventory = continuation["python_sources"]
    actual = {path.name for path in app_dir.glob("*.py") if path.is_file() and not path.is_symlink()}
    if actual != set(inventory):
        raise ValueError("strict source app code inventory differs from its campaign pin")
    pinned = {}
    for name, expected in inventory.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+\.py", name) or not re.fullmatch(r"[a-f0-9]{64}", str(expected)):
            raise ValueError("invalid campaign source-code inventory")
        path = app_dir / name
        if path.is_symlink() or checksum(path) != expected:
            raise ValueError("strict source code differs from campaign-pinned bytes")
        pinned[str(path)] = expected
    pinned[str(identity_path)] = checksum(identity_path)
    return code_root, pinned


def deterministic_sample_positions(total, sample_count):
    if type(total) is not int or type(sample_count) is not int or not 0 < sample_count <= total:
        raise ValueError("bounded positive validation sample required")
    positions = {round(index * (total - 1) / (sample_count - 1)) for index in range(sample_count)} if sample_count > 1 else {0}
    if len(positions) != sample_count:
        raise ValueError("deterministic stress sample must contain distinct source positions")
    return positions


def _sample_validation_rows(dataset, split_name="fold3-validation", sample_count=21000):
    split = dataset.split(split_name)
    if (dataset.manifest.get("stage") != "STRICT" or dataset.manifest.get("feature_schema_version") != 4
            or split.get("records") != 1_001_000 or split.get("normal") != 1_000_000
            or split.get("positive") != 1_000 or not 0 < sample_count <= split["records"]):
        raise ValueError("full strict fold-3 validation split is required; holdout is never eligible")
    target_indexes = deterministic_sample_positions(split["records"], sample_count)
    selected, seen = [], set()
    offset = 0
    for _descriptor, rows in dataset.iter_shards(split_name):
        for row in rows:
            if offset in target_indexes:
                values, cohort = row.get("features"), row.get("cohort")
                if (type(values) is not list or len(values) != 37
                        or any(type(value) not in (int, float) or not math.isfinite(value) for value in values)
                        or cohort not in ("READY", "UNSEEN_READY", "COLD")):
                    raise ValueError("strict validation stress vectors must be normalized and cohort-valid")
                frame_id = row.get("frame_id")
                if not isinstance(frame_id, str) or frame_id in seen:
                    raise ValueError("stress pool must contain distinct validation frames")
                seen.add(frame_id)
                selected.append((values, "COLD" if cohort == "COLD" else "READY"))
            offset += 1
    if offset != split["records"] or len(selected) != sample_count:
        raise ValueError("bounded deterministic sampling did not cover the exact validation split")
    return selected


def strict_sources(package_dir, catalog_root, campaign_root, *, dataset_sha256, archive_sha256, package_sha256):
    pins = (dataset_sha256, archive_sha256, package_sha256)
    if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in pins):
        raise ValueError("explicit trusted dataset, archive and package pins required")
    package_dir, version, metadata, manifest_path, checked, package = _strict_package(package_dir, package_sha256)
    catalog_root = Path(catalog_root).absolute()
    if (package.get("original_training_manifest_sha256") != dataset_sha256
            or package.get("strict_reference", {}).get("manifest_sha256") != dataset_sha256):
        raise ValueError("candidate package and strict source manifest differ")
    code_root, code_hashes = _campaign_code(campaign_root, catalog_root, dataset_sha256, archive_sha256)
    if "app" in sys.modules:
        raise ValueError("strict validation loader must be imported from the pinned campaign snapshot")
    sys.path.insert(0, str(code_root))
    try:
        from app.archived_catalog import ArchivedShardedDataset
        dataset = ArchivedShardedDataset(catalog_root, expected_sha256=dataset_sha256,
                                         expected_archive_sha256=archive_sha256)
        rows = _sample_validation_rows(dataset)
    finally:
        sys.path.remove(str(code_root))
    source_hashes = {str(manifest_path): checksum(manifest_path),
                     str(catalog_root / "manifest.json"): dataset_sha256,
                     str(catalog_root / "archives.private.json"): archive_sha256}
    for descriptor in dataset.split("fold3-validation")["shards"]:
        relative = descriptor["path"]
        archive_entry = dataset._archive_entries[relative]
        original = catalog_root / relative
        if original.exists():
            path, expected = original, archive_entry["original_sha256"]
        else:
            path, expected = catalog_root / archive_entry["archive_path"], archive_entry["archive_sha256"]
        if path.is_symlink() or checksum(path) != expected:
            raise ValueError("strict validation shard or archive changed during bounded scan")
        source_hashes[str(path)] = expected
    source_hashes.update(code_hashes)
    for name in ("model.py", "main.py", "contract.py", "normal_support.py", "hybrid_incident.py",
                 "hybrid_semantic.py", "semantic_model.py", "candidate_cache.py"):
        path = ROOT / "ueba-worker/app" / name
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError("worker source must be a regular nonsymlink file")
            source_hashes[str(path)] = checksum(path)
    runner_path = Path(__file__).resolve()
    source_hashes[str(runner_path)] = checksum(runner_path)
    for kind, path in checked.items():
        source_hashes[str(path)] = checksum(path)
    source_hashes[str(package_dir / "candidate-package.json")] = package_sha256
    return package_dir, version, {"metadata": metadata, "rows": rows, "catalog_root": catalog_root,
                                 "campaign_root": Path(campaign_root).absolute()}, source_hashes


def _verify_network_none_container(inspected, name, label, run_id, mounts, *, running):
    config, host = inspected.get("Config", {}), inspected.get("HostConfig", {})
    state, network = inspected.get("State", {}), inspected.get("NetworkSettings", {})
    actual_mounts = {item.get("Destination"): item for item in inspected.get("Mounts", [])}
    if (inspected.get("Name", "").lstrip("/") != name
            or config.get("Labels", {}).get(label) != run_id or config.get("User") != "1000:1000"
            or inspected.get("Image") != IMAGE or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is True
            or set(host.get("CapDrop") or []) != {"ALL"}
            or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
            or set(actual_mounts) - set(mounts) - {"/tmp"}
            or host.get("Memory", 0) <= 0 or host.get("Memory", 0) > 2 * 1024 ** 3
            or host.get("NanoCpus", 0) <= 0 or host.get("NanoCpus", 0) > 2_000_000_000
            or host.get("PidsLimit", 0) <= 0 or host.get("PidsLimit", 0) > 128
            or host.get("PortBindings") or any(value for value in (network.get("Ports") or {}).values())
            or state.get("Running") is not running):
        raise ValueError("owned stress container must be unprivileged, read-only and network-none")
    tmp_mount = actual_mounts.get("/tmp")
    if tmp_mount is not None and (tmp_mount.get("Type") != "tmpfs" or tmp_mount.get("RW") is not True):
        raise ValueError("only a writable tmpfs may supplement the read-only container filesystem")
    for target, (source, writable) in mounts.items():
        mount = actual_mounts.get(target)
        if (mount is None or Path(mount.get("Source", "")).resolve() != Path(source).resolve()
                or mount.get("RW") is not writable):
            raise ValueError("owned stress container mount identity or access mode changed")
    return state


def run_strict_isolated(package_dir, output, candidate_version, source_rows, source_hashes, *, smoke=False):
    """Stress only a qualified candidate inside network-none UID-1000 containers."""
    output = Path(output).absolute()
    if (".." in output.parts or any(parent.is_symlink() for parent in (output, *output.parents))
            or output.exists() or os.geteuid() != 1000):
        raise ValueError("new private stress evidence directory and worker-matching UID1000 required")
    protected = (Path(package_dir).resolve(), Path(source_rows["catalog_root"]).resolve())
    if any(output == path or output.is_relative_to(path) or path.is_relative_to(output) for path in protected):
        raise ValueError("stress evidence output must be separate from candidate and training source")
    metadata, pool_rows = source_rows["metadata"], source_rows["rows"]
    output.mkdir(mode=0o700, parents=True)
    socket_dir = output / "socket"
    socket_dir.mkdir(mode=0o700)
    token = secrets.token_urlsafe(40)
    private_write(output / "token", token)
    private_write(output / "bootstrap-unix.py", BOOTSTRAP_UDS)
    stages = (("SMOKE_STEADY", 1, 5),) if smoke else STAGES
    concurrency = 1 if smoke else CLIENTS
    run_id = uuid.uuid4().hex
    input_document = {"candidate_version": candidate_version,
        "metadata": {key: metadata[key] for key in ("feature_names", "calibration_sha256", "score_policy")},
        "rows": pool_rows, "stages": stages, "batch_size": BATCH_SIZE,
        "client_workers": concurrency}
    private_write(output / "stress-input.json", input_document)
    private_write(output / "driver.py", DRIVER)
    source_hashes = dict(source_hashes)
    for path in (output / "bootstrap-unix.py", output / "stress-input.json", output / "driver.py"):
        source_hashes[str(path)] = checksum(path)
    declaration = {"scope": "OWNED_STRICT_CANDIDATE_PERFORMANCE_ONLY", "run_id": run_id,
        "model_version": candidate_version,
        "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE",
        "independent_quality_samples": 0, "source_split": "fold3-validation",
        "source_validation_rows": 1_001_000, "source_unique_rows": len(pool_rows),
        "sampling": "21,000 deterministic evenly-spaced frame vectors; repeated load rows do not count as quality samples",
        "batch_size": BATCH_SIZE, "client_workers": concurrency, "stages": stages,
        "image": IMAGE, "memory_bytes": 2 * 1024 * 1024 * 1024, "cpu_limit": 2,
        "bootstrap_sha256": hashlib.sha256(BOOTSTRAP_UDS.encode()).hexdigest(),
        "driver_sha256": hashlib.sha256(DRIVER.encode()).hexdigest(),
        "cold_load_warmup_requests": 1, "measured_request_timeout_seconds": 15,
        "network_mode": "none", "transport": "Unix domain socket only",
        "training_calls_permitted": 0, "activation_calls_permitted": 0,
        "source_sha256": source_hashes, "sla_gate": "NOT_APPLICABLE_DIFFERENT_FROM_FULL_APPLICATION_PROFILE"}
    private_write(output / "predeclared.json", declaration)
    predeclared_sha = checksum(output / "predeclared.json")
    server_name = "ueba-hybrid-strict-stress-" + run_id[:16]
    driver_name = "ueba-hybrid-strict-driver-" + run_id[:16]
    server_created = driver_created = False
    resources = []; observed_phases = set()
    server_mounts = {"/service": (ROOT / "ueba-worker", False), "/models": (package_dir, False),
        "/owned": (output, False), "/socket": (socket_dir, True)}
    driver_mounts = {"/owned": (output, True), "/socket": (socket_dir, True)}
    try:
        docker("run", "-d", "--name", server_name, "--label", LABEL + "=" + run_id,
            "--user", "1000:1000", "--cpus", "2", "--memory", "2g", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=32m", "--network", "none",
            "-e", "UEBA_SERVICE_TOKEN_FILE=/owned/token", "-e", "UEBA_MODEL_DIR=/models",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/service",
            "-e", "OMP_NUM_THREADS=1", "-e", "OPENBLAS_NUM_THREADS=1",
            "-v", str((ROOT / "ueba-worker").resolve()) + ":/service:ro",
            "-v", str(package_dir.resolve()) + ":/models:ro",
            "-v", str(output.resolve()) + ":/owned:ro",
            "-v", str(socket_dir.resolve()) + ":/socket:rw",
            "--entrypoint", "python", IMAGE, "/owned/bootstrap-unix.py")
        server_created = True
        server_info = json.loads(docker("inspect", server_name))[0]
        _verify_network_none_container(server_info, server_name, LABEL, run_id, server_mounts, running=True)

        docker("run", "-d", "--name", driver_name, "--label", DRIVER_LABEL + "=" + run_id,
            "--user", "1000:1000", "--cpus", "1", "--memory", "1g", "--pids-limit", "64",
            "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=32m", "--network", "none",
            "-v", str(output.resolve()) + ":/owned:rw",
            "-v", str(socket_dir.resolve()) + ":/socket:rw",
            "--entrypoint", "python", IMAGE, "/owned/driver.py")
        driver_created = True
        deadline = time.monotonic() + sum(stage[2] for stage in stages) + 120
        while True:
            driver_info = json.loads(docker("inspect", driver_name))[0]
            state = _verify_network_none_container(driver_info, driver_name, DRIVER_LABEL, run_id,
                                                    driver_mounts, running=driver_info.get("State", {}).get("Running", False))
            if json.loads(docker("inspect", server_name))[0].get("State", {}).get("Running") is not True:
                raise RuntimeError("isolated candidate worker exited during stress")
            for phase, _rate, _seconds in stages:
                phase_path = output / (phase + ".json")
                if phase not in observed_phases and phase_path.is_file() and not phase_path.is_symlink():
                    resources.append({"phase": phase,
                        "docker_stats": json.loads(docker("stats", "--no-stream", "--format", "{{json .}}", server_name))})
                    observed_phases.add(phase)
            if state.get("Status") != "running":
                if state.get("ExitCode") != 0:
                    raise RuntimeError("isolated candidate load driver failed")
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("isolated bounded load driver exceeded its wall-time budget")
            time.sleep(.5)
        driver_info = json.loads(docker("inspect", driver_name))[0]
        _verify_network_none_container(driver_info, driver_name, DRIVER_LABEL, run_id, driver_mounts, running=False)
        server_info = json.loads(docker("inspect", server_name))[0]
        _verify_network_none_container(server_info, server_name, LABEL, run_id, server_mounts, running=True)
        result_path = output / "result.json"
        if result_path.is_symlink() or not result_path.is_file():
            raise RuntimeError("isolated driver did not write its completion receipt")
        measured = json.loads(result_path.read_text())
        if (measured.get("status") != "COMPLETED" or measured.get("stress_gate") != "PASS"
                or measured.get("quality_gate") != "NOT_APPLICABLE"
                or measured.get("network_mode") != "none_unix_socket_only"
                or measured.get("independent_quality_samples") != 0):
            raise ValueError("isolated strict-candidate stress receipt contract mismatch")
        if checksum(output / "predeclared.json") != predeclared_sha or (output / "token").read_text() != token:
            raise ValueError("stress predeclaration or private service token changed")
        journal = output / "requests.jsonl"
        if journal.is_symlink() or not journal.is_file() or journal.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("bounded owner-created request journal required")
        journal_rows = [json.loads(line) for line in journal.read_text().splitlines() if line]
        for row in journal_rows:
            if (type(row) is not dict or row.get("phase") not in {stage[0] for stage in stages}
                    or row.get("status") != 200 or row.get("error") is not None
                    or type(row.get("latency_seconds")) not in (int, float)
                    or not math.isfinite(row["latency_seconds"]) or row["latency_seconds"] < 0
                    or row.get("requested_rows") != BATCH_SIZE or row.get("validated_rows") != BATCH_SIZE):
                raise ValueError("every measured request must be a successful validated batch")
        measured_summary = summarize(journal_rows)
        if (measured_summary != {key: measured.get(key) for key in measured_summary}
                or len(journal_rows) != sum(phase.get("requests", -1) for phase in measured.get("phases", []))):
            raise ValueError("driver request journal and aggregate summary differ")
        phase_docs = {phase["phase"]: phase for phase in measured.get("phases", []) if type(phase) is dict and "phase" in phase}
        if set(phase_docs) != {stage[0] for stage in stages}:
            raise ValueError("each declared load phase needs a completion receipt")
        for phase, document in phase_docs.items():
            phase_summary = summarize([row for row in journal_rows if row["phase"] == phase])
            if any(document.get(key) != value for key, value in phase_summary.items()):
                raise ValueError("phase receipt differs from its raw request rows")
        warm = json.loads((output / "cold-load.json").read_text())
        profile_after = measured.get("profile_after")
        if (warm.get("status") != 200 or warm.get("error") is not None
                or warm.get("requested_rows") != BATCH_SIZE or warm.get("validated_rows") != BATCH_SIZE
                or type(profile_after) is not dict or profile_after.get("active_version") is not None
                or any(profile_after.get(key) != 0 for key in ("fits", "activation", "recalibration"))):
            raise ValueError("cold-load receipt or candidate-only mutation guards failed")
        after = {path: checksum(Path(path)) for path in source_hashes}
        if after != source_hashes:
            raise ValueError("qualified candidate, strict validation source or pinned code changed during stress")
        complete = declaration | measured | {"source_unchanged": True, "resources": resources,
            "model_sha256": metadata["sha256"], "calibration_sha256": metadata["calibration_sha256"],
            "model_state_sha256": metadata["model_state_sha256"], "candidate_model_sha_in_response": False}
        private_write(output / "host-verification.json", complete)
        return complete
    except BaseException as failure:
        if not (output / "failure.json").exists():
            private_write(output / "failure.json", {"status": "FAILED", "exception_type": type(failure).__name__,
                "reason": str(failure), "run_id": run_id, "quality_gate": "NOT_APPLICABLE"})
        raise
    finally:
        if driver_created:
            current = json.loads(docker("inspect", driver_name))[0]
            if current.get("Config", {}).get("Labels", {}).get(DRIVER_LABEL) == run_id:
                docker("rm", "-f", driver_name)
        if server_created:
            current = json.loads(docker("inspect", server_name))[0]
            if current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id:
                docker("rm", "-f", server_name)


def verify_target(origin, inspected, run_id):
    value = urllib.parse.urlsplit(origin)
    if (value.scheme != "http" or value.hostname != "127.0.0.1" or value.port is None
            or value.username or value.password or value.path not in ("", "/") or value.query or value.fragment):
        raise ValueError("explicit loopback-only origin required")
    config = inspected.get("Config", {})
    ports = inspected.get("HostConfig", {}).get("PortBindings", {}).get("8091/tcp", [])
    if (config.get("Labels", {}).get(LABEL) != run_id or config.get("User") != "1000:1000"
            or inspected.get("Image") != IMAGE or not inspected.get("State", {}).get("Running")
            or not any(v.get("HostIp") == "127.0.0.1" and v.get("HostPort") == str(value.port) for v in ports)):
        raise ValueError("target is not the exact disposable owned worker")
    return origin.rstrip("/")


def request(origin, path, token, payload=None, timeout=15):
    data = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    headers = {"X-UEBA-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    call = urllib.request.Request(origin + path, data=data, headers=headers)
    with urllib.request.build_opener(NoRedirect()).open(call, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ResponseContract(response.status)
        try:
            return response.status, json.loads(raw)
        except ValueError:
            raise ResponseContract(response.status) from None


def validate_response(value, payload, metadata, candidate_version=CANDIDATE):
    if (type(value) is not dict or value.get("available") is not True or value.get("model_version") != candidate_version
            or value.get("feature_schema_version") != 4 or value.get("feature_names") != metadata["feature_names"]
            or value.get("calibration_sha256") != metadata["calibration_sha256"]
            or value.get("score_policy") != metadata["score_policy"]
            or type(value.get("results")) is not list or len(value["results"]) != len(payload["vectors"])):
        raise ValueError("candidate response identity/shape mismatch")
    policy = json.loads(metadata["score_policy"]["policy_document_json"])
    for row, cohort in zip(value["results"], payload["cohorts"]):
        if type(row) is not dict:
            raise ValueError("candidate score record required")
        raw, percentile = row.get("raw_anomaly_score"), row.get("normal_percentile")
        if (type(raw) not in (int, float) or type(percentile) not in (int, float)
                or not math.isfinite(raw) or not math.isfinite(percentile) or not 0 <= percentile <= 100
                or row.get("scoring_cohort") != cohort):
            raise ValueError("candidate score/cohort is invalid")
        detected = policy["detection_percentile_micro"][cohort] / 1000000
        warning = policy["warning_percentile_micro"] / 1000000
        level = "VERY_UNUSUAL" if percentile >= detected else "UNUSUAL" if percentile >= warning else "NORMAL_RANGE"
        if row.get("level") != level:
            raise ValueError("candidate policy level mismatch")


def probe(origin, token, payload, metadata, *, timeout=15, candidate_version=CANDIDATE):
    start = time.monotonic(); status, error = 0, None
    try:
        status, value = request(origin, "/internal/v1/score-candidate", token, payload, timeout=timeout)
        validate_response(value, payload, metadata, candidate_version)
    except urllib.error.HTTPError as failure:
        status, error = failure.code, "HTTP"
    except ResponseContract as failure:
        status, error = failure.status, "RESPONSE_CONTRACT"
    except ValueError:
        error = "RESPONSE_CONTRACT"
    except (urllib.error.URLError, TimeoutError, OSError):
        error = "TRANSPORT"
    return {"status": status, "error": error, "latency_seconds": time.monotonic() - start,
            "requested_rows": len(payload["vectors"]), "validated_rows": len(payload["vectors"]) if status == 200 and error is None else 0}


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def summarize(rows):
    latency = [r["latency_seconds"] for r in rows]; counts = {}
    for row in rows:
        key = str(row["status"]); counts[key] = counts.get(key, 0) + 1
    return {"requests": len(rows), "status_counts": counts, "errors": sum(r["error"] is not None for r in rows),
            "requested_rows": sum(r["requested_rows"] for r in rows), "validated_rows": sum(r["validated_rows"] for r in rows),
            "p50_seconds": percentile(latency, .5), "p95_seconds": percentile(latency, .95), "p99_seconds": percentile(latency, .99)}


def run(model_dir, catalog, output, *, smoke=False, candidate_version=CANDIDATE,
        source_rows=None, source_hashes=None, strict=False):
    if output.exists() or output.is_symlink() or os.geteuid() != 1000:
        raise ValueError("new private output and worker-matching UID1000 required")
    if strict:
        metadata, pool_rows, before = source_rows["metadata"], source_rows["rows"], source_hashes
    else:
        metadata, pool_rows, before = sources(model_dir, catalog)
    output.mkdir(mode=0o700, parents=True)
    token = secrets.token_urlsafe(40); private_write(output / "token", token); private_write(output / "bootstrap.py", BOOTSTRAP)
    run_id = uuid.uuid4().hex; name = "ueba-hybrid-candidate-stress-" + run_id[:16]
    stages = (("SMOKE_STEADY", 1, 5),) if smoke else STAGES
    concurrency = 1 if smoke else CLIENTS
    declaration = {"scope": "OWNED_STRICT_CANDIDATE_PERFORMANCE_ONLY" if strict else "OWNED_PILOT_CANDIDATE_PERFORMANCE_ONLY",
                   "run_id": run_id, "model_version": candidate_version,
                   "quality_gate": "NOT_APPLICABLE", "independent_quality_samples": 0, "source_unique_rows": 21000,
                   "batch_size": BATCH_SIZE, "client_workers": concurrency, "stages": stages, "image": IMAGE,
                   "memory_bytes": 2 * 1024 * 1024 * 1024, "cpu_limit": 2,
                   "cold_load_warmup_requests": 1, "cold_load_timeout_seconds": 120,
                   "measured_request_timeout_seconds": 15, "shadow_background_lifespan_enabled": False,
                   "training_calls_permitted": 0, "activation_calls_permitted": 0, "source_sha256": before,
                   "sla_gate": "NOT_APPLICABLE_DIFFERENT_FROM_FULL_APPLICATION_PROFILE"}
    private_write(output / "predeclared.json", declaration)
    created = False; completed, phases, resources = [], [], []
    try:
        docker("run", "-d", "--name", name, "--label", LABEL + "=" + run_id, "--user", "1000:1000",
               "--cpus", "2", "--memory", "2g", "--pids-limit", "128", "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=32m",
               "-p", "127.0.0.1::8091", "-e", "UEBA_SERVICE_TOKEN_FILE=/owned/token", "-e", "UEBA_MODEL_DIR=/models",
               "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/service", "-e", "OMP_NUM_THREADS=1", "-e", "OPENBLAS_NUM_THREADS=1",
               "-v", str(ROOT / "ueba-worker") + ":/service:ro", "-v", str(model_dir.resolve()) + ":/models:ro",
               "-v", str(output.resolve()) + ":/owned:ro", "--entrypoint", "python", IMAGE, "/owned/bootstrap.py")
        created = True
        inspected = json.loads(docker("inspect", name))[0]
        port = inspected["NetworkSettings"]["Ports"]["8091/tcp"][0]["HostPort"]
        # Docker assigns the ephemeral port after start; use its actual binding proof.
        inspected["HostConfig"]["PortBindings"]["8091/tcp"] = inspected["NetworkSettings"]["Ports"]["8091/tcp"]
        origin = verify_target("http://127.0.0.1:" + port, inspected, run_id)
        deadline = time.monotonic() + 60
        while True:
            try:
                _, health = request(origin, "/health", token)
                if health.get("model_available") is not False: raise ValueError("candidate worker became active")
                break
            except (urllib.error.URLError, OSError):
                if time.monotonic() >= deadline: raise RuntimeError("owned worker startup timed out")
                time.sleep(.25)
        _, initial_profile = request(origin, "/owned/stress-profile", token)
        warmup_rows = pool_rows[:BATCH_SIZE - 1] + [next(row for row in pool_rows if row[1] == "COLD")]
        warmup_payload = {"model_version": candidate_version, "feature_schema_version": 4, "feature_names": metadata["feature_names"],
                          "vectors": [r[0] for r in warmup_rows], "cohorts": [r[1] for r in warmup_rows]}
        warmup = probe(origin, token, warmup_payload, metadata, timeout=120, candidate_version=candidate_version)
        private_write(output / "cold-load.json", warmup)
        if warmup["status"] != 200 or warmup["error"] is not None:
            raise RuntimeError("separate cold-load warmup failed")
        journal = output / "requests.jsonl"; journal.touch(mode=0o600, exist_ok=False)
        with journal.open("a") as stream, ThreadPoolExecutor(max_workers=concurrency) as clients:
            ordinal = 0
            for phase, rate, seconds in stages:
                start = time.monotonic(); next_tick = start; pending = set(); phase_rows = []; missed = 0; peak_pending = 0
                while time.monotonic() - start < seconds or pending:
                    now = time.monotonic()
                    if now - start < seconds and now >= next_tick:
                        if len(pending) < concurrency:
                            batch = [pool_rows[(ordinal * BATCH_SIZE + i) % len(pool_rows)] for i in range(BATCH_SIZE)]
                            payload = {"model_version": candidate_version, "feature_schema_version": 4, "feature_names": metadata["feature_names"],
                                       "vectors": [r[0] for r in batch], "cohorts": [r[1] for r in batch]}
                            pending.add(clients.submit(probe, origin, token, payload, metadata,
                                                       candidate_version=candidate_version)); ordinal += 1
                            peak_pending = max(peak_pending, len(pending))
                        else:
                            missed += 1
                        next_tick = now + 1 / rate
                    for future in tuple(pending):
                        if future.done():
                            row = future.result(); pending.remove(future); completed.append(row); phase_rows.append(row)
                            stream.write(json.dumps(row | {"phase": phase}, sort_keys=True) + "\n")
                    if now - start > seconds + 20: raise RuntimeError("bounded request drain exceeded")
                    time.sleep(.005)
                elapsed = time.monotonic() - start
                phases.append(summarize(phase_rows) | {"phase": phase, "target_rps": rate, "elapsed_seconds": elapsed,
                              "actual_rps": len(phase_rows) / elapsed, "missed_scheduling_ticks": missed, "peak_inflight": peak_pending})
                resources.append({"phase": phase, "docker_stats": json.loads(docker("stats", "--no-stream", "--format", "{{json .}}", name))})
                stream.flush(); private_write(output / (phase + ".json"), phases[-1])
                phase_state = json.loads(docker("inspect", name))[0]["State"]
                if not phase_state.get("Running"):
                    raise RuntimeError("owned worker exited during measured phase")
        _, final_profile = request(origin, "/owned/stress-profile", token)
        _, final_health = request(origin, "/health", token)
        if (final_health.get("model_available") is not False or final_profile.get("active_version") is not None
                or any(final_profile.get(k) != 0 for k in ("fits", "activation", "recalibration"))):
            raise ValueError("candidate-only no-mutation profile violated")
        after = {path: checksum(Path(path)) for path in before}
        if after != before: raise ValueError("read-only source bytes changed")
        result = declaration | summarize(completed) | {"status": "COMPLETED", "smoke_only": smoke, "phases": phases,
                    "resources": resources, "profile_before": initial_profile, "profile_after": final_profile,
                    "cold_load_warmup": warmup,
                    "source_unchanged": True, "model_sha256": metadata["sha256"], "calibration_sha256": metadata["calibration_sha256"],
                    "model_state_sha256": metadata["model_state_sha256"], "candidate_model_sha_in_response": False}
        private_write(output / "result.json", result)
        return result
    except BaseException as failure:
        diagnostic = {"status": "FAILED", "exception_type": type(failure).__name__,
                      "reason": str(failure), "run_id": run_id, "quality_gate": "NOT_APPLICABLE",
                      "completed_phases": phases, "partial": summarize(completed)}
        if created:
            try:
                state = json.loads(docker("inspect", name))[0]
                if state.get("Config", {}).get("Labels", {}).get(LABEL) == run_id:
                    diagnostic["docker_state"] = state["State"]
            except RuntimeError:
                diagnostic["fixture_unavailable"] = True
        if not (output / "failure.json").exists(): private_write(output / "failure.json", diagnostic)
        raise
    finally:
        if created:
            current = json.loads(docker("inspect", name))[0]
            if current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id:
                docker("rm", "-f", name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--model-dir", type=Path)
    source.add_argument("--qualified-package-dir", type=Path)
    parser.add_argument("--catalog-root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path)
    parser.add_argument("--dataset-sha256")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--package-sha256")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.model_dir is not None:
        if args.catalog_root is None or any(value is not None for value in
                (args.campaign_root, args.dataset_sha256, args.archive_sha256, args.package_sha256)):
            parser.error("PILOT mode requires --catalog-root and does not accept strict pins")
        result = run(args.model_dir, args.catalog_root, args.output_dir, smoke=args.smoke)
    else:
        if any(value is None for value in (args.catalog_root, args.campaign_root, args.dataset_sha256,
                                            args.archive_sha256, args.package_sha256)):
            parser.error("qualified mode requires catalog, campaign, dataset, archive and package pins")
        model_dir, candidate_version, source_rows, source_hashes = strict_sources(
            args.qualified_package_dir, args.catalog_root, args.campaign_root,
            dataset_sha256=args.dataset_sha256, archive_sha256=args.archive_sha256,
            package_sha256=args.package_sha256)
        result = run_strict_isolated(model_dir, args.output_dir, candidate_version,
                                     source_rows, source_hashes, smoke=args.smoke)
    print(json.dumps({key: result.get(key) for key in
        ("status", "stress_gate", "requests", "validated_rows", "errors", "p95_seconds", "source_unchanged")}))


if __name__ == "__main__":
    main()
