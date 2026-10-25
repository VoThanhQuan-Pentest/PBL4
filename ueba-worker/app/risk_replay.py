"""Bounded offline RPC into the production Java risk engine, never a Python rule clone."""

import hashlib
import math
import os
from pathlib import Path
import select
import subprocess
import time

from app.catalog import parse_json
from app.policy import ScorePolicy, canonical

CLASS_FILES = ("ops/UebaRiskReplay.class", "service/siem/AccountRiskEngine.class",
               "service/siem/UebaScorePolicy.class", "service/siem/AccountBehaviorFeatures.class")


def request(policy, rows, scores):
    if not policy.strict_gate or not 1 <= len(rows) <= 5000 or len(rows) != len(scores):
        raise ValueError("bounded corresponding numeric scores are required")
    transmitted = []
    ids = set()
    for row, score in zip(rows, scores):
        cohort = "COLD" if row["cohort"] == "COLD" else "READY"
        percentile, raw = score["normal_percentile"], score["raw_anomaly_score"]
        if (type(percentile) not in (int, float) or not math.isfinite(percentile) or not 0 <= percentile <= 100
                or type(raw) not in (int, float) or not math.isfinite(raw)
                or score["level"] != policy.level(percentile, cohort)
                or row["frame_id"] in ids): raise ValueError("score/policy or frame correspondence mismatch")
        ids.add(row["frame_id"])
        transmitted.append({"frame_id": row["frame_id"], "features": row["features"],
                            "baseline_established": row["baseline_established"], "scoring_cohort": cohort,
                            "raw_anomaly_score": raw, "normal_percentile": percentile, "level": score["level"]})
    # In particular, account identity, ground-truth label and family do NOT enter
    # the decision code. Only server-extracted numbers and actual ML scores do.
    return {"feature_schema_version": policy.document["feature_schema_version"], "score_policy": policy.wire(), "rows": transmitted}


def response(policy, rows, scores, value):
    if (not isinstance(value, dict) or value.get("feature_schema_version") != policy.document["feature_schema_version"]
            or value.get("data_provenance") != "DEMO_ONLY" or value.get("decision_code") != "AccountRiskEngine"
            or value.get("policy_sha256") != policy.sha256 or not isinstance(value.get("results"), list)
            or len(value["results"]) != len(rows)):
        raise ValueError("production decision replay response mismatch")
    output = []
    for row, score, result in zip(rows, scores, value["results"]):
        if (not isinstance(result, dict) or result.get("frame_id") != row["frame_id"]
                or type(result.get("model_positive")) is not bool or type(result.get("siem_positive")) is not bool
                or result["model_positive"] != policy.detected(score["normal_percentile"], "COLD" if row["cohort"] == "COLD" else "READY")):
            raise ValueError("replay row correspondence/independent detection mismatch")
        output.append({key: row[key] for key in ("frame_id", "account_id", "window_start", "label", "family", "cohort")}
                      | {"predictions": {"MODEL_ONLY": result["model_positive"], "SIEM_FINAL": result["siem_positive"]}})
    return output


class JavaRiskReplay:
    """Configured operator workspace only. No request may select an executable/path."""

    def __init__(self, workspace: Path, policy: ScorePolicy, *, expected_classes=None, timeout=60):
        if not policy.strict_gate: raise ValueError("strict replay policy required")
        self.root, self.policy, self.timeout = workspace.resolve(strict=True), policy, timeout
        self.classes = self.class_checksums()
        if expected_classes is not None and self.classes != expected_classes:
            raise ValueError("production decision binary binding mismatch")
        classpath = self.root / "backend/target/ueba-experiment.classpath"
        if not classpath.is_file() or classpath.stat().st_size > 65536: raise ValueError("bounded operator classpath required")
        command = ["java", "-Xmx128m", "-cp", str(self.root / "backend/target/classes") + ":" + classpath.read_text().strip(),
                   "com.flarefitness.backend.ops.UebaRiskReplay", "--demo-only"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def class_checksums(self):
        directory = self.root / "backend/target/classes/com/flarefitness/backend"
        return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in CLASS_FILES}

    def score(self, rows, scores):
        if self.process.poll() is not None: raise RuntimeError("production decision process exited")
        if self.class_checksums() != self.classes: raise ValueError("decision binaries changed during evaluation")
        data = (canonical(request(self.policy, rows, scores)) + "\n").encode()
        if len(data) > 8 * 1024 * 1024: raise ValueError("numeric replay batch exceeds byte bound")
        self.process.stdin.write(data); self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        received = bytearray()
        while not received.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError("production decision replay timed out")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk: raise RuntimeError("production decision replay ended before its response")
            received.extend(chunk)
            if len(received) > 2 * 1024 * 1024: raise ValueError("replay response exceeds bound")
        return response(self.policy, rows, scores, parse_json(received))

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            try: self.process.stdin.close()
            except BrokenPipeError: pass
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()
        self.process.stdout.close(); self.process.stderr.close()

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
