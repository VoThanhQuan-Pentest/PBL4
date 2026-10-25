"""Candidate-only shadow journal with real server clocks; no response-action integrations.

Default clocks cannot be set through an API. Injected test clocks permanently
mark a run TEST_CLOCK_ONLY and can never produce an activatable shadow proof.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
import uuid

from app.contract import feature_array
from app.model import ModelStore
from app.policy import ScorePolicy, canonical
from app.quality_proof import verify_quality

SIDE_EFFECTS = {"incidents": 0, "history": 0, "ip_lookups": 0, "ip_blocks": 0, "session_revocations": 0, "policy_publications": 0}


def boot_id():
    path = Path("/proc/sys/kernel/random/boot_id")
    if not path.is_file(): raise ValueError("real monotonic boot identity is unavailable")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ShadowStore:
    def __init__(self, store: ModelStore, *, clocks=None):
        self.store = store
        self.test_clock = clocks is not None
        self.utc, self.monotonic, self.boot = clocks or (lambda: datetime.now(timezone.utc), time.monotonic, boot_id)
        directory = store.directory / "shadow"
        if directory.is_symlink(): raise ValueError("private shadow directory must not be a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "runs.sqlite"
        if path.is_symlink(): raise ValueError("private shadow journal must not be a symlink")
        self.db = sqlite3.connect(path, timeout=30); path.chmod(0o600)
        self.db.executescript("""CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,state_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scores(run_id TEXT NOT NULL,window_id TEXT NOT NULL,source_sha256 TEXT NOT NULL,
                cohort TEXT NOT NULL,raw REAL NOT NULL,percentile REAL NOT NULL,level TEXT NOT NULL,
                PRIMARY KEY(run_id,window_id));""")

    def close(self): self.db.close()

    def save(self, state):
        with self.db:
            self.db.execute("INSERT INTO runs VALUES(?,?) ON CONFLICT(id) DO UPDATE SET state_json=excluded.state_json",
                            (state["run_id"], canonical(state)))

    def state(self, run_id):
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id): raise ValueError("invalid shadow run ID")
        value = self.db.execute("SELECT state_json FROM runs WHERE id=?", (run_id,)).fetchone()
        if value is None: raise ValueError("unknown shadow run")
        return json.loads(value[0])

    def start(self, version, *, run_id=None):
        if run_id is not None:
            if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
                raise ValueError("invalid server shadow request ID")
            previous = self.db.execute("SELECT state_json FROM runs WHERE id=?", (run_id,)).fetchone()
            if previous is not None:
                state = json.loads(previous[0])
                if state["model_version"] != version:
                    raise ValueError("shadow request ID is already bound to another model")
                return state
        metadata, _ = self.store.load_candidate(version)
        policy = ScorePolicy.from_wire(metadata["score_policy"])
        if not policy.strict_gate or metadata.get("calibration_scope") != "STRICT":
            raise ValueError("qualified strict calibrated candidate required for shadow")
        schema = metadata["feature_schema_version"]
        if schema != policy.document["feature_schema_version"]:
            raise ValueError("shadow candidate feature schema differs from policy")
        binding = {"model_version": version, "model_sha256": metadata["sha256"], "feature_schema_version": schema,
                   "calibration_sha256": metadata["calibration_sha256"], "policy_sha256": policy.sha256,
                   "dataset_sha256": metadata["dataset_manifest_sha256"]}
        verify_quality(self.store.directory, version, policy, binding)
        now, mono = self.utc(), self.monotonic()
        state = {**binding, "run_id": run_id or uuid.uuid4().hex, "status": "RUNNING", "started_at_utc": now.isoformat(),
                 "started_monotonic": mono, "last_heartbeat_monotonic": mono, "boot_sha256": self.boot(),
                 "elapsed_monotonic_seconds": 0, "maximum_heartbeat_gap_seconds": 0, "closed_windows": 0,
                 "clock_provenance": "TEST_CLOCK_ONLY" if self.test_clock else "REAL_SERVER_CLOCK",
                 "candidate_side_effects": dict(SIDE_EFFECTS)}
        self.save(state); return state

    def heartbeat(self, run_id):
        state = self.state(run_id)
        if state["status"] != "RUNNING": return state
        if self.test_clock: state["clock_provenance"] = "TEST_CLOCK_ONLY"
        now, mono = self.utc(), self.monotonic()
        gap = mono - state["last_heartbeat_monotonic"]
        metadata, _ = self.store.load_candidate(state["model_version"])
        policy = ScorePolicy.from_wire(metadata["score_policy"])
        if (self.boot() != state["boot_sha256"] or gap < 0 or gap > 300
                or metadata["sha256"] != state["model_sha256"] or metadata["calibration_sha256"] != state["calibration_sha256"]
                or metadata["feature_schema_version"] != state["feature_schema_version"]
                or policy.document["feature_schema_version"] != state["feature_schema_version"]
                or policy.sha256 != state["policy_sha256"] or metadata["dataset_manifest_sha256"] != state["dataset_sha256"]):
            state.update(status="INVALIDATED", failure_reason="CLOCK_GAP_BOOT_OR_ARTIFACT_BINDING_CHANGED")
        else:
            state["maximum_heartbeat_gap_seconds"] = max(state["maximum_heartbeat_gap_seconds"], gap)
            state["last_heartbeat_monotonic"] = mono
            state["elapsed_monotonic_seconds"] = mono - state["started_monotonic"]
            state["closed_windows"] = self.db.execute("SELECT count(*) FROM scores WHERE run_id=?", (run_id,)).fetchone()[0]
            wall = (now - datetime.fromisoformat(state["started_at_utc"])).total_seconds()
            if wall >= 86400 and state["elapsed_monotonic_seconds"] >= 86400 and state["closed_windows"] >= 600:
                state.update(status="TEST_COMPLETED" if state["clock_provenance"] != "REAL_SERVER_CLOCK" else "COMPLETED",
                             ended_at_utc=now.isoformat())
        self.save(state)
        if state["status"] == "COMPLETED":
            path = self.store.directory / f"{state['model_version']}.shadow.json"
            temporary = path.with_suffix(".tmp"); temporary.write_text(canonical(state)); temporary.chmod(0o600); temporary.replace(path)
        return state

    def heartbeat_all(self):
        identifiers = [row[0] for row in self.db.execute("SELECT id FROM runs WHERE json_extract(state_json,'$.status')='RUNNING'")]
        for run_id in identifiers:
            try: self.heartbeat(run_id)
            except (ValueError, OSError, KeyError, TypeError):
                state = self.state(run_id)
                state.update(status="INVALIDATED", failure_reason="CANDIDATE_OR_CLOCK_UNAVAILABLE")
                self.save(state)
        return len(identifiers)

    def score(self, run_id, windows):
        state = self.heartbeat(run_id)
        if state["status"] not in {"RUNNING", "COMPLETED"}: raise ValueError("shadow run is no longer eligible")
        if not isinstance(windows, list) or not 1 <= len(windows) <= 256: raise ValueError("bounded shadow window batch required")
        metadata, payload = self.store.load_candidate(state["model_version"])
        policy = ScorePolicy.from_wire(metadata["score_policy"])
        cohorts, encoded, pending, identities = [], [], [], set()
        now = self.utc()
        for row in windows:
            if set(row) != {"window_id", "window_end_utc", "baseline_established", "features"}:
                raise ValueError("shadow accepts existing server numeric windows only")
            if not isinstance(row["window_id"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{8,128}", row["window_id"]):
                raise ValueError("invalid server window ID")
            end = datetime.fromisoformat(row["window_end_utc"].replace("Z", "+00:00"))
            if (end.utcoffset() != timedelta(0) or end > now or end < datetime.fromisoformat(state["started_at_utc"])
                    or type(row["baseline_established"]) is not bool):
                raise ValueError("only closed UTC windows with actual baseline coverage are eligible")
            if row["window_id"] in identities: raise ValueError("duplicate window in shadow batch")
            identities.add(row["window_id"])
            digest = hashlib.sha256(canonical(row).encode()).hexdigest()
            previous = self.db.execute("SELECT source_sha256 FROM scores WHERE run_id=? AND window_id=?", (run_id, row["window_id"])).fetchone()
            if previous is not None:
                if previous[0] != digest: raise ValueError("shadow source window changed after scoring")
                continue
            cohorts.append("READY" if row["baseline_established"] else "COLD"); encoded.append(digest); pending.append(row)
        if pending:
            if state["status"] != "RUNNING": raise ValueError("completed shadow accepts exact acknowledged retries only")
            schema = state["feature_schema_version"]
            features = feature_array([row["features"] for row in pending], 256, schema)
            scores = ModelStore.score_payload(payload, features, state["model_version"], schema, policy=policy, cohorts=cohorts)["results"]
            with self.db:
                for row, digest, cohort, score in zip(pending, encoded, cohorts, scores):
                    self.db.execute("INSERT INTO scores VALUES(?,?,?,?,?,?,?)", (run_id, row["window_id"], digest, cohort,
                                    score["raw_anomaly_score"], score["normal_percentile"], score["level"]))
        return {"run_id": run_id, "newly_scored_windows": len(pending),
                "accepted_window_ids": [row["window_id"] for row in windows], "candidate_side_effects": dict(SIDE_EFFECTS)}
