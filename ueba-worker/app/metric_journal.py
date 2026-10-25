"""Bounded shard ingestion with real episode identities and disk-backed cluster counts."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from app.policy import ScorePolicy, canonical
from app.strict_metrics import Confusion, FAMILIES, SCOPES


class MetricJournal:
    def __init__(self, path: Path, *, policy: ScorePolicy, model_sha256: str, calibration_sha256: str,
                 dataset_sha256: str, storage_guard=False):
        if type(storage_guard) is not bool: raise ValueError("explicit journal storage guard required")
        self.path, self.storage_guard = path, storage_guard
        if storage_guard:
            from app.storage_budget import require_headroom
            require_headroom(path.parent, 2 * 1024 ** 2)
        if not policy.strict_gate: raise ValueError("strict metrics journal requires the strict policy")
        if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in (model_sha256, calibration_sha256, dataset_sha256)):
            raise ValueError("model/calibration/dataset checksum required")
        self.identity = {**policy.wire(), "model_sha256": model_sha256, "calibration_sha256": calibration_sha256,
                         "dataset_sha256": dataset_sha256}
        self.policy = policy
        self.db = sqlite3.connect(path, timeout=30)
        path.chmod(0o600)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS shards (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, records INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS source_shards (id TEXT PRIMARY KEY REFERENCES shards(id), input_sha256 TEXT NOT NULL, records INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS episodes (key TEXT PRIMARY KEY, frame_id TEXT UNIQUE NOT NULL,
                label INTEGER NOT NULL CHECK(label IN (0,1)), family TEXT NOT NULL, cohort TEXT NOT NULL,
                model_positive INTEGER NOT NULL CHECK(model_positive IN (0,1)),
                siem_positive INTEGER NOT NULL CHECK(siem_positive IN (0,1)), cluster_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counts (scope TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
                tp INTEGER NOT NULL DEFAULT 0, fn INTEGER NOT NULL DEFAULT 0, fp INTEGER NOT NULL DEFAULT 0, tn INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(scope,kind,key));
        """)
        if {row[1] for row in self.db.execute("PRAGMA table_info(episodes)")} != {
                "key", "frame_id", "label", "family", "cohort", "model_positive", "siem_positive", "cluster_id"}:
            self.db.close()
            raise ValueError("legacy aggregate-only journal cannot prove actual scored episodes; preserve it and use a fresh evaluation")
        encoded = canonical(self.identity)
        previous = self.db.execute("SELECT payload FROM identity WHERE singleton=1").fetchone()
        if previous is not None and previous[0] != encoded:
            self.db.close()
            raise ValueError("journal identity changed; old evidence cannot be reused")
        if previous is None:
            self.db.execute("INSERT INTO identity(singleton,payload) VALUES(1,?)", (encoded,))
            self.db.commit()

    def close(self): self.db.close()

    def ingest(self, shard_id: str, rows: list[dict], expected_sha256: str, *, source_sha256=None):
        if self.storage_guard:
            from app.storage_budget import require_headroom
            require_headroom(self.path.parent, len(rows) * 4096 + 2 * 1024 ** 2)
        if not re.fullmatch(r"[a-z0-9_-]{8,96}", shard_id) or not 1 <= len(rows) <= 5000:
            raise ValueError("invalid bounded evaluation shard")
        if source_sha256 is not None and (not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256)):
            raise ValueError("numeric source shard checksum required")
        digest = hashlib.sha256(canonical(rows).encode()).hexdigest()
        if digest != expected_sha256: raise ValueError("scored shard checksum mismatch")
        existing = self.db.execute("SELECT sha256,records FROM shards WHERE id=?", (shard_id,)).fetchone()
        if existing is not None:
            if existing != (digest, len(rows)): raise ValueError("shard identity reused with different input")
            if source_sha256 is not None and not self.completed_source_shard(shard_id, source_sha256, len(rows)):
                raise ValueError("replayed scoring lacks its original numeric source binding")
            return {"shard_id": shard_id, "records": len(rows), "replayed": True}
        updates = {}
        episodes = []
        for row in rows:
            if set(row) != {"frame_id", "account_id", "window_start", "label", "family", "cohort", "predictions"}:
                raise ValueError("unexpected evaluation row fields")
            frame, account = row["frame_id"], row["account_id"]
            if (not isinstance(frame, str) or not re.fullmatch(r"[a-z0-9_-]{8,128}", frame)
                    or not isinstance(account, str) or not re.fullmatch(r"[a-z0-9_-]{8,64}", account)):
                raise ValueError("invalid pseudonymous episode identity")
            try: at = datetime.fromisoformat(row["window_start"].replace("Z", "+00:00"))
            except (ValueError, TypeError, AttributeError): raise ValueError("invalid UTC episode timestamp") from None
            if at.tzinfo is None or at.utcoffset().total_seconds() != 0 or at.minute % 15 or at.second or at.microsecond:
                raise ValueError("UTC quarter-hour episode timestamp required")
            label, family, cohort = row["label"], row["family"], row["cohort"]
            if type(label) is not int or label not in (0, 1) or not (
                    label == 0 and family == "normal" or label == 1 and family in FAMILIES):
                raise ValueError("invalid predeclared ground truth")
            if cohort not in ("READY", "UNSEEN_READY", "COLD") or set(row["predictions"]) != set(SCOPES):
                raise ValueError("both prediction scopes and applicability cohort are required")
            episode = account + "/" + at.strftime("%Y-%m-%dT%H")
            cluster = account + "/" + at.date().isoformat()
            if any(type(row["predictions"][scope]) is not bool for scope in SCOPES):
                raise ValueError("prediction must be an actual boolean")
            episodes.append((episode, frame, label, family, cohort, int(row["predictions"]["MODEL_ONLY"]),
                             int(row["predictions"]["SIEM_FINAL"]), cluster))
            for scope in SCOPES:
                predicted = row["predictions"][scope]
                if type(predicted) is not bool: raise ValueError("prediction must be an actual boolean")
                index = 0 if label and predicted else 1 if label else 2 if predicted else 3
                for kind, key in (("global", "all"), ("cohort", cohort), ("cluster", cluster)):
                    value = updates.setdefault((scope, kind, key), [0, 0, 0, 0]); value[index] += 1
                if label:
                    value = updates.setdefault((scope, "family", family), [0, 0, 0, 0]); value[index] += 1
        with self.db:
            try: self.db.executemany("INSERT INTO episodes VALUES(?,?,?,?,?,?,?,?)", episodes)
            except sqlite3.IntegrityError: raise ValueError("duplicate account/hour episode or frame cannot increase sample counts") from None
            self.db.executemany("""INSERT INTO counts(scope,kind,key,tp,fn,fp,tn) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(scope,kind,key) DO UPDATE SET tp=tp+excluded.tp,fn=fn+excluded.fn,fp=fp+excluded.fp,tn=tn+excluded.tn""",
                [(scope, kind, key, *value) for (scope, kind, key), value in updates.items()])
            self.db.execute("INSERT INTO shards(id,sha256,records) VALUES(?,?,?)", (shard_id, digest, len(rows)))
            if source_sha256 is not None:
                self.db.execute("INSERT INTO source_shards VALUES(?,?,?)", (shard_id, source_sha256, len(rows)))
        return {"shard_id": shard_id, "records": len(rows), "replayed": False}

    def completed_source_shard(self, identity, checksum, records):
        value = self.db.execute("SELECT input_sha256,records FROM source_shards WHERE id=?", (identity,)).fetchone()
        if value is None: return False
        if value != (checksum, records): raise ValueError("committed numeric scoring source changed")
        return True

    def counter(self, scope, kind="global", key="all"):
        if scope not in SCOPES: raise ValueError("unknown prediction scope")
        row = self.db.execute("SELECT tp,fn,fp,tn FROM counts WHERE scope=? AND kind=? AND key=?", (scope, kind, key)).fetchone()
        return Confusion(*(row or (0, 0, 0, 0)))

    def groups(self, scope, kind):
        if scope not in SCOPES or kind not in ("family", "cohort", "cluster"): raise ValueError("unknown group")
        for row in self.db.execute("SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind=? ORDER BY key", (scope, kind)):
            yield row[0], Confusion(*row[1:])

    def progress(self):
        return {"shards": self.db.execute("SELECT count(*) FROM shards").fetchone()[0],
                "episodes": self.db.execute("SELECT count(*) FROM episodes").fetchone()[0],
                "scopes": {scope: self.counter(scope).metrics() for scope in SCOPES}}
