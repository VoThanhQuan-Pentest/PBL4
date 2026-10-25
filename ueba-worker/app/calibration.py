"""Streamed, resumable raw-score calibration. Labels are integrity checks, never model inputs."""

from datetime import timedelta
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3

import numpy as np

from app.catalog import MAX_SHARD_BYTES, ShardedDataset, sha256, utc
from app.contract import FEATURE_SCHEMAS, feature_array
from app.model import ModelStore
from app.policy import ScorePolicy, canonical


def private_directory(path):
    if path.is_symlink(): raise ValueError("worker-owned cache must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def connect(path):
    if path.is_symlink(): raise ValueError("cache journal must not be a symlink")
    db = sqlite3.connect(path, timeout=30); path.chmod(0o600)
    return db


def identity(db, value):
    db.execute("CREATE TABLE IF NOT EXISTS identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL)")
    encoded = canonical(value)
    previous = db.execute("SELECT payload FROM identity WHERE singleton=1").fetchone()
    if previous is not None and previous[0] != encoded: raise ValueError("cached raw-score identity changed")
    if previous is None:
        db.execute("INSERT INTO identity VALUES(1,?)", (encoded,)); db.commit()


def cohort_split(dataset, name, cohort):
    split = dataset.split(name)
    if (split["positive"] or split["cohorts"] != {cohort: split["records"]}
            or split["families"] != {"normal": split["records"]}):
        raise ValueError("independent all-normal calibration cohort required")
    return split


def prove_unique_split(dataset, name, directory):
    """One disk-backed episode proof per dataset/split, reused across forests."""
    split = dataset.split(name)
    proof = private_directory(directory / ("integrity-" + split["sha256"][:24]))
    with (proof / "writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = connect(proof / "episodes.sqlite")
        try:
            identity(db, {"dataset_sha256": dataset.sha256, "split_sha256": split["sha256"], "split": name})
            db.executescript("""CREATE TABLE IF NOT EXISTS windows(frame_id TEXT UNIQUE NOT NULL, episode TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS shards(id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, records INTEGER NOT NULL);""")
            for number, descriptor in enumerate(split["shards"]):
                previous = db.execute("SELECT sha256,records FROM shards WHERE id=?", (descriptor["id"],)).fetchone()
                if previous is not None:
                    if previous != (descriptor["sha256"], descriptor["records"]) or sha256(dataset._read(descriptor["path"], MAX_SHARD_BYTES)) != descriptor["sha256"]:
                        raise ValueError("integrity shard changed")
                    continue
                _, rows = dataset.load_shard(name, number)
                episodes = [(row["frame_id"], row["account_id"] + "/" + utc(row["window_start"]).strftime("%Y-%m-%dT%H")) for row in rows]
                with db:
                    try: db.executemany("INSERT INTO windows VALUES(?,?)", episodes)
                    except sqlite3.IntegrityError: raise ValueError("duplicate primary calibration episode/frame") from None
                    db.execute("INSERT INTO shards VALUES(?,?,?)", (descriptor["id"], descriptor["sha256"], len(rows)))
            if db.execute("SELECT count(*) FROM windows").fetchone()[0] != split["records"]:
                raise ValueError("incomplete integrity population")
        finally: db.close()


def numeric_cache(dataset, name, directory):
    """Private numeric memmap; every source shard and tensor slice remains hash-bound.

    Parsing/feature validation occurs once per immutable split, not once per
    forest or threshold sweep. No label/account/category enters this matrix.
    """
    split = dataset.split(name)
    schema = dataset.manifest["feature_schema_version"]
    columns = len(FEATURE_SCHEMAS[schema])
    binding = {"dataset_sha256": dataset.sha256, "split_sha256": split["sha256"], "feature_schema_version": schema,
               "records": split["records"], "columns": columns, "dtype": "little_endian_float64"}
    leaf = private_directory(directory / ("vectors-" + hashlib.sha256(canonical(binding).encode()).hexdigest()[:24]))
    with (leaf / "writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = connect(leaf / "vectors.sqlite")
        try:
            identity(db, binding)
            db.execute("CREATE TABLE IF NOT EXISTS shards(id TEXT PRIMARY KEY,input_sha256 TEXT NOT NULL,offset INTEGER NOT NULL,records INTEGER NOT NULL,vector_sha256 TEXT NOT NULL)")
            path = leaf / "features.f64"
            if path.is_symlink(): raise ValueError("numeric tensor cannot be a symlink")
            if not path.exists():
                if db.execute("SELECT count(*) FROM shards").fetchone()[0]: raise ValueError("committed numeric feature bytes lost")
                if getattr(dataset, "archive_sha256", None) is not None:
                    from app.storage_budget import require_headroom
                    require_headroom(leaf, split["records"] * columns * 8)
                with path.open("xb") as stream: stream.truncate(split["records"] * columns * 8)
                path.chmod(0o600)
            if path.stat().st_size != split["records"] * columns * 8: raise ValueError("cached numeric feature length changed")
            vectors = np.memmap(path, dtype="<f8", mode="r+", shape=(split["records"], columns))
            offset = 0
            try:
                for number, descriptor in enumerate(split["shards"]):
                    end = offset + descriptor["records"]
                    previous = db.execute("SELECT input_sha256,offset,records,vector_sha256 FROM shards WHERE id=?", (descriptor["id"],)).fetchone()
                    if previous is not None:
                        source = sha256(dataset._read(descriptor["path"], MAX_SHARD_BYTES))
                        vector = hashlib.sha256(vectors[offset:end].tobytes()).hexdigest()
                        if previous != (source, offset, descriptor["records"], vector) or source != descriptor["sha256"]:
                            raise ValueError("numeric tensor/source checkpoint changed")
                    else:
                        _, rows = dataset.load_shard(name, number)
                        values = feature_array([row["features"] for row in rows], 5000, schema)
                        vectors[offset:end] = values; vectors.flush()
                        with path.open("rb") as stream: os.fsync(stream.fileno())
                        digest = hashlib.sha256(vectors[offset:end].tobytes()).hexdigest()
                        with db: db.execute("INSERT INTO shards VALUES(?,?,?,?,?)", (descriptor["id"], descriptor["sha256"], offset, len(rows), digest))
                    offset = end
                if offset != split["records"] or db.execute("SELECT sum(records) FROM shards").fetchone()[0] != offset:
                    raise ValueError("incomplete actual numeric feature population")
            finally: vectors._mmap.close()
            return path
        finally: db.close()


def score_cache(dataset: ShardedDataset, name, model, source_sha256, directory: Path, *, progress=None, sort_output=True):
    """Private offline batches <=5000. Public scoring retains its <=256 limit."""
    split = dataset.split(name)
    schema = dataset.manifest["feature_schema_version"]
    columns = len(FEATURE_SCHEMAS[schema])
    binding = {"dataset_sha256": dataset.sha256, "split_sha256": split["sha256"], "source_model_sha256": source_sha256,
               "feature_schema_version": schema, "records": split["records"]}
    scorer_identity = ModelStore.scoring_identity(model)
    if scorer_identity is not None: binding["scoring_implementation"] = scorer_identity
    checksum = hashlib.sha256(canonical(binding).encode()).hexdigest()
    leaf = private_directory(directory / ("scores-" + checksum[:24]))
    prove_unique_split(dataset, name, directory)
    features_path = numeric_cache(dataset, name, directory)
    with (leaf / "writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = connect(leaf / "scores.sqlite")
        features = np.memmap(features_path, dtype="<f8", mode="r", shape=(split["records"], columns))
        try:
            identity(db, binding)
            db.execute("CREATE TABLE IF NOT EXISTS shards(id TEXT PRIMARY KEY, input_sha256 TEXT NOT NULL, offset INTEGER NOT NULL, records INTEGER NOT NULL, score_sha256 TEXT NOT NULL)")
            path = leaf / "raw.f64"
            if path.is_symlink(): raise ValueError("raw score file cannot be a symlink")
            if not path.exists():
                if db.execute("SELECT count(*) FROM shards").fetchone()[0]: raise ValueError("cached score bytes were lost")
                if getattr(dataset, "archive_sha256", None) is not None:
                    from app.storage_budget import require_headroom
                    require_headroom(leaf, split["records"] * 8)
                with path.open("xb") as stream: stream.truncate(split["records"] * 8)
                path.chmod(0o600)
            if path.stat().st_size != split["records"] * 8: raise ValueError("cached numeric score length changed")
            scores = np.memmap(path, dtype="<f8", mode="r+", shape=(split["records"],))
            offset, reused, computed = 0, 0, 0
            try:
                for descriptor in split["shards"]:
                    count = descriptor["records"]; end = offset + count
                    previous = db.execute("SELECT input_sha256,offset,records,score_sha256 FROM shards WHERE id=?", (descriptor["id"],)).fetchone()
                    if previous is not None:
                        digest = hashlib.sha256(scores[offset:end].tobytes()).hexdigest()
                        if previous != (descriptor["sha256"], offset, count, digest): raise ValueError("cached scoring checkpoint/bytes changed")
                        reused += 1
                    else:
                        raw = -model.score_samples(features[offset:end])
                        if raw.shape != (count,) or not np.isfinite(raw).all(): raise ValueError("invalid actual forest raw scores")
                        scores[offset:end] = raw; scores.flush()
                        with path.open("rb") as stream: os.fsync(stream.fileno())
                        digest = hashlib.sha256(scores[offset:end].tobytes()).hexdigest()
                        with db: db.execute("INSERT INTO shards VALUES(?,?,?,?,?)", (descriptor["id"], descriptor["sha256"], offset, count, digest))
                        computed += 1
                    offset = end
                    if progress: progress({"split": name, "scored_records": offset, "computed_shards": computed, "reused_shards": reused})
                if offset != split["records"] or db.execute("SELECT sum(records) FROM shards").fetchone()[0] != offset:
                    raise ValueError("incomplete actual calibration scoring")
                # Do not sort the checkpointed raw cache: validation/grid sweeps
                # reuse its correspondence. A single bounded cohort copy is sorted.
                ordered = np.array(scores, dtype=np.float64)
                if sort_output: ordered.sort()
                receipt = {**binding, "raw_score_sha256": hashlib.sha256(scores.tobytes()).hexdigest(),
                           "sorted_score_sha256": hashlib.sha256(ordered.astype("<f8", copy=False).tobytes()).hexdigest() if sort_output else None,
                           "returned_order": "SORTED" if sort_output else "INPUT_CORRESPONDENCE",
                           "computed_shards": computed, "reused_shards": reused}
            finally: scores._mmap.close()
            return ordered, receipt
        finally:
            features._mmap.close()
            db.close()


def recalibrate(store: ModelStore, dataset: ShardedDataset, fold: int, source_version: str,
                target_version: str, policy: ScorePolicy, directory: Path, *, progress=None):
    if type(fold) is not int or fold not in (1, 2, 3) or not policy.strict_gate:
        raise ValueError("approved temporal fold and strict score policy required")
    source, payload = store.load_candidate(source_version)
    fit = dataset.split(f"fold{fold}-fit")
    if (source["feature_schema_version"] != dataset.manifest["feature_schema_version"]
            or policy.document["feature_schema_version"] != dataset.manifest["feature_schema_version"]
            or source.get("dataset_manifest_sha256") != dataset.sha256
            or source.get("fit_split_sha256") != fit["sha256"] or source.get("training_windows") != fit["records"]):
        raise ValueError("fitted forest does not belong to this immutable dataset/fold")
    scope = "STRICT" if dataset.manifest["stage"] == "STRICT" else "PILOT_ONLY"
    minimum = 1_000_000 if scope == "STRICT" else 100
    arrays, receipts, hashes = {}, {}, {}
    directory = private_directory(directory)
    for cohort in ("READY", "COLD"):
        name = f"fold{fold}-calibration-{cohort.lower()}"
        split = cohort_split(dataset, name, cohort)
        if not minimum <= split["records"] <= 2_000_000: raise ValueError("independent cohort calibration population is insufficient/beyond bound")
        if utc(split["from"]) - utc(fit["to"]) <= timedelta(days=14):
            raise ValueError("calibration must follow fitted windows outside the baseline-history horizon")
        arrays[cohort], receipts[cohort] = score_cache(dataset, name, payload["model"], source["sha256"], directory, progress=progress)
        hashes[cohort] = split["sha256"]
    if store.load_candidate(source_version)[0]["sha256"] != source["sha256"]:
        raise ValueError("source forest changed during recalibration")
    existing = (store.directory / f"{target_version}.json").exists() or (store.directory / f"{target_version}.joblib").exists()
    if existing:
        result, payload = store.load_candidate(target_version)
        calibration_hash = store.calibration_hash({"calibration_by_cohort": arrays})
        required = {"source_model_sha256": source["sha256"], "source_model_version": source_version,
                    "dataset_manifest_sha256": dataset.sha256, "calibration_split_sha256": hashes,
                    "calibration_scope": scope, "score_policy": policy.wire(), "calibration_sha256": calibration_hash}
        if any(result.get(key) != value for key, value in required.items()) or store.calibration_hash(payload) != calibration_hash:
            raise ValueError("existing recalibrated publication differs from this immutable operation")
    else:
        result = store.recalibrated_candidate(source_version, target_version, arrays, policy,
                    expected_source_sha256=source["sha256"], dataset_sha256=dataset.sha256,
                    split_sha256=hashes, calibration_scope=scope)
    return {"metadata": result, "calibration_receipts": receipts, "additional_fit_calls": 0, "publication_recovered": existing}
