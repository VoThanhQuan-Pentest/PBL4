"""Read-only verification of frozen scored-episode evidence; PASS strings are not authority."""

import hashlib
import importlib.metadata
from contextlib import closing
from itertools import zip_longest
from pathlib import Path
import sqlite3
from urllib.parse import quote

from app.catalog import parse_json
from app.policy import ScorePolicy, canonical
from app.strict_metrics import Confusion, SCOPES, exact_bounds, strict_gate

COHORTS = ("READY", "UNSEEN_READY", "COLD")
PREDICTIONS = {"MODEL_ONLY": "model_positive", "SIEM_FINAL": "siem_positive"}


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()


def math_binding():
    directory = Path(__file__).resolve().parent
    return {"sources": {name: sha_file(directory / name) for name in ("quality_proof.py", "strict_metrics.py", "policy.py", "metric_journal.py")},
            "dependencies": {name: importlib.metadata.version(name) for name in ("numpy", "scipy")}}


def readonly(path):
    if path.is_symlink() or not path.is_file(): raise ValueError("worker-owned scored journal required")
    return sqlite3.connect("file:" + quote(str(path.resolve()), safe="/") + "?mode=ro", uri=True)


def column(scope):
    if scope not in PREDICTIONS: raise ValueError("unknown quality scope")
    return PREDICTIONS[scope]


def sums(scope):
    prediction = column(scope)
    return f"COALESCE(SUM(label=1 AND {prediction}=1),0),COALESCE(SUM(label=1 AND {prediction}=0),0)," \
           f"COALESCE(SUM(label=0 AND {prediction}=1),0),COALESCE(SUM(label=0 AND {prediction}=0),0)"


def derive(db, scope, group=None):
    expressions = sums(scope)
    if group is None: return Confusion(*db.execute(f"SELECT {expressions} FROM episodes").fetchone())
    if group not in ("family", "cohort", "cluster_id"): raise ValueError("unknown scored-episode group")
    where = " WHERE label=1" if group == "family" else ""
    return {key: Confusion(*values) for key, *values in db.execute(
        f"SELECT {group},{expressions} FROM episodes{where} GROUP BY {group} ORDER BY {group}")}


def cluster_binding(db, scope):
    digest = hashlib.sha256(); total = [0, 0, 0, 0]; count = 0
    for key, *values in db.execute("SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind='cluster' ORDER BY key", (scope,)):
        digest.update((canonical([key, *values]) + "\n").encode()); count += 1
        total = [left + right for left, right in zip(total, values)]
    return {"clusters": count, "cluster_counter_sha256": digest.hexdigest(), "totals": total}


def audit_actual_rows(db):
    """Run once at finalization: cached aggregate counters must match actual predictions."""
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok": raise ValueError("scored journal integrity check failed")
    expected_columns = {"key", "frame_id", "label", "family", "cohort", "model_positive", "siem_positive", "cluster_id"}
    if {row[1] for row in db.execute("PRAGMA table_info(episodes)")} != expected_columns:
        raise ValueError("aggregate-only fixtures cannot prove actual scoring")
    populations = []
    for scope in SCOPES:
        global_count = derive(db, scope); populations.append(global_count.normals + global_count.positives)
        groups = {"global": {"all": global_count}, "family": derive(db, scope, "family"),
                  "cohort": derive(db, scope, "cohort")}
        for kind, actual in groups.items():
            stored = {key: Confusion(*values) for key, *values in db.execute(
                "SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind=? ORDER BY key", (scope, kind))}
            if stored != actual: raise ValueError("aggregate counters differ from actual scored episodes")
        actual_clusters = db.execute(f"SELECT cluster_id,{sums(scope)} FROM episodes GROUP BY cluster_id ORDER BY cluster_id")
        stored_clusters = db.execute("SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind='cluster' ORDER BY key", (scope,))
        for actual, stored in zip_longest(actual_clusters, stored_clusters):
            if actual != stored: raise ValueError("cached cluster counters differ from actual scored episodes")
    if populations[0] != populations[1] or populations[0] != db.execute("SELECT count(*) FROM episodes").fetchone()[0]:
        raise ValueError("scoring scopes dropped episodes")
    return populations[0]


def verify_confidence(counts, policy, confidence, clusters):
    if not isinstance(confidence, dict) or any(not isinstance(confidence.get(key), dict) for key in ("exact", "cluster", "conservative")):
        raise ValueError("confidence computation is not bound to actual account/day clusters")
    quality = policy.document["quality"]
    alpha = quality["alpha_numerator"] / quality["alpha_denominator"] / quality["global_comparisons"]
    if (confidence.get("method") != "exact_binomial_and_account_day_cluster_bootstrap"
            or confidence.get("comparisons") != 6 or confidence.get("familywise_confidence") != 0.95
            or confidence.get("one_sided_alpha") != alpha or confidence.get("cluster_available") is not True
            or confidence.get("resamples") != quality["cluster_resamples"] or clusters["clusters"] < 2
            or confidence.get("clusters") != clusters["clusters"]
            or confidence.get("cluster_counter_sha256") != clusters["cluster_counter_sha256"]
            or clusters["totals"] != [counts.tp, counts.fn, counts.fp, counts.tn]):
        raise ValueError("confidence computation is not bound to actual account/day clusters")
    exact = {"precision": exact_bounds(counts.tp, counts.predictions, alpha),
             "recall": exact_bounds(counts.tp, counts.positives, alpha),
             "false_positive_rate": exact_bounds(counts.fp, counts.normals, alpha)}
    for name, expected in exact.items():
        if confidence.get("exact", {}).get(name) != expected: raise ValueError("exact confidence bound was altered")
        cluster = confidence.get("cluster", {}).get(name, {})
        lower, upper = cluster.get("lower"), cluster.get("upper")
        if (type(lower) not in (int, float) or type(upper) not in (int, float) or not 0 <= lower <= upper <= 1
                or cluster.get("available") is not True): raise ValueError("invalid cluster confidence bounds")
        conservative = {"lower": min(expected["lower"], lower), "upper": max(expected["upper"], upper), "available": expected["available"]}
        if confidence.get("conservative", {}).get(name) != conservative:
            raise ValueError("conservative confidence calculation was altered")


def verify_quality(directory: Path, version: str, policy: ScorePolicy, binding: dict):
    path = directory / f"{version}.evaluation.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("bounded frozen quality evidence required")
    evaluation = parse_json(path.read_bytes())
    if (not isinstance(evaluation, dict) or evaluation.get("status") != "SUCCEEDED" or evaluation.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or evaluation.get("data_provenance") != "DEMO_ONLY" or evaluation.get("quality_math_binding") != math_binding()
            or any(evaluation.get(key) != value for key, value in binding.items())):
        raise ValueError("frozen quality code/artifact/dataset binding mismatch")
    journal_path = directory / f"{version}.metrics.sqlite"
    if (journal_path.is_symlink() or not journal_path.is_file() or evaluation.get("scored_journal_file") != journal_path.name
            or sha_file(journal_path) != evaluation.get("scored_journal_sha256")):
        raise ValueError("actual scored journal checksum mismatch")
    if not isinstance(evaluation.get("scopes"), dict) or set(evaluation["scopes"]) != set(SCOPES):
        raise ValueError("both quality scopes required")
    with closing(readonly(journal_path)) as db:
        document = parse_json(db.execute("SELECT payload FROM identity WHERE singleton=1").fetchone()[0])
        required = {**policy.wire(), **{key: binding[key] for key in ("model_sha256", "calibration_sha256", "dataset_sha256")}}
        if document != required: raise ValueError("scored journal identity differs from selected artifact")
        for scope in SCOPES:
            stored = {key: Confusion(*values) for key, *values in db.execute(
                "SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind='global'", (scope,))}
            counts = stored.get("all")
            if counts is None: raise ValueError("missing actual global scoring counters")
            groups = {}
            for kind in ("family", "cohort"):
                groups[kind] = {key: Confusion(*values) for key, *values in db.execute(
                    "SELECT key,tp,fn,fp,tn FROM counts WHERE scope=? AND kind=?", (scope, kind))}
            supplied = evaluation["scopes"][scope]
            if not isinstance(supplied, dict) or not isinstance(supplied.get("confidence"), dict):
                raise ValueError("typed confidence evidence required for both scopes")
            verify_confidence(counts, policy, supplied["confidence"], cluster_binding(db, scope))
            computed = strict_gate(counts, policy, groups["family"], groups["cohort"], supplied["confidence"], scope=scope)
            if computed != supplied or computed["quality_gate"] != "PASS":
                raise ValueError("recomputed independent/final point or confidence gate failed")
        population = db.execute("SELECT count(*) FROM episodes").fetchone()[0]
        if evaluation.get("actual_scored_episodes") != population or evaluation.get("raw_episode_audit_completed") is not True:
            raise ValueError("actual episode audit/population evidence missing")
    if evaluation.get("quality_gate") != "PASS": raise ValueError("quality gate failed")
    return evaluation
