#!/usr/bin/env python3
"""One predeclared R2 validation config/fold; immutable caches, <=800 samples.

Run in the historically pinned worker image with read-only R2/legacy mounts.
Source mapping streams only the single validation split. It never rescores a
population, opens another split, fits, recalibrates, selects, or uses holdout.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import heapq
import json
import lzma
from pathlib import Path
import resource
import signal
import sqlite3
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish

RUN_ID = "hybrid-v1-iterations-100-leaves-15-l2-0-seed-42-fold-1"
POLICY_ID = "strict-v4d-r99990000-c99999500-rules70"
SPLIT = "fold1-validation"


def readonly(path):
    path = Path(path).absolute()
    if path.is_symlink() or any((Path(str(path) + suffix).exists() and Path(str(path) + suffix).stat().st_size)
                                for suffix in ("-wal", "-journal")):
        raise ValueError("static cache without a pending journal required")
    return sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)


def cache_path(parent, prefix, binding):
    # Matches the frozen worker's policy.canonical (ASCII; these bindings are ASCII).
    encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return parent / (prefix + "-" + hashlib.sha256(encoded.encode()).hexdigest()[:24])


def cache_journal(path, binding):
    with readonly(path) as db:
        value = db.execute("SELECT payload FROM identity WHERE singleton=1").fetchone()
        if not value or json.loads(value[0]) != binding:
            raise ValueError("cache identity mismatch")
        rows = db.execute("SELECT id,input_sha256,offset,records," +
                          ("score_sha256" if path.name == "scores.sqlite" else "decision_sha256") + " FROM shards").fetchall()
    return {row[0]: row[1:] for row in rows}


def keep_sample(heaps, row, category, predictions, raw, percentile, offset):
    """Hash-ranked, predeclared strata; metadata keys never enter the scorer."""
    cohort = row["cohort"]
    if category == "FP":
        key, cap = (category, cohort), {"READY": 100, "UNSEEN_READY": 50, "COLD": 50}[cohort]
    elif category == "FN":
        key, cap = (category,), 200
    elif category == "TN":
        key, cap = (category, cohort), {"READY": 100, "UNSEEN_READY": 50, "COLD": 50}[cohort]
    else:
        key, cap = (category, row["family"], cohort), {"READY": 28, "UNSEEN_READY": 8, "COLD": 4}[cohort]
    rank = int(hashlib.sha256(("p2-seed42/" + row["frame_id"]).encode()).hexdigest(), 16)
    item = (-rank, row["frame_id"], {"row": row, "category": category, "predictions": predictions,
                                   "raw_anomaly_score": raw, "normal_percentile": percentile, "source_offset": offset})
    heap = heaps[key]
    if len(heap) < cap:
        heapq.heappush(heap, item)
    elif item[:2] > heap[0][:2]:
        heapq.heapreplace(heap, item)


def read_validation_shard(root, descriptor, archive_map, budget):
    relative = Path(descriptor["path"])
    if (relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 2
            or relative.parts[0] != "shards" or not relative.name.startswith(SPLIT + "-")):
        raise ValueError("only predeclared validation shard paths are allowed")
    archived = archive_map[descriptor["path"]]
    if archived["original_sha256"] != descriptor["sha256"]:
        raise ValueError("archive/source binding changed")
    archive_relative = Path(archived["archive_path"])
    if str(archive_relative) != str(relative) + ".xz":
        raise ValueError("unexpected archive path")
    path = root / archive_relative
    if path.is_symlink() or path.parent.is_symlink() or path.stat().st_size != archived["archive_bytes"]:
        raise ValueError("archive file changed")
    budget["compressed_bytes"] += path.stat().st_size
    budget["decoded_bytes"] += archived["original_bytes"]
    if budget["compressed_bytes"] > 256 * 1024**2 or budget["decoded_bytes"] > 1536 * 1024**2:
        raise ValueError("P2 input byte budget exceeded")
    if digest(path) != archived["archive_sha256"] or archived["original_bytes"] > 8 * 1024**2:
        raise ValueError("archive checksum or per-shard byte bound failed")
    with lzma.open(path, "rb") as stream:
        payload = stream.read(archived["original_bytes"] + 1)
    if len(payload) != archived["original_bytes"] or hashlib.sha256(payload).hexdigest() != descriptor["sha256"]:
        raise ValueError("decoded validation shard checksum mismatch")
    rows = json.loads(payload)
    if len(rows) != descriptor["records"]:
        raise ValueError("validation row mapping changed")
    return rows


def run(r2, output):
    started = time.monotonic()
    def expired(*_):
        raise TimeoutError("STOP_BUDGET: predeclared 30 minute P2 deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(1800)
    output = private_directory(output)
    protocol = json.loads((output / "p2.protocol.private.json").read_text())
    if protocol["runner_sha256"] != digest(__file__) or protocol["run_id"] != RUN_ID or protocol["policy_id"] != POLICY_ID:
        raise ValueError("predeclared diagnostic runner/config/policy changed")
    import numpy as np
    from app.model import ModelStore
    from app.hybrid_incident import HybridIncidentScorer
    from app.normal_support import NormalSupportScorer
    from sklearn.ensemble import HistGradientBoostingClassifier
    def forbidden_fit(*_args, **_kwargs):
        raise AssertionError("P2 never fits")
    for cls, method in ((ModelStore, "train"), (HybridIncidentScorer, "fit"),
                        (NormalSupportScorer, "fit"), (HistGradientBoostingClassifier, "fit")):
        setattr(cls, method, forbidden_fit)
    standard = r2 / "source/standard"
    for relative, expected in protocol["input_sha256"].items():
        if digest(r2 / relative) != expected:
            raise ValueError("predeclared R2 metadata changed")
    identity = json.loads((r2 / "parallel-campaign.identity.private.json").read_text())
    for relative, expected in identity["continuation_identity"]["python_sources"].items():
        if digest(r2 / "code/app" / relative) != expected:
            raise ValueError("frozen Python changed")
    manifest = json.loads((standard / "manifest.json").read_text())
    split = manifest["splits"][SPLIT]
    validation = json.loads((standard / "hybrid-validations" / (RUN_ID + ".json")).read_text())
    if validation["validation_split_sha256"] != split["sha256"] or validation["evaluation_scope"] != "VALIDATION":
        raise ValueError("only pinned validation is permitted")
    selected = next(p for p in validation["policies"] if p["policy"]["policy_id"] == POLICY_ID)
    policy = json.loads(selected["policy"]["policy_document_json"])
    if policy["risk"]["auto_containment"] is not False:
        raise ValueError("detection-only policy required")
    raw_receipt, rule_receipt = validation["raw_score_receipt"], validation["production_rule_receipt"]
    # This serial validation was imported into R2. Its trusted cache location is
    # followed from R2's own immutable legacy reference, not guessed from offsets.
    legacy = Path(identity["legacy_campaign_reference"]["source_root"]) / "standard/hybrid-score-cache"
    score_binding = {key: raw_receipt[key] for key in ("dataset_sha256", "split_sha256", "source_model_sha256",
                      "feature_schema_version", "records", "scoring_implementation")}
    rule_binding = {key: rule_receipt[key] for key in ("dataset_sha256", "split_sha256", "classes", "policy_sha256", "records")}
    scores_leaf = cache_path(legacy, "scores", score_binding)
    rules_leaf = cache_path(legacy, "rules", rule_binding)
    score_journal = cache_journal(scores_leaf / "scores.sqlite", score_binding)
    rule_journal = cache_journal(rules_leaf / "rules.sqlite", rule_binding)
    if (digest(scores_leaf / "raw.f64") != raw_receipt["raw_score_sha256"]
            or digest(rules_leaf / "rules.u8") != rule_receipt["decision_sha256"]):
        raise ValueError("receipt-bound cached decisions/scores changed")
    count = split["records"]
    if count != 1_001_000 or len(score_journal) != len(split["shards"]) or len(rule_journal) != len(split["shards"]):
        raise ValueError("one complete cached validation mapping required")
    if (scores_leaf / "raw.f64").stat().st_size != count * 8 or (rules_leaf / "rules.u8").stat().st_size != count * 3:
        raise ValueError("cache lengths changed")
    raw = np.memmap(scores_leaf / "raw.f64", dtype="<f8", mode="r", shape=(count,))
    rules = np.memmap(rules_leaf / "rules.u8", dtype="u1", mode="r", shape=(count, 3))
    model_version = validation["model_version"]
    metadata_path = standard / "hybrid-models" / (model_version + ".json")
    model_path = standard / "hybrid-models" / (model_version + ".joblib")
    if digest(model_path) != validation["model_sha256"] or digest(metadata_path) != protocol["model_metadata_sha256"]:
        raise ValueError("own-worker model trust/integrity failed before deserialize")
    metadata, payload = ModelStore(standard / "hybrid-models").load_candidate(model_version)
    if metadata["calibration_sha256"] != validation["calibration_sha256"]:
        raise ValueError("validation calibration changed")
    archives = json.loads((standard / "archives.private.json").read_text())["shards"]
    heaps = defaultdict(list)
    counts = {scope: Counter() for scope in ("MODEL_ONLY", "SIEM_FINAL")}
    cohorts = {scope: defaultdict(Counter) for scope in counts}
    budget = {"compressed_bytes": 0, "decoded_bytes": 0}
    offset = 0
    for descriptor in split["shards"]:
        end = offset + descriptor["records"]
        score_bytes, rule_bytes = raw[offset:end].tobytes(), rules[offset:end].tobytes()
        for journal, chunk in ((score_journal, score_bytes), (rule_journal, rule_bytes)):
            if journal.get(descriptor["id"]) != (descriptor["sha256"], offset, descriptor["records"], hashlib.sha256(chunk).hexdigest()):
                raise ValueError("cache/source shard ordering changed")
        rows = read_validation_shard(standard, descriptor, archives, budget)
        if len(descriptor["cohorts"]) != 1:
            raise ValueError("explicit homogeneous cohort shard required")
        cohort = next(iter(descriptor["cohorts"]))
        calibration = payload["calibration_by_cohort"]["COLD" if cohort == "COLD" else "READY"]
        values = raw[offset:end]
        percentiles = (np.searchsorted(calibration, values, side="left") + np.searchsorted(calibration, values, side="right")) / (2 * len(calibration)) * 100
        threshold = policy["detection_percentile_micro"]["COLD" if cohort == "COLD" else "READY"] / 1_000_000
        model_positive = percentiles >= threshold
        if not np.isin(rules[offset:end], (0, 1)).all():
            raise ValueError("invalid cached rule decisions")
        observed_labels = Counter()
        for index, row in enumerate(rows):
            if row["cohort"] != cohort or type(row["label"]) is not int or row["label"] not in (0, 1):
                raise ValueError("source labels/cohorts changed")
            observed_labels[row["label"]] += 1
            predictions = {"MODEL_ONLY": bool(model_positive[index]),
                           "SIEM_FINAL": bool(model_positive[index] or rules[offset + index, 2])}
            categories = {}
            for scope, predicted in predictions.items():
                category = ("TP" if predicted else "FN") if row["label"] else ("FP" if predicted else "TN")
                categories[scope] = category
                counts[scope][category.lower()] += 1
                cohorts[scope][cohort][category.lower()] += 1
            category = "FP" if "FP" in categories.values() else "FN" if "FN" in categories.values() else categories["SIEM_FINAL"]
            keep_sample(heaps, row, category, predictions, float(values[index]), float(percentiles[index]), offset + index)
        if observed_labels != {0: descriptor["normal"], 1: descriptor["positive"]}:
            raise ValueError("source label counts differ from manifest")
        offset = end
    if offset != count:
        raise ValueError("incomplete validation mapping")
    for scope, actual in counts.items():
        if any(actual[k] != selected["scopes"][scope][k] for k in ("tp", "fn", "fp", "tn")):
            raise ValueError("cached predictions failed parity with frozen validation receipt")
    samples = sorted((item[2] for heap in heaps.values() for item in heap), key=lambda r: (r["category"], r["row"]["frame_id"]))
    sampled = Counter(row["category"] for row in samples)
    if sampled["FP"] > 200 or sampled["FN"] > 200 or sampled["TP"] + sampled["TN"] > 400:
        raise ValueError("P2 sample cap exceeded")
    components = payload["model"].score_components(np.asarray([s["row"]["features"] for s in samples], dtype=np.float64))
    if not np.allclose(components["raw_anomaly_score"], [s["raw_anomaly_score"] for s in samples], atol=1e-12, rtol=1e-12):
        raise ValueError("frozen component scoring differs from cached raw scores")
    for index, sample in enumerate(samples):
        sample["components"] = {key: value[index].tolist() for key, value in components.items()}
    publish(output / "p2.samples.private.json", {"samples": samples}, maximum=2 * 1024**2)
    component_summary = {}
    for category in sorted(sampled):
        group = [sample for sample in samples if sample["category"] == category]
        component_summary[category] = {key: {"minimum": float(np.min([s["components"][key] for s in group])),
                "median": float(np.median([s["components"][key] for s in group])),
                "maximum": float(np.max([s["components"][key] for s in group]))}
                for key in components if key != "uncalibrated_context_probabilities"}
    feature_summary = {category: {name: float(np.median([s["row"]["features"][index] for s in samples if s["category"] == category]))
                        for index, name in enumerate(manifest["feature_names"])} for category in sorted(sampled)}
    receipt = {"phase": "P2", "status": "DIAGNOSIS_COMPLETE", "run_id": RUN_ID, "policy_id": POLICY_ID,
               "scope": "ONE_CONFIG_ONE_FOLD_EXISTING_VALIDATION", "data_provenance": "DEMO_ONLY",
               "protocol_sha256": digest(output / "p2.protocol.private.json"), "samples_sha256": digest(output / "p2.samples.private.json"),
               "source_split_sha256": split["sha256"], "source_mapping_rows_read": count, "analysis_sample_counts": dict(sampled),
               "existing_validation_counts": {scope: dict(value) for scope, value in counts.items()},
               "existing_validation_cohort_counts": {scope: {key: dict(value) for key, value in groups.items()} for scope, groups in cohorts.items()},
               "component_summary": component_summary, "feature_medians": feature_summary,
               "source_model_sha256": validation["model_sha256"], "calibration_sha256": validation["calibration_sha256"],
               "score_cache": str(scores_leaf), "score_cache_sha256": raw_receipt["raw_score_sha256"],
               "rules_cache": str(rules_leaf), "rules_cache_sha256": rule_receipt["decision_sha256"],
               "source_bytes": budget, "additional_fit_calls": 0, "additional_population_score_calls": 0,
               "component_scored_rows": len(samples), "postlogin_slice_available": False,
               "holdout_scored": False, "auto_containment": False, "enforcement_changed": False, "aws_changed": False,
               "elapsed_seconds": round(time.monotonic() - started, 3),
               "peak_rss_kib_self": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               "sample_limitation": "Stratified diagnostic sample is not a population FPR estimate or qualification.",
               "next_action": "Versioned server-session telemetry and temporal representation repair before P3; preserve R2."}
    proof = commit(output, receipt, phase="p2")
    publish(output / "operator-state.private.json", {"version": 1, "phase": "P2", "status": receipt["status"],
            "last_verified_commit": proof, "active_handle": None, "composite_fits": 0, "component_fits": 0,
            "next_action": receipt["next_action"], "holdout_scored": False, "auto_containment": False, "aws_changed": False,
            "enforcement_semantics": "REJECT_SENSITIVE_ACTION_BEFORE_SIDE_EFFECT_OR_COMMIT"})
    print(canonical({key: receipt[key] for key in ("status", "analysis_sample_counts", "existing_validation_counts", "elapsed_seconds")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r2", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.r2.absolute(), args.output.absolute())


if __name__ == "__main__":
    main()
