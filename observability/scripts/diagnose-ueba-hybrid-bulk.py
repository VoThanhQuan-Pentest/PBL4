#!/usr/bin/env python3
"""One protected actual ModelStore BULK_PILOT diagnostic; never activation."""
import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import timedelta
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.catalog import ShardedDataset, parse_json, utc
from app.contract import FEATURE_NAMES_V4, feature_array
from app.hybrid_bulk_dataset import checksum, load_hybrid_bulk_fit, training_targets, value_sha
from app.hybrid_incident import HybridIncidentScorer, HybridResearchConfig
from app.hybrid_semantic import state_sha256 as fitted_state_sha
from app.model import ModelStore
from app.normal_support import NormalSupportScorer
from app.policy import ScorePolicy, canonical
from app.risk_replay import JavaRiskReplay

SPEC = importlib.util.spec_from_file_location("bulk_fixed_metric_helpers", ROOT / "observability/scripts/diagnose-ueba-normal-density.py")
fixed = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixed
SPEC.loader.exec_module(fixed)

BASE = ROOT / "observability/runtime/hybrid-bulk-20261004-Y6aJhfoH"
BULK = BASE / "data"
BULK_SHA = "05de02eed5b3adc5f0ea08b99d4e48f02e32053384413b62bb9b39e56af6f4c4"
CATALOG = BASE / "normal-catalog-v2"
CATALOG_SHA = "6bc1961168954a7a53287bf4a4eedcd56b94ab3f22c6625803f2cb94b85a9788"
IMAGE = fixed.IMAGE_ID
SOURCES = ("observability/scripts/diagnose-ueba-hybrid-bulk.py", "observability/scripts/diagnose-ueba-normal-density.py",
    "ueba-worker/app/model.py", "ueba-worker/app/model_state_dispatch.py", "ueba-worker/app/hybrid_incident.py",
    "ueba-worker/app/hybrid_semantic.py", "ueba-worker/app/hybrid_bulk_dataset.py", "ueba-worker/app/hybrid_dataset.py",
    "ueba-worker/app/normal_support.py", "ueba-worker/app/contract.py", "ueba-worker/app/catalog.py",
    "ueba-worker/app/policy.py", "ueba-worker/app/risk_replay.py", "ueba-worker/app/strict_metrics.py", "ueba-worker/app/validation.py")


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def fingerprint(catalog, manifest):
    shards = {d["path"]: d["sha256"] for s in catalog.manifest["splits"].values() for d in s["shards"]}
    bulk_shards = {d["path"]: d["sha256"] for s in manifest["training_sections"].values() for d in s["shards"]}
    if checksum(CATALOG / "manifest.json") != CATALOG_SHA or checksum(BULK / "manifest.private.json") != BULK_SHA:
        raise ValueError("fixed catalog/training manifest changed")
    if any(checksum(CATALOG / p) != h for p, h in shards.items()) or any(checksum(BULK / p) != h for p, h in bulk_shards.items()):
        raise ValueError("fixed source numeric shard changed")
    return {"sources": {p: checksum(ROOT / p) for p in SOURCES}, "dependencies": {
        p: importlib.metadata.version(p) for p in ("scikit-learn", "numpy", "scipy", "joblib")},
        "execution_image_id": IMAGE, "catalog_manifest_sha256": CATALOG_SHA, "catalog_shards": shards,
        "labeled_training_manifest_sha256": BULK_SHA, "labeled_shards": bulk_shards, "java": fixed.frozen_java()}


def load_inputs():
    normal, supervised, manifest = load_hybrid_bulk_fit(BULK, BULK_SHA)
    catalog = ShardedDataset(CATALOG, expected_sha256=CATALOG_SHA)
    if catalog.manifest["stage"] != "PILOT" or catalog.manifest["feature_names"] != list(FEATURE_NAMES_V4):
        raise ValueError("schema4 PILOT catalog required")
    splits = {n: [r for _, shard in catalog.iter_shards(n) for r in shard] for n in fixed.SPLITS}
    if splits["fold1-fit"] != normal or catalog.split("fold1-fit")["sha256"] != manifest["training_sections"]["NORMAL_COMPONENT"]["sha256"]:
        raise ValueError("catalog must contain actual 50000 source FIT rows, not an inflated descriptor")
    if len(normal) != 50000 or len(supervised) != 81500 or len(splits["fold1-validation"]) != 21000:
        raise ValueError("complete bulk training/old validation populations required")
    frames = {r["frame_id"] for r in supervised}
    hours = {(r["account_id"], utc(r["window_start"]).strftime("%Y-%m-%dT%H")) for r in supervised}
    for name in fixed.SPLITS[1:]:
        if any(r["frame_id"] in frames or (r["account_id"], utc(r["window_start"]).strftime("%Y-%m-%dT%H")) in hours for r in splits[name]):
            raise ValueError("score-only rows leaked into training")
    for cohort in ("READY", "COLD"):
        selected = splits["fold1-calibration-" + cohort.lower()]
        if len(selected) != 60000 or any(r["label"] or r["cohort"] != cohort for r in selected):
            raise ValueError("exact independent 60000-normal cohort calibration required")
        if min(utc(r["window_start"]) for r in selected) - max(utc(r["window_start"]) for r in supervised) <= timedelta(days=14):
            raise ValueError("training/calibration history gap required")
    return normal, supervised, manifest, catalog, splits


class FitAudit:
    def __init__(self):
        self.allowed = True
        self.counts = Counter()
        self.stack = ExitStack()

    def __enter__(self):
        for name, cls in (("composite", HybridIncidentScorer), ("normal", NormalSupportScorer), ("classifier", HistGradientBoostingClassifier)):
            original = cls.fit
            def tracked(model, *args, _name=name, _original=original, **kwargs):
                if not self.allowed: raise AssertionError("unexpected additional fit during load/recalibration/replay")
                self.counts[_name] += 1
                return _original(model, *args, **kwargs)
            self.stack.enter_context(patch.object(cls, "fit", tracked))
        return self

    def freeze(self):
        if self.counts != Counter({"composite": 1, "normal": 1, "classifier": 1}):
            raise AssertionError("one composite/two component genuine fits required")
        self.allowed = False

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


def verified_load(store, version, expected_sha):
    if checksum(store.directory / (version + ".joblib")) != expected_sha:
        raise ValueError("own trusted saved model artifact checksum changed")
    return store.load_candidate(version)


def run(output=None):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID") != IMAGE or not Path("/.dockerenv").exists():
        raise ValueError("pinned Docker-only diagnostic required")
    normal, supervised, manifest, catalog, rows = load_inputs()
    before = fingerprint(catalog, manifest)
    policy, config = ScorePolicy.strict(schema=4), HybridResearchConfig(200, 31, 1, 42)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="hybrid-bulk-default-", dir=ROOT / "observability/runtime"))
    else:
        output = Path(output).absolute()
        if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
            raise ValueError("new protected diagnostic output required")
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    declaration = {"stage": "BULK_PILOT_DEMO_ONLY", "integrity_before": before, "configuration": vars(config),
        "parameters": HybridIncidentScorer(config).parameters(), "policy": policy.wire(),
        "populations": {"normal_fit": 50000, "supervised_fit": 81500, "bootstrap_ready_calibration": 5000,
            "calibration": {"READY": 60000, "COLD": 60000}, "validation_normal": 20000, "validation_positive": 1000},
        "fit_calls_before_declaration": 0, "score_calls_before_declaration": 0,
        "threshold_or_label_or_feature_tuning": False, "activation_or_selection": False, "quality_gate": "NOT_APPLICABLE"}
    write_new(output / "predeclared.private.json", declaration)
    directory = output / "models"
    directory.mkdir(mode=0o700)
    store = ModelStore(directory)
    artifacts, started = {}, time.monotonic()
    with FitAudit() as fits:
        initial = store.train("bulk_hybrid_initial_42", [r["features"] for r in normal],
            [r["features"] for r in rows["fold1-calibration-ready"][:5000]], schema_version=4, config=config, policy=policy,
            labeled_samples=[r["features"] for r in supervised], labeled_targets=training_targets(supervised))
        fits.freeze()
        print(canonical({"stage": "TRAINED_SAVED", "actual_fit_calls": dict(fits.counts), "normal_fit": 50000,
            "labeled_fit": 81500, "quality_gate": "NOT_APPLICABLE"}), flush=True)
        _, payload = verified_load(store, initial["model_version"], initial["sha256"])
        fitted_sha = fitted_state_sha(payload["model"])
        bound = store.publish_candidate("bulk_hybrid_bound_42", payload, {**initial,
            "labeled_training_artifact_id": manifest["artifact_id"], "labeled_training_manifest_sha256": BULK_SHA,
            "dataset_manifest_sha256": CATALOG_SHA, "normal_fit_split_sha256": catalog.split("fold1-fit")["sha256"],
            "training_scope": "BULK_PILOT_DEMO_ONLY_SEPARATE_CHRONOLOGICAL_TRAINING"})
        _, payload = verified_load(store, bound["model_version"], bound["sha256"])
        if fitted_state_sha(payload["model"]) != fitted_sha: raise ValueError("saved/restored fitted numeric state changed")
        buckets = {}
        for cohort in ("READY", "COLD"):
            scores = []
            selected = rows["fold1-calibration-" + cohort.lower()]
            for offset in range(0, len(selected), 5000):
                scores.extend(payload["model"].anomaly_scores([r["features"] for r in selected[offset:offset+5000]]))
            buckets[cohort] = np.sort(np.asarray(scores, dtype=np.float64))
            print(canonical({"stage": "CALIBRATED", "cohort": cohort, "normal_rows": len(scores),
                "additional_fit_calls": 0, "quality_gate": "NOT_APPLICABLE"}), flush=True)
        write_new(output / "calibration.private.json", {k:v.tolist() for k,v in buckets.items()})
        calibrated = store.recalibrated_candidate(bound["model_version"], "bulk_hybrid_calibrated_42", buckets, policy,
            expected_source_sha256=bound["sha256"], dataset_sha256=CATALOG_SHA,
            split_sha256={c:catalog.split("fold1-calibration-"+c.lower())["sha256"] for c in buckets}, calibration_scope="PILOT_ONLY")
        metadata, payload = verified_load(store, calibrated["model_version"], calibrated["sha256"])
        if fitted_state_sha(payload["model"]) != fitted_sha or metadata["labeled_training_manifest_sha256"] != BULK_SHA:
            raise ValueError("recalibration changed fitted state/training source")
        decisions, raw, percentiles = [], [], []
        matrix = np.zeros((3,3), dtype=np.int64)
        scorepath = output / "scores-decisions.private.jsonl"
        fd = os.open(scorepath, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as evidence, JavaRiskReplay(fixed.WORKSPACE, policy, expected_classes=before["java"]["replay_classes"]) as java:
            validation = rows["fold1-validation"]
            for offset in range(0, len(validation), 1000):
                batch = validation[offset:offset+1000]
                features = feature_array([r["features"] for r in batch], 5000, 4)
                contexts = ["COLD" if r["cohort"]=="COLD" else "READY" for r in batch]
                scores = ModelStore.score_payload(payload, features, calibrated["model_version"], 4, policy=policy, cohorts=contexts)["results"]
                components = payload["model"].score_components(features)
                if not np.array_equal(components["raw_anomaly_score"], np.array([s["raw_anomaly_score"] for s in scores])):
                    raise ValueError("ModelStore/component actual raw scores differ")
                actual = java.score(batch, scores)
                predictions = np.argmax(components["uncalibrated_context_probabilities"],axis=1)
                targets = training_targets(batch)
                for i,(row,score,decision,target,predicted) in enumerate(zip(batch,scores,actual,targets,predictions)):
                    matrix[target,int(predicted)]+=1
                    evidence.write(canonical({"frame_id":row["frame_id"],**score,"predictions":decision["predictions"],
                        "planned_context_target":target,"predicted_context":int(predicted),
                        "incident_margin":float(components["incident_margin"][i]),
                        "normal_novelty_log_score":float(components["normal_novelty_log_score"][i]),
                        "uncalibrated_context_probabilities":components["uncalibrated_context_probabilities"][i].tolist()})+"\n")
                decisions.extend(actual); raw.extend(s["raw_anomaly_score"] for s in scores);percentiles.extend(s["normal_percentile"] for s in scores)
            evidence.flush();os.fsync(evidence.fileno())
        if len(decisions)!=21000 or store.active_version is not None or (directory/"active.json").exists():
            raise ValueError("full validation conservation/no-activation invariant failed")
        counts = dict(fits.counts)
    after = fingerprint(catalog, manifest)
    if before!=after: raise ValueError("source/dataset/Java/dependency drift; retain unqualified private evidence")
    for p in output.rglob("*"):
        if p.is_file(): artifacts[str(p.relative_to(output))]=checksum(p)
    metrics = fixed.decision_metrics(decisions)
    result = {"status":"COMPLETED","stage":"BULK_PILOT_DEMO_ONLY","data_provenance":"DEMO_ONLY","quality_gate":"NOT_APPLICABLE",
        "integrity_before":before,"integrity_after":after,"integrity_unchanged":True,"predeclared_sha256":checksum(output/"predeclared.private.json"),
        "actual_composite_fit_trials":counts["composite"],"actual_component_fit_calls":counts["normal"]+counts["classifier"],
        "additional_load_recalibration_fit_calls":0,"strict_fit_calls":0,"normal_fit_rows":50000,"labeled_fit_rows":81500,
        "actual_normal_calibration_rows":{"READY":60000,"COLD":60000},"actual_validation_rows_replayed":21000,
        "holdout_numeric_records_read":0,"policy_sha256":policy.sha256,"calibrated_model_metadata":metadata,
        "fitted_numeric_state_sha256":fitted_sha,"raw_score_sha256":fixed.array_sha(raw),"percentile_sha256":fixed.array_sha(percentiles),
        "decisions":metrics,"point_diagnostic":fixed.point_diagnostic(metrics,policy),
        "class_3_confusion":matrix.tolist(),"class_probabilities_are_uncalibrated_not_confirmed_attack_risk":True,
        "model_activated_selected_promoted_or_aws_changed":False,"private_artifacts":artifacts,"elapsed_seconds":time.monotonic()-started,
        "limitations":["ALREADY_OBSERVED_VALIDATION_NOT_BLINDED_HOLDOUT","BULK_TRAINING_AND_60000_CALIBRATION_NOT_STRICT_QUALIFICATION",
            "NO_INDEPENDENT_CONFIDENCE_GATE","PLANNED_SECURITY_AND_OPERATIONAL_CONTEXTS_NOT_CONFIRMED_ATTACKS"]}
    write_new(output/"result.private.json",result)
    print(canonical({"status":"COMPLETED","output":str(output),"result_sha256":checksum(output/"result.private.json"),
        "decisions":{k:v["complete_validation"] for k,v in metrics.items()},"quality_gate":"NOT_APPLICABLE"}),flush=True)
    return output,result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path);args=parser.parse_args()
    try: run(args.output)
    except Exception as failure:
        raise SystemExit("Bulk hybrid diagnostic refused/failed: "+type(failure).__name__+"; protected evidence retained") from None
