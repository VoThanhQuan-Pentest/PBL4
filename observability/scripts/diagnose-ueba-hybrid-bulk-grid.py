#!/usr/bin/env python3
"""All24 predeclared BULK recipes and descriptive original192-policy grids.

No winner/policy selection, activation, holdout, threshold invention or strict
qualification. Each recipe uses two actual ModelStore component fits, then
plain numeric saved-state load/recalibration with all further fits forbidden.
"""
import argparse
from collections import Counter
import importlib.util
import os
from pathlib import Path
import sys
import time

PATH=Path(__file__).resolve();ROOT=PATH.parents[2]
SPEC=importlib.util.spec_from_file_location("frozen_bulk_default_workflow",PATH.with_name("diagnose-ueba-hybrid-bulk.py"))
base=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=base;SPEC.loader.exec_module(base)
import numpy as np
from app.hybrid_incident import CONFIGURATIONS,HybridResearchConfig
from app.validation import java_rules,sweep,COHORT_NAMES,RULE_THRESHOLDS
from app.policy import DETECTION_GRID
from app.strict_metrics import FAMILIES


def fingerprint(catalog,manifest):
    return {**base.fingerprint(catalog,manifest),"grid_source_sha256":base.checksum(PATH)}


def trial(output,index,config,normal,supervised,catalog,rows,before,rules):
    output.mkdir(mode=0o700);(output/"models").mkdir(mode=0o700)
    policy=base.ScorePolicy.strict(schema=4);store=base.ModelStore(output/"models");started=time.monotonic()
    base.write_new(output/"predeclared.private.json",{"configuration":vars(config),"integrity_before":before,
        "fit_calls_before_declaration":0,"score_calls_before_declaration":0,"quality_gate":"NOT_APPLICABLE"})
    with base.FitAudit() as fits:
        initial=store.train("grid_initial_42",[r["features"] for r in normal],
            [r["features"] for r in rows["fold1-calibration-ready"][:5000]],schema_version=4,config=config,policy=policy,
            labeled_samples=[r["features"] for r in supervised],labeled_targets=base.training_targets(supervised))
        fits.freeze();_,payload=base.verified_load(store,initial["model_version"],initial["sha256"])
        fitted_sha=base.fitted_state_sha(payload["model"])
        bound=store.publish_candidate("grid_bound_42",payload,{**initial,"fold":1,
            "labeled_training_artifact_id":"hybrid-bulk-pilot-20261004-a01","labeled_training_manifest_sha256":base.BULK_SHA,
            "dataset_manifest_sha256":base.CATALOG_SHA,"normal_fit_split_sha256":catalog.split("fold1-fit")["sha256"]})
        _,payload=base.verified_load(store,bound["model_version"],bound["sha256"])
        buckets={}
        for cohort in ("READY","COLD"):
            selected=rows["fold1-calibration-"+cohort.lower()];raw=[]
            for offset in range(0,len(selected),5000):
                raw.extend(payload["model"].anomaly_scores([r["features"] for r in selected[offset:offset+5000]]))
            buckets[cohort]=np.sort(np.asarray(raw,dtype=np.float64))
        base.write_new(output/"calibration.private.json",{c:a.tolist() for c,a in buckets.items()})
        calibrated=store.recalibrated_candidate(bound["model_version"],"grid_calibrated_42",buckets,policy,
            expected_source_sha256=bound["sha256"],dataset_sha256=base.CATALOG_SHA,
            split_sha256={c:catalog.split("fold1-calibration-"+c.lower())["sha256"] for c in buckets},calibration_scope="PILOT_ONLY")
        metadata,payload=base.verified_load(store,calibrated["model_version"],calibrated["sha256"])
        if base.fitted_state_sha(payload["model"])!=fitted_sha:raise ValueError("saved/recalibrated fitted state changed")
        decisions=[];rawscores=[];percentiles=[];matrix=np.zeros((3,3),dtype=np.int64)
        path=output/"scores-decisions.private.jsonl";fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        validation=rows["fold1-validation"]
        with os.fdopen(fd,"w") as evidence,base.JavaRiskReplay(base.fixed.WORKSPACE,policy,expected_classes=before["java"]["replay_classes"]) as java:
            for offset in range(0,len(validation),1000):
                batch=validation[offset:offset+1000];features=base.feature_array([r["features"] for r in batch],5000,4)
                cohorts=["COLD" if r["cohort"]=="COLD" else "READY" for r in batch]
                scores=base.ModelStore.score_payload(payload,features,calibrated["model_version"],4,policy=policy,cohorts=cohorts)["results"]
                components=payload["model"].score_components(features)
                if not np.array_equal(components["raw_anomaly_score"],np.array([s["raw_anomaly_score"] for s in scores])):raise ValueError("actual score correspondence changed")
                actual=java.score(batch,scores);predicted=np.argmax(components["uncalibrated_context_probabilities"],axis=1)
                for row,score,decision,target,context in zip(batch,scores,actual,base.training_targets(batch),predicted):
                    matrix[target,int(context)]+=1
                    evidence.write(base.canonical({"frame_id":row["frame_id"],**score,"predictions":decision["predictions"],
                        "planned_context_target":target,"predicted_context":int(context)})+"\n")
                decisions.extend(actual);rawscores.extend(s["raw_anomaly_score"] for s in scores);percentiles.extend(s["normal_percentile"] for s in scores)
            evidence.flush();os.fsync(evidence.fileno())
        if len(decisions)!=21000 or store.active_version is not None or(store.directory/"active.json").exists():raise ValueError("no activation/full validation required")
        counts=dict(fits.counts)
    metrics=base.fixed.decision_metrics(decisions)
    labels=np.array([r["label"] for r in validation],dtype=np.int8)
    families=np.array([0 if r["family"]=="normal" else FAMILIES.index(r["family"])+1 for r in validation],dtype=np.int8)
    cohorts=np.array([COHORT_NAMES.index(r["cohort"]) for r in validation],dtype=np.int8)
    policies=sweep(np.asarray(percentiles),labels,families,cohorts,rules,schema=4)
    for case in policies:
        case["point_qualified_diagnostic_only"]=case.pop("point_qualified_for_selection")
        case["selection_performed"]=False;case["strict_qualification"]=False
    base.write_new(output/"descriptive-policy-grid.private.json",{"scope":"ALL192_ORIGINAL_VALIDATION_POLICIES_DESCRIPTIVE_ONLY",
        "cases":policies,"fit_calls":0,"selection_performed":False,"quality_gate":"NOT_APPLICABLE"})
    artifacts={str(p.relative_to(output)):base.checksum(p) for p in output.rglob("*") if p.is_file()}
    result={"status":"COMPLETED","configuration":vars(config),"ordinal":index,"actual_composite_fit_trials":counts["composite"],
        "actual_component_fit_calls":counts["normal"]+counts["classifier"],"additional_load_recalibration_fit_calls":0,
        "actual_validation_rows_replayed":len(decisions),"actual_normal_calibration_rows":{"READY":60000,"COLD":60000},
        "calibrated_model_metadata":metadata,"fitted_numeric_state_sha256":fitted_sha,"raw_score_sha256":base.fixed.array_sha(rawscores),
        "percentile_sha256":base.fixed.array_sha(percentiles),"decisions":metrics,"point_diagnostic":base.fixed.point_diagnostic(metrics,policy),
        "class_3_confusion":matrix.tolist(),"descriptive_policy_cases":len(policies),
        "descriptive_point_qualified_policy_count":sum(case["point_qualified_diagnostic_only"] for case in policies),
        "private_artifacts":artifacts,"elapsed_seconds":time.monotonic()-started,"quality_gate":"NOT_APPLICABLE","data_provenance":"DEMO_ONLY"}
    base.write_new(output/"result.private.json",result)
    return result


def run(output):
    if os.environ.get("UEBA_DIAGNOSTIC_IMAGE_ID")!=base.IMAGE or not Path("/.dockerenv").exists():raise ValueError("pinned Docker only")
    normal,supervised,manifest,catalog,rows=base.load_inputs();before=fingerprint(catalog,manifest)
    output=Path(output).absolute()
    if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():raise ValueError("new private grid directory required")
    output.mkdir(mode=0o700)
    declaration={"stage":"BULK_PILOT_DEMO_ONLY","seed":42,"fold":1,"configurations":[list(c) for c in CONFIGURATIONS],
        "integrity_before":before,"policy":base.ScorePolicy.strict(schema=4).wire(),"normal_fit":50000,"labeled_fit":81500,
        "calibration_rows":{"READY":60000,"COLD":60000},"validation_rows":21000,
        "descriptive_policy_grid":{"ready_detection":list(DETECTION_GRID),"cold_detection":list(DETECTION_GRID),"rules":list(RULE_THRESHOLDS),"cases":192},
        "fits_before_declaration":0,"scores_before_declaration":0,"selection_or_promotion":False,"threshold_tuning":False,"quality_gate":"NOT_APPLICABLE"}
    base.write_new(output/"predeclared.private.json",declaration)
    # Three real Java rule-only policies, cached once by the existing generic code.
    rules,rule_receipt=java_rules(catalog,"fold1-validation",output/"descriptive-rule-cache",base.fixed.WORKSPACE)
    base.write_new(output/"descriptive-rules.private.json",rule_receipt)
    results=[];started=time.monotonic()
    for index,configuration in enumerate(CONFIGURATIONS):
        result=trial(output/f"candidate-{index:02d}",index,HybridResearchConfig(*configuration,random_state=42),normal,supervised,catalog,rows,before,rules)
        results.append(result)
        print(base.canonical({"completed_configurations":len(results),"planned_configurations":24,"configuration":list(configuration),
            "fixed_policy_decisions":{s:v["complete_validation"] for s,v in result["decisions"].items()},
            "descriptive_point_qualified_policies":result["descriptive_point_qualified_policy_count"],"quality_gate":"NOT_APPLICABLE"}),flush=True)
    after=fingerprint(catalog,manifest)
    if before!=after:raise ValueError("source/data/Java/dependency drift")
    result={"status":"COMPLETED","stage":"BULK_PILOT_DEMO_ONLY","data_provenance":"DEMO_ONLY","quality_gate":"NOT_APPLICABLE",
        "integrity_before":before,"integrity_after":after,"integrity_unchanged":True,"predeclared_sha256":base.checksum(output/"predeclared.private.json"),
        "configurations":results,"actual_composite_fit_trials":24,"actual_component_fit_calls":48,"additional_load_recalibration_fit_calls":0,
        "actual_validation_rows_replayed":24*21000,"descriptive_policy_cases":24*192,"strict_fit_calls":0,"holdout_numeric_records_read":0,
        "minimum_strict_normal_validation":10000000,"minimum_strict_positive_validation":10000,"strict_qualification":False,
        "model_or_policy_selected_activated_promoted_or_aws_changed":False,"elapsed_seconds":time.monotonic()-started,
        "limitations":["ALREADY_OBSERVED_VALIDATION_EXPLORATORY_NOT_BLINDED_HOLDOUT","NO_WINNER_OR_POLICY_SELECTION","NO_INDEPENDENT_CONFIDENCE_GATE"]}
    base.write_new(output/"result.private.json",result)
    print(base.canonical({"status":"COMPLETED","output":str(output),"result_sha256":base.checksum(output/"result.private.json"),
        "actual_composite_fit_trials":24,"actual_component_fit_calls":48,"quality_gate":"NOT_APPLICABLE"}),flush=True)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);args=p.parse_args()
    try:run(args.output)
    except Exception as failure:raise SystemExit("Bulk grid refused/failed: "+type(failure).__name__+"; private completed trials retained") from None
