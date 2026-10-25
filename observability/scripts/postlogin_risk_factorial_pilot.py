#!/usr/bin/env python3
"""Follow-up to failed fold2: fixed classifier, orthogonal raw FIT controls.

Fold2 is now exposed development. Only untouched fold3 can confirm this new
recipe; it cannot retrospectively turn the failed replication into a PASS.
"""
import argparse
import json
from pathlib import Path
from postlogin_risk_factorial_data import export
from postlogin_risk_probe import frozen_generator
from postlogin_risk_rolling import java_classpath
from postlogin_risk_audit import load_source,audit_source
from postlogin_risk_boundary_pilot import validate_controls
from postlogin_risk_replication import ReplicationLedger,fit_sufficient
from postlogin_risk_ratio_pilot import fit as fit_ratio
from postlogin_risk_pilot import evaluate,compare
from postlogin_risk_source import resource_limits
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import writer
from ueba_research_artifacts import commit,digest,canonical,private_directory


class NamespacedLedger:
    def __init__(self,root):self.delegate=ReplicationLedger(root)
    def reserve(self,unit,kind):self.delegate.reserve("factorial-"+unit,kind)
    @property
    def state(self):return self.delegate.state


def point_gate(report):
    points=report["points"]
    return (points["precision"] is not None and points["precision"]>=.998 and points["recall"]>.99 and points["fpr"]<.001
        and all(v["tp"]/(v["tp"]+v["fn"])>.99 for name,v in report["counts"].items()
            if name.startswith(("cohort/","family/")) and v["tp"]+v["fn"]))


def run(a):
    assert resource_limits()["verified"]
    root=a.output;protocol=checked(root,"factorial-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected,"FROZEN_FACTORIAL_CODE_CHANGED"
    child=root/"factorial-v1";child.mkdir(mode=0o700,exist_ok=True);private_directory(child)
    source_sha=digest(root/"risk-source-protocol-v4.receipt.private.json")
    splits,bindings=load_source(root,a.fold,source_sha);audit_source(splits)
    if a.fold==3:assert checked(root,"factorial-development-fold2-result")["status"]=="GO_FOR_ONE_UNSEEN_FUTURE_CONFIRMATION_NOT_PASS"
    data=frozen_generator(a.source,a.frozen_code);cp=java_classpath(a.source,root)
    rows=export(data,a.fold,child,cp);validate_controls(rows,splits)
    batches=[f"factorial-control-rows-f{a.fold}-b{i:03d}" for i in range(8)]
    manifest={"rows_count":len(rows),"batches_sha256":{n:digest(child/(n+".receipt.private.json")) for n in batches},
        "normal_rows":sum(r["label"]==0 for r in rows),"review_rows":sum(r["label"]==1 for r in rows),"training_only":True}
    commit(child,manifest,phase=f"replication-controls-fold{a.fold}")
    if a.mode=="check":
        commit(root,{"status":"FACTORIAL_RAW_JAVA_CONTROL_PASS","new_fits":0,**manifest,
            "independent_axes":["absolute_requests","history_median","endpoint_category_count","operation"],
            "shared_normal_fit_unchanged":2000},phase="factorial-control-check-v1")
        print("FACTORIAL_RAW_JAVA_CONTROL_PASS",flush=True);return
    assert checked(root,"factorial-control-check-v1")["status"]=="FACTORIAL_RAW_JAVA_CONTROL_PASS"
    protocol_sha=digest(root/"factorial-protocol-v1.receipt.private.json")
    phase=f"factorial-{'development' if a.fold==2 else 'future'}-fold{a.fold}-result"
    if (root/(phase+".commit.private.json")).exists():print(canonical(checked(root,phase)),flush=True);return
    with writer(root):
        ledger=NamespacedLedger(root)
        if a.fold==2:baseline=checked(root,"risk-validation-fold2-replication-baseline65")
        else:
            old_splits,_=load_source(root,2,source_sha)
            assert min(r["window_start"] for r in splits["validation"])>max(r["window_start"] for r in old_splits["validation"])
            model,proof=fit_ratio(root,3,"baseline",splits,bindings,protocol_sha,ledger)
            baseline=evaluate(child,3,"baseline65",model,proof,splits["validation"],protocol_sha,bindings["validation"])
        model,proof=fit_sufficient(child,a.fold,splits,rows,bindings,protocol_sha,ledger)
        candidate=evaluate(child,a.fold,"factorial11",model,proof,splits["validation"],protocol_sha,bindings["validation"])
        comparison=compare(baseline,candidate)
        regressions=[name for name,v in baseline["counts"].items() if candidate["counts"][name]["fp"]>v["fp"] or candidate["counts"][name]["fn"]>v["fn"]]
        passed=not regressions and point_gate(candidate)
        if a.fold==2:passed=passed and comparison["status"]=="GO_RESEARCH_SCREEN_ONLY"
        status=("GO_FOR_ONE_UNSEEN_FUTURE_CONFIRMATION_NOT_PASS" if a.fold==2 else "SINGLE_UNSEEN_FUTURE_SCREEN_PASS_NEEDS_MORE_PROOF") if passed else "STOP_NO_IMPROVEMENT"
        result={"status":status,"protocol_sha256":protocol_sha,"fold":a.fold,"candidate_counts":candidate["counts"]["global"],
            "baseline_counts":baseline["counts"]["global"],"candidate_points":candidate["points"],"comparison":comparison,"regressions":regressions,
            "absolute_point_gate":point_gate(candidate),"model_classifier_unchanged":"RECIPE8_SUFFICIENT11_PARAMETERS_AND_FUSION_UNCHANGED",
            "data_change":"ORTHOGONAL_240_RAW_FIT_CONTROLS","validation_scope":"EXPOSED_DEVELOPMENT_AFTER_FAILED_REPLICATION" if a.fold==2 else "ONE_UNSEEN_FUTURE_FOLD_NOT_COMPLETE_P4",
            "new_round_reserved_fits":ledger.state,"source_class":"DEMO_ONLY_RULE_DISTILLATION","strict_admission":"INDEPENDENT_OUTCOME_SOURCE_AND_FULL_REPLICATION_STILL_REQUIRED",
            "holdout_scored":False,"auto_containment":False,"aws_changed":False}
        commit(root,result,phase=phase);print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--mode",choices=("check","development","future"),required=True);p.add_argument("--fold",type=int,choices=(2,3),required=True);run(p.parse_args())
