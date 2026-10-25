#!/usr/bin/env python3
"""The one preregistered zero-fit, fixed-model forward validation extension."""
import argparse
from collections import Counter
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import time

from postlogin_risk_probe import frozen_generator
from postlogin_risk_data import Sampler,FAMILIES
from postlogin_risk_source import source_batch,guard,resource_limits
from postlogin_risk_rolling import java_classpath,model_features
from postlogin_risk_audit import load_source,reference_context,audit_history
from postlogin_risk_replication import artifact
from postlogin_risk_factorial_pilot import point_gate
from postlogin_risk_pilot import evaluate
from postlogin_risk_result_diagnosis import checked
from ueba_research_artifacts import commit,digest,canonical,private_directory


def run(a):
    assert resource_limits()["verified"]
    root=a.output;protocol=checked(root,"forward-execution-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected,"FROZEN_FORWARD_CODE_CHANGED"
    assert checked(root,"factorial-future-fold3-result")["status"]=="SINGLE_UNSEEN_FUTURE_SCREEN_PASS_NEEDS_MORE_PROOF"
    before=digest(root/"risk-fit-ledger.private.json")
    splits,bindings=load_source(root,3,digest(root/"risk-source-protocol-v4.receipt.private.json"))
    baseline,baseproof=artifact(root,"ratio-fit-fold3-baseline")
    candidate,candproof=artifact(root/"factorial-v1","projection-fit-fold3-candidate")
    assert baseproof["bundle_sha256"]==protocol["model_bundles_sha256"]["baseline"]
    assert candproof["bundle_sha256"]==protocol["model_bundles_sha256"]["candidate"]
    child=root/"forward-validation-v1";child.mkdir(mode=0o700,exist_ok=True);private_directory(child)
    commit(child,{"status":"FIXED_MODELS_BOUND_BEFORE_FORWARD_ROW1","baseline":baseproof,"candidate":candproof,
        "source_fold3_splits":bindings,"new_fits":0,"recalibration":False},phase="model-binding-v1")
    data=frozen_generator(a.source,a.frozen_code)
    data.ANCHORS={**data.ANCHORS,4:data.ANCHORS[3]+timedelta(days=7)}
    cp=java_classpath(a.source,root)
    bank=[r["source_account_ordinal"] for r in splits["fit"]];assert len(bank)==4000
    sampler=Sampler(data,4,"validation",bank)
    protocol_sha=digest(root/"forward-execution-protocol-v1.receipt.private.json")
    start=time.monotonic();rows=[];hashes=[]
    for offset in range(0,21000,32):
        guard(root,start,max(1,a.maximum_seconds-100))
        phase=f"forward-source-f4-validation-{offset//32:04d}"
        binding={"protocol_sha256":protocol_sha,"fold":4,"split":"validation","offset":offset,"count":min(32,21000-offset),
            "fit_account_bank_sha256":hashlib.sha256(canonical(bank).encode()).hexdigest()}
        retained=source_batch(child,phase,binding,sampler,cp)
        assert len(retained["rows"])==binding["count"]
        rows.extend(retained["rows"]);hashes.append(digest(child/(phase+".commit.private.json")))
        if offset//32%16==0:print(canonical({"forward_committed_rows":len(rows),"elapsed_seconds":time.monotonic()-start}),flush=True)
    assert len(rows)==21000 and len({r["frame_id"] for r in rows})==21000
    assert Counter(r["label"] for r in rows)=={0:20000,1:1000}
    assert Counter(r["cohort"] for r in rows)=={"READY":14700,"UNSEEN_READY":4200,"COLD":2100}
    assert Counter(r["family"] for r in rows if r["label"])=={f:200 for f in FAMILIES}
    assert min(r["window_start"] for r in rows)>max(r["window_start"] for r in splits["validation"])
    for row in rows:
        model_features(row);audit_history(row)
        assert row["training_context"]==reference_context(row["rolling_features"])
        assert not row["normal_fit"]
    for field in ("frame_id","session_fingerprints","context_frame_ids"):
        def ids(items):return {v for r in items for v in (r[field] if isinstance(r[field],list) else [r[field]])}
        prior=[r for group in splits.values() for r in group]
        assert not ids(prior)&ids(rows),"FORWARD_SESSION_OR_FRAME_OVERLAP"
    fit_accounts=set(bank)
    assert not any(r["source_account_ordinal"] in fit_accounts for r in rows if r["cohort"]=="UNSEEN_READY")
    data_sha=hashlib.sha256(canonical(hashes).encode()).hexdigest()
    commit(child,{"status":"FORWARD_RAW_JAVA_SOURCE_COMPLETE","rows":21000,"commit_inventory_sha256":data_sha,
        "new_fits":0,"model_binding_before_source":True,"past_only_and_isolation_checks":True},phase="source-result-v1")
    base=evaluate(child,4,"baseline65",baseline,baseproof,rows,protocol_sha,data_sha)
    result=evaluate(child,4,"factorial11",candidate,candproof,rows,protocol_sha,data_sha)
    regressions=[n for n,v in base["counts"].items() if result["counts"][n]["fp"]>v["fp"] or result["counts"][n]["fn"]>v["fn"]]
    assert digest(root/"risk-fit-ledger.private.json")==before,"FORWARD_EXTENSION_PERFORMED_OR_RESERVED_A_FIT"
    report={"status":"FIXED_MODEL_FORWARD_STRESS_PASS_DEMO_ONLY" if point_gate(result) and not regressions else "FORWARD_STRESS_NOT_PASS",
        "candidate_counts":result["counts"]["global"],"candidate_points":result["points"],"baseline_counts":base["counts"]["global"],
        "regressions":regressions,"absolute_point_gate":point_gate(result),"new_fits":0,"recalibration":False,
        "fit_ledger_before_after_sha256":before,"model_hashes":protocol["model_bundles_sha256"],
        "validation_scope":"PREDECLARED_FIXED_MODEL_TRANSFER_ONE_WEEK_LATER_SAME_SIMULATOR",
        "not_an_additional_fit_fold":True,"not_full_p4_or_independent_incident_proof":True,
        "source_class":"DEMO_ONLY_RULE_DISTILLATION","holdout_scored":False,"auto_containment":False,"aws_changed":False}
    commit(root,report,phase="forward-stress-result-v1");print(canonical(report),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mode",choices=("evaluate",),required=True);p.add_argument("--fold",type=int,choices=(4,),required=True)
    p.add_argument("--maximum-seconds",type=int,required=True);run(p.parse_args())
