#!/usr/bin/env python3
"""Continue exactly two predeclared future folds under durable job/fit ledgers."""
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess

from postlogin_risk_result_diagnosis import checked
from postlogin_risk_source import remaining_projection
from postlogin_research_step import process_start
from ueba_research_artifacts import canonical,commit,digest,publish,private_directory

ROOT=Path(__file__).resolve().parents[2]
OUTPUT=ROOT/"observability/runtime/postlogin-risk-ratio-20261021-r1"
COMPARISON=ROOT/"observability/runtime/postlogin-risk-context-20261020-r1"
SOURCE=ROOT/"observability/runtime/postlogin-research-20261018-r2"
FROZEN=ROOT/"observability/runtime/hybrid-strict-source-20261013-parallel-resume-r2/code"


def main():
    root=private_directory(OUTPUT)
    with (root/"replication-controller.lock").open("a+") as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        approval=checked(root,"ratio-budget-amendment-v1")
        if approval["status"]!="USER_AUTHORIZED" or approval["cumulative_composite_cap"]!=11 or approval["cumulative_component_cap"]!=22:
            raise RuntimeError("EXPLICIT_REPLICATION_BUDGET_APPROVAL_REQUIRED")
        protocol=checked(root,"replication-protocol-v1")
        for name,expected in protocol["code_sha256"].items():
            if digest(Path(__file__).with_name(name))!=expected:raise ValueError("FROZEN_PIPELINE_CODE_CHANGED")
        assert checked(root,"replication-control-check-v1")["status"]=="REPLICATION_ZERO_FIT_CONTROLS_PASS"
        assert checked(root,"consensus-fold1-result")["status"]=="GO_FOR_UNSEEN_REPLICATION_NOT_PASS"
        state={"status":"RUNNING","pid":os.getpid(),"process_start":process_start(os.getpid()),"phase":"ADMISSION"}
        publish(root/"replication-controller.private.json",state)

        def budget():return json.loads((root/"budget.private.json").read_text())

        def step(unit,mode,fold,seconds):
            b=budget();remaining=min(b["cap_seconds"]-b["elapsed_seconds"],b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
            seconds=min(seconds,math.floor(remaining)-30)
            if seconds<30:raise RuntimeError("STOP_BUDGET_BEFORE_NEW_UNIT")
            command=["python3",str(ROOT/"observability/scripts/postlogin_research_step.py"),"--output",str(root),"--unit",unit,
                     "--group","pilot","--maximum-seconds",str(seconds+20)]
            for name in protocol["code_sha256"]:command += ["--input",str(Path(__file__).with_name(name))]
            command += ["--","python3",str(ROOT/"observability/scripts/run-risk-source-worker.py"),"--source",str(SOURCE),
                "--frozen-code",str(FROZEN),"--output",str(root),"--mode",mode,"--fold",str(fold),"--maximum-seconds",str(seconds)]
            if mode=="replication-pilot":command += ["--comparison-source",str(COMPARISON)]
            state.update(phase=unit);publish(root/"replication-controller.private.json",state)
            completed=subprocess.run(command,cwd=ROOT,timeout=seconds+70)
            if completed.returncode:raise RuntimeError("PIPELINE_UNIT_FAILED_"+unit)

        benchmark=checked(root,"risk-source-benchmark-v4")
        source_sha=digest(root/"risk-source-protocol-v4.receipt.private.json")
        projected=0.
        for fold in (2,3):
            if not (root/f"risk-source-fold{fold}-result.commit.private.json").exists():
                projected+=remaining_projection(root,fold,source_sha,benchmark)
            if not (root/f"replication-fold{fold}-result.commit.private.json").exists():projected+=100
        b=budget();remaining=min(b["cap_seconds"]-b["elapsed_seconds"]-300,b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
        if projected>remaining:
            state.update(status="STOP_BUDGET_BEFORE_REPLICATION",phase="ADMISSION",projection_seconds=projected,remaining_seconds=remaining)
            publish(root/"replication-controller.private.json",state)
            raise RuntimeError("NO_GO_FULL_REPLICATION_TIME_PROJECTION")
        try:
            for fold in (2,3):
                if fold==3 and checked(root,"replication-fold2-result")["status"]!="REPLICATION_FOLD_NONREGRESSION_PASS":
                    state.update(status="STOP_NO_IMPROVEMENT",phase="FOLD2_NONREGRESSION_FAILED");break
                if not (root/f"risk-source-fold{fold}-result.commit.private.json").exists():step(f"replication-source-fold{fold}-v1","generate",fold,6000)
                if not (root/f"replication-fold{fold}-result.commit.private.json").exists():step(f"replication-fit-fold{fold}-v1","replication-pilot",fold,1000)
            else:
                before=[checked(COMPARISON,"risk-validation-fold1-candidate")["counts"]["global"]]
                after=[checked(root,"consensus-fold1-result")["candidate_counts"]]
                folds=[]
                for fold in (2,3):
                    result=checked(root,f"replication-fold{fold}-result");folds.append(result)
                    before.append(result["baseline_counts"]);after.append(result["candidate_counts"])
                pooled_before={k:sum(v[k] for v in before) for k in ("tp","fn","fp","tn")}
                pooled_after={k:sum(v[k] for v in after) for k in ("tp","fn","fp","tn")}
                improved=sum(y["fn"]<x["fn"] for x,y in zip(before,after))
                reduction=pooled_before["fn"]-pooled_after["fn"]
                passed=all(f["status"]=="REPLICATION_FOLD_NONREGRESSION_PASS" for f in folds) and improved>=2 and reduction>=math.ceil(.25*pooled_before["fn"])
                result={"status":"THREE_FOLD_SCREEN_PASS_REQUIRES_INDEPENDENT_DATA" if passed else "STOP_NO_IMPROVEMENT",
                    "pooled_baseline_counts":pooled_before,"pooled_candidate_counts":pooled_after,"improving_folds":improved,
                    "pooled_fn_reduction":reduction,"source_class":"DEMO_ONLY_RULE_DISTILLATION",
                    "strict_admission":"NOT_ADMITTED_WITHOUT_INDEPENDENT_OUTCOME_SOURCE","holdout_scored":False,"auto_containment":False,"aws_changed":False}
                commit(root,result,phase="replication-final-result");state.update(status=result["status"],phase="TERMINAL_RESEARCH_SCREEN")
            publish(root/"replication-controller.private.json",state)
            print(canonical(state),flush=True)
        except BaseException as error:
            state.update(status="STOP_EXECUTION_FAILURE",error=type(error).__name__+":"+str(error))
            publish(root/"replication-controller.private.json",state);raise


if __name__=="__main__":main()
