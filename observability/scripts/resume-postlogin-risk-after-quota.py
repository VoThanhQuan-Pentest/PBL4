#!/usr/bin/env python3
"""Resume only verified quota interruptions, preserving frozen source/model recipes.

This orchestration adapter never alters the21 frozen producer files, fits a new
hypothesis, resets a ledger, or retries an execution/quality failure as quota.
"""
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[2]
FROZEN=ROOT/"observability/runtime/hybrid-strict-source-20261013-parallel-resume-r2/code"
sys.path.insert(0,str(FROZEN))
from postlogin_research_step import process_start
from postlogin_risk_result_diagnosis import checked
from postlogin_risk_source import remaining_projection
from ueba_research_artifacts import digest,publish,canonical

OUTPUT=ROOT/"observability/runtime/postlogin-risk-ratio-20261021-r1"
SOURCE=ROOT/"observability/runtime/postlogin-research-20261018-r2"
COMPARISON=ROOT/"observability/runtime/postlogin-risk-context-20261020-r1"


def quota(root):
    value=json.loads((root/"operator-state.private.json").read_text())["quota"]
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(value["observed_at_utc"])).total_seconds()
    if value["used_percent_5h"]>=97 or not 0<=age<=300:raise RuntimeError("WAIT_FRESH_QUOTA_BELOW97")
    hold=root/"operator-hold.private.json"
    if hold.exists() and json.loads(hold.read_text()).get("hold_new_units"):raise RuntimeError("EXPLICIT_OPERATOR_HOLD")


def main():
    root=OUTPUT;previous=json.loads((root/"replication-controller.private.json").read_text())
    if process_start(previous["pid"])==previous["process_start"]:raise RuntimeError("LIVE_CONTROLLER_MUST_BE_OBSERVED")
    b=json.loads((root/"budget.private.json").read_text())
    if b["active_unit"] is not None:raise RuntimeError("WAIT_VERIFIED_JOB_TERMINATION_OR_INDEPENDENT_DEADLINE")
    if not (root/"quota-wait.private.json").exists():raise RuntimeError("RECORDED_QUOTA_INTERRUPTION_REQUIRED")
    failed=previous["phase"];log=root/(failed+".log.private.txt")
    source_quota_failure=log.exists() and "STOP_QUOTA" in log.read_text()
    fresh_quota_failure=previous.get("error","").endswith("WAIT_FRESH_QUOTA_BELOW97")
    if not source_quota_failure and not fresh_quota_failure:raise RuntimeError("NOT_A_VERIFIED_QUOTA_FAILURE")
    quota(root)
    protocol=checked(root,"replication-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected
    approval=checked(root,"ratio-budget-amendment-v1")
    assert approval["status"]=="USER_AUTHORIZED" and approval["cumulative_composite_cap"]==11
    with (root/"replication-controller.lock").open("a+") as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state={"status":"RUNNING","pid":os.getpid(),"process_start":process_start(os.getpid()),
            "phase":"RESUME_AFTER_VERIFIED_QUOTA","predecessor":previous,"adapter_sha256":digest(Path(__file__))}
        publish(root/"replication-controller.private.json",state)
        benchmark=checked(root,"risk-source-benchmark-v4");source_sha=digest(root/"risk-source-protocol-v4.receipt.private.json")
        projection=sum(remaining_projection(root,f,source_sha,benchmark) for f in (2,3) if not (root/f"risk-source-fold{f}-result.commit.private.json").exists())
        b=json.loads((root/"budget.private.json").read_text());remaining=min(b["cap_seconds"]-b["elapsed_seconds"]-300,b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
        if projection+200>remaining:raise RuntimeError("STOP_BUDGET_BEFORE_RESUME")
        try:
            for fold in (2,3):
                if fold==3 and checked(root,"replication-fold2-result")["status"]!="REPLICATION_FOLD_NONREGRESSION_PASS":break
                for action,mode,seconds,result in [("source","generate",6000,f"risk-source-fold{fold}-result"),("fit","replication-pilot",1000,f"replication-fold{fold}-result")]:
                    if (root/(result+".commit.private.json")).exists():continue
                    quota(root);attempt=1
                    while (root/f"replication-{action}-fold{fold}-v{attempt}.commit.private.json").exists():
                        prior=checked(root,f"replication-{action}-fold{fold}-v{attempt}")
                        if prior["status"]=="COMMAND_PASS":raise RuntimeError("OUTER_PASS_WITHOUT_INNER_RESULT")
                        if "STOP_QUOTA" not in (root/prior["log"]).read_text():raise RuntimeError("REFUSE_NON_QUOTA_RETRY")
                        attempt+=1
                    if attempt>9:raise RuntimeError("STOP_ATTEMPT_CAP")
                    b=json.loads((root/"budget.private.json").read_text());remaining=min(b["cap_seconds"]-b["elapsed_seconds"],b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
                    seconds=min(seconds,math.floor(remaining)-30);assert seconds>=30
                    unit=f"replication-{action}-fold{fold}-v{attempt}";state["phase"]=unit;publish(root/"replication-controller.private.json",state)
                    command=["python3",str(ROOT/"observability/scripts/postlogin_research_step.py"),"--output",str(root),"--unit",unit,"--group","pilot","--maximum-seconds",str(seconds+20)]
                    for name in protocol["code_sha256"]:command += ["--input",str(Path(__file__).with_name(name))]
                    command += ["--input",str(Path(__file__)),"--","python3",str(ROOT/"observability/scripts/run-risk-source-worker.py"),"--source",str(SOURCE),"--frozen-code",str(FROZEN),"--output",str(root),"--mode",mode,"--fold",str(fold),"--attempt",str(attempt),"--maximum-seconds",str(seconds)]
                    if mode=="replication-pilot":command += ["--comparison-source",str(COMPARISON)]
                    if subprocess.run(command,cwd=ROOT,timeout=seconds+70).returncode:raise RuntimeError("PIPELINE_UNIT_FAILED_"+unit)
            state.update(status="RESUME_STAGES_FINISHED",phase="RETURN_TO_FROZEN_AGGREGATOR");publish(root/"replication-controller.private.json",state)
        except BaseException as error:
            state.update(status="STOP_EXECUTION_FAILURE",error=type(error).__name__+":"+str(error));publish(root/"replication-controller.private.json",state);raise
    # The original controller sees committed inner results and performs only its
    # unchanged non-regression/pooled aggregation; no source/model is rerun.
    env={**os.environ,"PYTHONPATH":str(FROZEN)}
    raise SystemExit(subprocess.run(["python3",str(ROOT/"observability/scripts/continue-postlogin-risk-replication.py")],cwd=ROOT,env=env).returncode)


if __name__=="__main__":main()
