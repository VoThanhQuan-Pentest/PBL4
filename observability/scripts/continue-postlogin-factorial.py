#!/usr/bin/env python3
"""One untouched future confirmation of the predeclared factorial FIT recipe."""
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
from postlogin_risk_source import remaining_projection
from postlogin_risk_result_diagnosis import checked
from ueba_research_artifacts import publish,digest,canonical

OUT=ROOT/"observability/runtime/postlogin-risk-ratio-20261021-r1"
SOURCE=ROOT/"observability/runtime/postlogin-research-20261018-r2"
COMPARISON=ROOT/"observability/runtime/postlogin-risk-context-20261020-r1"


def quota():
    state=json.loads((OUT/"operator-state.private.json").read_text())["quota"]
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(state["observed_at_utc"])).total_seconds()
    if state["used_percent_5h"]>=97 or not 0<=age<=300:raise RuntimeError("WAIT_FRESH_QUOTA_BELOW97")
    hold=OUT/"operator-hold.private.json"
    if hold.exists() and json.loads(hold.read_text()).get("hold_new_units"):raise RuntimeError("OPERATOR_HOLD")


def main():
    protocol=checked(OUT,"factorial-execution-protocol-v1")
    for name,h in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==h,"FROZEN_EXECUTION_CODE_CHANGED"
    assert checked(OUT,"factorial-development-fold2-result")["status"]=="GO_FOR_ONE_UNSEEN_FUTURE_CONFIRMATION_NOT_PASS"
    assert checked(OUT,"ratio-budget-amendment-v1")["status"]=="USER_AUTHORIZED"
    with (OUT/"factorial-controller.lock").open("a+") as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state={"status":"RUNNING","pid":os.getpid(),"process_start":process_start(os.getpid()),"phase":"FACTORIAL_FUTURE_ADMISSION"}
        publish(OUT/"factorial-controller.private.json",state)
        try:
            quota();b=json.loads((OUT/"budget.private.json").read_text());assert b["active_unit"] is None
            remaining=min(b["cap_seconds"]-b["elapsed_seconds"]-300,b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
            projected=100.
            if not (OUT/"risk-source-fold3-result.commit.private.json").exists():
                projected+=remaining_projection(OUT,3,digest(OUT/"risk-source-protocol-v4.receipt.private.json"),checked(OUT,"risk-source-benchmark-v4"))
            if projected>remaining:raise RuntimeError("STOP_BUDGET_BEFORE_FUTURE_CONFIRMATION")
            for kind,result,maximum in [("source","risk-source-fold3-result",6000),("fit","factorial-future-fold3-result",1000)]:
                if (OUT/(result+".commit.private.json")).exists():continue
                quota();attempt=1
                while (OUT/f"factorial-{kind}-fold3-v{attempt}.commit.private.json").exists():
                    old=checked(OUT,f"factorial-{kind}-fold3-v{attempt}")
                    if old["status"]=="COMMAND_PASS":raise RuntimeError("OUTER_PASS_WITHOUT_INNER_RESULT")
                    if "STOP_QUOTA" not in (OUT/old["log"]).read_text():raise RuntimeError("NO_BLIND_RETRY_OF_NON_QUOTA_FAILURE")
                    attempt+=1
                if attempt>9:raise RuntimeError("STOP_ATTEMPT_CAP")
                b=json.loads((OUT/"budget.private.json").read_text());remaining=min(b["cap_seconds"]-b["elapsed_seconds"],b["pilot_cap_seconds"]-b["group_seconds"].get("pilot",0))
                seconds=min(maximum,math.floor(remaining)-30);assert seconds>=30
                unit=f"factorial-{kind}-fold3-v{attempt}";state["phase"]=unit;publish(OUT/"factorial-controller.private.json",state)
                command=["python3",str(ROOT/"observability/scripts/postlogin_research_step.py"),"--output",str(OUT),"--unit",unit,"--group","pilot","--maximum-seconds",str(seconds+20)]
                for name in protocol["code_sha256"]:command += ["--input",str(Path(__file__).with_name(name))]
                if kind=="source":
                    command += ["--","python3",str(ROOT/"observability/scripts/run-risk-source-worker.py"),"--source",str(SOURCE),"--frozen-code",str(FROZEN),"--output",str(OUT),"--mode","generate","--fold","3","--attempt",str(attempt),"--maximum-seconds",str(seconds)]
                else:
                    command += ["--","python3",str(ROOT/"observability/scripts/run-risk-factorial-worker.py"),"--source",str(SOURCE),"--frozen-code",str(FROZEN),"--output",str(OUT),"--comparison-source",str(COMPARISON),"--mode","future","--fold","3","--attempt",str(attempt),"--maximum-seconds",str(seconds)]
                if subprocess.run(command,cwd=ROOT,timeout=seconds+70).returncode:raise RuntimeError("PIPELINE_UNIT_FAILED_"+unit)
            result=checked(OUT,"factorial-future-fold3-result")
            state.update(status=result["status"],phase="FACTORIAL_FUTURE_TERMINAL_RESEARCH_RESULT")
            publish(OUT/"factorial-controller.private.json",state);print(canonical(state),flush=True)
        except BaseException as error:
            state.update(status="STOP_EXECUTION_FAILURE",error=type(error).__name__+":"+str(error));publish(OUT/"factorial-controller.private.json",state);raise


if __name__=="__main__":main()
