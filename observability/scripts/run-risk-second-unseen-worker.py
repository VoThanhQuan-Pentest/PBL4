#!/usr/bin/env python3
"""Run the authorized second unseen factorial fold in the pinned offline worker."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from ueba_research_artifacts import private_directory,publish,commit

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("frozen_risk_launcher",Path(__file__).with_name("run-risk-source-worker.py"))
original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)


def run(a):
    name=f"flare-risk-second-unseen-{a.mode}-f{a.fold}-a{a.attempt}"
    if original.command(["docker","ps","-a","--filter","name=^/"+name+"$","--format","{{.ID}}"]):raise RuntimeError("OBSERVE_EXISTING_WORKER")
    assert original.command(["docker","image","inspect",original.IMAGE,"--format","{{.Id}} {{.Os}}/{{.Architecture}}"] )==original.IMAGE+" linux/amd64"
    base=Path(json.loads((a.source/"java-overlay-stream/identity.private.json").read_text())["base_workspace"])
    mounts=[(a.source,True),(a.frozen_code,True),(base,True),(Path(__file__).parent,True),(a.comparison_source,True),(a.output,False)]
    mounts += [(ROOT/"backend/src/main/java/com/flarefitness/backend"/suffix,True) for suffix in ("ops/PostLoginFeatureExport.java","service/siem/PostLoginRiskContextFeatures.java")]
    args=["docker","create","--init","--name",name,"--network","none","--cpus","2","--memory","2g","--pids-limit","128",
        "--user",f"{os.geteuid()}:{os.getegid()}","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges",
        "--tmpfs","/tmp:rw,nosuid,nodev,size=134217728","--env","PYTHONDONTWRITEBYTECODE=1","--env","OMP_NUM_THREADS=2",
        "--env","OPENBLAS_NUM_THREADS=2","--env","PYTHONPATH="+str(a.frozen_code)]
    for path,ro in mounts:args += ["--mount",f"type=bind,src={path},dst={path}"+(",readonly" if ro else "")]
    args += ["--entrypoint","/usr/bin/timeout",original.IMAGE,"--signal=TERM","--kill-after=5s",str(a.maximum_seconds),
        "python","-B",str(Path(__file__).with_name("postlogin_risk_second_unseen.py")),"--source",str(a.source),
        "--frozen-code",str(a.frozen_code),"--output",str(a.output),"--comparison-source",str(a.comparison_source),
        "--mode",a.mode,"--fold",str(a.fold),"--maximum-seconds",str(max(1,a.maximum_seconds-10))]
    container=original.command(args)
    try:
        config=json.loads(original.command(["docker","inspect",container,"--format","{{json .HostConfig}} "]))
        assert config["Memory"]==2*1024**3 and config["NanoCpus"]==2_000_000_000 and config["NetworkMode"]=="none" and config["ReadonlyRootfs"]
        state=json.loads((a.output/"operator-state.private.json").read_text());state["active_handle"]={"kind":"docker","id":container,"name":name};publish(a.output/"operator-state.private.json",state)
        subprocess.run(["docker","start","-a",container],timeout=a.maximum_seconds+30)
        final=json.loads(original.command(["docker","inspect",container,"--format","{{json .State}} "]))
        commit(a.output,{"name":name,"image_id":original.IMAGE,"exit_code":final["ExitCode"],"oom_killed":final["OOMKilled"],
            "cpu":2,"memory_bytes":2*1024**3,"network":"none"},phase=f"worker-second-unseen-{a.mode}-f{a.fold}-a{a.attempt}")
        return final["ExitCode"] if not final["OOMKilled"] else 137
    finally:
        if original.command(["docker","inspect",container,"--format","{{.State.Running}} "])=="true":subprocess.run(["docker","stop","--time","1",container],check=True,timeout=15)
        subprocess.run(["docker","rm",container],check=True,timeout=15)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--mode",choices=("check","campaign"),required=True);p.add_argument("--fold",type=int,choices=(5,),required=True)
    p.add_argument("--maximum-seconds",type=int,required=True);p.add_argument("--attempt",type=int,default=1);a=p.parse_args()
    assert 30<=a.maximum_seconds<=7200 and 1<=a.attempt<=9
    for key in ("source","output","comparison_source"):setattr(a,key,private_directory(getattr(a,key)))
    a.frozen_code=a.frozen_code.resolve();raise SystemExit(run(a))
