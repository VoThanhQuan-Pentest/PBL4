#!/usr/bin/env python3
"""Pinned, persistent, isolated zero-fit lab. Does not inspect provider usage."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from ueba_research_artifacts import private_directory, publish, commit, digest

ROOT=Path(__file__).resolve().parents[2]
IMAGES={"mysql":"mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af",
        "redis":"redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"}

def command(args,timeout=30):
    return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=timeout).strip()

def inspect(name,kind="container"):
    result=subprocess.run(["docker",kind,"inspect",name],capture_output=True,text=True,timeout=30)
    if result.returncode:return None
    return json.loads(result.stdout)[0]

def run(a):
    root=private_directory(a.output.resolve())
    authorization=json.loads((root/"preparation-authorization-v1.receipt.private.json").read_text())
    assert authorization["new_fit_cap"]==0 and authorization["quota_policy"]=="NOT_USED"
    child=root/(f"capture-smoke-v{a.attempt}" if a.mode=="smoke" else f"capture-smoke-v{a.reuse_smoke_attempt}" if a.mode=="recovery-check" else "capture-real-v1")
    child.mkdir(mode=0o700,exist_ok=True);private_directory(child)
    identifier=hashlib.sha256(str(child).encode()).hexdigest()[:12]
    labels={"flare.preparation.run":identifier,"flare.preparation.scope":"zero-fit-lab"}
    source=root/f"execution-source-v{a.execution_version}"
    if not source.exists():
        (source/"backend").mkdir(parents=True,mode=0o700)
        shutil.copy2(ROOT/"backend/pom.xml",source/"backend/pom.xml")
        shutil.copytree(ROOT/"backend/src",source/"backend/src")
        files={str(p.relative_to(source)):digest(p) for p in source.rglob("*") if p.is_file()}
        commit(root,{"status":"BACKEND_EXECUTION_SNAPSHOT","files_sha256":files},phase=f"execution-source-v{a.execution_version}")
    identity=json.loads((root/f"execution-source-v{a.execution_version}.receipt.private.json").read_text())
    for name,sha in identity["files_sha256"].items():assert digest(source/name)==sha,"EXECUTION_SNAPSHOT_CHANGED"
    cpus=sorted(os.sched_getaffinity(0))[:2];assert len(cpus)==2
    started=time.monotonic();owned=[];volumes=[];image_ids={}
    try:
        for service in ("mysql","redis"):
            image=IMAGES[service];image_ids[service]=command(["docker","image","inspect",image,"--format","{{.Id}}"])
            name=f"flare-prep-{identifier}-{service}";volume=name+"-data";volumes.append(volume)
            v=inspect(volume,"volume")
            if v is None:
                args=["docker","volume","create"]
                for k,value in labels.items():args += ["--label",k+"="+value]
                command(args+[volume]);v=inspect(volume,"volume")
            assert all(v["Labels"].get(k)==value for k,value in labels.items()),"UNOWNED_VOLUME"
            current=inspect(name)
            if current is not None:
                assert all(current["Config"]["Labels"].get(k)==value for k,value in labels.items()),"UNOWNED_CONTAINER"
                assert not current["State"]["Running"],"LIVE_LAB_MUST_BE_OBSERVED_NOT_RESTARTED"
                # Metadata-only container replacement; the named data volume remains intact.
                command(["docker","rm",name])
            port=3306 if service=="mysql" else 6379
            args=["docker","create","--name",name,"--cpus","1" if service=="mysql" else "0.5",
                  "--memory","1g" if service=="mysql" else "128m","--pids-limit","128",
                  "--publish",f"127.0.0.1::{port}","--mount",f"type=volume,src={volume},dst="+("/var/lib/mysql" if service=="mysql" else "/data")]
            for k,value in labels.items():args += ["--label",k+"="+value]
            if service=="mysql":
                args += ["--env","MYSQL_DATABASE=flare_fitness","--env","MYSQL_USER=flare","--env","MYSQL_PASSWORD=flare-preparation-only",
                         "--env","MYSQL_ROOT_PASSWORD=preparation-root-only","--entrypoint","/usr/bin/timeout",image,
                         "--signal=TERM","--kill-after=5s",str(a.maximum_seconds),"docker-entrypoint.sh","mysqld"]
            else:
                args += ["--entrypoint","/bin/sh",image,"-c",f"exec timeout -s TERM {a.maximum_seconds} docker-entrypoint.sh redis-server --appendonly yes --requirepass flare-preparation-redis-only"]
            command(args);owned.append(name);command(["docker","start",name])
        state=json.loads((root/"operator-state.private.json").read_text())
        state.update(active_handle={"kind":"zero-fit-lab","containers":owned,"artifacts":str(child)},status="ISOLATED_LAB_STARTING")
        publish(root/"operator-state.private.json",state)
        deadline=time.monotonic()+100
        while True:
            ready=subprocess.run(["docker","exec",owned[0],"mysqladmin","-h127.0.0.1","-uflare","-pflare-preparation-only","ping","--silent"],capture_output=True,timeout=10).returncode==0
            if ready:break
            if time.monotonic()>deadline:raise RuntimeError("LAB_DB_STARTUP_DEADLINE")
            time.sleep(2)
        mysql=inspect(owned[0]);redis=inspect(owned[1])
        for value,port,memory in ((mysql,3306,1024),(redis,6379,128)):
            config=value["HostConfig"]
            assert config["Memory"]==memory*1024**2 and config["NanoCpus"]<=1_000_000_000
            assert all(v["HostIp"]=="127.0.0.1" for v in value["NetworkSettings"]["Ports"][f"{port}/tcp"])
        mysql_port=mysql["NetworkSettings"]["Ports"]["3306/tcp"][0]["HostPort"]
        redis_port=redis["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"]
        environment={k:os.environ[k] for k in ("PATH","HOME","JAVA_HOME","LANG","LC_ALL","TMPDIR","DOCKER_HOST") if k in os.environ}
        environment.update(FLARE_PREPARATION_DB_URL=f"jdbc:mysql://127.0.0.1:{mysql_port}/flare_fitness?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
            FLARE_PREPARATION_REDIS_PORT=redis_port,JDK_JAVA_OPTIONS="-Xmx512m -XX:ActiveProcessorCount=2",MAVEN_OPTS="-Xmx128m")
        remaining=int(a.maximum_seconds-(time.monotonic()-started))-10
        if remaining<30:raise RuntimeError("PREPARATION_STARTUP_BUDGET")
        args=["taskset","-c",",".join(map(str,cpus)),"mvn","-q","-f",str(source/"backend/pom.xml"),
            "-Dtest=UebaPostLoginPreparationIntegrationTest","-Dpostlogin.preparation.enabled=true","-Dpostlogin.preparation.mode="+a.mode,
            "-Dpostlogin.preparation.output="+str(child),"test"]
        result=subprocess.run(args,cwd=source,env=environment,timeout=remaining)
        commit(root,{"status":"ZERO_FIT_LAB_JOB_PASS" if result.returncode==0 else "ZERO_FIT_LAB_JOB_FAIL","mode":a.mode,
            "exit_code":result.returncode,"new_fits":0,"external_mail":False,"container_names":owned,"persistent_volumes":volumes,
            "image_ids":image_ids,"execution_identity_sha256":digest(root/f"execution-source-v{a.execution_version}.receipt.private.json"),
            "artifact_root":str(child),"elapsed_seconds":time.monotonic()-started,"quota_policy":"NOT_USED"},phase="lab-"+a.mode+f"-worker-v{a.attempt}")
        return result.returncode
    finally:
        for name in reversed(owned):
            value=inspect(name)
            if value is not None and value["State"]["Running"]:
                subprocess.run(["docker","stop","--time","10",name],capture_output=True,timeout=20)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--mode",choices=("smoke","collect","recovery-check"),required=True)
    p.add_argument("--maximum-seconds",type=int,required=True);p.add_argument("--reuse-smoke-attempt",type=int,choices=(1,2,3),default=2);p.add_argument("--execution-version",type=int,choices=range(1,10),default=1);p.add_argument("--attempt",type=int,choices=(1,2,3),default=1);a=p.parse_args()
    assert 120<=a.maximum_seconds<=57000
    raise SystemExit(run(a))
