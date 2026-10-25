#!/usr/bin/env python3
"""Prepare an immutable local release, then apply it only with explicit --apply.

Keeps all databases, queues, models and old containers. No seed, train, restore,
watermark change, volume deletion or rollback to a gateway with an older schema.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
PRIVATE=ROOT/"observability/runtime/private-backups"

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/"observability/scripts"/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

ops=module("siem_upgrade_local","siem-upgrade-local.py")
compose=module("siem_validate_compose","siem-validate-compose.py")

def source_hashes():
    files=subprocess.check_output(["rg","--files","backend/src/main","desktop-client/src/main","gateway","nginx","frontend/src"],cwd=ROOT,text=True).splitlines()
    files += ["backend/pom.xml","backend/Dockerfile","desktop-client/pom.xml","frontend/package.json","frontend/package-lock.json",
              "docker-compose.siem-local.yml","observability/logstash/pipeline/nginx.conf","observability/filebeat/filebeat.yml",
              "observability/scripts/siem-cutover-local.py","observability/scripts/siem-validate-compose.py","observability/scripts/siem-upgrade-local.py","observability/scripts/siem-operational-gate.py","observability/scripts/siem-live-acceptance.py","observability/scripts/siem-practice-workflow.py","observability/scripts/siem-account-practice.py","observability/scripts/siem-live-monitor.py","observability/scripts/siem-recovery-acceptance.py","observability/scripts/siem-enable-recurrence.py","observability/scripts/siem-ui-followup.py","observability/scripts/siem-detail-ui-final.py"]
    files += [str(p.relative_to(ROOT)) for p in (ROOT/"observability/elasticsearch/templates").glob("*.json")]
    files += [str(p.relative_to(ROOT)) for pattern in ("auth_context*.py","siem-workspace*.py") for p in (ROOT/"observability/scripts").glob(pattern)]
    files += [str(p.relative_to(ROOT)) for p in (ROOT/"ueba-worker/app").glob("auth_shadow*.py")]
    files += ["ueba-worker/app/main.py"]
    return {f:ops.digest((ROOT/f).read_bytes()) for f in sorted(set(files))}

def image_id(tag):
    return json.loads(ops.run(["docker","image","inspect",tag]))[0]["Id"]

def private_file(path):
    p=path.resolve()
    if not p.is_relative_to(PRIVATE.resolve()) or path.is_symlink():raise RuntimeError("Private operator path required")
    return p

def prepare(folder,images):
    summary=compose.validate(images["app"],images["nginx"],images["gateway"])
    ids={key:image_id(tag) for key,tag in images.items()}
    backup=json.loads((folder/"backup.receipt.private.json").read_text())
    name="clone-"+ids["app"].split(":")[-1][:12]+".receipt.private.json"
    clone=json.loads((folder/name).read_text())
    migration="backend/src/main/resources/db/migration/V41__add_siem_evidence_containment_and_recurrence.sql"
    if clone["image_id"]!=ids["app"] or clone["backup_sha256"]!=backup["sha256"] or clone["migration_v41_sha256"]!=ops.digest((ROOT/migration).read_bytes()):
        raise RuntimeError("Exact candidate image/clone/schema receipt required")
    if backup["protected"]!=ops.fingerprint():raise RuntimeError("Protected state changed since backup")
    value={"status":"PREPARED_NOT_DEPLOYED","images":images,"image_ids":ids,"sources":source_hashes(),
           "protected":backup["protected"],"clone_receipt":name,"compose":summary,"new_fits":0,
           "strict_production_qualified":False,"created_at":time.time(),
           "desktop_jar_sha256":ops.digest((ROOT/"desktop-client/target/flare-security-monitor-0.1.0-SNAPSHOT.jar").read_bytes())}
    ops.publish(folder,"siem-release",value)
    print(json.dumps({"status":value["status"],"memory_gib":summary["memory_gib"],"recurrence_mode":"OBSERVE","live_modified":False}))

def effective_release(folder):
    path=folder/"siem-release.receipt.private.json"
    value=json.loads(path.read_text());parent=ops.digest(path.read_bytes())
    for path in sorted(folder.glob("release-amendment-*.receipt.private.json")):
        amendment=json.loads(path.read_text())
        if amendment["parent_receipt_sha256"]!=parent or amendment["image_ids"]!=value["image_ids"] or amendment["protected"]!=value["protected"]:
            raise RuntimeError("Invalid release amendment chain")
        value={**value,"sources":amendment["sources"]}
        parent=ops.digest(path.read_bytes())
    return value,parent

def apply(folder):
    receipt,_=effective_release(folder)
    if receipt["sources"]!=source_hashes():raise RuntimeError("Source changed after release preparation")
    if any(image_id(tag)!=receipt["image_ids"][key] for key,tag in receipt["images"].items()):raise RuntimeError("Image tag changed")
    if receipt["protected"]!=ops.fingerprint():raise RuntimeError("Protected state changed; reconcile before cutover")
    ops.admission()
    compose.validate(receipt["images"]["app"],receipt["images"]["nginx"],receipt["images"]["gateway"])
    args,env,_=compose.context(receipt["images"]["app"],receipt["images"]["nginx"],receipt["images"]["gateway"])
    env["FLARE_SIEM_RECURRENCE_MODE"]="OBSERVE"
    state=folder/"cutover.checkpoint.private.json"
    if state.exists():raise RuntimeError("Prior cutover checkpoint exists; reconcile it instead of blindly replaying")
    db_id=ops.inspect(ops.DB)["Id"]
    def checkpoint(phase,status="RUNNING"):
        pending=state.with_suffix(".partial")
        with pending.open("w") as output:
            json.dump({"phase":phase,"status":status,"updated_at":time.time(),"database_container_id":db_id},output)
            output.flush();os.fsync(output.fileno())
        pending.replace(state)
        print(json.dumps({"phase":phase,"status":status}),flush=True)
    def execute(command,timeout=180):
        with (folder/"cutover.private.log").open("ab") as log:
            result=subprocess.run(command,env=env,stdout=log,stderr=log,timeout=timeout)
        if result.returncode:raise RuntimeError("Cutover command failed; inspect private log; no database rollback performed")
    def wait(name,timeout=240):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=ops.inspect(name)["State"]
            if not value["Running"]:raise RuntimeError("Service exited: "+name)
            if value.get("Health",{}).get("Status","healthy")=="healthy":return
            time.sleep(2)
        raise RuntimeError("Health deadline: "+name)
    checkpoint("STOP_OLD_LOG_WRITERS")
    try:
        execute(["docker","stop","--time","30","flare-local-elk-filebeat-1","flare-local-elk-logstash-1",
                 "flare-local-elk-kibana-1","flare-local-elk-elasticsearch-1"])
        for volume in ("flare-local-elk_elasticsearch-data","flare-local-elk_logstash-data"):
            if ops.run(["docker","ps","-q","--filter","volume="+volume]).strip():raise RuntimeError("Existing writer still owns "+volume)
        checkpoint("START_SINGLE_ELK_WRITER")
        execute(args+["up","-d","--no-build","--pull","never","--no-deps","elasticsearch","logstash","kibana"])
        for service in ("elasticsearch","logstash","kibana"):wait("flare-otp-local-"+service+"-1",300)
        checkpoint("INITIALIZE_MAIN_LOG_QUEUES")
        execute(args+["up","--no-build","--pull","never","--no-deps","nginx-logs-init","security-event-logs-init","filebeat-data-init"])
        checkpoint("MIGRATE_MAIN_AND_REPLACE_FRONT_DOOR")
        execute(["docker","stop","--time","30","flare-otp-local-nginx-1"])
        execute(args+["up","-d","--no-build","--pull","never","--no-deps","app","nginx","gateway","filebeat"])
        for service in ("app","gateway"):wait("flare-otp-local-"+service+"-1",240)
        if ops.inspect(ops.DB)["Id"]!=db_id:raise RuntimeError("Main database container unexpectedly replaced")
        for service,key in (("app","app"),("nginx","nginx"),("gateway","gateway")):
            if ops.inspect("flare-otp-local-"+service+"-1")["Image"]!=receipt["image_ids"][key]:raise RuntimeError("Release image identity mismatch")
        for url in ("http://127.0.0.1:8088/","http://127.0.0.1:8089/api/health"):
            with urllib.request.urlopen(url,timeout=10) as response:
                if response.status!=200:raise RuntimeError("HTTP health failed")
        if ops.fingerprint()!=receipt["protected"]:raise RuntimeError("Protected state changed during rollout")
        checkpoint("STOP_DUPLICATE_APPLICATION_SERVICES")
        execute(["docker","stop","--time","30","flare-local-elk-app-1","flare-local-elk-db-1",
                 "flare-local-elk-redis-1","flare-local-elk-ueba-worker-1","flare-local-elk-nginx-1"])
        checkpoint("OBSERVE_PENDING_ONE_HOUR_GATE","DEPLOYED_OBSERVE")
        ops.publish(folder,"cutover",{"status":"DEPLOYED_OBSERVE","image_ids":receipt["image_ids"],
            "protected":ops.fingerprint(),"new_fits":0,"gate_required_seconds":3600,"gate_required_http_evaluations":30,
            "strict_production_qualified":False,"volumes_deleted":False})
    except BaseException:
        checkpoint("RECONCILE_KEEP_NEW_SCHEMA_AND_BINARY","FAILED_OBSERVE")
        raise

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--apply",action="store_true")
    parser.add_argument("--app-image");parser.add_argument("--nginx-image");parser.add_argument("--gateway-image")
    options=parser.parse_args();os.umask(0o077);folder=private_file(options.output)
    with (folder/"operator.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if options.apply:apply(folder)
        else:
            if not all((options.app_image,options.nginx_image,options.gateway_image)):parser.error("All candidate images are required for preparation")
            prepare(folder,{"app":options.app_image,"nginx":options.nginx_image,"gateway":options.gateway_image})
