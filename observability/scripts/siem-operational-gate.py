#!/usr/bin/env python3
"""Run the existing one-hour/33-evaluation fixed-model HTTP lab gate for this release.

Uses disposable Testcontainers accounts, mocked SMTP and a serving-only worker.
Never seeds the live DB, reads holdout data, trains, or changes live policy.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("siem_cutover",ROOT/"observability/scripts/siem-cutover-local.py")
release_ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(release_ops)
ops=release_ops.ops


def exact_classes(output,receipt):
    if ops.inspect(ops.APP)["Image"]!=receipt["image_ids"]["app"]:
        raise RuntimeError("Primary application image differs from release")
    jar=output/"deployed-application.private.jar"
    ops.run(["docker","cp",ops.APP+":/app/app.jar",str(jar)])
    os.chmod(jar,0o600)
    target=ROOT/"backend/target/classes"
    if target.is_symlink():raise RuntimeError("Refuse symlinked class directory")
    expected={}
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            if not name.startswith("BOOT-INF/classes/") or name.endswith("/"):continue
            relative=name[len("BOOT-INF/classes/"):]
            path=(target/relative).resolve()
            if not path.is_relative_to(target.resolve()):raise RuntimeError("Unsafe packaged class path")
            path.parent.mkdir(parents=True,exist_ok=True)
            data=archive.read(name);path.write_bytes(data)
            if name.endswith(".class"):expected[relative]=ops.digest(data)
    verify_classes(expected)
    return expected,ops.digest(jar.read_bytes())

def verify_classes(expected):
    target=ROOT/"backend/target/classes"
    actual={str(p.relative_to(target)):ops.digest(p.read_bytes()) for p in target.rglob("*.class")}
    if actual!=expected:raise RuntimeError("Test classpath differs from deployed application classes")

def main(folder,epoch):
    receipt,effective_sha256=release_ops.effective_release(folder)
    if receipt["sources"]!=release_ops.source_hashes():raise RuntimeError("Release sources changed")
    model_manifest=receipt["protected"]["model"]["manifest.json"]
    # The existing accepted test contract pins this manifest. Never substitute a new model silently.
    if model_manifest!="7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784":
        raise RuntimeError("Existing HTTP gate requires explicit review for a different manifest")
    output=folder/("operational-gate-"+str(epoch))
    output.mkdir(mode=0o700)
    class_hashes,application_jar_sha256=exact_classes(output,receipt)
    protection_before=ops.fingerprint()
    token=output/"lab.token";token.write_text("siem-isolated-serving-only-lab-token-20261023");os.chmod(token,0o600)
    hold=output/"operator-hold.json";hold.write_text('{"hold_new_units":false}');os.chmod(hold,0o600)
    app=ops.inspect(ops.APP)
    runtime=next(m["Source"] for m in app["Mounts"] if m["Destination"]=="/run/ueba-postlogin")
    worker=ops.inspect("flare-otp-local-postlogin-worker-1")["Image"]
    name="flare-siem-operational-gate-"+str(epoch)
    label="flare.siem-upgrade.gate="+str(epoch)
    child=None
    ops.run(["docker","run","-d","--name",name,"--label",label,"--cpus=1","--memory=384m",
        "--user=1000:1000","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges:true",
        "--tmpfs=/tmp:rw,nosuid,size=64m","-p","127.0.0.1::8091",
        "-e","UEBA_POSTLOGIN_SERVING_ONLY=true","-e","UEBA_SERVICE_TOKEN_FILE=/run/lab.token",
        "-e","UEBA_POSTLOGIN_MODEL_DIR=/run/model","-e","UEBA_POSTLOGIN_MANIFEST_SHA256="+model_manifest,
        "-e","OMP_NUM_THREADS=1","-e","OPENBLAS_NUM_THREADS=1",
        "-v",str(token)+":/run/lab.token:ro","-v",str(Path(runtime)/"model-v1")+":/run/model:ro",worker])
    try:
        ports=ops.inspect(name)["NetworkSettings"]["Ports"]["8091/tcp"]
        url="http://127.0.0.1:"+ports[0]["HostPort"]
        deadline=time.monotonic()+40
        while True:
            try:
                with urllib.request.urlopen(url+"/health",timeout=2) as response:health=json.loads(response.read(65536))
                if health.get("serving_only") is True and health["postlogin"].get("manifest_sha256")==model_manifest:break
            except (OSError,ValueError,KeyError):pass
            if time.monotonic()>deadline:raise RuntimeError("Serving-only worker start deadline")
            time.sleep(.5)
        env={**os.environ,"FLARE_POSTLOGIN_OBSERVE":"true","FLARE_CONTROLLED_ACTION_TRIAL":"true",
             "FLARE_POSTLOGIN_OBSERVE_DIR":str(output),"FLARE_POSTLOGIN_WORKER_URL":url,
             "FLARE_POSTLOGIN_TOKEN_FILE":str(token),"FLARE_POSTLOGIN_RUNTIME_HOLD_FILE":str(hold),
             "FLARE_POSTLOGIN_IMPLEMENTATION_HOLD_FILE":str(hold),
             "JAVA_TOOL_OPTIONS":"-Xmx640m -XX:ActiveProcessorCount=2","MAVEN_OPTS":"-Xmx256m"}
        with (output/"http-evaluation.private.log").open("xb") as log:
            child=subprocess.Popen(["mvn","-q","-o","-f","backend/pom.xml","-Dtest=PostloginProjectObserveTest","-Dmaven.main.skip=true","-Dmaven.resources.skip=true","test"],cwd=ROOT,env=env,stdout=log,stderr=log)
            code=child.wait(timeout=4050)
        result=json.loads((output/"observe-result.private.json").read_text())
        if code or result.get("status")!="PROJECT_ONE_HOUR_OBSERVE_PASS" or result.get("continuous_seconds",0)<3600 or result.get("evaluations",0)<30 or result.get("new_fits")!=0:
            raise RuntimeError("Continuous HTTP/model gate did not qualify; keep recurrence in OBSERVE")
        verify_classes(class_hashes)
        if receipt["sources"]!=release_ops.source_hashes() or protection_before!=ops.fingerprint():
            raise RuntimeError("Source or protected state changed during gate")
        ops.publish(folder,"operational-gate-"+str(epoch),{**result,"status":"SIEM_ONE_HOUR_HTTP_GATE_PASS",
            "release_sha256":effective_sha256,"compiled_class_parity":True,"compiled_classes_checked":len(class_hashes),"application_jar_sha256":application_jar_sha256,"protected_epoch_start":protection_before,"strict_production_qualified":False})
        print(json.dumps({"status":"SIEM_ONE_HOUR_HTTP_GATE_PASS","evaluations":result["evaluations"],"continuous_seconds":result["continuous_seconds"],"new_fits":0}))
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=20)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=10)
        if ops.inspect(name)["Config"]["Labels"].get("flare.siem-upgrade.gate")==str(epoch):ops.run(["docker","rm","-f",name])

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True);parser.add_argument("--epoch",type=int,default=1)
    args=parser.parse_args()
    if not 1<=args.epoch<=10:parser.error("Explicit epoch must be 1–10")
    os.umask(0o077);folder=release_ops.private_file(args.output)
    with (folder/"operator.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        main(folder,args.epoch)
