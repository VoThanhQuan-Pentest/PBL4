#!/usr/bin/env python3
"""Read-only admission and private backup for the unified local SOC upgrade.

Does not deploy, seed, prune, train, change watermarks or restore a live database.
Receipts are immutable; output contains only hashes and bounded summaries.
"""
import argparse
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "flare-otp-local"
DB = f"{PROJECT}-db-1"
APP = f"{PROJECT}-app-1"
ES = "flare-local-elk-elasticsearch-1"


def run(args, *, data=None, timeout=30):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed ({args[0]}, exit {result.returncode}); inspect private operator logs")
    return result.stdout


def inspect(name):
    return json.loads(run(["docker", "inspect", name]))[0]


def sql(statement, name=DB):
    return run(["docker", "exec", "-i", name, "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --default-character-set=utf8mb4 -N -B -uroot "$MYSQL_DATABASE"'],
               data=statement.encode(), timeout=60)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(database=DB):
    # Hash all protected account fields in the DB, then hash the sorted result.
    accounts = sql("""SELECT id,SHA2(CAST(JSON_OBJECT('password',password,'email',email,
      'verified',email_verified_at,'auth_version',auth_version,'role',role,'deleted',is_deleted) AS CHAR),256)
      FROM tbl_nguoi_dung ORDER BY id;""", database)
    cases = sql("""SELECT id,status,queue_tier,COALESCE(assignee_user_id,''),conclusion,version,updated_at,
      (SELECT COUNT(*) FROM siem_incident_notes n WHERE n.incident_id=i.id),
      (SELECT COUNT(*) FROM siem_incident_history h WHERE h.incident_id=i.id)
      FROM siem_incidents i WHERE LOWER(id) LIKE 'soc-demo-%' OR title LIKE 'SOC-DEMO-%' ORDER BY id;""", database)
    app = inspect(APP)
    configuration = sorted(item for item in app["Config"]["Env"] if item.split("=", 1)[0].startswith(
        ("APP_MAIL", "SPRING_MAIL", "APP_SENSITIVE_ACTION", "APP_JWT", "SIEM_POSTLOGIN")))
    model = {}
    for mount in app.get("Mounts", []):
        if mount["Destination"] == "/run/ueba-postlogin":
            for name in ("manifest.json", "calibration.json", "model-state.json"):
                path = Path(mount["Source"]) / "model-v1" / name
                if not path.is_file():
                    raise RuntimeError("Pinned serving model component missing")
                model[name] = digest(path.read_bytes())
    if not accounts or not cases or len(model) != 3:
        raise RuntimeError("Protected account/demo/model inventory incomplete")
    return {"accounts_sha256": digest(accounts), "reserved_cases_sha256": digest(cases),
            "otp_mail_model_configuration_sha256": digest(json.dumps(configuration).encode()), "model": model}


def admission():
    es_name=ES
    candidate=subprocess.run(["docker","inspect","flare-otp-local-elasticsearch-1"],capture_output=True,text=True,timeout=15)
    if candidate.returncode==0:
        current=json.loads(candidate.stdout)[0]
        if current["State"]["Running"] and current["Config"]["Labels"].get("com.docker.compose.project")==PROJECT:
            es_name="flare-otp-local-elasticsearch-1"
    db, app, es = inspect(DB), inspect(APP), inspect(es_name)
    for container in (db, app):
        if container["Config"]["Labels"].get("com.docker.compose.project") != PROJECT or not container["State"]["Running"]:
            raise RuntimeError("Running OTP project ownership check failed")
    volume = next(m for m in es["Mounts"] if m["Destination"] == "/usr/share/elasticsearch/data")
    # df runs inside Elasticsearch's actual data filesystem, not an unrelated cwd.
    fs = run(["docker", "exec", es_name, "df", "-Pk", "/usr/share/elasticsearch/data"]).decode().splitlines()[-1].split()
    available = int(fs[3]) * 1024
    if available < 30 * 1024**3:
        raise RuntimeError("Elasticsearch data filesystem requires at least 30 GiB free")
    responses = {}
    for label, endpoint in (("health", "/_cluster/health"),
                            ("allocation", "/_cluster/allocation/explain"),
                            ("watermarks", "/_cluster/settings?include_defaults=true&flat_settings=true")):
        # The allocation endpoint may return 400 when there are no unassigned shards.
        raw = run(["docker", "exec", es_name, "sh", "-ceu",
                   'exec curl --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt '
                   '--user "elastic:$(cat /run/flare-secrets/elasticsearch.password)" '
                   '"https://localhost:9200' + endpoint + '"'])
        responses[label] = json.loads(raw)
    if responses["health"].get("status") == "red" or responses["health"].get("unassigned_primary_shards", 0):
        raise RuntimeError("Elasticsearch primary shard admission failed; no watermark override is permitted")
    if "disk_threshold" in json.dumps(responses["allocation"]) and '"decision": "NO"' in json.dumps(responses["allocation"]):
        raise RuntimeError("Elasticsearch allocation blocked by disk threshold")
    containers = json.loads(run(["docker", "inspect", *run(["docker", "ps", "-q"]).decode().split()]))
    memory = sum(c["HostConfig"].get("Memory", 0) for c in containers)
    return {"filesystem_available_bytes": available, "elasticsearch_volume": volume.get("Name"),
            "elasticsearch_health": responses["health"], "allocation": responses["allocation"],
            "watermarks": responses["watermarks"], "current_container_memory_limits_bytes": memory,
            "images": {c["Name"].lstrip("/"): c["Image"] for c in containers},
            "protected": fingerprint(), "live_modified": False, "new_fits": 0}


def publish(folder, name, value):
    target = folder / f"{name}.receipt.private.json"
    if target.exists():
        raise RuntimeError(f"Receipt already exists: {name}; use a new run directory")
    pending = folder / f".{name}.partial"
    with pending.open("x") as output:
        os.chmod(pending, 0o600)
        json.dump(value, output, indent=2); output.flush(); os.fsync(output.fileno())
    pending.rename(target)


def backup(folder):
    before = fingerprint()
    target = folder / "otp-before-siem.sql.gz"
    if target.exists():
        raise RuntimeError("Backup already exists; refusing overwrite")
    with tempfile.TemporaryFile(dir=folder) as raw:
        result = subprocess.run(["docker", "exec", DB, "sh", "-ceu",
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump --single-transaction --quick '
            '--no-tablespaces --routines --triggers --events -uroot "$MYSQL_DATABASE"'],
            stdout=raw, stderr=subprocess.PIPE, timeout=180)
        if result.returncode:
            raise RuntimeError("Private MySQL backup failed")
        if raw.tell() < 1000:
            raise RuntimeError("Empty MySQL backup")
        raw.seek(0)
        with target.open("xb") as output:
            os.chmod(target, 0o600)
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
                shutil.copyfileobj(raw, compressed)
            output.flush(); os.fsync(output.fileno())
    with gzip.open(target, "rb") as stream:
        while stream.read(1024*1024):
            pass
    after = fingerprint()
    if before != after:
        raise RuntimeError("Protected state changed during backup; reconcile before rollout")
    value = {"backup": target.name, "sha256": digest(target.read_bytes()), "protected": before,
             "original_database_modified": False, "created_at": time.time()}
    publish(folder, "backup", value)
    return {"status": "PRIVATE_BACKUP_VERIFIED", "sha256": value["sha256"], "live_modified": False}


def clone(folder, image, expected_schema=41):
    import secrets
    if not image or not image.startswith("flare/siem-app:"):
        raise RuntimeError("A separate flare/siem-app release is required")
    proof = json.loads((folder/"backup.receipt.private.json").read_text())
    backup_path = folder/proof["backup"]
    if digest(backup_path.read_bytes()) != proof["sha256"]:
        raise RuntimeError("Backup checksum mismatch")
    image_id = json.loads(run(["docker", "image", "inspect", image]))[0]["Id"]
    clone_receipt="clone-"+image_id.split(":")[-1][:12]
    if (folder/(clone_receipt+".receipt.private.json")).exists():
        raise RuntimeError("This immutable image already has a clone receipt")
    suffix = secrets.token_hex(5)
    network = "flare-siem-clone-"+suffix
    names = [network+"-db", network+"-redis", network+"-app"]
    label = "flare.siem-upgrade.run="+suffix
    password = secrets.token_urlsafe(32)
    before = fingerprint()
    started = []
    clone_volume=network+"-data"
    def wait(name, mysql=False):
        deadline = time.monotonic()+150
        while time.monotonic()<deadline:
            state = inspect(name)["State"]
            if not state["Running"]:
                captured=subprocess.run(["docker","logs",name],capture_output=True,timeout=15)
                diagnostics=captured.stdout+captured.stderr
                log=folder/(name+".private.log");log.write_bytes(diagnostics);os.chmod(log,0o600)
                raise RuntimeError("Clone process exited; private diagnostic saved; original database untouched")
            command = ["docker", "exec", name, "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -h127.0.0.1 -uroot "$MYSQL_DATABASE" --silent -e "SELECT 1"'] if mysql else [
                "docker", "exec", name,"curl","--fail","--silent","http://127.0.0.1:8080/actuator/health"]
            result = subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            if not result.returncode:
                return
            time.sleep(2)
        raise RuntimeError("Clone health deadline exceeded")
    run(["docker","network","create","--internal","--label",label,network])
    run(["docker","volume","create","--label",label,clone_volume])
    try:
        mysql_image=inspect(DB)["Image"]
        env=folder/(".clone-"+suffix+".env")
        env.write_text("MYSQL_ROOT_PASSWORD="+password+"\nMYSQL_DATABASE=flare_fitness\n")
        os.chmod(env,0o600)
        try:
            run(["docker","run","-d","--name",names[0],"--label",label,"--network",network,"--network-alias","db",
                 "--memory=1g","--cpus=1","-v",clone_volume+":/var/lib/mysql","--env-file",str(env),mysql_image,"--innodb-buffer-pool-size=64M","--performance-schema=OFF","--max-allowed-packet=256M"])
        finally:
            env.unlink(missing_ok=True)
        started.append(names[0]);wait(names[0],True)
        with tempfile.TemporaryFile(dir=folder) as raw:
            with gzip.open(backup_path,"rb") as compressed:
                shutil.copyfileobj(compressed,raw)
            raw.seek(0)
            result=subprocess.run(["docker","exec","-i",names[0],"sh","-ceu",
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot "$MYSQL_DATABASE"'],stdin=raw,
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=120)
            if result.returncode:
                error_path=folder/("clone-restore-"+suffix+".private.log")
                error_path.write_bytes(result.stderr);os.chmod(error_path,0o600)
                raise RuntimeError("Restore into disposable clone failed; diagnostic saved privately")
        run(["docker","run","-d","--name",names[1],"--label",label,"--network",network,"--network-alias","redis",
             "--memory=64m","--cpus=0.5",inspect(PROJECT+"-redis-1")["Image"],"redis-server","--requirepass",password])
        started.append(names[1])
        env.write_text("\n".join([
            "SPRING_DATASOURCE_URL=jdbc:mysql://db:3306/flare_fitness?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
            "SPRING_DATASOURCE_USERNAME=root","SPRING_DATASOURCE_PASSWORD="+password,
            "SPRING_FLYWAY_IGNORE_MIGRATION_PATTERNS=repeatable:missing",
            "SPRING_DATA_REDIS_HOST=redis","SPRING_DATA_REDIS_PASSWORD="+password,
            "APP_JWT_SECRET="+secrets.token_urlsafe(48),"SPRING_PROFILES_ACTIVE=ueba-operator",
            "JAVA_TOOL_OPTIONS=-Xmx512m -XX:ActiveProcessorCount=1","MANAGEMENT_HEALTH_MAIL_ENABLED=false",
            "SIEM_ENABLED=false","SIEM_UEBA_ENABLED=false","SIEM_POSTLOGIN_ENABLED=false",
            "SIEM_SECURITY_EVENTS_ENABLED=false","APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED=false"]) + "\n")
        os.chmod(env,0o600)
        try:
            run(["docker","run","-d","--name",names[2],"--label",label,"--network",network,
                 "--memory=768m","--cpus=1","--read-only","--tmpfs","/tmp:rw,nosuid,size=64m",
                 "--env-file",str(env),image_id])
        finally:
            env.unlink(missing_ok=True)
        started.append(names[2]);wait(names[2])
        clone_protected=fingerprint(names[0])
        if clone_protected != proof["protected"]:
            raise RuntimeError("Clone migration changed protected account/demo/model fingerprints")
        versions=sql("SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1;",names[0]).decode().strip()
        if versions != str(expected_schema):
            raise RuntimeError("Clone did not migrate through V"+str(expected_schema))
        if before != fingerprint():
            raise RuntimeError("Original protected state changed during rehearsal")
        result={"status":"CLONE_V"+str(expected_schema)+"_PARITY_PASS","image_id":image_id,"backup_sha256":proof["sha256"],
                "protected":clone_protected,"schema_version":expected_schema,"original_database_modified":False,
                "model_fits":0,"live_mail_sent":False,"retained_private_clone_volume":clone_volume}
        result["migration_v41_sha256"]=digest((ROOT/"backend/src/main/resources/db/migration/V41__add_siem_evidence_containment_and_recurrence.sql").read_bytes())
        if expected_schema>=42:result["migration_v42_sha256"]=digest((ROOT/"backend/src/main/resources/db/migration/V42__add_auth_investigation_and_shadow_assessments.sql").read_bytes())
        publish(folder,clone_receipt,result)
        print(json.dumps({k:result[k] for k in ("status","schema_version","original_database_modified","model_fits")}))
    finally:
        for name in reversed(started):
            owned=inspect(name)
            if owned["Config"]["Labels"].get("flare.siem-upgrade.run")==suffix:
                diagnostic=subprocess.run(["docker","logs",name],capture_output=True,timeout=15)
                log=folder/(name+".private.log");log.write_bytes(diagnostic.stdout+diagnostic.stderr);os.chmod(log,0o600)
                state_path=folder/(name+".state.private.json");state_path.write_text(json.dumps(owned["State"]));os.chmod(state_path,0o600)
                run(["docker","rm","-f",name])
        run(["docker","network","rm",network])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("admission", "backup", "clone"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", help="Immutable candidate application tag for clone rehearsal")
    parser.add_argument("--expected-schema",type=int,choices=(41,42),default=41)
    args = parser.parse_args()
    private_root = ROOT / "observability/runtime/private-backups"
    folder = args.output.resolve()
    if not folder.is_relative_to(private_root.resolve()):
        raise RuntimeError("Output must be inside observability/runtime/private-backups")
    os.umask(0o077);folder.mkdir(parents=True, exist_ok=True);os.chmod(folder, 0o700)
    with (folder/"operator.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.phase == "admission":
            value = admission();publish(folder, "admission", value)
            print(json.dumps({"status": "ADMISSION_PASS", "free_gib": round(value["filesystem_available_bytes"]/1024**3, 1),
                              "elasticsearch_status": value["elasticsearch_health"]["status"], "live_modified": False}))
        elif args.phase == "backup":
            print(json.dumps(backup(folder)))
        else:
            clone(folder,args.image,args.expected_schema)


if __name__ == "__main__":
    main()
