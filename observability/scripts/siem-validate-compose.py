#!/usr/bin/env python3
"""Validate the unified OTP/SOC topology using live values in memory; emits no credentials."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]

def inspect(name):
    return json.loads(subprocess.check_output(["docker","inspect",name]))[0]

def context(app_image,nginx_image,gateway_image):
    app=inspect("flare-otp-local-app-1");db=inspect("flare-otp-local-db-1");redis=inspect("flare-otp-local-redis-1")
    existing=dict(e.split("=",1) for e in app["Config"]["Env"])
    env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","DOCKER_HOST","DOCKER_CONTEXT","XDG_RUNTIME_DIR")}
    env.update(existing);env.update(dict(e.split("=",1) for e in db["Config"]["Env"]))
    redis_env=dict(e.split("=",1) for e in redis["Config"]["Env"])
    env["REDIS_PASSWORD"]=redis_env["REDIS_PASSWORD"]
    env.update(FLARE_INTERNAL_SUBNET="172.31.90.0/24",OBSERVABILITY_ROOT_DIR=str(ROOT),FILEBEAT_CERTS_DIR=str(ROOT/".secrets/observability/web"),
        FLARE_SIEM_APP_IMAGE=app_image,FLARE_SIEM_NGINX_IMAGE=nginx_image,FLARE_SIEM_GATEWAY_IMAGE=gateway_image,
        FLARE_SIEM_PROTECTED_IPS="127.0.0.1",FLARE_POSTLOGIN_APP_IMAGE=app["Config"]["Image"],
        FLARE_POSTLOGIN_NGINX_IMAGE=inspect("flare-otp-local-nginx-1")["Config"]["Image"],
        FLARE_POSTLOGIN_WORKER_IMAGE=inspect("flare-otp-local-postlogin-worker-1")["Config"]["Image"],
        FLARE_POSTLOGIN_MANIFEST_SHA256=existing["SIEM_POSTLOGIN_MANIFEST_SHA256"])
    # Preserve an already-qualified mode when operating the same image. A new
    # application candidate still begins in OBSERVE for its own rollout gate.
    env["FLARE_SIEM_RECURRENCE_MODE"]=existing.get("SIEM_PREVENTION_RECURRENCE_MODE","OBSERVE") if app_image==app["Config"]["Image"] else "OBSERVE"
    for mount in app["Mounts"]:
        if mount["Destination"]=="/run/ueba-postlogin":env["FLARE_POSTLOGIN_RUNTIME_DIR"]=mount["Source"]
        if mount["Destination"]=="/run/secrets/ueba.token":env["FLARE_POSTLOGIN_SERVICE_TOKEN"]=mount["Source"]
    args=["docker","compose","--env-file","/dev/null","--project-name","flare-otp-local","--profile","observability"]
    for filename in ("docker-compose.yml","docker-compose.otp-local.yml","docker-compose.postlogin-project.yml",
                     "observability/docker-compose.monitor.yml","docker-compose.siem-local.yml"):
        args.extend(["-f",str(ROOT/filename)])
    return args,env,existing

def validate(app_image,nginx_image,gateway_image):
    args,env,existing=context(app_image,nginx_image,gateway_image)
    result=subprocess.run(args+["config","--format","json"],env=env,capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError("Compose configuration invalid; check required release variables")
    config=json.loads(result.stdout);services=config["services"]
    limits=sum(int(value.get("mem_limit",0)) for value in services.values())
    assert limits<=11*1024**3,"Memory budget exceeds 11 GiB"
    assert not services["nginx"].get("ports"),"Website must pass through gateway"
    assert "postlogin-worker" in services and "ueba-worker" not in services,"Only the pinned serving worker is allowed"
    application=services["app"]["environment"]
    assert "10001" in services["app"].get("group_add",[]),"ES reader credential group missing"
    assert services["gateway"]["tmpfs"]==["/tmp:rw,noexec,nosuid,size=32m,mode=0700,uid=10001,gid=10001"],"Gateway tmpfs must remain one mount entry"
    assert application["SIEM_UEBA_ENABLED"]=="false"
    assert application["SIEM_POSTLOGIN_MANIFEST_SHA256"]==existing["SIEM_POSTLOGIN_MANIFEST_SHA256"]
    for key in ("APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED","APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST",
                "APP_MAIL_USERNAME","APP_MAIL_FROM","APP_MAIL_PASSWORD","SPRING_MAIL_HOST","SPRING_MAIL_PORT"):
        assert application.get(key,"")==existing.get(key,""),"Existing OTP/mail setting changed: "+key
    assert application["SIEM_ELASTICSEARCH_URL"].startswith("https://")
    assert services["gateway"]["environment"]["PREVENTION_POLICY_CACHE"].endswith("gateway-policy.json")
    assert config["volumes"]["elasticsearch-data"].get("external")
    assert all(port["host_ip"]=="127.0.0.1" for port in services["gateway"]["ports"])
    summary={"status":"COMPOSE_CONTRACT_PASS","services":list(services),"memory_gib":round(limits/1024**3,3),
        "single_application":True,"existing_otp_mail_preserved":True,"recurrence_mode":application["SIEM_PREVENTION_RECURRENCE_MODE"],
        "external_es_volume":config["volumes"]["elasticsearch-data"]["name"],"live_modified":False}
    return summary

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-image",required=True);parser.add_argument("--nginx-image",required=True);parser.add_argument("--gateway-image",required=True)
    args=parser.parse_args()
    print(json.dumps(validate(args.app_image,args.nginx_image,args.gateway_image)))
