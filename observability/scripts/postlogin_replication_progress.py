#!/usr/bin/env python3
"""Compact read-only progress; verify actual PID identity, never restart jobs."""
import json
from pathlib import Path
import subprocess
from postlogin_research_step import process_start

root=Path(__file__).resolve().parents[2]/"observability/runtime/postlogin-risk-ratio-20261021-r1"
controllers=[p for p in (root/"replication-controller.private.json",root/"factorial-controller.private.json") if p.exists()]
controller=json.loads(max(controllers,key=lambda p:p.stat().st_mtime_ns).read_text())
budget=json.loads((root/"budget.private.json").read_text())
ledger=json.loads((root/"risk-fit-ledger.private.json").read_text())
alive=process_start(controller["pid"])==controller["process_start"]
active=budget["active_unit"]
job_alive=bool(active and active.get("pid") and process_start(active["pid"])==active.get("process_start"))
counts={}
for fold in (2,3,5):
    counts[str(fold)]={split:min(total,32*len(list(root.glob(f"risk-source-f{fold}-{split}-*.commit.private.json"))))
        for split,total in (("fit",4000),("calibration",10000),("validation",21000))}
forward=root/"forward-validation-v1"
if forward.exists():counts["4"]={"fit":0,"calibration":0,"validation":min(21000,32*len(list(forward.glob("forward-source-f4-validation-*.commit.private.json"))))}
if job_alive and not alive:
    controller={**controller,"phase":active["id"],"status":"ACTIVE_BOUNDED_JOB_WITHOUT_PARENT_CONTROLLER"}
elif not alive:
    operator=json.loads((root/"operator-state.private.json").read_text())
    controller={**controller,"phase":operator.get("last_verified_commit",{}).get("phase",controller["phase"]),
                "status":operator["status"]}
workers=subprocess.run(["docker","ps","--filter","name=flare-risk-","--format","{{.Names}}:{{.Status}}"],capture_output=True,text=True,check=True).stdout.strip().splitlines()
print(json.dumps({"controller_alive":alive,"job_alive":job_alive,"phase":controller["phase"],"controller_status":controller["status"],
    "source_rows_committed":counts,"cumulative_fits_reserved":[ledger["composite_invocations_reserved"]+2,ledger["component_invocations_reserved"]+4],
    "historical_prior_task_fits":[2,4],
    "postlogin_all_tasks_reserved":[ledger["composite_invocations_reserved"]+4,ledger["component_invocations_reserved"]+8],
    "committed_job_seconds":round(budget["elapsed_seconds"],2),"active_unit":active["id"] if active else None,"workers":workers}))
