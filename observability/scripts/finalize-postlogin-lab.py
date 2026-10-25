#!/usr/bin/env python3
"""Requirement-by-requirement closure of the approved LAB branch, never production qualification."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import subprocess

from postlogin_action_lab_gate import checked
from postlogin_pilot_artifacts import read_bundle
from ueba_research_artifacts import commit, digest, private_directory

ROOT=Path(__file__).resolve().parents[2]


def run(root):
    phases=("approved-protocol","original-approved-plan-retrieved","quota-policy-5h-only",
        "risk-source-fold1-result","risk-data-audit-fold1","risk-pilot-protocol-v2","risk-pilot-fold1-result",
        "risk-stopped-pilot-diagnosis","research-final-diagnostics-v1","lab-action-gate-protocol-v1",
        "lab-action-full-trials-v1","lab-action-full-gate-audit-v1","lab-action-gate-result-v1",
        "live-mail-verified-v1","live-profile-verified-v1","otp-dependency-and-network-failure-v3",
        "local-allowlist-acceptance-v2","mail-config-loader-tests-v1","smtp-transport-hostname-config-v1",
        "frontend-otp-real-forms-browser-v1","frontend-legacy-204-contract-v1","frontend-production-build-v5",
        "frontend-otp-wire-unit-v1","otp-operation-trial-benchmark-v3","source-sigkill-recovery",
        "model-publication-sigkill-proof-v1","quota-primary-supervisor-tests-v4","contract-tests-v1",
        "source-ready-slot-lineage-tests-v2","rolling-representation-java-tests-v2","backend-policy-binding-v4")
    data={phase:checked(root,phase) for phase in phases}
    for phase,document in data.items():
        if "binding" in document and "argv" in document["binding"] and document["status"]!="COMMAND_PASS":
            raise ValueError("required job did not pass: "+phase)
    for phase in ("risk-source-protocol-v4","risk-pilot-protocol-v2"):
        protocol=checked(root,phase)
        for name,value in protocol["code_sha256"].items():
            if digest(Path(__file__).with_name(name))!=value:raise ValueError("research source drift")
    gate=data["lab-action-gate-result-v1"]
    if gate["status"]!="LAB_ACTION_GATE_PASS":raise ValueError("lab action gate missing")
    for name,value in data["lab-action-gate-protocol-v1"]["code_sha256"].items():
        if digest(ROOT/name)!=value:raise ValueError("lab trial implementation drift")
    if digest(root/"otp-trial-full-v1.private.json")!=gate["raw_trials_sha256"]:
        raise ValueError("lab outcome evidence changed")
    for operation in ("EMAIL_CHANGE","PASSWORD_CHANGE"):
        values=gate["operations"][operation]
        if values["eligible_owner_operations"]!=5000 or values["invalid_proof_operations"]!=2000:
            raise ValueError("full operation counts changed")
        bounds=values["conditional_iid_zero_error_upper_bounds_familywise_95_six_comparisons"]
        if bounds["eligible_owner_failure"]>=.001 or 1-bounds["invalid_proof_mutation"]<=.99 or values["additional_replay_mutations"]:
            raise ValueError("operation confidence gate failed")
    pilot=data["risk-pilot-fold1-result"]
    if pilot["status"]!="STOP_NO_IMPROVEMENT" or pilot["p4_admitted"] or pilot["holdout_scored"]:
        raise ValueError("wrong research terminal branch")
    ledger=pilot["fit_invocations_reserved"]
    if ledger["composite_invocations_reserved"]!=2 or ledger["component_invocations_reserved"]!=4:
        raise ValueError("fit count changed")
    source=data["risk-source-fold1-result"]
    if source["split_rows"]!={"fit":4000,"calibration":10000,"validation":21000}:
        raise ValueError("research source counts changed")
    for projection in ("baseline","candidate"):
        binding={"protocol_sha256":pilot["protocol_sha256"],"source_splits_sha256":source["split_commit_hashes_sha256"],"projection":projection}
        members=read_bundle(root,"risk-fit-fold1-"+projection,binding)
        metadata=json.loads(members["metadata.json"])
        if metadata["actual_successful_component_fits"]!=2 or metadata["readback_probe_rows"]!=9 or metadata["feature_schema_version"]!=6:
            raise ValueError("fitted artifact/parity evidence missing")
    if data["live-profile-verified-v1"]["result"]["stage"]!=6:raise ValueError("real mail actions incomplete")
    # Current release code matches the latest relevant checks. Earlier UI cases
    # are reused only because the sole fixture delta was corrected HTTP 204,
    # and that branch was rerun on both viewport projects.
    for phase in ("otp-dependency-and-network-failure-v3","local-allowlist-acceptance-v2",
                  "mail-config-loader-tests-v1","smtp-transport-hostname-config-v1",
                  "frontend-legacy-204-contract-v1","frontend-production-build-v5","frontend-otp-wire-unit-v1"):
        for path,value in data[phase]["binding"]["inputs_sha256"].items():
            if digest(Path(path))!=value:raise ValueError("verified implementation changed: "+phase)
    fixture="frontend/tests/e2e/action-confirmation-storefront.spec.js"
    previous=root/"implementation-snapshot-v4"/fixture
    if previous.read_text().replace("if (path === '/api/profile/password') return respond({});",
            "if (path === '/api/profile/password') return route.fulfill({ status: 204, body: '' });")!=(ROOT/fixture).read_text():
        raise ValueError("unexpected UI fixture drift")
    for name,value in data["frontend-otp-real-forms-browser-v1"]["binding"]["inputs_sha256"].items():
        if name!=str(ROOT/fixture) and digest(Path(name))!=value:raise ValueError("UI production/component drift")
    for name in ("backend/src/main/resources/db/migration/V39__allow_multiple_customers_without_phone.sql",
                 "backend/src/test/java/com/flarefitness/backend/integration/FlywayUpgradeIntegrationTest.java"):
        if digest(ROOT/name)!=data["otp-operation-trial-benchmark-v3"]["binding"]["inputs_sha256"][str(ROOT/name)]:
            raise ValueError("verified migration/upgrade evidence changed")
    old=ROOT/"observability/runtime/postlogin-training-data-20261020-r1/current-source-feasibility-conclusion.receipt.private.json"
    if digest(old)!=data["approved-protocol"]["old_conclusion_sha256"]:raise ValueError("old research conclusion changed")
    parity=checked(root,"lab-production-code-parity-v1")
    for name,value in parity["source_sha256"].items():
        if digest(ROOT/name)!=value:raise ValueError("authorization logic changed after full lab trials")
    budget=json.loads((root/"budget.private.json").read_text())
    if budget["elapsed_seconds"]>=28800 or budget["group_seconds"]["pilot"]>=7200:
        raise ValueError("budget exceeded")
    if shutil.disk_usage(root).free<5000000000:raise ValueError("disk reserve exhausted")
    if subprocess.check_output(["docker","ps","--filter","label=org.testcontainers=true","--format","{{.ID}}"],text=True).strip():
        raise ValueError("lab containers still active")
    for port in (58068,58069):
        with socket.socket() as connection:
            connection.settimeout(1)
            if connection.connect_ex(("127.0.0.1",port))==0:raise ValueError("human lab listener still active")
    requirements={
        "T0_checkpoint_and_old_evidence":"COMPLETE_REUSED_HASH_VERIFIED",
        "T1_observable_context_contract":"COMPLETE_DEMO_ONLY_NO_ACTOR_INTENT_CLAIM",
        "T2_representation":"COMPLETE_SCHEMA6_RECIPE5_65D_AMENDMENT_BEFORE_FIT_FULL_SOURCE_AUDIT",
        "T3_pilot":"COMPLETE_35000_ROWS_2_COMPOSITE_4_COMPONENT_FITS",
        "T4_research_decision":"COMPLETE_TERMINAL_STOP_NO_IMPROVEMENT_NO_MORE_FITS",
        "T5_strict_and_independent_model_proof":"NOT_OPENED_AS_REQUIRED_BY_FAILED_ADMISSION",
        "T6_model_integration_shadow":"NOT_OPENED_MODEL_UNQUALIFIED_AUTO_CONTAINMENT_FALSE",
        "OTP_api_storage_frontend_policy":"COMPLETE_FUNCTIONAL_AND_WIRE_CONTRACT_TESTS",
        "OTP_binding_expiry_replay_attempt_budget":"COMPLETE_REAL_HTTP_REDIS_AND_UNIT_EVIDENCE",
        "OTP_failure_and_concurrency":"COMPLETE_SMTP_REDIS_TELEMETRY_DB_AND_REAL_NETWORK_DISCONNECT_TESTS",
        "OTP_real_smtp":"COMPLETE_HUMAN_CODES_BOTH_LAB_MUTATIONS_OLD_SESSION_REVOKED",
        "OTP_lab_statistical_gate":"PASS_5000_ELIGIBLE_2000_INVALID_PER_OPERATION_95_PERCENT_ONE_SIDED",
        "OTP_local_activation":"PASS_RUNTIME_ENV_EXPLICIT_DISPOSABLE_LAB_ALLOWLIST_OUTSIDE_ACCOUNTS_UNCHANGED",
        "Recovery":"COMPLETE_SIGKILL_PUBLICATION_SOURCE_RESUME_WRITER_HASH_AND_TIMEOUT_CHECKS",
        "Delivery":"COMPLETE_REPORT_RUNBOOK_MODELS_DATA_MANIFESTS_RECEIPTS_AND_SOURCE_SNAPSHOT",
        "Real_user_product_qualification":"NOT_CLAIMED_NOT_AN_AVAILABLE_SOURCE_IN_THIS_APPROVED_LAB_BRANCH"}
    files={ROOT/file.relative_to(root/"implementation-snapshot-v4") for file in (root/"implementation-snapshot-v4").rglob("*") if file.is_file()}
    files.update(Path(__file__).parent.glob("postlogin_action*.py"))
    files.update(ROOT/name for name in ("observability/scripts/run-postlogin-action-trials.py",
        "observability/scripts/accept-local-otp-allowlist.py","observability/scripts/finalize-postlogin-lab.py",
        "backend/src/main/resources/application.properties",
        "backend/src/test/java/com/flarefitness/backend/integration/SensitiveActionDependencyFailureIntegrationTest.java",
        "backend/src/test/java/com/flarefitness/backend/integration/SensitiveActionLocalAllowlistAcceptanceTest.java",
        "backend/src/test/java/com/flarefitness/backend/config/MailTransportConfigurationTest.java","docs/LOCAL_OTP_RUNBOOK.md"))
    destination=root/"implementation-snapshot-v5";destination.mkdir(mode=0o700)
    manifest={}
    for source in sorted(files):
        if source.is_symlink() or not source.is_file() or source.name==".env" or source.suffix==".env":
            raise ValueError("unsafe/credential snapshot input")
        name=source.relative_to(ROOT);target=destination/name
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(source,target);target.chmod(0o600)
        if digest(source)!=digest(target):raise ValueError("snapshot byte mismatch")
        manifest[str(name)]=digest(target)
    result={"status":"APPROVED_PLAN_LAB_BRANCH_COMPLETE","requirements":requirements,
        "snapshot":destination.name,"files_sha256":manifest,
        "evidence_receipts_sha256":{phase:digest(root/(phase+".receipt.private.json"))for phase in phases},
        "research":"COMPLETE_NEGATIVE_QUALIFICATION_RESULT","local_lab":"COMPLETE_OTP_LAB_GATE_AND_RUNTIME_ALLOWLIST",
        "product_outside_lab":"NOT_PROVEN_OR_DEPLOYED","holdout_scored":False,"auto_containment":False,"aws_changed":False,
        "allowlist_scope":"Disposable local accounts only; no existing user account selected, no global settings changed",
        "production_delta_after_trials":"Only SMTP hostname verification required in application.properties; dedicated production-config test PASS. Authorization source hashes unchanged.",
        "cumulative_job_seconds_before_checkpoint":budget["elapsed_seconds"],"global_cap_seconds":28800,
        "pilot_seconds":budget["group_seconds"]["pilot"],"new_round_composite_fits":2,"new_round_component_fits":4,
        "snapshot_credentials":"No live SMTP configuration, OTP values or JWTs included"}
    proof=commit(root,result,phase="approved-plan-completion-audit-v1")
    print(json.dumps({"status":result["status"],"requirements":len(requirements),"snapshot_files":len(manifest),"receipt":proof}),flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("output")
    args=parser.parse_args();run(private_directory(args.output))
