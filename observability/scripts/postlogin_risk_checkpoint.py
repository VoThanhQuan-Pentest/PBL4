#!/usr/bin/env python3
"""Freeze task-related worktree bytes and verify the final local evidence bindings."""
import argparse
import json
from pathlib import Path
import shutil

from ueba_research_artifacts import commit, digest, private_directory

ROOT = Path(__file__).resolve().parents[2]


def run(output):
    phases = ("risk-source-protocol-v4", "risk-source-fold1-result", "risk-data-audit-fold1",
              "risk-pilot-protocol-v2", "risk-pilot-fold1-result", "risk-stopped-pilot-diagnosis",
              "otp-controlled-trial-audit", "otp-http-wire-contract-v4", "otp-operation-trial-benchmark-v3",
              "frontend-otp-real-forms-browser-v1", "frontend-production-build-v5", "frontend-otp-wire-unit-v1",
              "otp-trial-auditor-tests-v1")
    evidence = {}
    for phase in phases:
        marker = json.loads((output / (phase + ".commit.private.json")).read_text())
        path = output / (phase + ".receipt.private.json")
        if marker["receipt"] != path.name or digest(path) != marker["receipt_sha256"]:
            raise ValueError("checkpoint receipt changed: " + phase)
        evidence[phase] = marker["receipt_sha256"]
    for phase in ("risk-source-protocol-v4", "risk-pilot-protocol-v2"):
        protocol = json.loads((output / (phase + ".receipt.private.json")).read_text())
        for name, checksum in protocol["code_sha256"].items():
            if digest(Path(__file__).with_name(name)) != checksum:
                raise ValueError("producer/model code drift: " + name)
    for phase in ("otp-http-wire-contract-v4", "otp-operation-trial-benchmark-v3", "frontend-otp-real-forms-browser-v1", "frontend-production-build-v5", "frontend-otp-wire-unit-v1"):
        receipt = json.loads((output / (phase + ".receipt.private.json")).read_text())
        if receipt["status"] != "COMMAND_PASS" or any(digest(Path(name)) != value for name, value in receipt["binding"]["inputs_sha256"].items()):
            raise ValueError("verified implementation drift: " + phase)
    old = output / "implementation-snapshot-v1"
    files = {ROOT / p.relative_to(old) for p in old.rglob("*") if p.is_file()}
    files.update(Path(__file__).parent.glob("postlogin_risk*.py"))
    files.update(Path(__file__).parent.glob("postlogin_action*.py"))
    files.update((ROOT / "observability/tests").glob("test_postlogin_risk*.py"))
    files.update(ROOT / name for name in (
        "observability/scripts/run-risk-source-worker.py", "observability/scripts/postlogin_pilot_source.py",
        "observability/scripts/postlogin_pilot_artifacts.py", "observability/scripts/postlogin_data_quality.py",
        "observability/scripts/ueba_research_artifacts.py", "observability/tests/test_postlogin_action_trial_report.py",
        "frontend/tests/e2e/action-confirmation.spec.js", "frontend/tests/e2e/action-confirmation-storefront.spec.js", "frontend/vite.config.js",
        "backend/src/main/java/com/flarefitness/backend/ops/PostLoginFeatureExport.java",
        "backend/src/main/java/com/flarefitness/backend/service/siem/PostLoginRiskContextFeatures.java",
        "backend/src/main/resources/db/migration/V38__bind_sensitive_action_policy.sql",
        "backend/src/main/resources/db/migration/V39__allow_multiple_customers_without_phone.sql",
        "backend/src/test/java/com/flarefitness/backend/integration/SensitiveActionTrialIntegrationTest.java",
        "backend/src/test/java/com/flarefitness/backend/integration/SensitiveActionConfirmationIntegrationTest.java",
        "backend/src/test/java/com/flarefitness/backend/integration/FlywayUpgradeIntegrationTest.java",
        "docs/POSTLOGIN_RISK_OTP_STATUS_2026-10-20.md"))
    target = output / "implementation-snapshot-v3"
    target.mkdir(mode=0o700)
    manifest = {}
    for source in sorted(files):
        if source.is_symlink() or not source.is_file():
            raise ValueError("missing task snapshot input")
        name = source.relative_to(ROOT)
        destination = target / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, destination); destination.chmod(0o600)
        if digest(destination) != digest(source):
            raise ValueError("snapshot byte mismatch")
        manifest[str(name)] = digest(destination)
    proof = commit(output, {"status": "LOCAL_IMPLEMENTATION_CHECKPOINT_WITH_EXTERNAL_GATES_PENDING",
                           "snapshot": target.name, "files_sha256": manifest, "evidence_receipts_sha256": evidence,
                           "scope": "Task-context worktree snapshot includes pre-existing edits; not a clean Git patch",
                           "model_decision": "STOP_NO_IMPROVEMENT", "real_smtp": "USER_CONFIRMED_UNCONFIGURED",
                           "action_population_gate": "INCONCLUSIVE", "holdout_scored": False,
                           "auto_containment": False, "aws_changed": False}, phase="local-implementation-checkpoint-v3")
    print(json.dumps({"files": len(manifest), "receipt": proof}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(private_directory(args.output))
