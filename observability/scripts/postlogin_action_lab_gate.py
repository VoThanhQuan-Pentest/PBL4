#!/usr/bin/env python3
"""Approved LAB action gate, separate from any real-user population claim."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import shutil

from postlogin_action_trial_report import summarize
from ueba_research_artifacts import commit, digest, private_directory

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ("observability/scripts/run-postlogin-action-trials.py",
          "observability/scripts/postlogin_action_trial_report.py", "observability/scripts/postlogin_action_lab_gate.py",
          "backend/src/test/java/com/flarefitness/backend/integration/SensitiveActionTrialIntegrationTest.java",
          "backend/src/test/java/com/flarefitness/backend/integration/ContainerizedIntegrationTest.java")


def checked(root, phase):
    marker = json.loads((root / (phase + ".commit.private.json")).read_text())
    path = root / (phase + ".receipt.private.json")
    if marker["receipt"] != path.name or digest(path) != marker["receipt_sha256"]:
        raise ValueError("immutable evidence changed")
    return json.loads(path.read_text())


def admit(root):
    benchmark = json.loads((root / "otp-trial-benchmark-v4.private.json").read_text())
    summarize(benchmark)
    assert checked(root, "lab-action-capped-benchmark-v4")["status"] == "COMMAND_PASS"
    timings = defaultdict(list)
    for row in benchmark["outcomes"]:
        timings[row["operation"], row["scenario"]].append(row["trial_seconds"])
    projection = 0.
    for (_, scenario), values in timings.items():
        count = 5000 if scenario == "OWNER_VALID_PROOF" else 1 if scenario.endswith("CONTROL") else 500
        projection += sum(values) / len(values) * count
    projection = projection * 1.5 + 120
    budget = json.loads((root / "budget.private.json").read_text())
    if (projection > 8650 or budget["cap_seconds"] - budget["elapsed_seconds"] < 8700 + 300
            or shutil.disk_usage(root).free < 5000000000
            or sum(p.stat().st_size for p in root.rglob("*") if p.is_file()) >= 2 * 1024**3):
        raise RuntimeError("NO_GO_LAB_TRIAL_TIME_OR_STORAGE_BUDGET")
    document = {"status": "LAB_ACTION_FULL_TRIAL_ADMITTED", "scope": "LAB_ONLY_NOT_REAL_USER_ERROR_RATES",
        "approved_plan_sha256": digest(root / "original-approved-plan-retrieved.receipt.private.json"),
        "benchmark_sha256": digest(root / "otp-trial-benchmark-v4.private.json"),
        "timeout_amendment": "Benchmark passed; full maximum derived from measured throughput under original 8h global cap. No change to scenario assignment or gates.",
        "owners_per_operation": 5000, "invalid_proofs_per_operation": 2000,
        "invalid_scenarios": ["WRONG_CODE", "OTHER_SESSION", "EXPIRED", "AUTH_VERSION_CHANGED"],
        "invalid_scenario_rows_each_operation": 500, "extra_controls_each_operation": 2,
        "eligible_owner_definition": "Correct current password/business input, verified current contact, own current session and valid operation-bound proof before expiry",
        "missing_owner_proof_control": "Report denial as intended eligibility failure; not an attack label or a false block of a proof-eligible operation",
        "compromised_mailbox_control": "Correct proof can authorize this out-of-assumption actor; retain and report",
        "lab_false_block_maximum_exclusive": .001, "lab_invalid_proof_prevention_minimum_exclusive": .99,
        "confidence": {"one_sided_familywise": .95, "comparisons": 6,
                       "zero_error_upper_bound": "1-(0.05/6)**(1/n)",
                       "assumption": "Independent operation-scoped lab trials under the fixed controlled protocol; no real-user generalization"},
        "projection_seconds_with_50_percent_margin_and_startup": projection,
        "inner_deadline_seconds": 8650, "outer_deadline_seconds": 8700,
        "cpus": 2, "jvm_heap_mb": 512, "maven_heap_mb": 128, "mysql_memory_mb": 512, "redis_memory_mb": 128,
        "real_smtp_already_verified": "live-profile-verified-v1", "full_batch_mail": "MOCK_ONLY_NO_EXTRA_EXTERNAL_EMAIL",
        "quality_failure_retry": "FORBIDDEN", "new_fits": 0, "holdout_scored": False,
        "code_sha256": {name: digest(ROOT / name) for name in INPUTS}}
    return commit(root, document, phase="lab-action-gate-protocol-v1")


def audit(root):
    protocol = checked(root, "lab-action-gate-protocol-v1")
    for name, checksum in protocol["code_sha256"].items():
        if digest(ROOT / name) != checksum: raise ValueError("frozen lab protocol implementation changed")
    raw = root / "otp-trial-full-v1.private.json"
    document = json.loads(raw.read_text())
    report = summarize(document)
    if document["planned_eligible_owners_per_operation"] != 5000 or document["planned_invalid_proofs_per_operation"] != 2000:
        raise ValueError("declared full lab counts changed")
    live = checked(root, "live-profile-verified-v1")
    if live["result"]["stage"] != 6 or not live["result"]["old_session_revoked"]:
        raise ValueError("real SMTP/profile evidence missing")
    passed = all(
        values["conditional_iid_zero_error_upper_bounds_familywise_95_six_comparisons"]["eligible_owner_failure"] < .001
        and 1 - values["conditional_iid_zero_error_upper_bounds_familywise_95_six_comparisons"]["invalid_proof_mutation"] > .99
        and values["additional_replay_mutations"] == 0
        for values in report["operations"].values())
    output = {"status": "LAB_ACTION_GATE_PASS" if passed else "LAB_ACTION_GATE_FAIL",
        "scope": protocol["scope"], "operations": report["operations"],
        "confidence_assumption": protocol["confidence"]["assumption"],
        "real_user_population_gate": "NOT_ESTABLISHED_NOT_REQUIRED_FOR_THIS_LAB_GATE",
        "external_smtp": "LIVE_PROFILE_EMAIL_PASSWORD_PASS", "global_activation": False,
        "latency_excludes_email_and_human": report["execution_latency_excludes_smtp_and_human"],
        "raw_trials_sha256": digest(raw), "protocol_sha256": digest(root / "lab-action-gate-protocol-v1.receipt.private.json"),
        "new_fits": 0, "holdout_scored": False, "auto_containment": False}
    return commit(root, output, phase="lab-action-gate-result-v1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("admit", "audit")); parser.add_argument("output")
    args = parser.parse_args()
    proof = admit(private_directory(args.output)) if args.mode == "admit" else audit(private_directory(args.output))
    print(json.dumps(proof), flush=True)
