#!/usr/bin/env python3
"""Audit bounded real-HTTP ground truth without fitting, scoring, or changing labels."""
import argparse
from collections import Counter
from datetime import datetime
import json
import math
from pathlib import Path

from ueba_research_artifacts import canonical, commit, digest, private_directory


FEATURE_KEYS = {"case_id", "feature_version", "feature_names", "values", "as_of",
                "input_event_ids", "authenticated_session_covered", "same_session_login_observed"}
CLOCK_INTERVALS = {"session_age_seconds", "seconds_since_observed_login", "seconds_since_previous_attempt"}
SOURCE_KEYS = {"event_id", "account_id", "event_type", "action", "outcome", "event_timestamp",
               "telemetry_contract_version", "session_pseudonym", "session_issued_at", "http_status", "endpoint_category"}
FILES = {"label-manifest.private.json", "server-observations.private.json",
         "before-attempt-features.private.json", "outcomes-labels.private.json"}
EXPECTED_NAMES = [
    "current_operation_password_change", "current_operation_email_change", "authenticated_session_covered",
    "same_session_successful_login_observed", "session_age_seconds", "seconds_since_observed_login",
    "prior_sensitive_attempts_same_session_15m", "prior_sensitive_successes_same_session_15m",
    "prior_password_changes_same_session_15m", "prior_email_changes_same_session_15m",
    "prior_http_requests_same_session_15m", "prior_http_4xx_same_session_15m", "prior_http_5xx_same_session_15m",
    "prior_profile_reads_same_session_15m", "other_authenticated_sessions_account_15m",
    "unassociated_sensitive_actions_account_15m", "prior_password_resets_for_account_15m",
    "previous_attempt_password_change", "previous_attempt_email_change", "seconds_since_previous_attempt",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024,
            "Bounded ordinary capture file required")
    require(path.stat().st_mode & 0o077 == 0, "Private capture file required")
    return json.loads(path.read_text(), parse_constant=lambda _: require(False, "Nonfinite JSON"))


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def committed(root, phase):
    marker = read(root / (phase + ".commit.private.json"))
    require(marker["receipt"] == phase + ".receipt.private.json", "Unexpected receipt reference")
    path = root / marker["receipt"]
    require(digest(path) == marker["receipt_sha256"], "Committed receipt changed")
    return read(path), {"receipt": str(path), "receipt_sha256": digest(path)}


def validate_inputs(manifest, source, snapshots, outcomes):
    plans = {p["case_id"]: p for p in manifest["plans"]}
    require(len(plans) == len(manifest["plans"]) and 2 <= len(plans) <= 24 and len(plans) % 2 == 0,
            "Bounded distinct sealed cases required")
    require(all(p["actor_role"] in {"OWNER", "NONOWNER"} and type(p["valid_proof"]) is bool
                and p["operation"] in {"PASSWORD_CHANGE", "EMAIL_CHANGE"} for p in plans.values()),
            "Explicit actor roles and verifier controls required")
    require(len(snapshots) == len(outcomes) == len(plans), "Exact case coverage required")
    require({s["case_id"] for s in snapshots} == {o["case_id"] for o in outcomes} == set(plans),
            "Feature/label case mapping differs")
    require(source and len(source) <= 300, "Bounded server observations required")
    events = {e["event_id"]: e for e in source}
    require(len(events) == len(source), "Duplicate server observation")
    require(all(instant(e["event_timestamp"]) > instant(manifest["sealed_at"]) for e in source),
            "Labels were not sealed before observed HTTP activity")
    required_source = SOURCE_KEYS - {"http_status", "endpoint_category"}
    require(all(required_source <= set(e) <= SOURCE_KEYS for e in source), "Unexpected observation fields or oracle leakage")
    feature_names = snapshots[0]["feature_names"]
    require(feature_names == EXPECTED_NAMES, "Exact versioned numeric feature contract required")
    by_case = {}
    for snapshot in snapshots:
        require(set(snapshot) == FEATURE_KEYS, "Unexpected feature transport fields")
        require(snapshot["feature_version"] == "postlogin-before-action-v1"
                and snapshot["feature_names"] == feature_names, "Feature version/name mismatch")
        require(len(snapshot["values"]) == 20 and all(type(v) in (float, int) and math.isfinite(v)
                                                     for v in snapshot["values"]), "Numeric bounded vector required")
        case = snapshot["case_id"]
        case_events = [e for e in source if e["account_id"] == "account-" + case]
        attempts = [e for e in case_events if e["event_type"] == "SENSITIVE_ACTION_ATTEMPT"]
        require(len(attempts) == 1 and attempts[0]["outcome"] == "ATTEMPT"
                and attempts[0]["action"] == plans[case]["operation"], "Exact target attempt required")
        require(snapshot["as_of"] == attempts[0]["event_timestamp"], "Snapshot cutoff differs from attempt")
        expected = {e["event_id"] for e in case_events if instant(e["event_timestamp"]) < instant(snapshot["as_of"])}
        inputs = snapshot["input_event_ids"]
        require(len(inputs) == len(set(inputs)) and set(inputs) == expected, "Past-only context differs")
        require(snapshot["authenticated_session_covered"] is True and snapshot["same_session_login_observed"] is True,
                "Verified session/login coverage required")
        by_case[case] = dict(zip(feature_names, snapshot["values"]))
    for outcome in outcomes:
        plan = plans[outcome["case_id"]]
        label = "AUTHORIZED_OWNER_ACTION" if plan["actor_role"] == "OWNER" else "CONTROLLED_UNAUTHORIZED_ACTION"
        require(outcome["actor_role"] == plan["actor_role"] and outcome["ground_truth"] == label
                and outcome["label_source"] == "SEALED_ROLE_MANIFEST", "Label differs from independent role oracle")
        require(outcome["pair_id"] == plan["pair_id"] and outcome["operation"] == plan["operation"], "Wrong label mapping")
        require(outcome["account_mutated"] == plan["valid_proof"], "Capture contradicts declared verifier controls")
    return plans, by_case


def run(capture, selection, audit):
    capture = private_directory(capture)
    selection = private_directory(selection)
    audit = private_directory(audit)
    result, capture_ref = committed(capture, "capture")
    require(result["status"] == "CAPTURE_PASS_TRAINING_NOT_ADMITTED" and result["new_fit_calls"] == 0,
            "Completed zero-fit capture required")
    require(set(result["files_sha256"]) == FILES, "Unexpected capture file allowlist")
    for name, checksum in result["files_sha256"].items():
        require(digest(capture / name) == checksum, "Capture data changed")
    manifest = read(capture / "label-manifest.private.json")
    source = read(capture / "server-observations.private.json")
    snapshots = read(capture / "before-attempt-features.private.json")
    outcomes = read(capture / "outcomes-labels.private.json")
    plans, values = validate_inputs(manifest, source, snapshots, outcomes)
    pairs = []
    for pair in sorted({p["pair_id"] for p in plans.values()}):
        members = [p for p in plans.values() if p["pair_id"] == pair]
        require(len(members) == 2 and {p["actor_role"] for p in members} == {"OWNER", "NONOWNER"},
                "Matched opposite-role pair required")
        left, right = [values[p["case_id"]] for p in members]
        different = [name for name in left if left[name] != right[name]]
        pairs.append({"pair_id": pair, "different_feature_names": different,
                      "equal_except_clock_intervals": set(different) <= CLOCK_INTERVALS,
                      "interpretation": "Timing jitter alone is not independently supported evidence of actor role."})
    selection_receipt, selection_ref = committed(selection, "source-selection")
    previous = selection_receipt["prior_evidence"]["label-overlap-audit/label-overlap"]
    prior_path = Path(previous["path"])
    require(prior_path.name == "label-overlap.receipt.private.json" and digest(prior_path) == previous["sha256"],
            "Original overlap proof changed")
    prior = read(prior_path)
    require(len(prior["comparisons"]) == 5 and all(p["raw_server_observations_equal"] and p["candidate57_equal"]
                                                  for p in prior["comparisons"]), "Original hard pairs missing")
    receipt = {
        "status": "NO_GO_TRAINING_SOURCE_OR_OBSERVABILITY_GAP", "capture": capture_ref, "selection": selection_ref,
        "independent_role_labels": "PASS_CONTROLLED_LAB_ONLY", "past_only_transport": "PASS",
        "real_otp_verifier": result["real_http_jwt_mysql_redis_otp_verifier"] and not result["otp_verifier_mocked"],
        "pairs": pairs, "sensitive_attempts": len(outcomes), "label_counts": dict(Counter(o["ground_truth"] for o in outcomes)),
        "preexisting_auth_rejections": sum(o["http_status"] == 400 for o in outcomes),
        "controlled_nonowner_mutations": sum(o["actor_role"] == "NONOWNER" and o["account_mutated"] for o in outcomes),
        "preserved_original_counterfactual_proof": previous,
        "admission_reasons": [
            "Independent labels establish lab actor roles, but no new precommit feature evidence supports separating them.",
            "The original five full-observation overlap pairs remain unresolved; keep their original labels and gates.",
            "All new accounts are COLD; this small two-action capture does not establish the required training population.",
        ],
        "next_action": "Choose an evidence-backed precommit signal or authorization-proof design before any new training admission.",
        "new_fit_calls": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False,
        "audit_script_sha256": digest(Path(__file__)),
    }
    commit(audit, receipt, phase="groundtruth-audit")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("capture", "selection", "audit"):
        parser.add_argument("--" + arg, required=True, type=Path)
    args = parser.parse_args()
    print(canonical(run(args.capture, args.selection, args.audit)))
