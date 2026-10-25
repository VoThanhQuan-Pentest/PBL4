"""Catalog real lab captures without inventing prefixes, labels, or history.

The sealed actor-role oracle is retained outside numeric inputs. Its labels are
not automatically converted to the three planned-context training classes.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path

from postlogin_data_quality import read
from ueba_research_artifacts import canonical, commit, digest, private_directory, publish

POSTLOGIN = ("current_operation_password_change", "current_operation_email_change", "authenticated_session_covered",
 "same_session_successful_login_observed", "session_age_seconds", "seconds_since_observed_login",
 "prior_sensitive_attempts_same_session_15m", "prior_sensitive_successes_same_session_15m",
 "prior_password_changes_same_session_15m", "prior_email_changes_same_session_15m",
 "prior_http_requests_same_session_15m", "prior_http_4xx_same_session_15m", "prior_http_5xx_same_session_15m",
 "prior_profile_reads_same_session_15m", "other_authenticated_sessions_account_15m",
 "unassociated_sensitive_actions_account_15m", "prior_password_resets_for_account_15m",
 "previous_attempt_password_change", "previous_attempt_email_change", "seconds_since_previous_attempt",
 "action_proof_observed", "action_proof_verified", "action_proof_age_seconds", "action_proof_scope_bound")
BASELINE = ("request_count", "http_4xx_count", "http_5xx_count", "failed_login_count", "successful_login_count",
 "sensitive_action_count", "distinct_route_group_count", "distinct_source_ip_count", "new_ip_flag",
 "new_user_agent_flag", "unusual_hour_flag", "request_log_mad_deviation", "route_group_log_mad_deviation",
 "http_client_error_rate", "failed_login_rate", "request_peak_10s", "request_gap_median_seconds", "request_gap_cv",
 "route_transition_count", "route_transition_rate", "failed_login_log_mad_deviation", "sensitive_action_log_mad_deviation",
 "failed_login_peak_60s", "sensitive_action_peak_60s", "consecutive_client_error_peak", "endpoint_metadata_count",
 "distinct_endpoint_category_count", "unmatched_endpoint_request_count", "unresolved_endpoint_request_count",
 "write_request_count", "same_endpoint_peak_10s", "session_metadata_count", "distinct_authenticated_session_count",
 "minimum_authenticated_session_age_seconds", "workflow_transition_count", "prior_request_window_count",
 "short_history_request_log_ratio")
CLOCK = {"request_gap_median_seconds", "request_gap_cv", "minimum_authenticated_session_age_seconds",
         "session_age_seconds", "seconds_since_observed_login", "seconds_since_previous_attempt", "action_proof_age_seconds"}


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_rows(oracle, snapshots, outcomes, source_hash, *, allow_legacy=False):
    plans = {p["case_id"]: p for p in oracle["plans"]}
    if len(plans) != len(oracle["plans"]) or len(plans) != len(snapshots) or len(plans) != len(outcomes):
        raise ValueError("exact sealed-plan/snapshot/outcome coverage required")
    if {s["case_id"] for s in snapshots} != set(plans) or {s["case_id"] for s in outcomes} != set(plans):
        raise ValueError("case coverage changed")
    labels = {o["case_id"]: o for o in outcomes}; result = []
    for s in snapshots:
        p, o = plans[s["case_id"]], labels[s["case_id"]]
        expected = {"OWNER": "AUTHORIZED_OWNER_ACTION", "NONOWNER": "CONTROLLED_UNAUTHORIZED_ACTION"}
        if p["role"] not in expected or o["ground_truth"] != expected[p["role"]] or o["label_source"] != "SEALED_ROLE_MANIFEST":
            raise ValueError("label differs from independent sealed role oracle")
        if p["action"] not in ("PASSWORD_CHANGE", "EMAIL_CHANGE") or instant(oracle["sealed_at"]) >= instant(s["as_of"]):
            raise ValueError("oracle must precede observed sensitive attempt")
        if (s["current_outcome_known"] is not False or s["account_mutation_observed_at_capture"] is not False
                or s["proof_stage"] != "SERVER_BODY_ADVICE_BEFORE_PROFILE_SERVICE"):
            raise ValueError("future target outcome must not be a feature")
        if s["feature_names"] != list(POSTLOGIN) or len(s["values"]) != 24:
            raise ValueError("exact postlogin24 contract required")
        legacy = "baseline_features" not in s
        if s["feature_version"] != ("postlogin-action-proof-lab-v1" if legacy else "postlogin-action-proof-lab-v2"):
            raise ValueError("feature version differs from actual source width")
        if legacy and not allow_legacy:
            raise ValueError("legacy capture has no observed baseline37; never zero-fill")
        if not legacy and (s["baseline_feature_names"] != list(BASELINE) or len(s["baseline_features"]) != 37
                           or type(s["baseline_established"]) is not bool or type(s["trusted_window_count"]) is not int):
            raise ValueError("exact observed baseline37 contract required")
        numeric = (s.get("baseline_features", []) + s["values"])
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in numeric):
            raise ValueError("finite numeric values required")
        if s["server_proof_state"] == "VERIFIED" and any(s["values"][i] != 1 for i in (20, 21, 23)):
            raise ValueError("verified proof flags contradict server state")
        if s["server_proof_state"] == "NOT_OBSERVED" and any(s["values"][20:]):
            raise ValueError("absent proof must not be invented")
        identity = hashlib.sha256(canonical([source_hash, s["case_id"]]).encode()).hexdigest()
        result.append({"episode_id": identity, "pair_id": source_hash + "/" + p["pair_id"],
                       "features": numeric if not legacy else None, "legacy_width": 24 if legacy else None,
                       "ground_truth": o["ground_truth"], "action": p["action"], "role": p["role"],
                       "as_of": s["as_of"], "proof_state": s["server_proof_state"],
                       "cohort": None if legacy else "READY" if s["baseline_established"] else "COLD",
                       "trusted_window_count": s.get("trusted_window_count"), "source_sha256": source_hash})
    return result


def load_capture(root, *, allow_legacy=False):
    root = private_directory(root)
    marker = read(root / "capture.commit.private.json")
    if marker["receipt"] != "capture.receipt.private.json" or digest(root / marker["receipt"]) != marker["receipt_sha256"]:
        raise ValueError("capture commit changed")
    receipt = read(root / marker["receipt"])
    if receipt["status"] != "PROOF_SIGNAL_OBSERVED_RESEARCH_ONLY" or receipt["fit_calls"] != 0:
        raise ValueError("completed zero-fit controlled capture required")
    names = {"oracle.private.json", "precommit.private.json", "outcomes.private.json", "controls.private.json"}
    if set(receipt["files_sha256"]) != names or not receipt["real_http_jwt_mysql_redis_otp"]:
        raise ValueError("controlled real-server capture allowlist required")
    for name, sha in receipt["files_sha256"].items():
        if digest(root / name) != sha: raise ValueError("capture member changed")
    rows = validate_rows(read(root / "oracle.private.json"), read(root / "precommit.private.json"),
                         read(root / "outcomes.private.json"), marker["receipt_sha256"], allow_legacy=allow_legacy)
    return rows, {"root": str(root), "receipt_sha256": marker["receipt_sha256"], "files_sha256": receipt["files_sha256"]}


def assemble(captures, output, legacy_captures=()):
    rows, sources = [], []
    for path in captures:
        batch, ref = load_capture(path); rows.extend(batch); sources.append(ref)
    excluded = []
    for path in legacy_captures:
        batch, ref = load_capture(path, allow_legacy=True)
        if any(r["features"] is not None for r in batch): raise ValueError("legacy exclusion must actually lack baseline37")
        excluded.extend(batch); sources.append(ref)
    if len({r["episode_id"] for r in rows}) != len(rows): raise ValueError("duplicate capture episodes")
    pairs = []
    names = BASELINE + POSTLOGIN
    for pair in sorted({r["pair_id"] for r in rows}):
        members = [r for r in rows if r["pair_id"] == pair]
        if len(members) != 2 or {r["role"] for r in members} != {"OWNER", "NONOWNER"}:
            raise ValueError("matched opposite-role pair required")
        differences = [names[i] for i, (a, b) in enumerate(zip(members[0]["features"], members[1]["features"])) if a != b]
        pairs.append({"pair_id": pair, "different_features": differences,
                      "different_nonclock_features": [name for name in differences if name not in CLOCK],
                      "clock_note": "Timing jitter from sequential lab execution is not independently supported actor-role evidence."})
    feature_path, label_path = output / "uniform61-features.private.json", output / "uniform61-labels.private.json"
    publish(feature_path, {"feature_names": list(names), "rows": [{"episode_id": r["episode_id"], "values": r["features"]} for r in rows]}, maximum=262144)
    publish(label_path, {"label_meaning": "CONTROLLED_LAB_ACTOR_ROLE_NOT_THREE_CLASS_CONTEXT", "rows": [{k: v for k, v in r.items() if k != "features"} for r in rows]}, maximum=262144)
    result = {"status": "UNIFORM61_CATALOG_COMPLETE_TRAINING_NOT_ADMITTED", "sources": sources,
              "eligible_vector_rows": len(rows), "legacy_rows_excluded_without_padding": len(excluded),
              "feature_width": 61, "role_labels": dict(Counter(r["ground_truth"] for r in rows)),
              "cohorts": dict(Counter(r["cohort"] for r in rows)), "operations": dict(Counter(r["action"] for r in rows)),
              "pair_comparisons": pairs, "features_sha256": digest(feature_path), "labels_sha256": digest(label_path),
              "admission_gaps": ["Small COLD-only controlled source; no READY/UNSEEN chronological FIT/calibration/validation population.",
                                 "Sealed actor-role labels have no automatic mapping to NORMAL/SECURITY_BEHAVIOR_CONTEXT/OPERATIONAL_FAILURE_CONTEXT.",
                                 "All-five-family and operational-failure coverage is absent; optional-proof and shared-mailbox counterexamples remain."],
              "new_fits": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False}
    commit(output, result, phase="uniform61-catalog")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, action="append", required=True)
    parser.add_argument("--legacy-capture", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = assemble(args.capture, private_directory(args.output), args.legacy_capture)
    print(json.dumps({k: report[k] for k in ("status", "eligible_vector_rows", "legacy_rows_excluded_without_padding", "cohorts")}, sort_keys=True))
