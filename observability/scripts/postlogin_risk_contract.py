"""Versioned, observable DEMO_ONLY context target, independent of actor intent.

This is an explicit rule-distillation benchmark, not incident ground truth.
The reference reads raw server observations, never planned cause or actor role.
Numeric model inputs remain the existing 37 + 20 pre-attempt dimensions.
"""
from datetime import datetime, timedelta
import math
from statistics import median

TASK_ID = "postlogin-observable-risk-context-v1"
FEATURE_SCHEMA_VERSION = 5
RECIPE_VERSION = 4
FEATURE_WIDTH = 57
LABELS = ("ROUTINE_CONTEXT", "BEHAVIOR_REVIEW_CONTEXT", "SERVICE_DEGRADATION_CONTEXT")
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst",
            "sensitive_action_burst", "http_error_burst")
PRIORITY = ("auth_failure_burst", "sensitive_action_burst", "endpoint_scan", "request_burst")
THRESHOLDS = {"request_minimum": 120, "request_history_multiplier": 4,
              "request_without_history_minimum": 1200, "scan_request_minimum": 50,
              "scan_endpoint_minimum": 7, "scan_client_error_rate_minimum": .45,
              "failed_login_minimum": 8, "sensitive_attempt_minimum": 5,
              "degradation_request_minimum": 40, "server_error_rate_minimum": .35}


def instant(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError("explicit UTC timestamp required")
    return result


def contract():
    return {"task_id": TASK_ID, "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "recipe_version": RECIPE_VERSION, "feature_width": FEATURE_WIDTH,
            "baseline_projection": list(range(37)), "candidate_projection": list(range(57)),
            "labels": list(LABELS), "families": list(FAMILIES), "thresholds": THRESHOLDS.copy(),
            "priority": list(PRIORITY), "data_provenance": "DEMO_ONLY",
            "label_basis": "RAW_SERVER_OBSERVATIONS_BEFORE_CURRENT_ATTEMPT",
            "estimand": "Observable context, not actor ownership or malicious intent",
            "admission_limit": "RULE_DISTILLATION_ONLY_WITHOUT_INDEPENDENT_TARGET_EVIDENCE",
            "missing_coverage": "UNDETERMINED_RETAINED_AND_REPORTED_NOT_SILENTLY_DROPPED",
            "otp_or_current_outcome_in_features": False}


def model_features(row, *, projection="candidate"):
    if projection not in ("baseline", "candidate"):
        raise ValueError("explicit feature projection required")
    first, postlogin = row["baseline_features"], row["postlogin_features"]
    if len(first) != 37 or len(postlogin) != 20:
        raise ValueError("exact baseline37/postlogin20 required; no padding legacy or proof rows")
    values = first + postlogin
    if any(type(value) not in (float, int) or not math.isfinite(value) for value in values):
        raise ValueError("finite numeric features only")
    return tuple(values[:37] if projection == "baseline" else values)


def reference(frame):
    """Return rule context + coverage; ignores all metadata outside raw frames."""
    attempt, context, histories = frame["attempt"], frame["context"], frame["baseline_frames"]
    if (len(context) > 10_000 or attempt.get("event_type") != "SENSITIVE_ACTION_ATTEMPT"
            or attempt.get("action") not in ("EMAIL_CHANGE", "PASSWORD_CHANGE")
            or attempt.get("outcome") != "ATTEMPT"):
        raise ValueError("bounded before-action frame required")
    at = instant(attempt["event_timestamp"])
    account = attempt.get("actor_user_id")
    issued = attempt.get("session_issued_at")
    session = attempt.get("session_pseudonym")
    covered = (isinstance(account, str) and bool(account)
               and attempt.get("telemetry_contract_version") == 4
               and isinstance(session, str) and len(session) == 64
               and all(c in "0123456789abcdef" for c in session)
               and issued is not None and instant(issued) <= at)
    if not covered:
        return {"training_context": None, "label": None, "family": None,
                "coverage": "UNDETERMINED", "reasons": ["MISSING_SERVER_SESSION_ASSOCIATION"]}
    recent, identities = [], set()
    for event in context:
        stamp = instant(event["event_timestamp"])
        if stamp >= at:
            continue  # Current outcome and future/tied events cannot change this target.
        identity = event.get("event_id")
        if identity and identity in identities:
            raise ValueError("duplicate context event identity")
        identities.add(identity)
        if stamp > at - timedelta(minutes=15) and (event.get("actor_user_id") == account
                or event.get("event_type") == "AUTH" and event.get("actor_user_id") is None
                and event.get("target_user_id") == account):
            recent.append(event)
    http = [e for e in recent if e.get("event_type") == "HTTP_REQUEST"]
    count = len(http)
    errors4 = sum(type(e.get("http_status")) is int and 400 <= e["http_status"] < 500 for e in http)
    errors5 = sum(type(e.get("http_status")) is int and 500 <= e["http_status"] < 600 for e in http)
    endpoints = {e["endpoint_category"] for e in http if e.get("endpoint_category")}
    failures = sum(e.get("event_type") == "AUTH" and e.get("action") == "LOGIN"
                   and e.get("outcome") != "SUCCESS" for e in recent)
    sensitive = sum(e.get("event_type") == "SENSITIVE_ACTION_ATTEMPT"
                    and e.get("action") in ("EMAIL_CHANGE", "PASSWORD_CHANGE") for e in recent)
    historical_counts = []
    window_start = at.replace(minute=at.minute // 15 * 15, second=0, microsecond=0)
    for history in histories:
        if history.get("account_id") != account:
            raise ValueError("history belongs to a different account")
        if instant(history["window_start"]) + timedelta(minutes=15) > window_start:
            raise ValueError("history is not a closed past window")
        historical_counts.append(sum(e.get("event_type") == "HTTP_REQUEST"
                                     for e in history["events"]))
    typical = median(historical_counts) if historical_counts else None
    volume = (count >= THRESHOLDS["request_minimum"]
              and typical is not None and typical > 0
              and count >= THRESHOLDS["request_history_multiplier"] * typical)
    if typical is None:
        volume = count >= THRESHOLDS["request_without_history_minimum"]
    matches = {"request_burst": volume,
               "endpoint_scan": count >= THRESHOLDS["scan_request_minimum"]
               and len(endpoints) >= THRESHOLDS["scan_endpoint_minimum"]
               and errors4 >= THRESHOLDS["scan_client_error_rate_minimum"] * count,
               "auth_failure_burst": failures >= THRESHOLDS["failed_login_minimum"],
               "sensitive_action_burst": sensitive >= THRESHOLDS["sensitive_attempt_minimum"],
               "http_error_burst": count >= THRESHOLDS["degradation_request_minimum"]
               and errors5 >= THRESHOLDS["server_error_rate_minimum"] * count}
    reasons = [family for family in FAMILIES if matches[family]]
    family = next((f for f in PRIORITY if matches[f]), "http_error_burst" if matches["http_error_burst"] else "normal")
    target = 0 if family == "normal" else 2 if family == "http_error_burst" else 1
    return {"training_context": target, "label": int(target != 0), "family": family,
            "coverage": "COVERED", "reasons": reasons,
            "reference_observations": {"requests": count, "endpoint_categories": len(endpoints),
                "client_errors": errors4, "server_errors": errors5, "failed_logins": failures,
                "sensitive_attempts": sensitive, "historical_request_median": typical}}
