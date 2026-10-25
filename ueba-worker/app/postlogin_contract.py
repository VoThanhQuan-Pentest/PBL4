"""Schema6 pre-attempt context contract. Actor identity is never a model target.

Separate from the schema1-4 window API: a 65-wide array alone cannot silently
turn a closed-window request into a sensitive-action snapshot.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from .contract import FEATURE_NAMES_V4

EVALUATION_UNIT = "SENSITIVE_ACTION_ATTEMPT"
SCHEMA_VERSION = 6
RECIPE_VERSION = 2
LABELS = ("ROUTINE_CONTEXT", "BEHAVIOR_REVIEW_CONTEXT", "SERVICE_DEGRADATION_CONTEXT")
POSTLOGIN_NAMES = ('current_operation_password_change', 'current_operation_email_change', 'authenticated_session_covered', 'same_session_successful_login_observed', 'session_age_seconds', 'seconds_since_observed_login', 'prior_sensitive_attempts_same_session_15m', 'prior_sensitive_successes_same_session_15m', 'prior_password_changes_same_session_15m', 'prior_email_changes_same_session_15m', 'prior_http_requests_same_session_15m', 'prior_http_4xx_same_session_15m', 'prior_http_5xx_same_session_15m', 'prior_profile_reads_same_session_15m', 'other_authenticated_sessions_account_15m', 'unassociated_sensitive_actions_account_15m', 'prior_password_resets_for_account_15m', 'previous_attempt_password_change', 'previous_attempt_email_change', 'seconds_since_previous_attempt')
ROLLING_NAMES = ("prior_http_requests_account_15m", "prior_endpoint_categories_account_15m",
    "prior_http_4xx_account_15m", "prior_http_5xx_account_15m",
    "prior_target_associated_failed_logins_account_15m", "prior_sensitive_attempts_account_15m",
    "closed_history_request_median", "closed_history_request_median_available")
FEATURE_NAMES = FEATURE_NAMES_V4 + POSTLOGIN_NAMES + ROLLING_NAMES
SNAPSHOT_FIELDS = {"snapshot_id", "evaluation_unit", "feature_schema_version", "feature_names", "features",
                   "as_of", "baseline_established", "trusted_window_count"}


def validate_snapshot(value):
    if not isinstance(value, dict) or set(value) != SNAPSHOT_FIELDS:
        raise ValueError("exact pre-attempt snapshot contract required; no labels, proof or outcome fields")
    if value["evaluation_unit"] != EVALUATION_UNIT or type(value["feature_schema_version"]) is not int or value["feature_schema_version"] != 6:
        raise ValueError("explicit schema6 sensitive-action evaluation unit required")
    if not isinstance(value["snapshot_id"], str) or not re.fullmatch(r"[a-z0-9_-]{8,128}", value["snapshot_id"]):
        raise ValueError("bounded opaque snapshot identity required")
    if value["feature_names"] != list(FEATURE_NAMES):
        raise ValueError("feature order or width differs from Java65")
    rows = value["features"]
    if not isinstance(rows, list) or len(rows) != 65 or any(type(v) not in (int, float) or not math.isfinite(v) for v in rows):
        raise ValueError("exact finite65 numeric inputs required; never pad61")
    if rows[64] not in (0, 1) or any(v < 0 for v in rows[57:65]):
        raise ValueError("invalid observed rolling counts/history availability")
    if rows[37] not in (0, 1) or rows[38] not in (0, 1) or rows[37]+rows[38] != 1 or rows[39] != 1:
        raise ValueError("one declared sensitive operation and server session coverage required")
    if any(v != int(v) for v in rows[57:63]) or rows[59]+rows[60]>rows[57] or rows[58]>rows[57]:
        raise ValueError("rolling counts contradict observed HTTP evidence")
    if rows[64] == 0 and rows[63] != 0:
        raise ValueError("missing history cannot contain an invented median")
    count = value["trusted_window_count"]
    if type(value["baseline_established"]) is not bool or type(count) is not int or not 0 <= count <= 1344:
        raise ValueError("observed history readiness required")
    if value["baseline_established"] != (count >= 30):
        raise ValueError("READY cannot be invented from missing history")
    try:
        at = datetime.fromisoformat(value["as_of"].replace("Z", "+00:00"))
        if at.utcoffset() != timezone.utc.utcoffset(at): raise ValueError()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("explicit UTC as_of required") from None
    return tuple(float(v) for v in rows)


def source_protocol(dataset_id):
    from .hybrid_strict_protocol import source_protocol as legacy
    protocol = legacy(dataset_id)
    protocol.update(format="POSTLOGIN_STRICT_SOURCE_PROTOCOL_V2", feature_schema_version=6,
        telemetry_contract_version=4, feature_names=list(FEATURE_NAMES), recipe_version=2,
        evaluation_unit=EVALUATION_UNIT, class_target_names=list(LABELS),
        task_id="postlogin-observable-context-independent-lab-v2",
        data_provenance="CONTROLLED_REAL_TIME_LAB", preparation_fit_cap=0,
        admission="AWAIT_MEASURED_CAMPAIGN_BUDGET", actor_role_is_ml_target=False,
        label_basis="PRESEALED_INDEPENDENT_SCENARIO_CONTEXT_NOT_FEATURE_THRESHOLDS",
        otp_or_current_outcome_in_features=False, quota_policy="NOT_USED")
    for run in protocol["campaign"]:
        identity={"legacy_recipe_sha256":run["recipe_sha256"],"raw_width":65,"normal_width":37,
                  "classifier_width":11,"evaluation_unit":EVALUATION_UNIT,"labels":LABELS,"recipe_version":2}
        run.update(recipe_version=2,recipe_sha256=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":")).encode()).hexdigest())
        run["run_id"]="postlogin-v2-"+run["run_id"].removeprefix("hybrid-v1-")
    return protocol


def require_campaign_admission(protocol, approval):
    if protocol.get("format") != "POSTLOGIN_STRICT_SOURCE_PROTOCOL_V2":
        raise ValueError("new schema/target requires its own source protocol")
    if not isinstance(approval, dict) or approval.get("status") != "USER_AUTHORIZED_CAMPAIGN":
        raise ValueError("zero-fit preparation cannot authorize training")
    expected=hashlib.sha256(json.dumps(protocol,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if approval.get("protocol_sha256") != expected:
        raise ValueError("campaign approval must bind this exact protocol")
    if (type(approval.get("maximum_composite_fits")) is not int
            or type(approval.get("maximum_component_fits")) is not int
            or approval["maximum_composite_fits"] < 360 or approval["maximum_component_fits"] < 720):
        raise ValueError("full strict fit budget not approved")
