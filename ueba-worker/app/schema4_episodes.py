"""Versioned offline DEMO_ONLY simulations, not captured traffic or quality proof.

Truth is the frozen planned cause, assigned before execution. Labels, business
intent and evidence never enter the returned Java-compatible telemetry frame.
The caller must join the separate label only at the offline export boundary.
Ambiguous legitimate/anomalous counterfactuals are deliberately retained.
No networking, fitting, promotion, credential material or dataset file writes.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import re


PROTOCOL_VERSION = "schema4-causal-episodes-v1"
DATA_PROVENANCE = "DEMO_ONLY_SIMULATION"
PROTOCOL_ANCHOR = datetime(2026, 4, 1, tzinfo=timezone.utc)
MAX_EVENTS = 4096
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_ACCOUNT_ORDINAL = 1_000_000
MAX_EPISODE_ORDINAL = 1343
BLIND_SEEDS = (190811, 290823, 390842, 490873, 590901)
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst",
            "sensitive_action_burst", "http_error_burst")
LEGITIMATE_CAUSES = ("normal", "benign_heavy_burst", "benign_retries",
                    "benign_missing_metadata", "benign_password_maintenance",
                    "benign_operational_errors", "benign_endpoint_traversal",
                    "benign_login_only_retries", "benign_expected_degradation")
BASE_COUNTS = (2, 4, 6, 9, 12, 18, 28, 42, 70, 130)
AGENTS = ("CHROMIUM", "FIREFOX", "SAFARI", "EDGE")
READ_HANDLERS = (("products", "PRODUCT_LIST"), ("profile", "PROFILE_READ"),
                 ("orders", "ORDERS_READ"), ("support", "SUPPORT_READ"),
                 ("reviews", "REVIEW_READ"), ("promo_hunt", "PROMO_LIST"),
                 ("sync", "SYNC_READ"))
HANDLER_PATTERNS = {
    ("GET", "products", "PRODUCT_LIST"): "/api/products",
    ("GET", "products", "PRODUCT_DETAIL"): "/api/products/{id}",
    ("GET", "profile", "PROFILE_READ"): "/api/profile",
    ("PUT", "profile", "PROFILE_PASSWORD"): "/api/profile/password",
    ("GET", "orders", "ORDERS_READ"): "/api/orders/me",
    ("GET", "support", "SUPPORT_READ"): "/api/support/me/messages",
    ("GET", "reviews", "REVIEW_READ"): "/api/reviews/products/{productId}",
    ("GET", "promo_hunt", "PROMO_LIST"): "/api/promo-hunt/campaigns",
    ("GET", "sync", "SYNC_READ"): "/api/sync/me/{key}",
    ("GET", "other_api", "OTHER_MATCHED"): "/api/owned-lab/controlled-faults",
}
COHORT_MAP = {"READY": "DEVELOPMENT", "UNSEEN_READY": "UNSEEN", "COLD": "COLD",
              "DEVELOPMENT": "DEVELOPMENT", "UNSEEN": "UNSEEN"}
COUNTERPARTS = {"benign_heavy_burst": "request_burst", "benign_retries": "auth_failure_burst",
                "benign_password_maintenance": "sensitive_action_burst",
                "benign_expected_degradation": "http_error_burst",
                "benign_endpoint_traversal": "endpoint_scan",
                "benign_login_only_retries": "auth_failure_burst"}
SOURCE_FILES = (
    "ueba-worker/app/schema4_episodes.py",
    "observability/scripts/prepare-ueba-strict.py",
    "backend/src/main/java/com/flarefitness/backend/ops/UebaFeatureExport.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/EndpointCategory.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/SecurityEventNormalizer.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/AccountBaselinePolicy.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/AccountBehaviorFeatures.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/ContextualBehaviorFeatures.java",
    "backend/src/main/java/com/flarefitness/backend/service/siem/SessionEndpointBehaviorFeatures.java",
    "backend/src/main/java/com/flarefitness/backend/security/IpRateLimitService.java",
    "backend/src/main/java/com/flarefitness/backend/security/JwtTokenService.java",
    "backend/src/main/resources/application.properties",
    "backend/src/main/java/com/flarefitness/backend/service/AuthService.java",
    "backend/src/main/java/com/flarefitness/backend/service/ProfileService.java",
    "backend/src/main/java/com/flarefitness/backend/config/SecurityEventFilter.java",
    "backend/src/test/java/com/flarefitness/backend/controller/OwnedLabControlledFaultController.java",
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def stable_seed(*parts):
    """Length-delimited deterministic streams; cause is never an identity seed."""
    return int(_digest(list(parts))[:16], 16)


def _integer(value, lower, upper, name):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"invalid bounded {name}")


def _start(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as failure:
            raise ValueError("invalid window timestamp") from failure
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("UTC window timestamp required")
    if value.minute % 15 or value.second or value.microsecond:
        raise ValueError("window must align to a quarter hour")
    if not PROTOCOL_ANCHOR <= value < PROTOCOL_ANCHOR + timedelta(days=110):
        raise ValueError("window is outside the frozen 110-day protocol")
    return value.astimezone(timezone.utc)


def _timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AccountProfile:
    """Shared nuisance population for all planned causes; no truth-bearing fields."""

    requests: int
    routes: int
    first_hour: int
    ip: str
    ua: str

    def __post_init__(self):
        _integer(self.requests, 1, 800, "profile request count")
        _integer(self.routes, 1, len(READ_HANDLERS), "profile route count")
        _integer(self.first_hour, 0, 12, "profile first hour")
        try:
            address = ipaddress.ip_address(self.ip)
        except (ValueError, TypeError) as failure:
            raise ValueError("synthetic documentation address required") from failure
        if address not in ipaddress.ip_network("198.51.100.0/24") or self.ua not in AGENTS:
            raise ValueError("invalid synthetic profile address or browser")


def account_profile(dataset_id, account_ordinal):
    """Original base-count/browser recipe, independent of labels and episodes."""
    _identity_inputs(dataset_id, account_ordinal)
    rng = random.Random(stable_seed("profile", dataset_id, account_ordinal))
    return AccountProfile(rng.choice(BASE_COUNTS), rng.randint(1, 7), rng.randint(0, 12),
                          f"198.51.100.{1 + account_ordinal % 250}", AGENTS[account_ordinal % len(AGENTS)])


def _identity_inputs(dataset_id, account_ordinal):
    if not isinstance(dataset_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,64}", dataset_id):
        raise ValueError("invalid dataset identity")
    _integer(account_ordinal, 0, MAX_ACCOUNT_ORDINAL, "account ordinal")


def _cohort(value):
    if not isinstance(value, str) or value not in COHORT_MAP:
        raise ValueError("invalid episode cohort")
    return COHORT_MAP[value]


def _plan(seed, profile, cause, cohort, context):
    """The causal plan and label are committed before any event is emitted."""
    label = int(cause in FAMILIES)
    execution = COUNTERPARTS.get(cause, cause)
    rng = random.Random(stable_seed("actions", seed))
    requests = max(1, min(800, round(profile.requests * rng.lognormvariate(0, 0.28))))
    routes = max(1, min(7, requests, profile.routes + rng.choice((-1, 0, 0, 1))))
    successes = rng.choice((0, 0, 1, 1, 2))
    failed = client_errors = server_errors = sensitive = 0
    if not context and execution in ("normal", "benign_missing_metadata"):
        variant = rng.random()
        if variant < 0.03:
            failed = rng.randint(1, 7)
            # A forgotten-credential retry is not an authenticated browsing
            # session. Keep the original rare retry probability/counts without
            # inventing HTTP coverage for its target-associated failures.
            execution, requests, routes, successes = "auth_failure_burst", 0, 1, 0
        elif variant < 0.06:
            client_errors = min(requests, rng.randint(1, 6))
        elif variant < 0.08:
            server_errors = min(requests, rng.randint(1, 4))
        elif variant < 0.10:
            sensitive = rng.choice((1, 1, 2))
        elif variant < 0.13:
            requests = min(1000, requests * rng.randint(2, 5))
    elif execution == "request_burst":
        requests = min(1600, max(120, round(profile.requests * rng.uniform(4, 10))))
        client_errors, routes = rng.randint(0, min(15, requests)), rng.randint(2, 7)
    elif execution == "endpoint_scan":
        requests = rng.randint(50, 240)
        client_errors, routes = round(requests * rng.uniform(0.45, 0.95)), 7
    elif execution == "auth_failure_burst":
        # No authenticated principal exists in this login-only experiment.
        requests, routes, successes, failed = 0, 1, 0, rng.randint(8, 45)
        if cause == "benign_login_only_retries":
            failed = rng.randint(1, 7)
    elif execution == "sensitive_action_burst":
        requests, routes, sensitive = rng.randint(2, 18), 2, rng.randint(5, 25)
    elif execution == "http_error_burst":
        requests = rng.randint(40, 240)
        client_errors = rng.randint(0, 6)
        server_errors = round((requests - client_errors) * rng.uniform(0.35, 0.90))
        routes = rng.randint(1, 7)
    elif execution == "benign_operational_errors":
        server_errors = min(requests, rng.randint(1, 4))
    nuisance = random.Random(stable_seed("capture-and-session", seed))
    # Capture omissions, prior session age, parallel sessions and browser/IP
    # novelty are drawn from the same stream irrespective of planned truth.
    metadata_mode = nuisance.choice(("FULL", "FULL", "FULL", "PARTIAL", "ABSENT"))
    if cause == "benign_missing_metadata":
        metadata_mode = "ABSENT"
    # Default JWT lifetime is 86400s: do not simulate an already expired token
    # as an authenticated request merely because the feature can cap its age.
    age = nuisance.choice((30, 30, 300, 600, 3600, 72000))
    return {"protocol_version": PROTOCOL_VERSION, "planned_cause": cause, "execution_seed": seed,
            "label": label, "family": cause if label else "normal", "execution_recipe": execution,
            "profile": asdict(profile), "cohort": cohort, "background_requests": requests,
            "route_count": routes, "failed_logins": failed, "successful_logins": successes,
            "client_errors": client_errors, "server_errors": server_errors, "password_changes": sensitive,
            "capture_mode": metadata_mode, "initial_session_age_seconds": age,
            "parallel_session": nuisance.random() < 0.15, "novel_client": nuisance.random() < 0.16 and not context,
            "baseline_context": context,
            "data_provenance": DATA_PROVENANCE}


def build_scenario(seed, profile, planned_cause, window_start, cohort="READY", *, account_id=None, frame_id=None, context=False):
    """Return {frame, scenario, client_ledger, evidence}; bounded offline only.

    Each episode is an independent virtual owned world with no other IP traffic.
    It is not a replay or independent replicate of any authentic captured source.
    Hard legitimate counterparts can have exactly the same observed telemetry.
    """
    _integer(seed, 0, 2**64 - 1, "seed")
    if not isinstance(profile, AccountProfile):
        raise ValueError("validated AccountProfile required")
    if not isinstance(planned_cause, str) or planned_cause not in (*LEGITIMATE_CAUSES, *FAMILIES):
        raise ValueError("unknown frozen planned cause")
    if type(context) is not bool or context and planned_cause != "normal":
        raise ValueError("context must be an unlabelled normal baseline recipe")
    start, cohort = _start(window_start), _cohort(cohort)
    account_id = account_id if account_id is not None else "acct-" + _digest(["account", asdict(profile)])[:32]
    frame_id = frame_id if frame_id is not None else "frame-" + _digest(["frame", seed, account_id, _timestamp(start)])[:40]
    for identity, limit in ((account_id, 64), (frame_id, 128)):
        if not isinstance(identity, str) or not re.fullmatch(r"[a-z0-9_-]{8," + str(limit) + "}", identity):
            raise ValueError("invalid opaque episode identity")
        if any(cause in identity for cause in (*FAMILIES, *LEGITIMATE_CAUSES)):
            raise ValueError("truth-bearing episode identity refused")
    plan = _plan(seed, profile, planned_cause, cohort, context)
    plan.update(window_start=_timestamp(start), account_id=account_id, frame_id=frame_id)
    plan_sha = _digest(plan)
    # From here execution consumes the frozen action/nuisance plan, not its label.
    events, ledger = [], []
    ip = f"203.0.113.{1 + int(_digest([seed, 'ip'])[:8], 16) % 250}" if plan["novel_client"] else profile.ip
    ua = AGENTS[(AGENTS.index(profile.ua) + 1) % len(AGENTS)] if plan["novel_client"] else profile.ua
    session_number = 0
    issued = start - timedelta(seconds=plan["initial_session_age_seconds"])
    session = _digest(["session", seed, session_number])

    def attempt(at, kind, method, group, status, indexes=()):
        ledger.append({"attempt_sequence": len(ledger), "attempted_at": _timestamp(at),
                       "attempt_kind": kind, "http_method": method, "route_group": group,
                       "http_status": status, "server_event_indexes": list(indexes),
                       "data_provenance": DATA_PROVENANCE})

    def auth(at, success, *, csrf_at=None):
        nonlocal session_number, session, issued
        attempt(csrf_at if csrf_at is not None else at - timedelta(seconds=0.25),
                "CSRF_READ", "GET", "auth", 200)
        index = len(events)
        events.append({"event_timestamp": _timestamp(at), "event_type": "AUTH", "action": "LOGIN",
                       "outcome": "SUCCESS" if success else "FAILURE", "route_group": "auth",
                       "source_ip": ip, "user_agent_family": ua})
        attempt(at, "LOGIN", "POST", "auth", 200 if success else 401, (index,))
        if success:
            session_number += 1
            session, issued = _digest(["session", seed, session_number]), at

    def http(at, group, category, status=200, method="GET", *, parallel=False):
        handler = HANDLER_PATTERNS.get((method, group, category))
        if handler is None and (method, group, category, status) not in (
                ("GET", "other_api", "UNMATCHED", 404), ("GET", "admin", "UNRESOLVED", 403)):
            raise ValueError("method/group/category lacks a valid simulated server handler")
        value = {"event_timestamp": _timestamp(at), "event_type": "HTTP_REQUEST", "action": "API_REQUEST",
                 "outcome": "FAILURE" if status >= 400 else "SUCCESS", "route_group": group,
                 "source_ip": ip, "user_agent_family": ua, "http_method": method, "http_status": status}
        metadata = random.Random(stable_seed("metadata", seed, len(events)))
        mode = plan["capture_mode"]
        if mode == "FULL" or mode == "PARTIAL" and metadata.random() >= 0.20:
            value["endpoint_category"] = category
        if mode == "FULL" or mode == "PARTIAL" and metadata.random() >= 0.20:
            value.update(session_pseudonym=_digest(["session", seed, "parallel"]) if parallel else session,
                         session_issued_at=_timestamp(start - timedelta(seconds=plan["initial_session_age_seconds"])) if parallel else _timestamp(issued))
        index = len(events)
        events.append(value)
        attempt(at, "AUTHENTICATED_REQUEST", method, group, status, (index,))
        ledger[-1].update(handler_pattern=handler, server_endpoint_category=category,
                          handler_resolution="RESOURCE_HANDLER" if category == "UNMATCHED" else
                          "PRE_MVC_AUTHORIZATION_DENIAL" if category == "UNRESOLVED" else "APPLICATION_CONTROLLER")

    if plan["execution_recipe"] == "auth_failure_burst":
        # 61-second paced blocks preserve 8..45 target-attributed failures while
        # respecting both 5/IP and 5/account TTL buckets; sixth attempts are
        # un-attributable rate limits, never fake account AUTH or HTTP events.
        for index in range(plan["failed_logins"]):
            block, position = divmod(index, 5)
            auth(start + timedelta(seconds=2 + block * 61 + position), False)
            if position == 4:
                attempt(start + timedelta(seconds=6.75 + block * 61), "CSRF_READ", "GET", "auth", 200)
                attempt(start + timedelta(seconds=7 + block * 61), "RATE_LIMITED_LOGIN", "POST", "auth", 429)
    else:
        for index in range(plan["successful_logins"]):
            auth(start + timedelta(seconds=0.25 + index * 0.50), True)
        for index in range(plan["background_requests"]):
            group, category = READ_HANDLERS[index % plan["route_count"]]
            if index < plan["client_errors"]:
                if index % 3 == 0:
                    group, category, status = "admin", "UNRESOLVED", 403
                elif index % 3 == 1:
                    group, category, status = "products", "PRODUCT_DETAIL", 404
                else:
                    group, category, status = "other_api", "UNMATCHED", 404
            elif index < plan["client_errors"] + plan["server_errors"]:
                # The actual owned-lab fault is an application controller GET,
                # not an invented high-cardinality endpoint or malicious claim.
                group, category, status = "other_api", "OTHER_MATCHED", 503
            else:
                status = 200
                if group == "products" and index % 2:
                    category = "PRODUCT_DETAIL"
            # Preserve legacy 1+index%800 timing, except prerequisite password
            # background reads must finish before the first mutation/revocation.
            seconds = 1 + index % 800 if not plan["password_changes"] else 1 + index * 17 / max(1, plan["background_requests"])
            http(start + timedelta(seconds=seconds), group, category, status,
                 parallel=plan["parallel_session"] and not plan["password_changes"] and index % 3 == 1)
        for index in range(plan["failed_logins"]):
            # The original rare 1..7 normal retry mixture is quota-pacing aware.
            block, position = divmod(index, 5)
            auth(start + timedelta(seconds=805 + block * 61 + position), False)
        for index in range(plan["password_changes"]):
            at = start + timedelta(seconds=20 + index * 28)
            http(at, "profile", "PROFILE_READ")
            # Login clears pre-login CSRF state. The authenticated refresh must
            # precede the PUT, not be invented after it has already succeeded.
            attempt(at + timedelta(seconds=2), "CSRF_REFRESH", "GET", "auth", 200)
            http(at + timedelta(seconds=4), "profile", "PROFILE_PASSWORD", 204, "PUT")
            events.append({"event_timestamp": _timestamp(at + timedelta(seconds=3, microseconds=999999)),
                           "event_type": "DOMAIN_ACTION", "action": "PASSWORD_CHANGE", "outcome": "SUCCESS",
                           "route_group": "account", "source_ip": None, "user_agent_family": None})
            ledger[-1]["server_event_indexes"].append(len(events) - 1)
            attempt(at + timedelta(seconds=5), "REVOKED_SESSION_ATTEMPT", "GET", "profile", 401)
            auth(at + timedelta(seconds=8), True, csrf_at=at + timedelta(seconds=6))
    # Keep ledger indices meaningful (no event reorder); both consumers sort
    # temporal observations rather than treating array order as chronology.
    frame = {"frame_id": frame_id, "account_id": account_id,
             "day": (start.date() - PROTOCOL_ANCHOR.date()).days + 1, "cohort": cohort,
             "window_start": _timestamp(start), "telemetry_contract_version": 3, "events": events}
    _validate_execution(frame, ledger)
    scenario = {"label": plan["label"], "family": plan["family"], "planned_cause": planned_cause,
                "data_provenance": DATA_PROVENANCE, "protocol_version": PROTOCOL_VERSION,
                "plan_sha256": plan_sha, "plan": plan,
                "causal_estimand": "PLANNED_ACCOUNT_BEHAVIOR_ANOMALY_NOT_MALICIOUSNESS",
                "attribution_kind": "TARGET_ASSOCIATED_UNAUTHENTICATED" if plan["execution_recipe"] == "auth_failure_burst" else "SIMULATED_AUTHENTICATED_ACCOUNT",
                "authenticated_actor_claimed": plan["execution_recipe"] != "auth_failure_burst"}
    evidence = {"protocol_version": PROTOCOL_VERSION, "data_provenance": DATA_PROVENANCE,
                "authentic_capture": False, "captured_sources_replayed_or_relabelled": False,
                "labels_assigned_before_events": True, "labels_present_in_frame": False,
                "plan_sha256": plan_sha, "frame_sha256": _digest(frame),
                "server_events_sha256": _digest(events), "client_ledger_sha256": _digest(ledger),
                "event_count": len(events), "client_attempt_count": len(ledger),
                "server_event_conservation": True, "per_world_login_quota_checked": True,
                "global_deployment_stream_quota_claimed": False, "independent_virtual_owned_world": True,
                "quality_proof": False, "observational_ambiguity_retained": True}
    requests = [event for event in events if event["event_type"] == "HTTP_REQUEST"]
    ages = [(datetime.fromisoformat(event["event_timestamp"].replace("Z", "+00:00"))
             - datetime.fromisoformat(event["session_issued_at"].replace("Z", "+00:00"))).total_seconds()
            for event in requests if "session_issued_at" in event]
    evidence.update(observed_request_count=len(requests),
                    observed_endpoint_metadata_count=sum("endpoint_category" in event for event in requests),
                    observed_session_metadata_count=len(ages),
                    actual_minimum_observed_session_age_seconds=min(ages) if ages else None)
    return {"frame": frame, "scenario": scenario, "client_ledger": ledger, "evidence": evidence}


def _validate_execution(frame, ledger):
    start = _start(frame["window_start"])
    if not 1 <= len(frame["events"]) <= MAX_EVENTS or len(_canonical(frame).encode()) >= MAX_FRAME_BYTES:
        raise ValueError("episode exceeds raw event or byte bound")
    for event in frame["events"]:
        at = datetime.fromisoformat(event["event_timestamp"].replace("Z", "+00:00"))
        if not start <= at < start + timedelta(minutes=15):
            raise ValueError("episode event outside its window")
        if event["event_type"] != "HTTP_REQUEST" and any(key in event for key in ("endpoint_category", "session_pseudonym", "session_issued_at")):
            raise ValueError("non-HTTP event cannot invent request/session metadata")
        if ("session_pseudonym" in event) != ("session_issued_at" in event):
            raise ValueError("paired session metadata required")
    logins = sorted(datetime.fromisoformat(row["attempted_at"].replace("Z", "+00:00"))
                    for row in ledger if row["attempt_kind"] == "LOGIN")
    for index in range(5, len(logins)):
        if (logins[index] - logins[index - 5]).total_seconds() < 60:
            raise ValueError("accepted login attempts violate 5/IP/minute")
    covered = [index for row in ledger for index in row["server_event_indexes"]]
    if sorted(covered) != list(range(len(frame["events"]))):
        raise ValueError("client/server event conservation failed")


def make_frame(dataset_id, account_ordinal, episode_ordinal, window_start, *, planned_cause="normal", context=False, cohort="READY"):
    """Opaque identities and seeds allocated independently of planned cause."""
    _identity_inputs(dataset_id, account_ordinal)
    _integer(episode_ordinal, 0, MAX_EPISODE_ORDINAL, "episode ordinal")
    if type(context) is not bool or context and planned_cause != "normal":
        raise ValueError("context must be an unlabelled normal baseline recipe")
    start = _start(window_start)
    account = "acct-" + _digest([dataset_id, account_ordinal])[:32]
    master_seed = BLIND_SEEDS[stable_seed("world", dataset_id, account_ordinal) % len(BLIND_SEEDS)]
    seed = stable_seed(PROTOCOL_VERSION, master_seed, dataset_id, account_ordinal, episode_ordinal, _timestamp(start), context)
    identity = "frame-" + _digest([dataset_id, account_ordinal, episode_ordinal, _timestamp(start), context])[:40]
    return build_scenario(seed, account_profile(dataset_id, account_ordinal), planned_cause, start, cohort,
                          account_id=account, frame_id=identity, context=context)


def context_frames(dataset_id, account_ordinal, window_start, *, cohort="READY"):
    """Past-only, cause-independent 48-hour history, or 3 hours for COLD."""
    start, normalized = _start(window_start), _cohort(cohort)
    count = 3 if normalized == "COLD" else 48
    if start - timedelta(hours=count) < PROTOCOL_ANCHOR:
        raise ValueError("insufficient time before target for frozen context")
    return [make_frame(dataset_id, account_ordinal, index, start - timedelta(hours=count - index),
                       planned_cause="normal", context=True, cohort=cohort) for index in range(count)]


def protocol_document():
    """A producer-source binding, not an immutable compiled-exporter attestation."""
    root = Path(__file__).resolve().parents[2]
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_FILES}
    return {"protocol_version": PROTOCOL_VERSION, "data_provenance": DATA_PROVENANCE,
            "feature_schema_version": 4, "telemetry_contract_version": 3,
            "source_sha256": hashes, "families": list(FAMILIES), "legitimate_causes": list(LEGITIMATE_CAUSES),
            "counterpart_execution_recipes": COUNTERPARTS.copy(),
            "handler_patterns": [{"http_method": method, "route_group": group, "endpoint_category": category,
                                  "handler_pattern": pattern}
                                 for (method, group, category), pattern in sorted(HANDLER_PATTERNS.items())],
            "endpoint_recipes": [{"method": method, "route_group": group, "endpoint_category": category,
                                  "handler_pattern": pattern}
                                 for (method, group, category), pattern in sorted(HANDLER_PATTERNS.items())],
            "blind_seeds": list(BLIND_SEEDS), "blind_seed_policy": "FIXED_BEFORE_DIAGNOSTICS_NO_RESULT_BASED_RESELECTION",
            "master_seed_selection": "BLIND_SEEDS[stable_seed('world', dataset_id, account_ordinal) % len(BLIND_SEEDS)]",
            "episode_seed_recipe": "stable_seed(PROTOCOL_VERSION, master_seed, dataset_id, account_ordinal, episode_ordinal, UTC_window_start, context)",
            "anchor": _timestamp(PROTOCOL_ANCHOR), "maximum_events_per_frame": MAX_EVENTS,
            "maximum_frame_bytes": MAX_FRAME_BYTES, "baseline_context_windows": {"READY": 48, "UNSEEN_READY": 48, "COLD": 3},
            "legacy_preserved": ["base_counts", "profile_browser_recipe", "family_count_ranges_where_causal",
                                 "rare_normal_retries_errors_password_changes_and_heavy_activity", "legacy_request_timing"],
            "required_deltas": ["auth_failure_attempts_have_zero_HTTP_and_no_authenticated_session",
                                "auth_failures_8_to_45_paced_in_5_attempt_61_second_blocks",
                                "rare_normal_retry_windows_are_login_only_1_to_7_failures",
                                "rate_limited_and_revoked_401_attempts_client_ledger_only",
                                "password_changes_require_PROFILE_PASSWORD_PUT_and_domain_event_then_relogin",
                                "password_HTTP_count_is_background_plus_two_requests_per_change",
                                "unsupported_EMAIL_CHANGE_and_PASSWORD_RESET_removed_from_mutation_cycle",
                                "label_dependent_IP_browser_novelty_removed_and_shared_nuisance_recipe_used",
                                "explicit_hard_legitimate_controls_can_share_exact_observed_events"],
            "hard_counterpart_scope": "SEPARATE_STRESS_IDENTIFIABILITY_AUDIT_NOT_REPRESENTATIVE_QUALITY_TARGETS",
            "operational_estimand": "persistent_http_error_burst_is_operational_anomaly_not_confirmed_attack; benign_operational_errors_are_1_to_4_transient_503s",
            "limitations": ["all_events_are_synthetic_not_authentic_captures",
                            "independent_virtual_worlds_not_a_concurrent_deployment_stream",
                            "no_credential_or_database_HTTP_execution",
                            "pre_window_sessions_are_simulated_state_not_observed_login_evidence",
                            "HTTP_timestamps_model_filter_completion_DOMAIN_mutation_precedes_its_HTTP_completion",
                            "expected_maintenance_and_unexpected_disruption_may_be_observationally_identical",
                            "small_pilot_is_not_representative_prevalence_or_accuracy_quality_proof",
                            "strict_population_recipe_and_all_quality_gates_remain_unchanged"]}
