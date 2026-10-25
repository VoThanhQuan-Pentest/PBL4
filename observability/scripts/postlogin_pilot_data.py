"""New DEMO_ONLY before-attempt episodes from the frozen causal simulator.

The simulator's explicit server execution state supplies session association.
This never joins historical events by IP, timestamp proximity, or window.
Original planned-context labels and ambiguous legitimate counterparts remain
external. They are not confirmed compromise or labels for the future outcome.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json

from app import schema4_episodes as original

VERSION = "postlogin-pilot-data-v1"
DATASET_ID = "postlogin-pilot-20261018-v1"
FAMILIES = original.FAMILIES
NORMAL_CAUSES = original.LEGITIMATE_CAUSES
ANCHORS = {1: datetime(2026, 4, 16, tzinfo=timezone.utc),
           2: datetime(2026, 4, 23, tzinfo=timezone.utc),
           3: datetime(2026, 4, 30, tzinfo=timezone.utc)}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def moment(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def specifications(fold, split):
    """Canonical IDs/account membership/splits, shared by baseline and candidate."""
    if fold not in ANCHORS or split not in ("fit", "calibration", "validation"):
        raise ValueError("predeclared chronological pilot split required")
    anchor = ANCHORS[fold] + timedelta(days={"fit": 0, "calibration": 17, "validation": 34}[split])
    if split == "fit":
        count = 4000
    elif split == "calibration":
        count = 10_000
    else:
        count = 21_000
    for index in range(count):
        if split == "fit":
            cohort, account = "READY", index
            cause = NORMAL_CAUSES[index % len(NORMAL_CAUSES)] if index < 3000 else FAMILIES[(index - 3000) // 200]
            normal_fit = index < 2000
        elif split == "calibration":
            cohort = "READY" if index < 5000 else "COLD"
            account = index % 4000 if cohort == "READY" else 200_000 + index
            cause, normal_fit = NORMAL_CAUSES[index % len(NORMAL_CAUSES)], False
        else:
            ordinal = index if index < 20_000 else index - 20_000
            if index < 20_000:
                cohort = "READY" if ordinal < 14_000 else "UNSEEN_READY" if ordinal < 18_000 else "COLD"
            else:
                local = ordinal % 200
                cohort = "READY" if local < 140 else "UNSEEN_READY" if local < 180 else "COLD"
            account = ordinal % 4000 if cohort == "READY" else 100_000 + ordinal if cohort == "UNSEEN_READY" else 300_000 + ordinal
            cause = NORMAL_CAUSES[ordinal % len(NORMAL_CAUSES)] if index < 20_000 else FAMILIES[ordinal // 200]
            normal_fit = False
        # Repeated READY accounts get distinct account-hour episodes. No source
        # history/session/frame crosses a split: their anchors are >14 days apart.
        episode = index // 4000
        start = anchor + timedelta(hours=episode)
        yield {"fold": fold, "split": split, "index": index, "account": account, "episode": episode,
               "window_start": stamp(start), "cohort": cohort, "cause": cause,
               "current_operation": "PASSWORD_CHANGE" if index % 2 == 0 else "EMAIL_CHANGE", "normal_fit": normal_fit}


def build(specification):
    spec = specification
    start = moment(spec["window_start"])
    episode = original.make_frame(DATASET_ID, spec["account"], spec["episode"], start,
                                  planned_cause=spec["cause"], cohort=spec["cohort"])
    plan = episode["scenario"]["plan"]
    account = episode["frame"]["account_id"]
    seed, serial, original_serial = plan["execution_seed"], 0, 0
    issued = start - timedelta(seconds=plan["initial_session_age_seconds"])
    session = digest([VERSION, "session", seed, serial])
    original_session = original._digest(["session", seed, original_serial])
    active = plan["execution_recipe"] != "auth_failure_burst"
    original_active = active
    skip_next_relogin = False
    mutation_index = 0
    context = []
    for index, raw in enumerate(episode["frame"]["events"]):
        at = moment(raw["event_timestamp"])
        event = {key: copy.deepcopy(value) for key, value in raw.items()
                 if key not in ("request_path", "user_agent")}
        event["event_id"] = "event-" + digest([episode["frame"]["frame_id"], index])[:40]
        event["actor_user_id"] = None if raw["event_type"] == "AUTH" and raw["outcome"] != "SUCCESS" else account
        event["target_user_id"] = None if raw["event_type"] == "HTTP_REQUEST" else account
        if raw["event_type"] == "AUTH":
            event["route_group"] = "auth"
            if raw["outcome"] == "SUCCESS":
                original_serial += 1; original_session = original._digest(["session", seed, original_serial]); original_active = True
                if skip_next_relogin:
                    skip_next_relogin = False
                    continue # An email update retains its session; no invented revocation/login.
                serial += 1; session = digest([VERSION, "session", seed, serial]); issued = at; active = True
                event.update(telemetry_contract_version=4, session_pseudonym=session, session_issued_at=stamp(issued))
        elif raw["event_type"] == "HTTP_REQUEST":
            event["telemetry_contract_version"] = 3
            if not active or not original_active:
                raise ValueError("frozen source attributed a request to a revoked session")
            observed = raw.get("session_pseudonym")
            parallel = original._digest(["session", seed, "parallel"])
            if observed not in (None, original_session, parallel):
                raise ValueError("frozen simulator/server session state diverged")
            if observed is not None:
                event.update(session_pseudonym=digest([VERSION, "parallel", seed]) if observed == parallel else session,
                             session_issued_at=raw["session_issued_at"] if observed == parallel else stamp(issued))
            if raw.get("http_method") == "PUT" and raw.get("endpoint_category") == "PROFILE_PASSWORD":
                if original.stable_seed("mutation-kind", seed, mutation_index) % 2:
                    event["endpoint_category"] = "PROFILE_UPDATE"
        elif raw["event_type"] == "DOMAIN_ACTION":
            if not active or raw["action"] != "PASSWORD_CHANGE":
                raise ValueError("unsupported causal domain action")
            attempt_at = at - timedelta(microseconds=100)
            if attempt_at < issued: raise ValueError("attempt precedes verified issuance")
            operation = "EMAIL_CHANGE" if original.stable_seed("mutation-kind", seed, mutation_index) % 2 else "PASSWORD_CHANGE"
            mutation_index += 1
            prior_attempt = {"event_id": event["event_id"] + "-attempt", "event_type": "SENSITIVE_ACTION_ATTEMPT",
                "action": operation, "outcome": "ATTEMPT", "event_timestamp": stamp(attempt_at),
                "actor_user_id": account, "target_user_id": account, "route_group": "account",
                "telemetry_contract_version": 4, "session_pseudonym": session, "session_issued_at": stamp(issued)}
            context.append(prior_attempt)
            event.update(action=operation, telemetry_contract_version=4, session_pseudonym=session, session_issued_at=stamp(issued))
            original_active = False
            active = operation == "EMAIL_CHANGE"
            skip_next_relogin = active
        context.append(event)
    latest = max(moment(event["event_timestamp"]) for event in context)
    if not active:
        serial += 1; session = digest([VERSION, "session", seed, serial])
        # Five known-account/IP failures fill the existing 60-second bucket.
        # A new accepted login must wait for it rather than bypass rate limiting.
        issued = latest + timedelta(seconds=61 if plan["execution_recipe"] == "auth_failure_burst" else 8)
        context.append({"event_id": "event-" + digest([episode["frame"]["frame_id"], "fresh-login"])[:40],
            "event_type": "AUTH", "action": "LOGIN", "outcome": "SUCCESS", "event_timestamp": stamp(issued),
            "actor_user_id": account, "target_user_id": account, "route_group": "auth",
            "telemetry_contract_version": 4, "session_pseudonym": session, "session_issued_at": stamp(issued)})
        latest = issued
    # The same delay/operation rule applies to normal and every planned family.
    as_of = latest + timedelta(seconds=1 + original.stable_seed("target-delay", seed) % 20)
    if original.stable_seed("cross-window-target", seed) % 4 == 0:
        boundary = latest.replace(minute=(latest.minute // 15) * 15, second=0, microsecond=0) + timedelta(minutes=15)
        as_of = boundary + timedelta(seconds=1 + original.stable_seed("target-delay", seed) % 20)
    if as_of - issued >= timedelta(days=1): raise ValueError("expired simulated session cannot author an attempt")
    target = {"event_id": "event-" + digest([episode["frame"]["frame_id"], "target"])[:40],
        "event_type": "SENSITIVE_ACTION_ATTEMPT", "action": spec["current_operation"], "outcome": "ATTEMPT",
        "event_timestamp": stamp(as_of), "actor_user_id": account, "target_user_id": account, "route_group": "account",
        "telemetry_contract_version": 4, "session_pseudonym": session, "session_issued_at": stamp(issued)}
    current_start = as_of.replace(minute=(as_of.minute // 15) * 15, second=0, microsecond=0)
    histories = original.context_frames(DATASET_ID, spec["account"], current_start, cohort=spec["cohort"])
    baseline = [{**item["frame"], "demo_label": "NORMAL", "family": "normal"} for item in histories]
    frame_id = "episode-" + digest([VERSION, spec["fold"], spec["split"], spec["index"], account, stamp(as_of)])[:40]
    label = episode["scenario"]["label"]
    family = episode["scenario"]["family"]
    nature = 0 if not label else 2 if family == "http_error_burst" else 1
    metadata = {"frame_id": frame_id, "account_id": account, "as_of": stamp(as_of), "window_start": stamp(current_start),
                "cohort": spec["cohort"], "label": label, "training_context": nature, "family": family,
                "normal_fit": spec["normal_fit"], "current_operation": spec["current_operation"],
                "planned_cause": spec["cause"], "plan_sha256": episode["scenario"]["plan_sha256"]}
    return {"frame_id": frame_id, "attempt": target, "context": context, "baseline_frames": baseline}, metadata


def protocol():
    return {"version": VERSION, "dataset_id": DATASET_ID, "data_provenance": "DEMO_ONLY",
            "model_kind": "normal_plus_incident_research", "representation": "postlogin-before-action-v1",
            "baseline_width": 37, "candidate_width": 57, "folds": [1, 2, 3], "seed": 42,
            "normal_fit": 2000, "labeled_fit": {"NORMAL": 3000, "SECURITY_BEHAVIOR_CONTEXT": 800, "OPERATIONAL_FAILURE_CONTEXT": 200},
            "normal_fit_shared_with_labeled": 2000, "calibration": {"READY": 5000, "COLD": 5000},
            "validation": {"normal": 20000, "positive": 1000, "positive_each_family": 200},
            "families": list(FAMILIES), "normal_causes": list(NORMAL_CAUSES),
            "fit_anchors": {str(fold): stamp(anchor) for fold, anchor in ANCHORS.items()},
            "calibration_offset_days": 17, "validation_offset_days": 34,
            "label_meaning": "Frozen planned behavior/incident context, not maliciousness or the future target outcome.",
            "current_target_outcome": "UNOBSERVED_NOT_USED", "session_association": "EXPLICIT_SIMULATED_SERVER_EXECUTION_STATE",
            "cross_window_target_assignment": "cause-independent stable seed; one quarter of worlds",
            "mutation_recipe": "Cause-independent PASSWORD_CHANGE/EMAIL_CHANGE; password revokes, email retains session; no target outcome used.",
            "ambiguity": "Original ambiguous legitimate/planned-context counterparts are retained; hidden intent is never a feature.",
            "adoption": "PILOT_ONLY_UNQUALIFIED_NO_HOLDOUT_NO_ENFORCEMENT"}
