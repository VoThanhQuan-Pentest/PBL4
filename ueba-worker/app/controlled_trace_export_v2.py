"""Private capture-v2 -> immutable Java schema4, without assigning attack labels.

Client observations are hash-bound but never promoted to server events. Missing
session data and target-associated AUTH failures remain as observed. These small
partial windows are diagnostics, not an independent accuracy/training dataset.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

from app.catalog import parse_json
from app.collision_replay import workspace_identity
from app.contract import FEATURE_NAMES_V4, feature_array
from app.policy import canonical
from app.strict_campaign import sha, write

COMMON = {"account_alias", "event_sequence", "event_timestamp", "event_type", "action", "outcome",
          "route_group", "source_ip", "user_agent_family"}
HTTP = {"http_method", "http_status", "telemetry_contract_version", "endpoint_category"}
SESSION = {"session_pseudonym", "session_issued_at"}
GROUPS = {"admin", "profile", "orders", "support", "reviews", "promo_hunt", "sync", "products", "other_api"}
AGENTS = {"EDGE", "FIREFOX", "CHROMIUM", "SAFARI", "OTHER"}
ENDPOINTS = {"PRODUCT_LIST", "PRODUCT_DETAIL", "PROFILE_READ", "PROFILE_UPDATE", "PROFILE_EMAIL_OTP",
             "PROFILE_PASSWORD", "ORDERS_READ", "ORDER_CREATE", "ORDER_CANCEL", "ORDER_RETURN", "SUPPORT_READ",
             "SUPPORT_SEND", "REVIEW_READ", "REVIEW_CREATE", "PROMO_LIST", "PROMO_CLAIM", "SYNC_READ", "SYNC_WRITE",
             "PRIVILEGED", "OTHER_MATCHED", "UNMATCHED", "UNRESOLVED"}
SCENARIOS = {("OWNED_AUTH_FAILURE_GUESSTEST", "OWNED_AUTH_FAILURE"),
             ("BENIGN_PASSWORD_CHANGE", "BENIGN"),
             ("CONTROLLED_PASSWORD_CHANGE_SEQUENCE", "UNSCORED_CONTROLLED_SEQUENCE"),
             ("OPERATIONAL_FAULT", "CONTROLLED_OPERATIONAL_ANOMALY"),
             ("OWNED_RESOURCE_PROBE", "OBSERVATIONAL_AMBIGUOUS")}
LEDGERS = {"client-http-attempts.json", "client-attempts.ndjson", "client-ledger.ndjson"}


def utc(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise ValueError("bounded UTC timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("actual UTC timestamp required")
    return parsed


def read_private(path, maximum):
    """Read one regular, mode0600 inode; refuse symlinks and bounded-size races."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        identity = os.fstat(stream.fileno())
        if not stat.S_ISREG(identity.st_mode) or stat.S_IMODE(identity.st_mode) != 0o600 or identity.st_size > maximum:
            raise ValueError("bounded private regular capture file required")
        data = stream.read(maximum + 1)
        if len(data) > maximum or len(data) != identity.st_size:
            raise ValueError("capture file size changed or exceeded bound")
        return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ledger_count(name, data, started, finished):
    if name == "client-http-attempts.json":
        envelope = parse_json(data)
        if (not isinstance(envelope, dict) or set(envelope) != {"capture_contract_version", "scope", "attempts"}
                or envelope["capture_contract_version"] != 2):
            raise ValueError("known client AUTH ledger required")
        rows = envelope["attempts"]
        fields = {"attempt_sequence", "request_timestamp", "response_timestamp", "operation", "http_status"}
        sequence, timestamp = "attempt_sequence", "request_timestamp"
    else:
        rows = [parse_json(line) for line in data.splitlines()]
        if name == "client-attempts.ndjson":
            fields = {"client_attempt_sequence", "intended_account_alias", "attempted_at", "attempt_kind",
                      "http_method", "route_group", "http_status", "provenance"}
            sequence, timestamp = "client_attempt_sequence", "attempted_at"
        else:
            fields = {"client_sequence", "account_alias", "sent_at", "request_kind", "http_method", "expected_status", "observed_status"}
            sequence, timestamp = "client_sequence", "sent_at"
    if not isinstance(rows, list) or not 1 <= len(rows) <= 300:
        raise ValueError("bounded complete client ledger required")
    for number, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != fields or type(row[sequence]) is not int or row[sequence] != number:
            raise ValueError("sanitized client ledger allowlist/sequence mismatch")
        if not started <= utc(row[timestamp]) <= finished:
            raise ValueError("client observation outside actual capture interval")
        status_fields = ("expected_status", "observed_status") if name == "client-ledger.ndjson" else ("http_status",)
        if any(type(row[key]) is not int or not 100 <= row[key] <= 599 for key in status_fields):
            raise ValueError("actual bounded client HTTP status required")
        if name == "client-http-attempts.json":
            if row["operation"] not in {"CSRF_READ", "LOGIN_POST"} or not utc(row[timestamp]) <= utc(row["response_timestamp"]) <= finished:
                raise ValueError("known bounded AUTH observation required")
        elif name == "client-attempts.ndjson":
            if (row["attempt_kind"] not in {"CSRF_READ", "CSRF_REFRESH", "LOGIN", "CURRENT_SESSION_REQUEST", "REVOKED_SESSION_ATTEMPT"}
                    or row["provenance"] != "CLIENT_OBSERVED_NOT_SERVER_ATTRIBUTION"
                    or row["route_group"] not in {"auth", "account", "profile"}):
                raise ValueError("known unassigned or current-session client observation required")
        elif row["request_kind"] not in {"CSRF_READ", "LOGIN", "NORMAL_READ", "CONTROLLED_FAULT", "AFTER_FAULT_NORMAL_READ", "RESOURCE_PROBE"}:
            raise ValueError("known controlled operational observation required")
        if name != "client-http-attempts.json":
            alias = row.get("account_alias", row.get("intended_account_alias"))
            if not isinstance(alias, str) or not re.fullmatch(r"account-[a-f0-9]{32}", alias) or row["http_method"] not in {"GET", "POST", "PUT"}:
                raise ValueError("opaque client account and bounded method required")
    return rows


def reconcile_observations(ledger_file, ledger, events, scenarios, evidence):
    """Only verified current-session/LOGIN observations match server events."""
    families = {entry["family"] for entry in scenarios.values()}
    http, logins, changes = Counter(), Counter(), Counter()
    for event in events:
        alias = event["account_alias"]
        if event["event_type"] == "HTTP_REQUEST":
            http[(alias, event["http_method"], event["http_status"])] += 1
        elif event["event_type"] == "AUTH":
            logins[(alias, event["outcome"])] += 1
        else:
            changes[alias] += 1
    if ledger_file == "client-http-attempts.json":
        statuses = Counter(row["http_status"] for row in ledger)
        if (families != {"OWNED_AUTH_FAILURE_GUESSTEST"} or len(scenarios) != 1 or len(ledger) != 7
                or ledger[0]["operation"] != "CSRF_READ" or any(row["operation"] != "LOGIN_POST" for row in ledger[1:])
                or statuses != {200: 1, 401: 5, 429: 1} or ledger[-1]["http_status"] != 429
                or any(row["http_status"] != (200 if index == 0 else 429 if index == 6 else 401) for index, row in enumerate(ledger))
                or http or changes or sum(logins.values()) != 4
                or evidence.get("captured_auth_event_count") != 6
                or evidence.get("unattributable_auth_outcome_counts") != {"FAILURE": 1, "RATE_LIMITED": 1}
                or evidence.get("unattributable_auth_event_count") != 2):
            raise ValueError("actual known-target versus unknown/throttled AUTH conservation required")
        return
    current, observed_logins, observed_changes, csrf, refreshed, revoked = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    for row in ledger:
        alias = row.get("account_alias", row.get("intended_account_alias"))
        if alias not in scenarios:
            raise ValueError("client ledger account must belong to a planned scenario")
        if ledger_file == "client-attempts.ndjson":
            if not families <= {"BENIGN_PASSWORD_CHANGE", "CONTROLLED_PASSWORD_CHANGE_SEQUENCE"}:
                raise ValueError("password ledger must match password scenarios")
            kind, method, status = row["attempt_kind"], row["http_method"], row["http_status"]
            if kind in {"CSRF_READ", "CSRF_REFRESH", "LOGIN"}:
                if row["route_group"] != "auth" or status != 200 or method != ("POST" if kind == "LOGIN" else "GET"):
                    raise ValueError("actual CSRF/login client observation required")
            elif kind == "CURRENT_SESSION_REQUEST":
                if row["route_group"] != "profile" or (method, status) not in {("GET", 200), ("PUT", 204)}:
                    raise ValueError("actual attributed current-session profile observation required")
                current[(alias, method, status)] += 1
                if method == "PUT":
                    observed_changes[alias] += 1
            elif (method, status, row["route_group"]) != ("GET", 401, "profile"):
                raise ValueError("revoked-session denial must remain client-only")
            if kind == "REVOKED_SESSION_ATTEMPT":
                revoked[alias] += 1
            elif kind == "CSRF_REFRESH":
                refreshed[alias] += 1
        else:
            if not families <= {"OPERATIONAL_FAULT", "OWNED_RESOURCE_PROBE"}:
                raise ValueError("operational ledger must match controlled scenarios")
            kind, method, status = row["request_kind"], row["http_method"], row["observed_status"]
            if row["expected_status"] != status or status != (503 if kind == "CONTROLLED_FAULT" else 200):
                raise ValueError("controlled actual client status must match frozen observation plan")
            if method != ("POST" if kind == "LOGIN" else "GET"):
                raise ValueError("controlled actual request method required")
            if kind not in {"CSRF_READ", "LOGIN"}:
                current[(alias, method, status)] += 1
            if kind == "CONTROLLED_FAULT" and scenarios[alias]["family"] != "OPERATIONAL_FAULT":
                raise ValueError("controlled service fault must not imply resource-probe attack")
            if kind == "RESOURCE_PROBE" and scenarios[alias]["family"] != "OWNED_RESOURCE_PROBE":
                raise ValueError("ambiguous resource probe must remain in its planned scenario")
        if kind == "LOGIN":
            observed_logins[(alias, "SUCCESS")] += 1
        elif kind == "CSRF_READ":
            csrf[alias] += 1
    if (current != http or observed_logins != logins or observed_changes != changes
            or csrf != Counter({alias: count for (alias, _), count in observed_logins.items()})
            or (ledger_file == "client-attempts.ndjson" and (revoked != observed_changes or refreshed != observed_changes))):
        raise ValueError("separate attributable HTTP/AUTH/DOMAIN conservation required")


def source_frames(directory):
    directory = directory.absolute()
    if directory.resolve(strict=True) != directory or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ValueError("non-symlink private capture directory required")
    evidence_bytes = read_private(directory / "capture-evidence.json", 1024 * 1024)
    scenario_bytes = read_private(directory / "scenarios.json", 1024 * 1024)
    events_bytes = read_private(directory / "trace-events.ndjson", 16 * 1024 * 1024)
    evidence, scenarios = parse_json(evidence_bytes), parse_json(scenario_bytes)
    if (not isinstance(evidence, dict) or not isinstance(scenarios, dict)
            or type(evidence.get("capture_contract_version")) is not int or evidence["capture_contract_version"] != 2
            or scenarios.get("capture_contract_version") != 2
            or evidence.get("passed") is not True or evidence.get("provenance") != "CONTROLLED_OWNED_LOCAL_HTTP"
            or scenarios.get("provenance") != "CONTROLLED_OWNED_LOCAL_HTTP"
            or evidence.get("source_event_conservation") is not True
            or evidence.get("labels_present_in_event_records") is not False
            or scenarios.get("labels_separate_from_events") is not True
            or evidence.get("timestamps_rewritten") is not False
            or evidence.get("elapsed_window_closure_proven") is not False
            or digest(events_bytes) != evidence.get("trace_events_sha256")
            or digest(scenario_bytes) != evidence.get("scenarios_sha256")):
        raise ValueError("capture-v2 immutable provenance binding mismatch")
    started, finished = utc(evidence.get("capture_started_at")), utc(evidence.get("capture_finished_at"))
    if not timedelta(0) <= finished - started <= timedelta(seconds=60):
        raise ValueError("bounded real captured interval required")
    ledger_file = evidence.get("client_ledger_file")
    if ledger_file not in LEDGERS:
        raise ValueError("known hash-bound client ledger required")
    ledger_bytes = read_private(directory / ledger_file, 1024 * 1024)
    ledger = ledger_count(ledger_file, ledger_bytes, started, finished)
    client_requests = len(ledger)
    if digest(ledger_bytes) != evidence.get("client_ledger_sha256") or client_requests != evidence.get("client_request_count"):
        raise ValueError("complete actual client attempt ledger required")
    entries = scenarios.get("scenarios")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ValueError("bounded separate planned scenarios required")
    by_account = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("separate scenario object required")
        alias = entry.get("account_alias")
        if not isinstance(alias, str) or not re.fullmatch(r"account-[a-f0-9]{32}", alias) or alias in by_account:
            raise ValueError("unique opaque account alias required")
        if (entry.get("family"), entry.get("expected_label")) not in SCENARIOS:
            raise ValueError("unreviewed cause or attack-label inference refused")
        if entry.get("family") == "OWNED_AUTH_FAILURE_GUESSTEST" and (entry.get("attribution_kind") != "TARGET_ASSOCIATED_UNAUTHENTICATED"
                or entry.get("authenticated_actor_claimed") is not False):
            raise ValueError("target-associated AUTH must not claim authenticated actor")
        if entry.get("family") != "OWNED_AUTH_FAILURE_GUESSTEST" and entry.get("attribution_kind", "OWNED_AUTHENTICATED_ACTOR") != "OWNED_AUTHENTICATED_ACTOR":
            raise ValueError("bounded verified actor attribution required")
        by_account[alias] = entry
    rows = events_bytes.splitlines()
    if not 1 <= len(rows) <= 10000 or type(evidence.get("event_count")) is not int or len(rows) != evidence["event_count"]:
        raise ValueError("complete bounded attributed server capture required")
    groups, counts, kinds, sequences, events = defaultdict(list), Counter(), Counter(), set(), []
    for line in rows:
        if len(line) > 16384:
            raise ValueError("bounded sanitized event line required")
        event = parse_json(line)
        if not isinstance(event, dict):
            raise ValueError("sanitized event object required")
        kind = event.get("event_type")
        fields = set(event)
        if kind == "HTTP_REQUEST":
            if fields not in (COMMON | HTTP, COMMON | HTTP | SESSION):
                raise ValueError("HTTP privacy allowlist or paired session mismatch")
        elif kind not in {"AUTH", "DOMAIN_ACTION"} or fields != COMMON:
            raise ValueError("server event privacy allowlist mismatch")
        alias, sequence = event["account_alias"], event["event_sequence"]
        if alias not in by_account or type(sequence) is not int or sequence < 0 or sequence in sequences:
            raise ValueError("known account and unique actual sequence required")
        sequences.add(sequence)
        at = utc(event["event_timestamp"])
        if not started <= at <= finished:
            raise ValueError("unmodified timestamp outside captured interval")
        if kind == "DOMAIN_ACTION":
            if (event["action"], event["outcome"], event["route_group"], event["source_ip"], event["user_agent_family"]) != ("PASSWORD_CHANGE", "SUCCESS", "account", None, None):
                raise ValueError("DOMAIN producer metadata must not be fabricated")
            if by_account[alias]["family"] not in {"BENIGN_PASSWORD_CHANGE", "CONTROLLED_PASSWORD_CHANGE_SEQUENCE"}:
                raise ValueError("DOMAIN event outside planned password sequence")
        else:
            if event["source_ip"] != "127.0.0.1" or event["user_agent_family"] not in AGENTS:
                raise ValueError("actual normalized owned loopback capture required")
            if kind == "AUTH":
                if event["action"] != "LOGIN" or event["route_group"] != "auth" or event["outcome"] not in {"SUCCESS", "FAILURE"}:
                    raise ValueError("known account-observable AUTH required")
                if event["outcome"] == "FAILURE" and by_account[alias]["family"] != "OWNED_AUTH_FAILURE_GUESSTEST":
                    raise ValueError("failure target attribution must be explicitly declared")
                if event["outcome"] == "SUCCESS" and by_account[alias]["family"] == "OWNED_AUTH_FAILURE_GUESSTEST":
                    raise ValueError("target-only failure capture must not invent successful actor")
            elif (event["action"] != "API_REQUEST" or event["outcome"] not in {"SUCCESS", "FAILURE"}
                  or type(event["http_status"]) is not int or not 100 <= event["http_status"] <= 599
                  or event["http_method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                  or event["route_group"] not in GROUPS or type(event["telemetry_contract_version"]) is not int
                  or event["telemetry_contract_version"] != 3 or event["endpoint_category"] not in ENDPOINTS):
                raise ValueError("known real server HTTP telemetry required")
        if kind == "HTTP_REQUEST":
            family = by_account[alias]["family"]
            if family in {"BENIGN_PASSWORD_CHANGE", "CONTROLLED_PASSWORD_CHANGE_SEQUENCE"}:
                if (event["http_method"], event["http_status"], event["endpoint_category"], event["route_group"], event["outcome"]) not in {
                        ("GET", 200, "PROFILE_READ", "profile", "SUCCESS"),
                        ("PUT", 204, "PROFILE_PASSWORD", "profile", "SUCCESS")}:
                    raise ValueError("password capture client denial must not become attributed HTTP")
            elif family in {"OPERATIONAL_FAULT", "OWNED_RESOURCE_PROBE"}:
                if (event["http_method"] != "GET" or event["http_status"] not in {200, 503}
                        or event["outcome"] != ("FAILURE" if event["http_status"] == 503 else "SUCCESS")
                        or event["endpoint_category"] in {"UNMATCHED", "UNRESOLVED"} or not SESSION <= fields):
                    raise ValueError("controlled operational capture must preserve real verified-session GET")
                if event["http_status"] == 503 and (family, event["route_group"], event["endpoint_category"]) != ("OPERATIONAL_FAULT", "other_api", "OTHER_MATCHED"):
                    raise ValueError("503 must remain the controlled resolved operational fault")
            else:
                raise ValueError("target-only AUTH capture must not invent HTTP request")
        if SESSION <= fields and (not isinstance(event["session_pseudonym"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", event["session_pseudonym"]) or utc(event["session_issued_at"]) > at):
            raise ValueError("actual paired session metadata required")
        counts[alias] += 1
        kinds[kind] += 1
        events.append(event)
        numeric = {key: value for key, value in event.items() if key not in {"account_alias", "event_sequence", "telemetry_contract_version"}}
        start = at.replace(minute=at.minute // 15 * 15, second=0, microsecond=0)
        groups[(alias, start)].append(numeric)
    if set(sequences) != set(range(len(rows))) or dict(kinds) != evidence.get("event_type_counts"):
        raise ValueError("actual complete server event type/sequence conservation required")
    if any(type(entry.get("observed_event_count")) is not int or counts[alias] != entry["observed_event_count"] for alias, entry in by_account.items()):
        raise ValueError("actual scenario population changed")
    reconcile_observations(ledger_file, ledger, events, by_account, evidence)
    frames, expected, attribution = [], {}, []
    for number, ((alias, start), events) in enumerate(sorted(groups.items())):
        frame_id = f"capture-v2-frame-{number:06d}"
        # Legacy CLI requires a label; this fixed transport placeholder is not
        # ground truth, affects no feature, and is stripped from numeric output.
        frames.append({"frame_id": frame_id, "account_id": alias, "day": 1, "cohort": "COLD", "window_start": start.isoformat().replace("+00:00", "Z"),
                       "telemetry_contract_version": 3, "demo_label": "NORMAL", "family": "normal", "events": sorted(events, key=lambda item: utc(item["event_timestamp"]))})
        expected[frame_id] = {"request_count": sum(event["event_type"] == "HTTP_REQUEST" for event in events),
                              "session_count": sum("session_pseudonym" in event for event in events),
                              "event_count": len(events), "account_id": alias, "window_start": frames[-1]["window_start"]}
        entry = by_account[alias]
        attribution.append({"frame_id": frame_id, "scenario_family": entry["family"], "scenario_label": entry["expected_label"],
                            "attribution_kind": entry.get("attribution_kind", "OWNED_AUTHENTICATED_ACTOR"),
                            "attack_quality_eligible": False})
    return frames, expected, attribution, {**evidence, "capture_evidence_sha256": digest(evidence_bytes)}


def export(directory, workspace, workspace_sha, output):
    frames, expected, attribution, source = source_frames(directory)
    classpath, package = workspace_identity(workspace, workspace_sha)
    output.mkdir(mode=0o700)
    raw = "".join(canonical(frame) + "\n" for frame in frames).encode()
    with (output / "java-export.log").open("xb") as stderr:
        (output / "java-export.log").chmod(0o600)
        actual = subprocess.run(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"],
                                input=raw, stdout=subprocess.PIPE, stderr=stderr, timeout=60, check=True)
    if len(actual.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded Java numeric output required")
    lines = actual.stdout.splitlines()
    if len(lines) != len(frames):
        raise ValueError("actual Java did not conserve captured windows")
    rows, seen = [], set()
    for line in lines:
        if len(line) > 16384:
            raise ValueError("bounded numeric line required")
        row = parse_json(line)
        frame_id = row.get("frame_id")
        if frame_id not in expected or frame_id in seen:
            raise ValueError("unknown or duplicate numeric frame")
        seen.add(frame_id)
        measurement = expected[frame_id]
        if (row.get("feature_schema_version") != 4 or row.get("telemetry_contract_version") != 3
                or row.get("feature_names") != list(FEATURE_NAMES_V4) or row.get("data_provenance") != "DEMO_ONLY"
                or row.get("account_id") != measurement["account_id"] or row.get("window_start") != measurement["window_start"]
                or row.get("label") != 0 or row.get("family") != "normal"):
            raise ValueError("schema4 immutable producer/transport contract mismatch")
        vector = feature_array([row["features"]], 1, 4)[0]
        if (vector[0] != measurement["request_count"] or vector[25] != measurement["request_count"]
                or vector[31] != measurement["session_count"]):
            raise ValueError("missing HTTP/endpoint/session coverage must not be invented")
        rows.append({key: value for key, value in row.items() if key not in {"label", "family"}})
    write(output / "numeric-unlabelled-captured-windows.private.json", rows)
    write(output / "separate-scenario-attribution.private.json", attribution)
    result = {"status": "COMPLETED", "capture_contract_version": 2, "scope": "ACTUAL_OWNED_CAPTURE_V2_TO_UNLABELLED_IMMUTABLE_JAVA_FEATURES_ONLY",
              "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE", "attack_quality_eligible": False,
              "source_events_sha256": source["trace_events_sha256"], "source_scenarios_sha256": source["scenarios_sha256"],
              "source_client_ledger_sha256": source["client_ledger_sha256"], "source_capture_evidence_sha256": source["capture_evidence_sha256"],
              "captured_attributed_server_events": source["event_count"], "actual_client_requests": source["client_request_count"],
              "event_type_counts": source["event_type_counts"], "actual_exported_partial_windows": len(rows),
              "feature_count": 37, "workspace_snapshot_sha256": workspace_sha, "bound_class_count": len(package["classes"]),
              "export_source_sha256": sha(Path(__file__)), "numeric_output_sha256": sha(output / "numeric-unlabelled-captured-windows.private.json"),
              "attribution_output_sha256": sha(output / "separate-scenario-attribution.private.json"),
              "cli_label_placeholder": "FIXED_NEUTRAL_TRANSPORT_ONLY_STRIPPED_NOT_GROUND_TRUTH",
              "client_observations_promoted_to_server_events": False, "timestamps_rewritten": False,
              "elapsed_window_closure_proven": False, "fit_or_model_score_calls": 0, "source_or_cloud_state_changed": False}
    write(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--workspace-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(canonical(export(args.capture, args.workspace, args.workspace_sha256, args.output)), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Capture-v2 export failed: " + type(failure).__name__ + "; private event/command data omitted") from None
