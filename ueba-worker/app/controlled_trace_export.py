"""Private owned HTTP capture -> actual immutable Java schema4 vectors.

Partial captured windows remain partial; no timestamp rewriting, fitting,
simulated independence, quality PASS or real elapsed-closure claim is made.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import subprocess

from app.catalog import parse_json
from app.collision_replay import workspace_identity
from app.contract import FEATURE_NAMES_V4, feature_array
from app.policy import canonical
from app.strict_campaign import sha, write

COMMON = {"account_alias", "event_sequence", "event_timestamp", "event_type", "action", "outcome",
          "route_group", "source_ip", "user_agent_family"}
HTTP = {"http_method", "http_status", "telemetry_contract_version", "endpoint_category", "session_pseudonym", "session_issued_at"}


def utc(text):
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.utcoffset() != timedelta(0): raise ValueError("actual captured UTC timestamp required")
    return value


def bounded_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("bounded regular capture metadata required")
    return parse_json(path.read_bytes())


def source_frames(directory):
    evidence = bounded_json(directory / "capture-evidence.json"); scenarios = bounded_json(directory / "scenarios.json")
    path = directory / "trace-events.ndjson"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("bounded private trace source required")
    source = path.read_bytes()
    if (evidence.get("passed") is not True or evidence.get("provenance") != "CONTROLLED_OWNED_LOCAL_HTTP"
            or evidence.get("source_event_conservation") is not True or evidence.get("labels_present_in_event_records") is not False
            or hashlib.sha256(source).hexdigest() != evidence.get("trace_events_sha256")
            or sha(directory / "scenarios.json") != evidence.get("scenarios_sha256")):
        raise ValueError("actual controlled capture binding mismatch")
    entries = scenarios.get("scenarios")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32: raise ValueError("bounded separate scenarios required")
    by_account = {}
    for entry in entries:
        alias = entry.get("account_alias")
        if not isinstance(alias, str) or not re.fullmatch(r"[a-z0-9_-]{8,64}", alias) or alias in by_account:
            raise ValueError("unique captured opaque account aliases required")
        label = entry.get("expected_label")
        if label not in ("BENIGN", "OWNED_ENDPOINT_SCAN"): raise ValueError("unreviewed capture scenario")
        by_account[alias] = entry
    groups = defaultdict(list); counts = Counter(); sequences = set(); http_count = 0
    rows = source.splitlines()
    if not 1 <= len(rows) <= 10000 or len(rows) != evidence.get("event_count"): raise ValueError("complete bounded capture required")
    for line in rows:
        if len(line) > 16384: raise ValueError("bounded sanitized event line required")
        event = parse_json(line); kind = event.get("event_type")
        if kind not in ("HTTP_REQUEST", "AUTH") or set(event) != (COMMON | HTTP if kind == "HTTP_REQUEST" else COMMON):
            raise ValueError("trace privacy allowlist or event type mismatch")
        alias = event["account_alias"]
        if alias not in by_account or event["source_ip"] != "127.0.0.1": raise ValueError("owned loopback capture only")
        sequence = event["event_sequence"]
        if type(sequence) is not int or sequence < 0 or sequence in sequences: raise ValueError("unique actual capture sequence required")
        sequences.add(sequence); counts[alias] += 1
        at = utc(event["event_timestamp"])
        if not utc(evidence["capture_started_at"]) <= at <= utc(evidence["capture_finished_at"]):
            raise ValueError("event is outside the actual captured interval")
        start = at.replace(minute=at.minute // 15 * 15, second=0, microsecond=0)
        numeric_event = {key: value for key, value in event.items() if key not in ("account_alias", "event_sequence")}
        if kind == "HTTP_REQUEST":
            http_count += 1
            if event["telemetry_contract_version"] != 3 or not re.fullmatch(r"[a-f0-9]{64}", event["session_pseudonym"]):
                raise ValueError("actual sanitized HTTP metadata required")
            if utc(event["session_issued_at"]) > at: raise ValueError("future session issuance")
            # The Java envelope pins contract3 once per frame. Preserve every
            # measured signal, remove only the redundant per-event version tag.
            numeric_event.pop("telemetry_contract_version")
        groups[(alias, start)].append(numeric_event)
    if http_count != evidence.get("http_request_count") or len(rows) - http_count != evidence.get("successful_login_count"):
        raise ValueError("captured event-type totals changed")
    if any(counts[alias] != entry.get("observed_event_count") for alias, entry in by_account.items()):
        raise ValueError("captured scenario population changed")
    frames = []; expected = {}
    for number, ((alias, start), events) in enumerate(sorted(groups.items())):
        scenario = by_account[alias]; benign = scenario["expected_label"] == "BENIGN"
        frame_id = f"controlled-capture-frame-{number:06d}"
        frames.append({"frame_id": frame_id, "account_id": alias, "day": 1, "cohort": "COLD",
                       "window_start": start.isoformat().replace("+00:00", "Z"), "telemetry_contract_version": 3,
                       "demo_label": "NORMAL" if benign else "ABNORMAL", "family": "normal" if benign else "endpoint_scan",
                       "events": sorted(events, key=lambda item: utc(item["event_timestamp"]))})
        expected[frame_id] = sum(event["event_type"] == "HTTP_REQUEST" for event in events)
    return frames, expected, evidence


def export(directory, workspace, workspace_sha, output):
    frames, expected, source = source_frames(directory); classpath, package = workspace_identity(workspace, workspace_sha)
    output.mkdir(mode=0o700)
    raw = "".join(canonical(frame) + "\n" for frame in frames).encode()
    with (output / "java-export.log").open("xb") as stderr:
        (output / "java-export.log").chmod(0o600)
        completed = subprocess.run(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport",
                                    "--demo-only", "--schema4"], input=raw, stdout=subprocess.PIPE, stderr=stderr, timeout=60, check=True)
    lines = completed.stdout.splitlines()
    if len(lines) != len(frames): raise ValueError("actual Java did not conserve captured windows")
    result = []; seen = set()
    for line in lines:
        if len(line) > 16384: raise ValueError("bounded numeric output required")
        row = parse_json(line); frame_id = row["frame_id"]
        if frame_id not in expected or frame_id in seen: raise ValueError("unknown or duplicate numeric window")
        seen.add(frame_id)
        if row.get("feature_schema_version") != 4 or row.get("feature_names") != list(FEATURE_NAMES_V4) or row.get("data_provenance") != "DEMO_ONLY":
            raise ValueError("schema4 feature/provenance contract mismatch")
        vector = feature_array([row["features"]], 1, 4)[0]
        if vector[0] != expected[frame_id] or vector[25] != vector[0] or vector[31] != vector[0]:
            raise ValueError("actual HTTP/session/endpoint coverage was lost")
        result.append(row)
    write(output / "numeric-captured-windows.private.json", result)
    evidence = {"status": "COMPLETED", "scope": "ACTUAL_OWNED_CAPTURE_TO_IMMUTABLE_JAVA_NUMERIC_FEATURES_ONLY",
                "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE",
                "source_events_sha256": source["trace_events_sha256"], "source_scenarios_sha256": source["scenarios_sha256"],
                "captured_events": source["event_count"], "captured_http_events": source["http_request_count"],
                "actual_exported_partial_windows": len(result), "feature_count": 37, "workspace_snapshot_sha256": workspace_sha,
                "bound_class_count": len(package["classes"]), "export_source_sha256": sha(Path(__file__)),
                "timestamps_rewritten": False, "elapsed_window_closure_proven": False,
                "fit_or_model_score_calls": 0, "source_or_cloud_state_changed": False}
    write(output / "result.json", evidence); return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True); parser.add_argument("--workspace-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    print(canonical(export(args.capture, args.workspace, args.workspace_sha256, args.output)), flush=True)


if __name__ == "__main__":
    try: main()
    except Exception as failure:
        raise SystemExit("Controlled trace export failed: " + type(failure).__name__ + "; private event/command data omitted") from None
