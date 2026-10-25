#!/usr/bin/env python3
"""P1 only: <=12 controlled pairs through the pinned real schema-4 producer.

No model loading, fitting, scoring, dataset scanning, network, or holdout access.
Fixture semantics stay in a separate ledger; exporter labels never enter features.
"""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish

START = datetime(2026, 8, 1, tzinfo=timezone.utc)
RESERVE = 5_000_000_000
MAXIMUM_INPUT = 4 * 1024 * 1024
VERSION = "postlogin-representation-audit-v1"


def stamp(seconds=0):
    return (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def auth(at=1):
    return {"event_timestamp": stamp(at), "event_type": "AUTH", "action": "LOGIN",
            "outcome": "SUCCESS", "route_group": "auth", "source_ip": "198.51.100.1",
            "user_agent_family": "CHROMIUM"}


def action(name="PASSWORD_CHANGE", at=20):
    return {"event_timestamp": stamp(at), "event_type": "DOMAIN_ACTION", "action": name,
            "outcome": "SUCCESS", "route_group": "account"}


def request(at=10, category="PROFILE_READ", *, session="a", issued=0, status=200):
    return {"event_timestamp": stamp(at), "event_type": "HTTP_REQUEST", "action": "API_REQUEST",
            "outcome": "SUCCESS" if status < 400 else "FAILURE", "route_group": "profile",
            "http_method": "GET" if category == "PROFILE_READ" else "PUT", "http_status": status,
            "source_ip": "198.51.100.1", "user_agent_family": "CHROMIUM",
            "endpoint_category": category, "session_pseudonym": session * 64,
            "session_issued_at": stamp(issued)}


def case(events, *, prior=None, label=False, semantics=None):
    return {"events": events, "prior": prior or [], "label": label, "semantics": semantics or {}}


def pairs():
    """Fixed use cases, never selected using validation or holdout outcomes."""
    values = []
    for name in ("PASSWORD_CHANGE", "EMAIL_CHANGE"):
        values.append((name.lower() + "_login_order", "required_order",
                       case([auth(1), request(), action(name, 20)]),
                       case([action(name, 1), request(), auth(20)])))
    values.append(("password_reset_is_not_postlogin", "required_action_context",
                   case([auth(), request(), action()]),
                   case([auth(), request(), action("PASSWORD_RESET")])))
    values.append(("email_and_password_action_identity", "required_action_identity",
                   case([auth(), request(), action()]),
                   case([auth(), request(), action("EMAIL_CHANGE")])))
    observed = [auth(), request(10), request(12, session="b"), action()]
    values.append(("parallel_sessions_action_association", "missing_server_association",
                   case(copy.deepcopy(observed), semantics={"action_session": "a", "observable": False}),
                   case(copy.deepcopy(observed), semantics={"action_session": "b", "observable": False})))
    values.append(("http_workflow_order_positive_control", "existing_coverage",
                   case([auth(), request(10), request(20, "PROFILE_PASSWORD"), action(at=19)]),
                   case([auth(), request(20), request(10, "PROFILE_PASSWORD"), action(at=19)])))
    values.append(("boundary_session_age", "existing_coverage",
                   case([request(901, "PROFILE_PASSWORD", issued=899), action(at=900.5)], prior=[auth(899)]),
                   case([request(901, "PROFILE_PASSWORD", issued=1), action(at=900.5)], prior=[auth(1)])))
    values.append(("boundary_domain_action_order", "required_order",
                   case([request(902), action(at=905), action("EMAIL_CHANGE", 920)], prior=[auth(899)]),
                   case([request(902), action("EMAIL_CHANGE", 905), action(at=920)], prior=[auth(899)])))
    values.append(("legitimate_new_device_vs_existing_session", "legitimate_control",
                   case([auth(), request(10), action()], semantics={"legitimate": True, "new_device": True}),
                   case([auth(), request(10, issued=-3600), action()], semantics={"legitimate": True})))
    values.append(("sparse_history_is_not_attack", "legitimate_control",
                   case([auth(), request(), action()], semantics={"legitimate": True, "history": "absent"}),
                   case([auth(), request(), action()], prior=[request(-890, issued=-900)],
                        semantics={"legitimate": True, "history": "one_past_window"})))
    values.append(("operational_failure_control", "operational_control",
                   case([auth(), request(10, "PROFILE_PASSWORD"), action()]),
                   case([auth(), request(10, "PROFILE_PASSWORD", status=503)],
                        semantics={"incident_nature": "OPERATIONAL_FAILURE_CONTEXT"})))
    values.append(("identical_observations_hidden_intent", "information_limit",
                   case([auth(), request(), action()], semantics={"legitimate": True}),
                   case([auth(), request(), action()], label=True,
                        semantics={"simulated_hidden_intent": "different_but_unobservable"})))
    return values


def frame(pair_id, side, value):
    evaluated_at = 900 if any(datetime.fromisoformat(e["event_timestamp"].replace("Z", "+00:00")) >= START + timedelta(seconds=900)
                              for e in value["events"]) else 0
    account = f"postlogin-{pair_id}-{side}"
    base = {"account_id": account, "day": 1, "cohort": "COLD", "telemetry_contract_version": 3,
            "demo_label": "ABNORMAL" if value["label"] else "NORMAL",
            "family": "sensitive_action_burst" if value["label"] else "normal"}
    frames = []
    if value["prior"]:
        prior_at = 0 if evaluated_at else -900
        frames.append({**base, "frame_id": account + "-prior", "window_start": stamp(prior_at),
                       "demo_label": "NORMAL", "family": "normal", "events": value["prior"]})
    frames.append({**base, "frame_id": account + "-evaluated", "window_start": stamp(evaluated_at), "events": value["events"]})
    return frames


def pinned_workspace(workspace, expected):
    workspace = Path(workspace).absolute()
    if workspace.is_symlink() or digest(workspace / "snapshot.json") != expected:
        raise ValueError("trusted JVM snapshot required")
    document = json.loads((workspace / "snapshot.json").read_text())
    roots = {"classes": workspace / "backend/target/classes/com/flarefitness/backend", "jars": workspace / "jars"}
    jars = []
    for kind, pins in document.items():
        if kind not in roots:
            raise ValueError("unexpected JVM inventory")
        for name, expected_sha in pins.items():
            relative = Path(name)
            path = roots[kind] / relative
            if relative.is_absolute() or ".." in relative.parts or path.is_symlink() or digest(path) != expected_sha:
                raise ValueError("declared JVM bytes changed")
            if kind == "jars":
                jars.append(str(path))
    if "ops/UebaFeatureExport.class" not in document["classes"]:
        raise ValueError("real feature exporter required")
    return str(workspace / "backend/target/classes") + ":" + ":".join(sorted(jars)), document


def run(repo, workspace, workspace_sha, output):
    started = time.monotonic()
    output = private_directory(output)
    if (output / "p1.commit.private.json").exists():
        marker = json.loads((output / "p1.commit.private.json").read_text())
        if marker["receipt_sha256"] != digest(output / marker["receipt"]):
            raise ValueError("committed P1 receipt changed")
        return json.loads((output / marker["receipt"]).read_text())
    if shutil.disk_usage(output).free < RESERVE + MAXIMUM_INPUT:
        raise ValueError("disk reserve required")
    classpath, package = pinned_workspace(workspace, workspace_sha)
    specifications = pairs()
    if not 1 <= len(specifications) <= 12:
        raise ValueError("P1 pair cap exceeded")
    protocol = {"version": VERSION, "scope": "P1_REPRESENTATION_ONLY", "pairs": [
        {"id": name, "kind": kind, "semantics": [left["semantics"], right["semantics"]]}
        for name, kind, left, right in specifications], "maximum_pairs": 12,
        "fit_calls": 0, "model_score_calls": 0, "holdout_access": False,
        "enforcement_semantics": "REJECT_SENSITIVE_ACTION_BEFORE_SIDE_EFFECT_OR_COMMIT",
        "maximum_java_seconds": 30, "java_heap_mib": 256, "maximum_input_bytes": MAXIMUM_INPUT,
        "reserve_bytes": RESERVE, "runner_sha256": digest(__file__), "workspace_snapshot_sha256": workspace_sha}
    protocol_path = output / "p1.protocol.private.json"
    if protocol_path.exists() and json.loads(protocol_path.read_text()) != protocol:
        raise ValueError("P1 protocol changed; new experiment required")
    publish(protocol_path, protocol, maximum=32 * 1024)
    frames = [f for name, _, left, right in specifications for side, value in (("left", left), ("right", right))
              for f in frame(name, side, value)]
    payload = "".join(canonical(f) + "\n" for f in frames).encode()
    if len(payload) > MAXIMUM_INPUT:
        raise ValueError("P1 input byte cap exceeded")
    publish(output / "p1.fixtures.private.json", {"frames": frames}, maximum=MAXIMUM_INPUT)
    process = subprocess.run(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport",
                              "--demo-only", "--schema4"], input=payload, capture_output=True, timeout=30)
    if process.returncode:
        raise RuntimeError("pinned Java exporter refused fixtures: " + process.stderr.decode(errors="replace")[-512:])
    if len(process.stdout) > MAXIMUM_INPUT:
        raise ValueError("P1 output cap exceeded")
    rows = [json.loads(line) for line in process.stdout.splitlines()]
    if len(rows) != len(frames) or len({r["frame_id"] for r in rows}) != len(rows):
        raise ValueError("Java must conserve unique fixture frames")
    by_id = {row["frame_id"]: row for row in rows}
    comparisons = []
    for name, kind, _, _ in specifications:
        left, right = (by_id[f"postlogin-{name}-{side}-evaluated"] for side in ("left", "right"))
        if any(row.get("feature_schema_version") != 4 or len(row["features"]) != 37 or row.get("data_provenance") != "DEMO_ONLY"
               for row in (left, right)):
            raise ValueError("actual schema4 producer required")
        changed = [feature for feature, a, b in zip(left["feature_names"], left["features"], right["features"]) if a != b]
        comparisons.append({"id": name, "kind": kind, "equal_features": not changed, "changed_features": changed,
                            "trusted_windows": [left["trusted_window_count"], right["trusted_window_count"]]})
    publish(output / "p1.numeric.private.json", {"rows": rows}, maximum=MAXIMUM_INPUT)
    source_names = ["service/siem/SecurityEventService.java", "service/siem/SessionEndpointBehaviorFeatures.java",
                    "config/RequestCorrelationFilter.java", "service/AuthService.java", "service/ProfileService.java",
                    "ops/UebaFeatureExport.java"]
    sources = {name: digest(repo / "backend/src/main/java/com/flarefitness/backend" / name) for name in source_names}
    receipt = {"version": VERSION, "status": "FIX_REPRESENTATION", "phase": "P1", "data_provenance": "DEMO_ONLY",
               "protocol_sha256": digest(protocol_path), "fixture_sha256": digest(output / "p1.fixtures.private.json"),
               "numeric_sha256": digest(output / "p1.numeric.private.json"), "workspace_snapshot_sha256": workspace_sha,
               "feature_producer_sha256": package["classes"]["ops/UebaFeatureExport.class"], "current_source_sha256": sources,
               "pair_count": len(specifications), "frame_count": len(rows), "comparisons": comparisons,
               "additional_fit_calls": 0, "model_score_calls": 0, "holdout_scored": False, "aws_changed": False,
               "auto_containment": False, "enforcement_changed": False,
               "information_limit": "Identical server observations cannot reveal hidden intent or an unrecorded session association.",
               "static_source_findings": ["AUTH LOGIN and DOMAIN_ACTION do not persist verified session metadata.",
                   "traceId may reuse a client-supplied X-Request-ID and is insufficient as a unique trusted join key.",
                   "schema4 counts PASSWORD_RESET together with authenticated sensitive actions.",
                   "schema4 session workflows use HTTP_REQUEST only within one window."],
               "elapsed_seconds": round(time.monotonic() - started, 3),
               "peak_rss_kib_self": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               "peak_rss_kib_child": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
               "free_bytes_after": shutil.disk_usage(output).free}
    proof = commit(output, receipt, phase="p1")
    publish(output / "operator-state.private.json", {"version": 1, "phase": "P1", "status": receipt["status"],
            "last_verified_commit": proof, "active_handle": None, "composite_fits": 0, "component_fits": 0,
            "next_action": "P2 bounded R2 diagnosis; then versioned telemetry/representation repair before P3",
            "enforcement_semantics": protocol["enforcement_semantics"], "holdout_scored": False,
            "auto_containment": False, "aws_changed": False})
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--workspace-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run(args.repo.absolute(), args.workspace, args.workspace_sha256, args.output)
    print(canonical({key: receipt[key] for key in ("status", "pair_count", "frame_count", "additional_fit_calls", "elapsed_seconds")}))


if __name__ == "__main__":
    main()
