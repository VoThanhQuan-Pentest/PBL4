#!/usr/bin/env python3
"""P1 repair parity: <=12 pairs, real versioned Java overlay, no model/fit/holdout."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish

START = datetime(2026, 8, 1, tzinfo=timezone.utc)


def stamp(seconds):
    return (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def event(kind, action, at, *, session="a", issued=0, status=None):
    value = {"actor_user_id": "owned-account", "target_user_id": "owned-account", "event_type": kind,
             "action": action, "outcome": "ATTEMPT" if kind == "SENSITIVE_ACTION_ATTEMPT" else "SUCCESS",
             "event_timestamp": stamp(at), "telemetry_contract_version": 3 if kind == "HTTP_REQUEST" else 4}
    if session:
        value.update(session_pseudonym=session * 64, session_issued_at=stamp(issued))
    if kind == "HTTP_REQUEST":
        value.update(http_status=200 if status is None else status, http_method="GET", route_group="profile", endpoint_category="PROFILE_READ")
        if value["http_status"] >= 400: value["outcome"] = "FAILURE"
    return value


def scenario(*, action="PASSWORD_CHANGE", at=20, session="a", issued=0, context=None):
    return {"attempt": event("SENSITIVE_ACTION_ATTEMPT", action, at, session=session, issued=issued),
            "context": context if context is not None else [event("AUTH", "LOGIN", 1), event("HTTP_REQUEST", "API_REQUEST", 10)],
            "baseline_frames": []}


def fixtures():
    pairs = []
    for name in ("PASSWORD_CHANGE", "EMAIL_CHANGE"):
        left = scenario(action=name); right = copy.deepcopy(left); right["context"][0]["session_pseudonym"] = "b" * 64
        pairs.append((name.lower() + "_login_session", "POSTLOGIN_DIFFERENCE", left, right))
    pairs.append(("current_operation", "POSTLOGIN_DIFFERENCE", scenario(), scenario(action="EMAIL_CHANGE")))
    left = scenario(at=901, issued=899, context=[event("AUTH", "LOGIN", 899, issued=899)])
    right = copy.deepcopy(left); right["context"][0]["session_pseudonym"] = "b" * 64
    pairs.append(("window_boundary_association", "POSTLOGIN_DIFFERENCE", left, right))
    left = scenario(context=[event("AUTH", "LOGIN", 1), event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 5)])
    right = copy.deepcopy(left); right["context"][1]["action"] = "EMAIL_CHANGE"
    pairs.append(("previous_attempt_operation", "POSTLOGIN_DIFFERENCE", left, right))
    left = scenario(session="b", context=[event("AUTH", "LOGIN", 1, session="b")])
    reset = event("DOMAIN_ACTION", "PASSWORD_RESET", -10, session=None); reset["actor_user_id"] = None
    left["context"].append(reset)
    right = scenario(session="b", context=[event("AUTH", "LOGIN", 1, session="b"),
                                            event("DOMAIN_ACTION", "PASSWORD_CHANGE", -10, issued=-20)])
    pairs.append(("reset_is_separate_account_context", "POSTLOGIN_DIFFERENCE", left, right))
    context = [event("AUTH", "LOGIN", 1), event("HTTP_REQUEST", "API_REQUEST", 2), event("AUTH", "LOGIN", 3, session="b")]
    pairs.append(("two_legitimate_parallel_sessions", "POSTLOGIN_DIFFERENCE", scenario(context=context), scenario(session="b", context=context)))
    pairs.append(("legitimate_new_device", "POSTLOGIN_DIFFERENCE", scenario(),
                  scenario(issued=-3600, context=[event("AUTH", "LOGIN", -3599, issued=-3600),
                                                event("HTTP_REQUEST", "API_REQUEST", 10, issued=-3600)])))
    left, right = scenario(), scenario()
    right["baseline_frames"] = [{"frame_id": "owned-past-context", "account_id": "owned-account", "day": 1, "cohort": "COLD",
        "window_start": stamp(-900), "demo_label": "NORMAL", "family": "normal", "telemetry_contract_version": 3,
        "events": [{"event_timestamp": stamp(-890), "event_type": "HTTP_REQUEST", "action": "API_REQUEST", "outcome": "SUCCESS",
                    "route_group": "profile", "http_status": 200, "http_method": "GET", "endpoint_category": "PROFILE_READ",
                    "session_pseudonym": "c" * 64, "session_issued_at": stamp(-900)}]}]
    pairs.append(("sparse_history_control", "BASELINE_DIFFERENCE", left, right))
    left, right = scenario(), scenario(); right["context"][1] = event("HTTP_REQUEST", "API_REQUEST", 10, status=503)
    pairs.append(("operational_failure_control", "POSTLOGIN_DIFFERENCE", left, right))
    left, right = scenario(), scenario()
    for value in [right["attempt"], *right["context"]]:
        value["actor_user_id"] = "renamed-account"; value["target_user_id"] = "renamed-account"; value["session_pseudonym"] = "c" * 64
    future = event("DOMAIN_ACTION", "PASSWORD_CHANGE", 21, session="c"); future["actor_user_id"] = "renamed-account"
    right["context"].append(future)
    pairs.append(("identifier_and_future_outcome_invariance", "INVARIANT", left, right))
    pairs.append(("identical_observations_hidden_intent", "INFORMATION_LIMIT", scenario(), scenario()))
    return pairs


def run(output):
    started = time.monotonic(); output = private_directory(output)
    overlay = output / "java-overlay"; identity_path = overlay / "identity.private.json"
    identity = json.loads(identity_path.read_text())
    for relative, expected in identity["overlay_classes_sha256"].items():
        if digest(overlay / "classes" / relative) != expected: raise ValueError("research Java overlay changed")
    source = Path(__file__).with_name("audit-ueba-postlogin-representation.py")
    spec = importlib.util.spec_from_file_location("p1_workspace", source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    base_classpath, _ = module.pinned_workspace(identity["base_workspace"], identity["base_workspace_snapshot_sha256"])
    specifications = fixtures()
    if len(specifications) > 12: raise ValueError("P1 pair cap exceeded")
    protocol = {"version": "postlogin-before-action-parity-v1", "pairs": [{"id": name, "expectation": kind} for name, kind, _, _ in specifications],
        "maximum_pairs": 12, "runner_sha256": digest(__file__), "workspace_checker_sha256": digest(source),
        "overlay_identity_sha256": digest(identity_path), "maximum_java_seconds": 30, "fit_calls": 0,
        "model_score_calls": 0, "holdout_access": False, "data_provenance": "DEMO_ONLY",
        "label_meaning": "Use-case expectations only; new devices/sparse history/actions are not attack labels.",
        "information_limit": "The final pair differs only in external hidden intent; no numeric separation is expected."}
    protocol_path = output / "p1-precommit.protocol.private.json"
    if protocol_path.exists() and json.loads(protocol_path.read_text()) != protocol: raise ValueError("new protocol requires new experiment")
    publish(protocol_path, protocol, maximum=32 * 1024)
    frames = [{"frame_id": name + "-" + side, **value} for name, _, left, right in specifications
              for side, value in (("left", left), ("right", right))]
    publish(output / "p1-precommit.fixtures.private.json", {"frames": frames}, maximum=4 * 1024**2)
    process = subprocess.run(["java", "-Xmx256m", "-cp", str(overlay / "classes") + ":" + base_classpath,
        "com.flarefitness.backend.ops.PostLoginFeatureExport", "--demo-only"],
        input="".join(canonical(frame) + "\n" for frame in frames), text=True, capture_output=True, timeout=30)
    if process.returncode: raise ValueError("pinned precommit exporter refused: " + process.stderr[-512:])
    rows = [json.loads(line) for line in process.stdout.splitlines()]
    if len(rows) != len(frames) or len({row["frame_id"] for row in rows}) != len(rows): raise ValueError("Java frame mapping changed")
    by_id = {row["frame_id"]: row for row in rows}; comparisons = []
    for name, kind, _, _ in specifications:
        left, right = (by_id[name + "-" + side] for side in ("left", "right"))
        for row in (left, right):
            if (row["representation_version"] != "postlogin-before-action-v1" or len(row["baseline_features"]) != 37
                    or len(row["postlogin_features"]) != 20 or row["before_current_outcome"] is not True):
                raise ValueError("new before-attempt research representation required")
        post_equal = left["postlogin_features"] == right["postlogin_features"]
        base_equal = left["baseline_features"] == right["baseline_features"]
        passed = (not post_equal if kind == "POSTLOGIN_DIFFERENCE" else not base_equal if kind == "BASELINE_DIFFERENCE" else post_equal and base_equal)
        comparisons.append({"id": name, "expectation": kind, "passed": passed, "baseline_equal": base_equal, "postlogin_equal": post_equal})
    publish(output / "p1-precommit.numeric.private.json", {"rows": rows}, maximum=4 * 1024**2)
    receipt = {"phase": "P1_PRECOMMIT_PARITY", "status": "REPRESENTATION_PARITY_PASS" if all(c["passed"] for c in comparisons) else "FIX_REPRESENTATION",
        "protocol_sha256": digest(protocol_path), "overlay_identity_sha256": digest(identity_path), "pair_count": len(specifications),
        "frame_count": len(rows), "comparisons": comparisons, "fixture_sha256": digest(output / "p1-precommit.fixtures.private.json"),
        "numeric_sha256": digest(output / "p1-precommit.numeric.private.json"), "additional_fit_calls": 0, "model_score_calls": 0,
        "holdout_scored": False, "auto_containment": False, "aws_changed": False, "elapsed_seconds": round(time.monotonic() - started, 3),
        "limitations": ["DEMO_ONLY parity does not establish security ground truth or model quality.",
                        "Identical observations remain indistinguishable; no hidden-intent/identity feature is introduced.",
                        "Versioned research representation is not a serving policy or enforcement implementation."]}
    proof = commit(output, receipt, phase="p1-precommit")
    state = json.loads((output / "operator-state.private.json").read_text())
    state.update(phase="P1_PRECOMMIT_PARITY", status=receipt["status"], last_verified_commit=proof, active_handle=None,
                 next_action="Predeclare new pilot population/labels/splits and test bounded recovery before any fits")
    publish(output / "operator-state.private.json", state)
    print(canonical({key: receipt[key] for key in ("status", "pair_count", "frame_count", "elapsed_seconds", "additional_fit_calls")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.absolute())
