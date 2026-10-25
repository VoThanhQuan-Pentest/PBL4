"""Independent stress-pair evidence through immutable schema4 Java, never quality.

Run with PYTHONPATH=ueba-worker. This helper intentionally does not import the
pilot, dataset catalogue, model, fitting, scoring or activation modules.
"""

import argparse
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import numpy as np

from app.contract import FEATURE_NAMES_V4, feature_array
from app.schema4_episodes import COUNTERPARTS, PROTOCOL_ANCHOR, context_frames, make_frame, protocol_document


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "ueba-worker/app/schema4_episodes.py"
EXPECTED_GENERATOR = "6797225920eba88e6a26f1f1ff3ee28ee722105c6667e370eab378ce3cb34139"
EXPECTED_WORKSPACE = "64e5aee49d6f716a66e2f700e3888e9fe0e53e6123ad11e3a1713fd57f83f8d2"
DEFAULT_WORKSPACE = ROOT / "observability/runtime/schema4-java-workspace-20261002-bleITZXE/frozen-exporter"
STAGE = "INDEPENDENT_STRESS_IDENTIFIABILITY_ONLY"
DATASET = "schema4-independent-stress-20261002"
START = PROTOCOL_ANCHOR + timedelta(days=14, hours=12)
COHORTS = ("READY", "UNSEEN_READY", "COLD")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def checksum(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def value_checksum(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def duplicate_free(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON field")
        output[key] = value
    return output


def private_write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(canonical(value))


def producer_identity(workspace):
    snapshot = workspace / "snapshot.json"
    if snapshot.is_symlink() or snapshot.stat().st_size > 1024 * 1024 or checksum(snapshot) != EXPECTED_WORKSPACE:
        raise ValueError("expected immutable Java workspace required")
    package = json.loads(snapshot.read_bytes(), object_pairs_hook=duplicate_free)
    base = workspace / "backend/target/classes/com/flarefitness/backend"
    for name, expected in package["classes"].items():
        path = base / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink() or checksum(path) != expected:
            raise ValueError("immutable Java class bytes changed")
    jars = []
    for name, expected in sorted(package["jars"].items()):
        path = workspace / "jars" / name
        if Path(name).name != name or not name.endswith(".jar") or path.is_symlink() or checksum(path) != expected:
            raise ValueError("immutable Java dependency bytes changed")
        jars.append(str(path))
    required = ("ops/UebaFeatureExport.class", "service/siem/AccountBehaviorFeatures.class",
                "service/siem/AccountBaselinePolicy.class", "service/siem/ContextualBehaviorFeatures.class",
                "service/siem/SessionEndpointBehaviorFeatures.class", "service/siem/EndpointCategory.class",
                "service/siem/SecurityEventNormalizer.class", "service/siem/AccountRiskEngine.class")
    if not set(required) <= package["classes"].keys():
        raise ValueError("schema4 producer bytes missing")
    return str(workspace / "backend/target/classes") + ":" + ":".join(jars), {
        "snapshot_sha256": EXPECTED_WORKSPACE,
        "verified_class_count": len(package["classes"]),
        "verified_dependency_count": len(package["jars"]),
        "feature_producer_sha256": {name: package["classes"][name] for name in required},
    }


def transported(episode):
    frame, scenario = episode["frame"], episode["scenario"]
    if set(frame) & {"label", "family", "demo_label", "planned_cause"}:
        raise ValueError("causal frame must remain label-free")
    return {**frame, "demo_label": "ABNORMAL" if scenario["label"] else "NORMAL", "family": scenario["family"]}


def actual_world(context, evaluation, classpath, output, pair_number, side):
    frames = [transported(episode) for episode in (*context, evaluation)]
    raw = "".join(canonical(frame) + "\n" for frame in frames)
    if len(raw.encode()) > 64 * 1024 * 1024 or len(frames) > 49:
        raise ValueError("stress world exceeds independent bound")
    command = ["java", "-Xmx256m", "-cp", classpath,
               "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"]
    result = subprocess.run(command, input=raw, text=True, capture_output=True, timeout=40)
    if result.returncode:
        raise ValueError("immutable Java stress world refused")
    rows = [json.loads(line, object_pairs_hook=duplicate_free) for line in result.stdout.splitlines()]
    if len(rows) != len(frames) or any(row["frame_id"] != frame["frame_id"] for row, frame in zip(rows, frames)):
        raise ValueError("actual Java did not conserve every context/evaluation frame")
    for row, frame in zip(rows, frames):
        if (row["feature_schema_version"] != 4 or row["telemetry_contract_version"] != 3
                or row["feature_names"] != list(FEATURE_NAMES_V4) or row["data_provenance"] != "DEMO_ONLY"
                or row["label"] != int(frame["demo_label"] == "ABNORMAL") or row["family"] != frame["family"]):
            raise ValueError("actual Java stress contract changed")
        feature_array([row["features"]], 1, 4)
    evidence = {"context": context, "evaluation": evaluation, "transport_frames": frames,
                "actual_java_rows": rows, "java_stderr": result.stderr,
                "raw_transport_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "actual_java_stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}
    path = output / f"pair-{pair_number:02d}-{side}.private.json"
    private_write(path, evidence)
    return rows[-1], {"path": path.name, "sha256": checksum(path),
                      "actual_exported_frames": len(rows),
                      "raw_transport_sha256": evidence["raw_transport_sha256"],
                      "actual_java_stdout_sha256": evidence["actual_java_stdout_sha256"]}


def numeric_key(row, dtype):
    array = feature_array([row["features"]], 1, 4).astype(dtype)
    array[array == 0] = 0
    return ("COLD" if row["cohort"] == "COLD" else "READY", array.tobytes())


def run(workspace):
    if checksum(GENERATOR) != EXPECTED_GENERATOR:
        raise ValueError("frozen causal generator source changed")
    protocol = protocol_document()
    protocol_hash = value_checksum(protocol)
    classpath, producers = producer_identity(workspace)
    output = Path(tempfile.mkdtemp(prefix="schema4-independent-stress-20261002-", dir=ROOT / "observability/runtime"))
    os.chmod(output, 0o700)
    pairs = [(benign, anomaly) for benign, anomaly in COUNTERPARTS.items() if benign != "benign_login_only_retries"]
    if len(pairs) != 5 or len({anomaly for _, anomaly in pairs}) != 5:
        raise ValueError("exact five-family stress counterpart matrix required")
    results = []
    for cohort_number, cohort in enumerate(COHORTS):
        for family_number, (benign, anomaly) in enumerate(pairs):
            number = cohort_number * len(pairs) + family_number
            context = context_frames(DATASET, number, START, cohort=cohort)
            left = make_frame(DATASET, number, 0, START, planned_cause=benign, cohort=cohort)
            right = make_frame(DATASET, number, 0, START, planned_cause=anomaly, cohort=cohort)
            a, left_evidence = actual_world(context, left, classpath, output, number, "control")
            b, right_evidence = actual_world(context, right, classpath, output, number, "anomaly")
            differences = [FEATURE_NAMES_V4[index] for index, (x, y) in enumerate(zip(a["features"], b["features"])) if x != y]
            result = {"pair_number": number, "cohort": cohort, "benign_planned_cause": benign, "anomaly_family": anomaly,
                      "context_frame_count": len(context), "same_label_free_raw_frame": left["frame"] == right["frame"],
                      "same_client_ledger": left["client_ledger"] == right["client_ledger"],
                      "same_execution_seed": left["scenario"]["plan"]["execution_seed"] == right["scenario"]["plan"]["execution_seed"],
                      "same_profile": left["scenario"]["plan"]["profile"] == right["scenario"]["plan"]["profile"],
                      "actual_labels": [a["label"], b["label"]], "actual_cohorts": [a["cohort"], b["cohort"]],
                      "actual_baseline_established": [a["baseline_established"], b["baseline_established"]],
                      "actual_trusted_window_counts": [a["trusted_window_count"], b["trusted_window_count"]],
                      "actual_rule_only_risks": [a["rule_only_risk"], b["rule_only_risk"]],
                      "actual_rule_only_incidents": [a["rule_only_incident"], b["rule_only_incident"]],
                      "feature_count": len(a["features"]), "features_equal_float64": numeric_key(a, "<f8") == numeric_key(b, "<f8"),
                      "features_equal_float32": numeric_key(a, "<f4") == numeric_key(b, "<f4"),
                      "differing_feature_names": differences, "actual_control_features": a["features"], "actual_anomaly_features": b["features"],
                      "control_evidence": left_evidence, "anomaly_evidence": right_evidence}
            results.append(result)
            print(canonical({"stage": STAGE, "completed_pairs": len(results), "cohort": cohort,
                             "family": anomaly, "features_equal_float64": result["features_equal_float64"]}), flush=True)
    if checksum(GENERATOR) != EXPECTED_GENERATOR or value_checksum(protocol_document()) != protocol_hash:
        raise ValueError("causal source/protocol changed during independent stress check")
    _, after_producers = producer_identity(workspace)
    if after_producers != producers:
        raise ValueError("immutable Java changed during independent stress check")
    source = Path(__file__).resolve()
    summary = {"stage": STAGE, "status": "COMPLETED", "data_provenance": "DEMO_ONLY_SIMULATION",
               "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
               "helper_source_sha256": checksum(source), "generator_source_sha256": EXPECTED_GENERATOR,
               "protocol_document_sha256": protocol_hash, "protocol_source_sha256": protocol["source_sha256"],
               "workspace": str(workspace), "immutable_java": producers,
               "planned_pair_count": 15, "retained_pair_count": len(results), "independent_java_processes": len(results) * 2,
               "actually_exported_frames": sum(pair[side]["actual_exported_frames"] for pair in results for side in ("control_evidence", "anomaly_evidence")),
               "exact_float64_feature_pairs": sum(pair["features_equal_float64"] for pair in results),
               "exact_float32_feature_pairs": sum(pair["features_equal_float32"] for pair in results),
               "baseline_expectation_matches": all(pair["actual_baseline_established"] == [pair["cohort"] != "COLD"] * 2 for pair in results),
               "fit_calls": 0, "model_score_calls": 0, "holdout_records_read": 0, "aws_calls": 0,
               "quality_gate": "NOT_APPLICABLE", "representative_prevalence_claimed": False,
               "overall_population_impossibility_claimed": False, "original_captures_relabelled": False,
               "conclusion_scope": "FIFTEEN_EXPLICIT_SAME_OBSERVATION_PLANNED_CAUSE_STRESS_PAIRS_ONLY",
               "limitations": ["Purpose-selected counterfactual stress cases; not the blind main pilot or a prevalence sample.",
                               "Exact equality establishes local observational ambiguity, not overall dataset impossibility.",
                               "Expected degradation controls are separate stress causes; faults remain operational anomalies, not attacks.",
                               "No fitted scores, threshold decisions, model metrics, activation or representative real accuracy."],
               "pairs": results}
    private_write(output / "result.private.json", summary)
    private_write(output / "receipt.json", {"stage": STAGE, "status": "COMPLETED", "result_sha256": checksum(output / "result.private.json"),
                                           "retained_pairs": len(results), "actual_exported_frames": summary["actually_exported_frames"]})
    print(canonical({"stage": STAGE, "result": str(output / "result.private.json"), "result_sha256": checksum(output / "result.private.json"),
                     "retained_pairs": len(results), "exact_float64_pairs": summary["exact_float64_feature_pairs"],
                     "exact_float32_pairs": summary["exact_float32_feature_pairs"], "baseline_expectation_matches": summary["baseline_expectation_matches"]}), flush=True)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    run(parser.parse_args().workspace.resolve())
