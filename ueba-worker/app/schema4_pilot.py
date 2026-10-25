"""Blind, bounded schema4 causal simulation preflight through immutable Java.

This is not a fitting job, a holdout, a representative prevalence estimate, or
an accuracy result. It conserves planned labels outside model input and checks
necessary float64/float32 learnability conditions before expensive campaigns.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import subprocess
import threading

from app.catalog import ShardedDataset, parse_json, validate_rows
from app.collision_replay import workspace_identity
from app.contract import FEATURE_NAMES_V4
from app.controlled_trace_export_v2 import read_private
from app.policy import canonical
from app.strict_campaign import sha, write
from app.validation_collisions import collision_split

FRAME_FIELDS = {"frame_id", "account_id", "day", "cohort", "window_start", "telemetry_contract_version", "events"}
NUMERIC_FIELDS = {"frame_id", "account_id", "window_start", "label", "family", "baseline_established", "trusted_window_count", "features"}
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")


def binding():
    root = Path(__file__).parent
    sources = {name: sha(root / name) for name in ("schema4_pilot.py", "schema4_episodes.py", "catalog.py", "contract.py",
                                                "policy.py", "validation_collisions.py", "strict_metrics.py", "controlled_trace_export_v2.py")}
    return {"sources": sources, "sha256": hashlib.sha256(canonical(sources).encode()).hexdigest()}


def transport(episode):
    if not isinstance(episode, dict) or set(episode) != {"frame", "scenario", "client_ledger", "evidence"}:
        raise ValueError("separate causal simulation envelopes required")
    frame, scenario = episode["frame"], episode["scenario"]
    if not isinstance(frame, dict) or set(frame) != FRAME_FIELDS or frame.get("telemetry_contract_version") != 3:
        raise ValueError("label-free schema4 telemetry frame required")
    label, family = scenario.get("label"), scenario.get("family")
    if (type(label) is not int or label not in (0, 1) or family not in {"normal", *FAMILIES}
            or (label == 0) != (family == "normal") or scenario.get("data_provenance") != "DEMO_ONLY_SIMULATION"
            or not isinstance(scenario.get("plan_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", scenario["plan_sha256"])):
        raise ValueError("frozen separate planned anomaly labels required")
    # Only the exporter transport receives labels. Its feature builders do not;
    # scenario, client ledger, source evidence never enter feature extraction.
    return {**frame, "demo_label": "ABNORMAL" if label else "NORMAL", "family": family}


def check_endpoint_proof(path, expected_sha, workspace_sha, package):
    raw = read_private(path, 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("actual endpoint classifier proof checksum mismatch")
    proof = parse_json(raw)
    if (proof.get("scope") != "ACTUAL_IMMUTABLE_ENDPOINT_CLASSIFIER_OFFLINE_ONLY"
            or proof.get("workspace_snapshot_sha256") != workspace_sha
            or proof.get("endpoint_class_sha256") != package["classes"].get("service/siem/EndpointCategory.class")
            or proof.get("feature_schema_version") != 4 or proof.get("telemetry_contract_version") != 3
            or proof.get("http_handler_resolution_proven") is not False
            or proof.get("authenticated_session_proven") is not False):
        raise ValueError("same immutable endpoint classifier bytes required; not live authentication proof")
    return proof


def check_declared_endpoints(protocol, proof):
    mappings = {(row["method"], row["handler_pattern"]): row["endpoint_category"] for row in proof["handler_mappings"]}
    recipes = protocol.get("endpoint_recipes")
    if not isinstance(recipes, list) or not 1 <= len(recipes) <= 100:
        raise ValueError("bounded independently declared server handler recipes required")
    for recipe in recipes:
        if (not isinstance(recipe, dict) or not {"method", "handler_pattern", "endpoint_category"} <= set(recipe)
                or mappings.get((recipe["method"], recipe["handler_pattern"])) != recipe["endpoint_category"]):
            raise ValueError("simulation handler metadata differs from actual immutable classifier")


class Shards:
    def __init__(self, output, name):
        self.output, self.name, self.rows, self.descriptors = output, name, [], []

    def append(self, row):
        self.rows.append(row)
        if len(self.rows) == 500:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        stats = validate_rows(self.rows, 4)
        identifier = f"{self.name}-{len(self.descriptors):06d}"
        path = self.output / "shards" / (identifier + ".json")
        write(path, self.rows)
        self.descriptors.append({"id": identifier, "path": "shards/" + path.name, "sha256": sha(path), **stats})
        self.rows = []

    def finish(self):
        self.flush()
        counts, families, cohorts = Counter(), Counter(), Counter()
        for descriptor in self.descriptors:
            counts.update({key: descriptor[key] for key in ("records", "normal", "positive")})
            families.update(descriptor["families"])
            cohorts.update(descriptor["cohorts"])
        result = {**dict(counts), "families": dict(sorted(families.items())), "cohorts": dict(sorted(cohorts.items())),
                  "from": min(row["from"] for row in self.descriptors), "to": max(row["to"] for row in self.descriptors), "shards": self.descriptors}
        return {**result, "sha256": hashlib.sha256(canonical(result).encode()).hexdigest()}


def export_batch(batch, classpath, output, writer, state):
    frames, expectations, scenarios = [], {}, []
    for cohort, context, evaluation in batch:
        frames.extend(transport(episode) for episode in context)
        evaluated = transport(evaluation)
        frames.append(evaluated)
        expectations[evaluated["frame_id"]] = {"label": int(evaluated["demo_label"] == "ABNORMAL"), "family": evaluated["family"], "cohort": cohort,
                                             "account_id": evaluated["account_id"], "window_start": evaluated["window_start"]}
        scenarios.append(evaluation["scenario"])
    raw = b"".join((canonical(frame) + "\n").encode() for frame in frames)
    if len(raw) > 64 * 1024 * 1024 or len(frames) > 4000 or len(expectations) != len(batch):
        raise ValueError("bounded unique immutable Java batch required")
    state["raw_stream_hash"].update(raw)
    state["raw_frames"] += len(frames)
    state["planned_scenarios_hash"].update(canonical(scenarios).encode())
    with (output / "java-export.log").open("ab") as log:
        (output / "java-export.log").chmod(0o600)
        process = subprocess.Popen(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        errors = []
        def feed():
            try:
                process.stdin.write(raw)
            except Exception as failure:
                errors.append(type(failure).__name__)
            finally:
                process.stdin.close()
        thread = threading.Thread(target=feed, daemon=True)
        thread.start()
        seen, all_frames = set(), 0
        try:
            for line in process.stdout:
                if len(line) > 16384:
                    raise ValueError("bounded Java numeric output required")
                row = parse_json(line)
                all_frames += 1
                wanted = expectations.get(row.get("frame_id"))
                if wanted is None:
                    continue
                if row["frame_id"] in seen:
                    raise ValueError("duplicate evaluated Java frame")
                seen.add(row["frame_id"])
                if (row.get("feature_schema_version") != 4 or row.get("feature_names") != list(FEATURE_NAMES_V4)
                        or row.get("telemetry_contract_version") != 3 or row.get("data_provenance") != "DEMO_ONLY"
                        or any(row.get(key) != wanted[key] for key in ("label", "family", "account_id", "window_start"))):
                    raise ValueError("actual schema4 exporter changed protocol/label/population")
                if row.get("baseline_established") != (wanted["cohort"] != "COLD"):
                    raise ValueError("actual past-only baseline differs from requested cohort; never override readiness")
                selected = {key: row[key] for key in NUMERIC_FIELDS}
                selected["cohort"] = wanted["cohort"]
                writer.append(selected)
            thread.join(timeout=30)
            if thread.is_alive() or process.wait(timeout=30) or errors or seen != set(expectations) or all_frames != len(frames):
                raise ValueError("actual Java must conserve every simulated context/evaluated frame")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
            thread.join(timeout=10)
    state["evaluated_rows"] += len(seen)


def observable_shortcut_audit(dataset):
    """Descriptive nuisance checks, not feature selection or threshold tuning."""
    rows = [row for _, shard in dataset.iter_shards("fold1-validation") for row in shard]
    if not 200 <= len(rows) <= 2000:
        raise ValueError("bounded blind descriptive population required")
    grouped = {}
    for row in rows:
        grouped.setdefault((row["label"], row["family"], row["cohort"]), []).append(row)
    selected = (0, 3, 4, 5, 8, 9, 10, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36)
    result = []
    for (label, family, cohort), group in sorted(grouped.items()):
        measurements = {}
        for index in selected:
            values = [row["features"][index] for row in group]
            measurements[FEATURE_NAMES_V4[index]] = {"min": min(values), "max": max(values), "mean": sum(values) / len(values),
                                                    "zero_count": sum(value == 0 for value in values), "unique_values": len(set(values))}
        result.append({"label": label, "family": family, "cohort": cohort, "records": len(group), "observed_features": measurements})
    normal = [row for row in rows if row["label"] == 0]
    return {"scope": "BLIND_PILOT_DESCRIPTIVE_NUISANCE_AND_APPLICABILITY_ONLY", "quality_gate": "NOT_APPLICABLE",
            "no_threshold_or_feature_selection": True, "records": len(rows), "groups": result,
            "normal_login_only_window_count": sum(row["features"][0] == 0 and row["features"][3] > 0 for row in normal),
            "normal_absent_endpoint_metadata_window_count": sum(row["features"][0] > 0 and row["features"][25] == 0 for row in normal),
            "normal_absent_authenticated_session_window_count": sum(row["features"][31] == 0 for row in normal),
            "manual_protocol_review_required": True,
            "limitations": ["Family differences may be causal, not proof of leakage", "Balanced PILOT is not deployment prevalence",
                            "No observed feature uniquely proves business intent or compromise", "Simulated worlds are not independent real captures"]}


def run(dataset_id, workspace, workspace_sha, endpoint_proof, endpoint_proof_sha, output, *, normal=1000, positive=1000):
    from app import schema4_episodes as generator
    if (not isinstance(dataset_id, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset_id)
            or type(normal) is not int or type(positive) is not int or not 100 <= normal <= 1000 or not 100 <= positive <= 1000
            or normal % 100 or positive % 100):
        raise ValueError("fresh bounded PILOT identity and populations in hundreds required")
    classpath, package = workspace_identity(workspace, workspace_sha)
    proof = check_endpoint_proof(endpoint_proof, endpoint_proof_sha, workspace_sha, package)
    protocol = generator.protocol_document()
    check_declared_endpoints(protocol, proof)
    source_identity = binding()
    output.mkdir(mode=0o700)
    (output / "shards").mkdir(mode=0o700)
    identity = {"dataset_id": dataset_id, "data_provenance": "DEMO_ONLY_SIMULATION", "protocol": protocol,
                "protocol_sha256": hashlib.sha256(canonical(protocol).encode()).hexdigest(), "source_binding": source_identity,
                "workspace_snapshot_sha256": workspace_sha, "bound_java_classes": len(package["classes"]),
                "endpoint_proof_sha256": endpoint_proof_sha, "normal": normal, "positive": positive,
                "target_semantics": "PLANNED_CAUSAL_ANOMALIES_INCLUDE_NONMALICIOUS_OPERATIONAL_FAULTS_NOT_COMPROMISE_VERDICTS",
                "labels_assigned_before_event_generation": True, "pilot_prevalence_is_not_deployment_prevalence": True,
                "quality_gate": "NOT_APPLICABLE", "fit_or_score_calls": 0, "holdout_accessed": False}
    write(output / "generation.identity.json", identity)
    state = {"raw_stream_hash": hashlib.sha256(), "planned_scenarios_hash": hashlib.sha256(), "raw_frames": 0, "evaluated_rows": 0}
    writer = Shards(output, "fold1-validation")
    ordinal, positive_index, batch = 0, 0, []
    for cohort, weight in (("READY", 7), ("UNSEEN_READY", 2), ("COLD", 1)):
        for label, count in ((0, normal * weight // 10), (1, positive * weight // 10)):
            for _ in range(count):
                cause = "normal" if label == 0 else FAMILIES[positive_index % 5]
                positive_index += label
                start = datetime(2026, 4, 15, tzinfo=timezone.utc) + timedelta(hours=ordinal % 12)
                context = generator.context_frames(dataset_id, ordinal, start, cohort=cohort)
                evaluation = generator.make_frame(dataset_id, ordinal, 0, start, planned_cause=cause, cohort=cohort)
                if evaluation["scenario"]["label"] != label or evaluation["scenario"]["family"] != (cause if label else "normal"):
                    raise ValueError("planned population/family changed by simulator")
                batch.append((cohort, context, evaluation))
                ordinal += 1
                if len(batch) == 64:
                    export_batch(batch, classpath, output, writer, state)
                    batch = []
                    write(output / "generation.progress.json", {"status": "RUNNING", "evaluated_rows": state["evaluated_rows"], "raw_frames": state["raw_frames"], "quality_gate": "NOT_APPLICABLE"})
                    print(f"Schema4 causal PILOT actually exported={state['evaluated_rows']}", flush=True)
    if batch:
        export_batch(batch, classpath, output, writer, state)
    split = writer.finish()
    if (split["normal"] != normal or split["positive"] != positive or binding() != source_identity
            or generator.protocol_document() != protocol or workspace_identity(workspace, workspace_sha)[1] != package):
        raise ValueError("immutable simulator or actual populations changed; retain failed artifacts")
    manifest = {"catalog_schema_version": 2, "dataset_id": dataset_id, "stage": "PILOT", "data_provenance": "DEMO_ONLY",
                "simulation_provenance": "INDEPENDENTLY_SPECIFIED_CAUSAL_EPISODE_WORLDS_NOT_AMPLIFIED_REAL_OBSERVATIONS",
                "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                "generation_identity_sha256": sha(output / "generation.identity.json"), "workspace_snapshot_sha256": workspace_sha,
                "raw_stream_sha256": state["raw_stream_hash"].hexdigest(), "raw_frames": state["raw_frames"],
                "planned_scenarios_sha256": state["planned_scenarios_hash"].hexdigest(), "splits": {"fold1-validation": split}}
    write(output / "manifest.json", manifest)
    dataset = ShardedDataset(output)
    collisions = collision_split(dataset, "fold1-validation")
    write(output / "validation-collision-diagnostic.json", collisions)
    shortcuts = observable_shortcut_audit(dataset)
    write(output / "observable-shortcut-diagnostic.json", shortcuts)
    result = {"status": "COMPLETED", "scope": "BLIND_SIMULATED_SCHEMA4_EXTRACTION_AND_NECESSARY_LEARNABILITY_ONLY", "stage": "PILOT",
              "quality_gate": "NOT_APPLICABLE", "data_provenance": "DEMO_ONLY", "normal": normal, "positive": positive,
              "actual_exported_evaluated_rows": state["evaluated_rows"], "actual_exported_raw_frames": state["raw_frames"],
              "manifest_sha256": dataset.sha256, "collision_diagnostic_sha256": sha(output / "validation-collision-diagnostic.json"),
              "observable_shortcut_diagnostic_sha256": sha(output / "observable-shortcut-diagnostic.json"),
              "normal_login_only_windows": shortcuts["normal_login_only_window_count"],
              "representations": {name: {"mixed_label_input_keys": value["mixed_label_input_keys"], "precision_feasible_max_recall": value["oracle"]["precision_feasible_max_recall"],
                                         "any_observed_slice_provably_fails": value["slice_necessary_conditions"]["any_observed_slice_provably_fails_strict_recall_requirement"]}
                                  for name, value in collisions["representations"].items()},
              "fit_or_score_calls": 0, "holdout_accessed": False, "active_model_or_aws_changed": False,
              "collision_pass_is_not_model_accuracy_or_strict_qualification": True, "shortcut_audit_required_before_large_training": True}
    write(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--workspace-sha256", required=True)
    parser.add_argument("--endpoint-proof", type=Path, required=True)
    parser.add_argument("--endpoint-proof-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--normal", type=int, default=1000)
    parser.add_argument("--positive", type=int, default=1000)
    args = parser.parse_args()
    print(canonical(run(args.dataset_id, args.workspace, args.workspace_sha256, args.endpoint_proof, args.endpoint_proof_sha256, args.output, normal=args.normal, positive=args.positive)), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Schema4 PILOT refused/failed: " + type(failure).__name__ + "; private frames and process output omitted") from None
