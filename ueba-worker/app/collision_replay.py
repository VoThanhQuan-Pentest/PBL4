"""Replay original validation collisions through real schema-3 Java extraction.

No fit, score, holdout, relabel or primary update. The original raw generator is
hash-bound; every replay must reproduce the frozen schema-2 prefix and history.
Only aggregate counterexamples leave the private diagnostic directory.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import importlib.util
import math
from pathlib import Path
import re
import subprocess
import sys

import numpy as np

from app.catalog import ShardedDataset, parse_json
from app.contract import feature_array
from app.policy import canonical
from app.strict_campaign import sha, timestamp, write
from app.validation_collisions import FP_TP_RATIO, MAX_RECORDS, VALIDATION_SPLITS

MAX_MATCH_ROWS = 4096
MAX_RAW_FRAMES = 4096
MAX_STREAM_BYTES = 64 * 1024 * 1024


class ValidationOnlyDataset(ShardedDataset):
    """Fail closed before filesystem I/O even if a diagnostic requests holdout."""
    def _read(self, relative, maximum):
        if relative != "manifest.json" and not re.fullmatch(r"shards/fold[123]-validation-[0-9]{6}\.json", relative):
            raise ValueError("diagnostic file access is limited to validation shards")
        return super()._read(relative, maximum)


def input_key(row, schema):
    vector = feature_array([row["features"]], 1, schema).astype("<f4")
    vector[vector == 0] = 0
    return ("COLD" if row["cohort"] == "COLD" else "READY", vector.tobytes())


def input_keys(rows, schema):
    vectors = feature_array([row["features"] for row in rows], 5000, schema).astype("<f4")
    vectors[vectors == 0] = 0
    return [("COLD" if row["cohort"] == "COLD" else "READY", vector.tobytes()) for row, vector in zip(rows, vectors)]


def collision_rows(dataset, split_name, *, progress=None):
    if split_name not in VALIDATION_SPLITS or dataset.manifest["feature_schema_version"] != 2:
        raise ValueError("only original schema-2 validation records are eligible")
    split = dataset.split(split_name)
    if not 1 <= split["positive"] <= 1000 or split["records"] > MAX_RECORDS:
        raise ValueError("bounded validation population required")
    positive = Counter()
    for number, descriptor in enumerate(split["shards"]):
        if descriptor["positive"]:
            _, rows = dataset.load_shard(split_name, number)
            positive.update(key for row, key in zip(rows, input_keys(rows, 2)) if row["label"] == 1)
    if sum(positive.values()) != split["positive"]:
        raise ValueError("positive descriptor pass differs from manifest")
    matched = defaultdict(list); totals = Counter(); families = Counter(); cohorts = Counter()
    positive_families = Counter(); positive_cohorts = Counter(); verified_positive = Counter(); matched_count = 0
    for descriptor, rows in dataset.iter_shards(split_name):
        for row, key in zip(rows, input_keys(rows, 2)):
            totals["records"] += 1; totals["positive" if row["label"] else "normal"] += 1
            families[row["family"]] += 1; cohorts[row["cohort"]] += 1
            if row["label"]:
                verified_positive[key] += 1; positive_families[row["family"]] += 1; positive_cohorts[row["cohort"]] += 1
            if key in positive:
                matched[key].append(row); matched_count += 1
                if matched_count > MAX_MATCH_ROWS: raise ValueError("private collision replay row budget exceeded")
        if progress: progress({"split": split_name, "verified_validation_rows": totals["records"]})
    actual = {key: totals[key] for key in ("records", "normal", "positive")}
    actual.update(families=dict(families), cohorts=dict(cohorts))
    if any(split[key] != value for key, value in actual.items()) or verified_positive != positive:
        raise ValueError("second validation pass differs from manifest or positive inputs")
    selected = [row for group in matched.values() if any(row["label"] == 0 for row in group) for row in group]
    if len({row["frame_id"] for row in selected}) != len(selected): raise ValueError("duplicate collision frame")
    return selected, {**actual, "positive_by_family": dict(positive_families), "positive_by_cohort": dict(positive_cohorts)}


def load_generator(dataset):
    path = dataset.root / "generator-original.py"
    expected = dataset.manifest["source_sha256"]["observability/scripts/prepare-ueba-strict.py"]
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 or sha(path) != expected:
        raise ValueError("original reviewed raw generator checksum mismatch")
    spec = importlib.util.spec_from_file_location("owned_original_collision_generator", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module, expected


def original_sequence(part, account):
    total = part.normal + part.positive
    maximum = min(20, part.days * 12) if part.cohort == "COLD" else part.days * 12
    accounts = math.ceil(total / maximum)
    if type(account) is not int or not 0 <= account < accounts: raise ValueError("invalid original account ordinal")
    per_account, extra = divmod(total, accounts)
    count = per_account + (account < extra); beginning = account * per_account + min(account, extra)
    return [before if (beginning + ordinal + 1) * part.positive // total > before else None
            for ordinal in range(count) for before in [(beginning + ordinal) * part.positive // total]]


def raw_frames(dataset, split_name, rows, generator):
    if split_name not in VALIDATION_SPLITS: raise ValueError("numeric holdout must not be reconstructed")
    parts = {part.cohort: part for part in generator.recipe("STRICT") if part.split == split_name}
    anchor = datetime.fromisoformat(dataset.manifest["anchor_utc"])
    if anchor.utcoffset().total_seconds() != 0: raise ValueError("original UTC anchor required")
    accounts = defaultdict(dict)
    expression = re.compile(re.escape(dataset.manifest["dataset_id"] + "-" + split_name) + r"-(cold|dev|unseen)-(\d{6})-eval-(\d{3})")
    for row in rows:
        match = expression.fullmatch(row["frame_id"])
        if match is None: raise ValueError("frame does not belong to the original raw recipe")
        cohort, account, ordinal = row["cohort"], int(match[2]), int(match[3])
        if cohort not in parts or (match[1] == "cold") != (cohort == "COLD"):
            raise ValueError("original frame cohort changed")
        accounts[(cohort, account)][ordinal] = row
    frames = []
    for (cohort, account), wanted in sorted(accounts.items()):
        part = parts[cohort]; sequence = original_sequence(part, account)
        if max(wanted) >= len(sequence): raise ValueError("original evaluated window ordinal changed")
        for ordinal in range(3 if cohort == "COLD" else 48):
            frames.append(generator.make_frame(dataset.manifest["dataset_id"], part, account, ordinal, anchor, context=True)[0])
        for ordinal in range(max(wanted) + 1):
            frame = generator.make_frame(dataset.manifest["dataset_id"], part, account, ordinal, anchor,
                                         positive_index=sequence[ordinal])[0]
            if ordinal in wanted:
                old = wanted[ordinal]
                if (frame["frame_id"] != old["frame_id"] or frame["account_id"] != old["account_id"]
                        or frame["window_start"] != old["window_start"] or frame["family"] != old["family"]
                        or (frame["demo_label"] == "ABNORMAL") != bool(old["label"])):
                    raise ValueError("raw reconstruction does not match original validation ground truth")
            frames.append(frame)
    if len(frames) > MAX_RAW_FRAMES: raise ValueError("raw replay frame budget exceeded")
    return frames


def workspace_identity(workspace, expected_sha):
    snapshot = workspace / "snapshot.json"
    if snapshot.is_symlink() or snapshot.stat().st_size > 1024 * 1024 or sha(snapshot) != expected_sha:
        raise ValueError("frozen Java workspace checksum mismatch")
    identity = parse_json(snapshot.read_bytes()); required = {"ops/UebaFeatureExport.class", "service/siem/ContextualBehaviorFeatures.class"}
    if not required.issubset(identity["classes"]): raise ValueError("actual contextual producer is missing")
    for name, checksum in identity["classes"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts or sha(workspace / "backend/target/classes/com/flarefitness/backend" / name) != checksum:
            raise ValueError("frozen Java producer changed")
    jars = []
    for name, checksum in sorted(identity["jars"].items()):
        if not re.fullmatch(r"[0-9]{4}-[a-zA-Z0-9_.-]+\.jar", name): raise ValueError("invalid frozen jar path")
        path = workspace / "jars" / name
        if path.is_symlink() or sha(path) != checksum: raise ValueError("frozen Java dependency changed")
        jars.append(str(path))
    return str(workspace / "backend/target/classes") + ":" + ":".join(jars), identity


def extract(frames, rows, classpath, log):
    if not rows: return []
    raw = "".join(canonical(frame) + "\n" for frame in frames).encode()
    if len(raw) > MAX_STREAM_BYTES: raise ValueError("private raw stream exceeds diagnostic bound")
    with log.open("xb") as stderr:
        log.chmod(0o600)
        actual = subprocess.run(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport",
                                 "--demo-only", "--schema3"], input=raw, stdout=subprocess.PIPE, stderr=stderr, timeout=120, check=True)
    if len(actual.stdout) > MAX_STREAM_BYTES: raise ValueError("numeric replay stream exceeds diagnostic bound")
    wanted = {row["frame_id"]: row for row in rows}; selected = {}
    lines = actual.stdout.splitlines()
    if len(lines) != len(frames): raise ValueError("actual Java exporter did not conserve source frames")
    for line in lines:
        if len(line) > 16384: raise ValueError("numeric replay line exceeds diagnostic bound")
        value = parse_json(line); old = wanted.get(value["frame_id"])
        if old is None: continue
        if value["frame_id"] in selected: raise ValueError("duplicate Java replay result")
        if (value.get("feature_schema_version") != 3 or value.get("telemetry_contract_version") != 2
                or value.get("data_provenance") != "DEMO_ONLY" or value["features"][:15] != old["features"]
                or any(value[key] != old[key] for key in ("account_id", "window_start", "label", "family", "baseline_established", "trusted_window_count"))):
            raise ValueError("schema-3 replay changed original prefix, ground truth or past baseline")
        selected[value["frame_id"]] = {**old, "features": value["features"]}
    if set(selected) != set(wanted): raise ValueError("actual Java replay omitted collision rows")
    return list(selected.values())


def bounds(rows, population):
    if (not 1 <= population["positive"] <= 1000
            or sum(population["positive_by_family"].values()) != population["positive"]
            or sum(population["positive_by_cohort"].values()) != population["positive"]
            or len({row["frame_id"] for row in rows}) != len(rows)):
        raise ValueError("observed global positive/slice populations and distinct replay frames required")
    groups = defaultdict(list)
    for row in rows: groups[input_key(row, 3)].append(row)
    forced_families = Counter(); forced_cohorts = Counter(); mixed = 0; collided_positives = 0; collided_normals = 0
    budget = population["positive"] // FP_TP_RATIO
    for group in groups.values():
        positives = [row for row in group if row["label"]]; normals = len(group) - len(positives)
        if positives and normals:
            mixed += 1; collided_positives += len(positives); collided_normals += normals
            if normals > budget:
                forced_families.update(row["family"] for row in positives); forced_cohorts.update(row["cohort"] for row in positives)
    def slices(source, misses):
        return {key: {"positive_samples": total, "forced_missed_positives": misses[key],
                      "optimistic_recall_upper_bound": (total - misses[key]) / total,
                      "strict_recall_above_99_percent_necessary_condition": (total - misses[key]) * 100 > total * 99}
                for key, total in sorted(source.items())}
    families = slices(population["positive_by_family"], forced_families); cohorts = slices(population["positive_by_cohort"], forced_cohorts)
    return {"actual_java_replayed_rows": len(rows), "schema_3_mixed_input_keys": mixed,
            "positive_rows_in_remaining_mixed_keys": collided_positives, "normal_rows_in_remaining_mixed_keys": collided_normals,
            "necessary_global_fp_budget": budget, "by_family": families, "by_cohort": cohorts,
            "any_slice_provably_cannot_meet_strict_recall": any(not item["strict_recall_above_99_percent_necessary_condition"]
                                                              for item in (*families.values(), *cohorts.values()))}


def run(dataset, workspace, expected_workspace_sha, output):
    if dataset.manifest["stage"] != "STRICT": raise ValueError("original immutable strict source required")
    output.mkdir(mode=0o700); classpath, package = workspace_identity(workspace, expected_workspace_sha)
    generator, generator_sha = load_generator(dataset); folds = []
    for name in VALIDATION_SPLITS:
        rows, population = collision_rows(dataset, name, progress=lambda value: write(output / "progress.json", value))
        frames = raw_frames(dataset, name, rows, generator)
        actual = extract(frames, rows, classpath, output / (name + ".java.log"))
        # Private generated evidence supports reproduction; not a training catalogue.
        write(output / (name + ".private-replay.json"), {"original_rows": rows, "actual_schema3_rows": actual})
        folds.append({"split": name, "split_sha256": dataset.split(name)["sha256"], "actual_validation_population": population,
                      "reconstructed_raw_frames": len(frames), "schema2_prefix_and_baseline_preserved": True, **bounds(actual, population)})
    result = {"status": "COMPLETED", "conclusion_scope": "NECESSARY_CONDITION_COUNTEREXAMPLE_ONLY", "data_provenance": "DEMO_ONLY",
              "quality_gate": "NOT_APPLICABLE", "source_manifest_sha256": dataset.sha256, "raw_generator_sha256": generator_sha,
              "java_workspace_snapshot_sha256": expected_workspace_sha, "actual_java_producers": package["classes"],
              "replay_source_sha256": sha(Path(__file__)), "folds": folds, "holdout_numeric_records_read": 0,
              "fit_or_model_score_calls": 0, "primary_changed": False, "completed_at_utc": timestamp()}
    write(output / "result.json", result); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True); parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--workspace", type=Path, required=True); parser.add_argument("--expected-workspace-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    result = run(ValidationOnlyDataset(args.dataset, expected_sha256=args.expected_manifest_sha256), args.workspace,
                 args.expected_workspace_sha256, args.output)
    print(canonical({"status": result["status"], "quality_gate": result["quality_gate"], "folds": [
        {key: fold[key] for key in ("split", "actual_java_replayed_rows", "schema_3_mixed_input_keys", "any_slice_provably_cannot_meet_strict_recall")}
        for fold in result["folds"]]}), flush=True)


if __name__ == "__main__": main()
