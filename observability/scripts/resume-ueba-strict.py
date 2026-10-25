#!/usr/bin/env python3
"""Resume the verified interrupted raw-v2 generator using immutable Java binaries.

The original reviewed event generator is retained and hash-checked. Existing
numeric shards are validated and hashed before reuse. The pre-interruption raw
stream digest is unavailable, explicitly recorded as such, never invented.
"""

import argparse
import fcntl
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.catalog import ShardedDataset, parse_json, validate_rows
from app.contract import FEATURE_NAMES_V2
from app.policy import canonical


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def replace_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(canonical(value)); temporary.chmod(0o600); temporary.replace(path)


def original_module(destination, identity):
    path = destination / "generator-original.py"
    if digest(path) != identity["source_sha256"]["observability/scripts/prepare-ueba-strict.py"]:
        raise ValueError("retained event generator differs from original frozen source")
    spec = importlib.util.spec_from_file_location("retained_strict_generator", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    module.ROOT = ROOT
    current = module.source_identity()
    retained_key = str(path.relative_to(ROOT))
    current["source_sha256"]["observability/scripts/prepare-ueba-strict.py"] = current["source_sha256"].pop(retained_key)
    if current != identity: raise ValueError("original normalization/generator sources or binaries changed")
    return module


def frozen_exporter(destination, identity):
    root = destination / "frozen-exporter"
    if not root.exists():
        temporary = destination / "frozen-exporter.pending"
        temporary.mkdir(mode=0o700)
        (temporary / "backend/target").mkdir(parents=True)
        shutil.copytree(ROOT / "backend/target/classes", temporary / "backend/target/classes")
        jars = temporary / "jars"; jars.mkdir()
        copied = []
        for index, value in enumerate((ROOT / "backend/target/ueba-experiment.classpath").read_text().strip().split(":")):
            source = Path(value)
            if not source.is_file(): raise ValueError("bounded JVM classpath must contain regular dependency jars")
            target = jars / f"{index:04d}-{source.name}"
            shutil.copy2(source, target); copied.append(str(root / "jars" / target.name))
        (temporary / "backend/target/ueba-experiment.classpath").write_text(":".join(copied))
        package = {"classes": {name: digest(temporary / "backend/target/classes/com/flarefitness/backend" / name)
                    for name in identity["compiled_feature_sha256"]},
                   "jars": {path.name: digest(path) for path in jars.iterdir()}}
        if package["classes"] != identity["compiled_feature_sha256"]: raise ValueError("snapshot does not match original numeric extractor")
        (temporary / "snapshot.json").write_text(canonical(package))
        temporary.rename(root)
    package = parse_json((root / "snapshot.json").read_bytes())
    for name, checksum in package["classes"].items():
        if digest(root / "backend/target/classes/com/flarefitness/backend" / name) != checksum:
            raise ValueError("frozen exporter binary changed")
    for name, checksum in package["jars"].items():
        if digest(root / "jars" / name) != checksum: raise ValueError("frozen exporter dependency changed")
    return root, digest(root / "snapshot.json")


def restored_writer(module, destination, name):
    writer = module.ShardWriter(destination, name)
    counts = Counter()
    paths = sorted((destination / "shards").glob(name + "-*.json"))
    for number, path in enumerate(paths):
        if path.name != f"{name}-{number:06d}.json" or path.is_symlink(): raise ValueError("interrupted numeric shard sequence changed")
        rows = parse_json(path.read_bytes()); stats = validate_rows(rows)
        writer.shards.append({"id": path.stem, "path": "shards/" + path.name, "sha256": digest(path), **stats})
        counts.update(stats["cohorts"])
    return writer, counts


class PrefixWriter:
    def __init__(self, writer, skip): self.writer, self.skip, self.appended = writer, skip, 0
    def append(self, value):
        if self.skip: self.skip -= 1
        else: self.writer.append(value); self.appended += 1


def resume(dataset):
    if not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset): raise ValueError("invalid interrupted dataset ID")
    destination = ROOT / "observability/runtime/ueba-experiments" / dataset
    if (destination / "manifest.json").exists(): raise ValueError("a published corpus cannot be resumed or rewritten")
    identity = parse_json((destination / "generation.identity.json").read_bytes())
    module = original_module(destination, identity)
    exporter, exporter_sha = frozen_exporter(destination, identity)
    parts = module.recipe("STRICT")
    writers, completed = {}, {}
    for name in dict.fromkeys(part.split for part in parts):
        writers[name], completed[name] = restored_writer(module, destination, name)
    adopted = {name: list(writer.shards) for name, writer in writers.items()}
    receipt = destination / "recovery-adoption.json"
    if not receipt.exists():
        replace_json(receipt, {"status": "VERIFIED_NUMERIC_SHARDS_ADOPTED", "original_identity": identity,
                              "frozen_exporter_sha256": exporter_sha, "shards": adopted,
                              "pre_interruption_raw_stream_digest_available": False})
    checkpoint = destination / "resume-checkpoint.json"
    statistics = {"raw_frames": 0, "raw_hash": hashlib.sha256(), "exported": sum(sum(value.values()) for value in completed.values()),
                  "abnormal": 0, "abnormal_familiar": 0, "python_sampled_peak_rss_kib": 0, "java_sampled_peak_rss_kib": 0}
    anchor = datetime(2026, 5, 1, tzinfo=timezone.utc)
    module.ROOT = exporter  # Only the JVM loader uses ROOT in export_batch().
    before = time.monotonic()
    for part in parts:
        prefix = completed[part.split].get(part.cohort, 0)
        if prefix > part.normal + part.positive: raise ValueError("adopted cohort exceeds its requested actual population")
        position = 0
        for batch in module.actor_batches(part):
            count = sum(len(values) for _, values in batch)
            if position + count <= prefix:
                position += count; continue
            skip = max(0, prefix - position)
            target = PrefixWriter(writers[part.split], skip)
            previous = statistics["exported"]
            module.export_batch(dataset, part, batch, anchor, target, statistics, destination)
            statistics["exported"] = previous + target.appended
            position += count
            # Flush all successfully produced rows and persist their hashes at
            # every batch boundary. Subsequent interruptions lose no full batch.
            writers[part.split].flush()
            completed[part.split][part.cohort] = position
            state = {"status": "RUNNING", "stage": "STRICT", "split": part.split, "cohort": part.cohort,
                     "actually_exported": statistics["exported"], "resumed_elapsed_seconds": time.monotonic() - before,
                     "frozen_exporter_sha256": exporter_sha, "completed": {name: dict(value) for name, value in completed.items()},
                     "shards": {name: writer.shards for name, writer in writers.items()}}
            replace_json(checkpoint, state)
            replace_json(destination / "generation.progress.json", {key: value for key, value in state.items() if key != "shards"})
            print(f"RESUMED actual numeric records={statistics['exported']} {part.split}/{part.cohort}", flush=True)
    splits = {name: writer.finish() for name, writer in writers.items()}
    for name, split in splits.items():
        if (split["normal"] != sum(part.normal for part in parts if part.split == name)
                or split["positive"] != sum(part.positive for part in parts if part.split == name)):
            raise ValueError("complete resumed corpus differs from actual recipe population")
    manifest = {"catalog_schema_version": 2, "dataset_id": dataset, "stage": "STRICT", "data_provenance": "DEMO_ONLY",
                "feature_schema_version": 2, "telemetry_contract_version": 2, "feature_names": list(FEATURE_NAMES_V2),
                "anchor_utc": anchor.isoformat(), "split_strategy": "past_only_raw_server_normalization_account_hour_episodes",
                **identity, "recovery_orchestrator_sha256": digest(Path(__file__)), "frozen_exporter_sha256": exporter_sha,
                "recovery_adoption_sha256": digest(receipt), "raw_stream_sha256": None,
                "raw_stream_limitation": "Pre-interruption raw stream was transient; complete raw digest cannot be reconstructed. Numeric shards and original event/extractor sources are hash-bound.",
                "resumed_raw_stream_sha256": statistics["raw_hash"].hexdigest(), "resumed_raw_frames": statistics["raw_frames"],
                "evaluated_records": sum(value["records"] for value in splits.values()), "split_recipe": [part.__dict__ for part in parts], "splits": splits}
    module.write_json(destination / "manifest.json", manifest)
    catalogue = ShardedDataset(destination)
    for name in splits:
        for _ in catalogue.iter_shards(name): pass
    complete = {"status": "COMPLETED", "stage": "STRICT", "actually_exported": manifest["evaluated_records"], "manifest_sha256": catalogue.sha256,
                "resumed_elapsed_seconds": time.monotonic() - before, "frozen_exporter_sha256": exporter_sha}
    replace_json(destination / "generation.progress.json", complete)
    print(canonical(complete), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--dataset", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9_-]{8,32}", args.dataset): parser.error("invalid dataset ID")
    directory = ROOT / "observability/runtime/ueba-experiments" / args.dataset
    with (directory / "resume-process.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        resume(args.dataset)
