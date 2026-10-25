#!/usr/bin/env python3
"""Stream fresh schema-4 causal worlds into an immutable numeric catalogue.

No old numeric corpus is read, relabelled, or amplified. PILOT is a complete
small fit/calibration/validation extraction, never STRICT qualification. STRICT
retains the original population recipe; neither mode fits, scores, or activates
a model. Independent virtual worlds are simulations, not authentic HTTP captures.
"""

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import timedelta
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.catalog import MAX_SHARD_BYTES, ShardedDataset, parse_json, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.policy import canonical

GENERATOR_SHA256 = "6797225920eba88e6a26f1f1ff3ee28ee722105c6667e370eab378ce3cb34139"
DEFAULT_WORKSPACE = ROOT / "observability/runtime/schema4-java-workspace-20261002-bleITZXE/frozen-exporter"
DEFAULT_WORKSPACE_SHA256 = "64e5aee49d6f716a66e2f700e3888e9fe0e53e6123ad11e3a1713fd57f83f8d2"
DEFAULT_ENDPOINT_PROOF = ROOT / "observability/runtime/schema4-endpoint-vocabulary-20261002-final.json"
DEFAULT_ENDPOINT_SHA256 = "ee4ec86bcd4a2b3e62c492de4d8ae97ed9760187400d4e20b55359a93a5d0ffe"
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
FRAME_FIELDS = {"frame_id", "account_id", "day", "cohort", "window_start", "telemetry_contract_version", "events"}
NUMERIC_FIELDS = {"frame_id", "account_id", "window_start", "label", "family", "baseline_established", "trusted_window_count", "features"}
SOURCE_FILES = (Path(__file__), ROOT / "ueba-worker/app/schema4_episodes.py", ROOT / "ueba-worker/app/catalog.py",
                ROOT / "ueba-worker/app/contract.py", ROOT / "ueba-worker/app/policy.py", ROOT / "ueba-worker/app/strict_metrics.py")
MAX_JAVA_RSS_KIB = 500 * 1024
MAX_BATCH_ACTORS = 128
MAX_SHARD_ROWS = 5000
MAX_RECEIPT_BYTES = 1024 * 1024
PRODUCER = "schema4-full-causal-catalogue-v1"


def checked_path(path):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("symlink paths are not accepted")
    return path


def read_file(path, maximum):
    path = checked_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("bounded regular file required")
        data = stream.read(maximum + 1)
        if len(data) > maximum or len(data) != info.st_size:
            raise ValueError("file changed size or exceeded bound")
        return data


def digest(path):
    path = checked_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    result = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular checksum input required")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def object_digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def write_new(path, value):
    descriptor = os.open(checked_path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def replace_progress(path, value):
    temporary = path.with_suffix(".pending")
    # Only this run's disposable progress file may be overwritten under flock.
    descriptor = os.open(checked_path(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def source_binding():
    sources = {str(path.relative_to(ROOT)): digest(path) for path in SOURCE_FILES}
    if sources["ueba-worker/app/schema4_episodes.py"] != GENERATOR_SHA256:
        raise ValueError("frozen cause-planned episode source changed")
    return {"source_sha256": sources, "sha256": object_digest(sources)}


def load_generator():
    path = ROOT / "ueba-worker/app/schema4_episodes.py"
    if digest(path) != GENERATOR_SHA256:
        raise ValueError("refuse to execute a changed frozen episode generator")
    specification = importlib.util.spec_from_file_location("frozen_schema4_catalogue_episodes", path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def workspace_identity(workspace, expected_sha):
    """Bind every class/JAR, including rejecting unlisted loadable classes."""
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
        raise ValueError("immutable Java snapshot SHA256 required")
    workspace = checked_path(workspace).resolve(strict=True)
    if os.pathsep in str(workspace):
        raise ValueError("workspace cannot contain a classpath separator")
    raw = read_file(workspace / "snapshot.json", 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("frozen Java snapshot checksum mismatch")
    package = parse_json(raw)
    if (not isinstance(package, dict) or set(package) != {"classes", "jars"}
            or not isinstance(package["classes"], dict) or not 1 <= len(package["classes"]) <= 2000
            or not isinstance(package["jars"], dict) or not 1 <= len(package["jars"]) <= 512):
        raise ValueError("bounded complete Java snapshot required")
    required = {"ops/UebaFeatureExport.class", "service/siem/EndpointCategory.class", "service/siem/SessionEndpointBehaviorFeatures.class"}
    if not required <= set(package["classes"]):
        raise ValueError("actual schema4 producer classes missing")
    classes = workspace / "backend/target/classes"
    if any(path.is_symlink() for path in classes.rglob("*")):
        raise ValueError("symlink entries in a frozen classpath are not accepted")
    prefix = "com/flarefitness/backend/"
    expected_paths = set()
    for name, checksum in package["classes"].items():
        if (not re.fullmatch(r"(?:[A-Za-z0-9_$]+/)*[A-Za-z0-9_$]+\.class", name)
                or not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum)
                or digest(classes / prefix / name) != checksum):
            raise ValueError("immutable Java class changed")
        expected_paths.add(prefix + name)
    if {str(path.relative_to(classes)) for path in classes.rglob("*.class")} != expected_paths:
        raise ValueError("unlisted Java class in frozen classpath")
    jars = []
    for name, checksum in sorted(package["jars"].items()):
        if (not re.fullmatch(r"[0-9]{4}-[A-Za-z0-9_.-]+\.jar", name)
                or not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum)
                or digest(workspace / "jars" / name) != checksum):
            raise ValueError("immutable Java dependency changed")
        jars.append(str(workspace / "jars" / name))
    if {path.name for path in (workspace / "jars").iterdir()} != set(package["jars"]):
        raise ValueError("unlisted Java dependency in frozen workspace")
    return os.pathsep.join([str(classes), *jars]), package


def endpoint_identity(path, expected_sha, workspace_sha, package, generator):
    raw = read_file(path, 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("actual endpoint proof checksum mismatch")
    proof = parse_json(raw)
    if (not isinstance(proof, dict) or proof.get("scope") != "ACTUAL_IMMUTABLE_ENDPOINT_CLASSIFIER_OFFLINE_ONLY"
            or proof.get("workspace_snapshot_sha256") != workspace_sha
            or proof.get("endpoint_class_sha256") != package["classes"]["service/siem/EndpointCategory.class"]
            or proof.get("feature_schema_version") != 4 or proof.get("telemetry_contract_version") != 3
            or proof.get("http_handler_resolution_proven") is not False or proof.get("authenticated_session_proven") is not False):
        raise ValueError("same immutable endpoint classifier required; not authentic session proof")
    mappings = proof.get("handler_mappings")
    if not isinstance(mappings, list) or not 1 <= len(mappings) <= 100:
        raise ValueError("bounded actual handler mappings required")
    actual = {(row["method"], row["handler_pattern"]): row["endpoint_category"] for row in mappings}
    for (method, _, category), pattern in generator.HANDLER_PATTERNS.items():
        if actual.get((method, pattern)) != category:
            raise ValueError("generator endpoint metadata differs from immutable classifier")
    return {"sha256": expected_sha, "handler_mapping_sha256": object_digest(mappings)}


@dataclass(frozen=True)
class Part:
    split: str
    cohort: str
    day: int
    days: int
    normal: int
    positive: int = 0

    def __post_init__(self):
        if (not isinstance(self.split, str) or not re.fullmatch(r"[a-z0-9_-]{4,64}", self.split)
                or self.cohort not in ("READY", "UNSEEN_READY", "COLD")
                or any(type(value) is not int for value in (self.day, self.days, self.normal, self.positive))
                or not 5 <= self.day <= 110 or not 1 <= self.days <= 14 or self.day + self.days - 1 > 110
                or self.normal < 0 or self.positive < 0 or not self.normal + self.positive
                or ("fit" in self.split or "calibration" in self.split) and self.positive):
            raise ValueError("invalid bounded schema4 campaign part")


def proportions(normal, positive):
    return [("READY", normal * 7 // 10, positive * 7 // 10),
            ("UNSEEN_READY", normal * 2 // 10, positive * 2 // 10),
            ("COLD", normal - normal * 7 // 10 - normal * 2 // 10,
             positive - positive * 7 // 10 - positive * 2 // 10)]


def recipe(mode, pilot_fit=2000, pilot_calibration=1000, pilot_normal=1000, pilot_positive=10):
    if mode == "STRICT":
        parts = []
        for fold, fit_day, cal_day, val_day in ((1, 15, 33, 51), (2, 22, 40, 58), (3, 29, 47, 65)):
            parts.extend((Part(f"fold{fold}-fit", "READY", fit_day, 1, 50000),
                          Part(f"fold{fold}-calibration-ready", "READY", cal_day, 3, 1000000),
                          Part(f"fold{fold}-calibration-cold", "COLD", cal_day, 3, 1000000)))
            parts.extend(Part(f"fold{fold}-validation", cohort, val_day, 4, normal, positive)
                         for cohort, normal, positive in proportions(1000000, 1000))
        parts.extend(Part("holdout", cohort, 85, 14, normal, positive)
                     for cohort, normal, positive in proportions(10000000, 10000))
        return parts
    if (mode != "PILOT" or any(type(value) is not int for value in (pilot_fit, pilot_calibration, pilot_normal, pilot_positive))
            or not 1 <= pilot_fit <= 50000 or not 10 <= pilot_calibration <= 100000
            or not 10 <= pilot_normal <= 100000 or not 5 <= pilot_positive <= 1000 or pilot_positive % 5):
        raise ValueError("bounded complete PILOT populations required; positives must be divisible by five")
    return [Part("fold1-fit", "READY", 15, 1, pilot_fit),
            Part("fold1-calibration-ready", "READY", 33, 3, pilot_calibration),
            Part("fold1-calibration-cold", "COLD", 33, 3, pilot_calibration),
            *(Part("fold1-validation", cohort, 51, 4, normal, positive)
              for cohort, normal, positive in proportions(pilot_normal, pilot_positive) if normal + positive)]


def actor_layout(part, ready_pool):
    total = part.normal + part.positive
    maximum = min(20, part.days * 12) if part.cohort == "COLD" else part.days * 12
    accounts = total if part.split.endswith("-fit") else (total + maximum - 1) // maximum
    if accounts > 1000000 or part.cohort == "READY" and accounts > ready_pool:
        raise ValueError("READY evaluated identities must be covered by the same fold's fitted pool")
    per_actor, extra = divmod(total, accounts)
    return accounts, per_actor, extra


def actor_batches(part, ready_pool=50000, batch_accounts=128):
    if type(batch_accounts) is not int or not 1 <= batch_accounts <= MAX_BATCH_ACTORS:
        raise ValueError("at most 128 actors per Java process")
    total = part.normal + part.positive
    accounts, per_actor, extra = actor_layout(part, ready_pool)
    for begin in range(0, accounts, batch_accounts):
        batch, global_ordinal = [], begin * per_actor + min(begin, extra)
        for account in range(begin, min(begin + batch_accounts, accounts)):
            evaluations = []
            for ordinal in range(per_actor + (account < extra)):
                before = global_ordinal * part.positive // total
                after = (global_ordinal + 1) * part.positive // total
                evaluations.append((ordinal, before if after > before else None))
                global_ordinal += 1
            batch.append((account, evaluations))
        yield batch


def namespace(dataset, part):
    # Hash the fold and actor kind, never expose cohort/kind words in identities.
    fold = part.split[:5] if part.split.startswith("fold") else "fold3"
    kind = {"READY": "development", "UNSEEN_READY": "unseen", "COLD": "cold"}[part.cohort]
    return "world-" + object_digest([PRODUCER, dataset, fold, kind])[:48]


def make_episode(generator, dataset, part, account, ordinal, *, context=False, positive_index=None):
    world = namespace(dataset, part)
    profile = generator.account_profile(world, account)
    offset = ordinal - (3 if part.cohort == "COLD" else 48) if context else ordinal
    day_offset, hour = divmod(offset, 12)
    at = generator.PROTOCOL_ANCHOR + timedelta(days=part.day - 1 + day_offset, hours=profile.first_hour + hour)
    cause = "normal" if positive_index is None else FAMILIES[positive_index % len(FAMILIES)]
    return generator.make_frame(world, account, ordinal, at, planned_cause=cause, context=context, cohort=part.cohort)


def transport(episode):
    frame, scenario = episode["frame"], episode["scenario"]
    label, family = scenario.get("label"), scenario.get("family")
    if (set(frame) != FRAME_FIELDS or frame.get("telemetry_contract_version") != 3
            or type(label) is not int or label not in (0, 1) or family not in ("normal", *FAMILIES)
            or (label == 0) != (family == "normal") or scenario.get("data_provenance") != "DEMO_ONLY_SIMULATION"
            or not episode["evidence"].get("server_event_conservation") or episode["evidence"].get("authentic_capture") is not False):
        raise ValueError("separate frozen plan and simulated telemetry required")
    return {**frame, "demo_label": "ABNORMAL" if label else "NORMAL", "family": family}


def jobs(parts, batch_accounts):
    positive_offsets = Counter()
    pools = {part.split[:5]: part.normal for part in parts if part.split.endswith("-fit")}
    for part_number, part in enumerate(parts):
        fold = part.split[:5] if part.split.startswith("fold") else "fold3"
        for batch_number, batch in enumerate(actor_batches(part, pools[fold], batch_accounts)):
            yield f"part{part_number:02d}-batch{batch_number:06d}", part, batch, positive_offsets[part.split]
        positive_offsets[part.split] += part.positive


def job_ids(parts, batch_accounts):
    pools = {part.split[:5]: part.normal for part in parts if part.split.endswith("-fit")}
    for number, part in enumerate(parts):
        fold = part.split[:5] if part.split.startswith("fold") else "fold3"
        accounts = actor_layout(part, pools[fold])[0]
        for batch in range((accounts + batch_accounts - 1) // batch_accounts):
            yield f"part{number:02d}-batch{batch:06d}"


class BatchShards:
    def __init__(self, pending, split, batch_id):
        self.pending, self.split, self.batch_id = pending, split, batch_id
        self.rows, self.descriptors = [], []

    def append(self, row):
        self.rows.append(row)
        if len(self.rows) == MAX_SHARD_ROWS:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        stats = validate_rows(self.rows, 4)
        identifier = f"{self.split}-{self.batch_id}-{len(self.descriptors):03d}"
        path = self.pending / (identifier + ".json")
        write_new(path, self.rows)
        if path.stat().st_size > MAX_SHARD_BYTES:
            raise ValueError("numeric schema4 shard exceeds catalogue byte bound")
        self.descriptors.append({"id": identifier, "path": "shards/" + path.name, "sha256": digest(path), **stats})
        self.rows = []


def rss_kib(pid):
    try:
        with Path(f"/proc/{pid}/statm").open() as stream:
            return int(stream.read(256).split()[1]) * os.sysconf("SC_PAGE_SIZE") // 1024
    except (OSError, ValueError, IndexError):
        return 0


def export_batch(generator, dataset, part, batch, positive_offset, classpath, output, writer, timeout=1800):
    """One episode at a time; bounded expectation queue, JVM heap/RSS/time."""
    if not 1 <= len(batch) <= MAX_BATCH_ACTORS or not 1 <= timeout <= 3600:
        raise ValueError("bounded actor batch and timeout required")
    state = {"raw_frames": 0, "evaluated_rows": 0, "java_sampled_peak_rss_kib": 0,
             "python_sampled_peak_rss_kib": 0, "events": 0, "client_attempts": 0}
    raw_hash, plans_hash = hashlib.sha256(), hashlib.sha256()
    expected = queue.Queue(maxsize=256)
    errors, stopped = [], threading.Event()
    before = time.monotonic()
    log_path = output / "java-export.log"
    log_descriptor = os.open(checked_path(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(log_descriptor, "ab") as log:
        process = subprocess.Popen(["java", "-Xmx256m", "-cp", classpath,
                                    "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)

        def send(episode, evaluated):
            frame = transport(episode)
            data = (canonical(frame) + "\n").encode()
            if len(frame["events"]) >= 4096 or len(data) >= generator.MAX_FRAME_BYTES:
                raise ValueError("strictly bounded schema4 raw frame required")
            wanted = {key: frame[key] for key in ("frame_id", "account_id", "window_start", "family")}
            wanted.update(label=episode["scenario"]["label"], cohort=part.cohort, evaluated=evaluated)
            while not stopped.is_set():
                try:
                    expected.put(wanted, timeout=0.2)
                    break
                except queue.Full:
                    continue
            if stopped.is_set():
                raise RuntimeError("bounded export stopped")
            process.stdin.write(data)
            raw_hash.update(data)
            plans_hash.update((canonical(episode["scenario"]) + "\n").encode())
            state["raw_frames"] += 1
            state["events"] += len(frame["events"])
            state["client_attempts"] += len(episode["client_ledger"])

        def feed():
            try:
                for account, evaluations in batch:
                    for ordinal in range(3 if part.cohort == "COLD" else 48):
                        send(make_episode(generator, dataset, part, account, ordinal, context=True), False)
                    for ordinal, positive_index in evaluations:
                        index = None if positive_index is None else positive_offset + positive_index
                        send(make_episode(generator, dataset, part, account, ordinal, positive_index=index), True)
            except Exception as failure:
                errors.append(type(failure).__name__)
                stopped.set()
                process.terminate()
            finally:
                process.stdin.close()

        def watch():
            while not stopped.wait(0.2):
                peak = rss_kib(process.pid)
                state["java_sampled_peak_rss_kib"] = max(state["java_sampled_peak_rss_kib"], peak)
                state["python_sampled_peak_rss_kib"] = max(state["python_sampled_peak_rss_kib"], rss_kib(os.getpid()))
                if peak >= MAX_JAVA_RSS_KIB or time.monotonic() - before > timeout:
                    errors.append("JavaMemoryOrTimeBoundExceeded")
                    stopped.set()
                    process.kill()
                    break

        feeder = threading.Thread(target=feed, daemon=True)
        watcher = threading.Thread(target=watch, daemon=True)
        feeder.start()
        watcher.start()
        all_frames = 0
        try:
            while line := process.stdout.readline(16385):
                if len(line) > 16384 or not line.endswith(b"\n"):
                    raise ValueError("bounded complete numeric Java line required")
                row = parse_json(line)
                wanted = expected.get(timeout=5)
                if (not isinstance(row, dict) or row.get("feature_schema_version") != 4
                        or row.get("feature_names") != list(FEATURE_NAMES_V4) or row.get("telemetry_contract_version") != 3
                        or row.get("data_provenance") != "DEMO_ONLY"
                        or any(row.get(key) != wanted[key] for key in ("frame_id", "account_id", "window_start", "label", "family"))):
                    raise ValueError("actual Java failed frame/schema/planned-label conservation")
                all_frames += 1
                if wanted["evaluated"]:
                    if row.get("baseline_established") != (part.cohort != "COLD"):
                        raise ValueError("actual past-only baseline differs; never override readiness")
                    selected = {key: row[key] for key in NUMERIC_FIELDS}
                    selected["cohort"] = part.cohort
                    writer.append(selected)
                    state["evaluated_rows"] += 1
            feeder.join(timeout=10)
            if (feeder.is_alive() or process.wait(timeout=10) or errors or not expected.empty()
                    or all_frames != state["raw_frames"]
                    or state["evaluated_rows"] != sum(len(values) for _, values in batch)):
                raise RuntimeError("incomplete bounded actual Java extraction")
        finally:
            stopped.set()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            process.stdout.close()
            feeder.join(timeout=10)
            watcher.join(timeout=2)
    writer.flush()
    return {**state, "raw_stream_sha256": raw_hash.hexdigest(), "planned_scenarios_sha256": plans_hash.hexdigest(),
            "elapsed_seconds": time.monotonic() - before,
            "rss_sampling_method": "Linux proc statm every 0.2s; sampled, not an exact peak"}


def promote(output, committed, receipt):
    for descriptor in receipt["shards"]:
        source = committed / (descriptor["id"] + ".json")
        data = read_file(source, MAX_SHARD_BYTES)
        rows = parse_json(data)
        stats = validate_rows(rows, 4)
        if hashlib.sha256(data).hexdigest() != descriptor["sha256"] or any(descriptor[key] != value for key, value in stats.items()):
            raise ValueError("committed batch shard checksum/statistics changed")
        destination = output / descriptor["path"]
        if destination.exists():
            if digest(destination) != descriptor["sha256"]:
                raise ValueError("existing projected shard differs from committed receipt")
        else:
            os.link(source, destination)


def split_descriptor(descriptors):
    counts, families, cohorts = Counter(), Counter(), Counter()
    for descriptor in descriptors:
        counts.update({key: descriptor[key] for key in ("records", "normal", "positive")})
        families.update(descriptor["families"])
        cohorts.update(descriptor["cohorts"])
    value = {**dict(counts), "families": dict(sorted(families.items())), "cohorts": dict(sorted(cohorts.items())),
             "from": min(item["from"] for item in descriptors), "to": max(item["to"] for item in descriptors), "shards": descriptors}
    return {**value, "sha256": object_digest(value)}


def check_receipt(receipt, batch_id, part, batch, positive_offset, identity_sha):
    expected_fields = {"batch_id", "split", "cohort", "generation_identity_sha256", "assignment_sha256", "shards", "statistics"}
    if (not isinstance(receipt, dict) or set(receipt) != expected_fields
            or receipt["batch_id"] != batch_id or receipt["split"] != part.split or receipt["cohort"] != part.cohort
            or receipt["generation_identity_sha256"] != identity_sha
            or receipt["assignment_sha256"] != object_digest([asdict(part), batch, positive_offset])
            or not isinstance(receipt["shards"], list) or not receipt["shards"]):
        raise ValueError("receipt does not match frozen deterministic actor assignment")
    descriptor = split_descriptor(receipt["shards"])
    ShardedDataset._check_split(descriptor, set(), set())
    families = Counter("normal" if index is None else FAMILIES[(positive_offset + index) % 5]
                       for _, values in batch for _, index in values)
    count = sum(families.values())
    state = receipt["statistics"]
    if (descriptor["records"] != count or descriptor["families"] != dict(sorted(families.items()))
            or descriptor["cohorts"] != {part.cohort: count} or not isinstance(state, dict)
            or state.get("evaluated_rows") != count
            or state.get("raw_frames") != count + len(batch) * (3 if part.cohort == "COLD" else 48)
            or type(state.get("elapsed_seconds")) not in (int, float) or state["elapsed_seconds"] <= 0
            or any(not isinstance(state.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", state[key])
                   for key in ("raw_stream_sha256", "planned_scenarios_sha256"))):
        raise ValueError("receipt differs from actual expected frame/family/cohort population")


def prepare(dataset, mode="PILOT", *, workspace=DEFAULT_WORKSPACE, workspace_sha=DEFAULT_WORKSPACE_SHA256,
            endpoint_proof=DEFAULT_ENDPOINT_PROOF, endpoint_sha=DEFAULT_ENDPOINT_SHA256, output=None, resume=False,
            pilot_fit=2000, pilot_calibration=1000, pilot_normal=1000, pilot_positive=10, batch_accounts=128,
            batch_timeout=1800, maximum_batches=None):
    if not isinstance(dataset, str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset):
        raise ValueError("fresh bounded dataset identity required")
    if type(batch_accounts) is not int or not 1 <= batch_accounts <= 128 or type(batch_timeout) is not int or not 1 <= batch_timeout <= 3600:
        raise ValueError("bounded actors and Java timeout required")
    if maximum_batches is not None and (type(maximum_batches) is not int or maximum_batches < 1):
        raise ValueError("positive optional stop-after-batches bound required")
    parts = recipe(mode, pilot_fit, pilot_calibration, pilot_normal, pilot_positive)
    # Validate pool coverage before allocating a directory or starting Java.
    pools = {part.split[:5]: part.normal for part in parts if part.split.endswith("-fit")}
    all_jobs = 0
    for part in parts:
        fold = part.split[:5] if part.split.startswith("fold") else "fold3"
        accounts = actor_layout(part, pools[fold])[0]
        all_jobs += (accounts + batch_accounts - 1) // batch_accounts
    sources = source_binding()
    generator = load_generator()
    classpath, package = workspace_identity(Path(workspace), workspace_sha)
    endpoints = endpoint_identity(Path(endpoint_proof), endpoint_sha, workspace_sha, package, generator)
    output = checked_path(output or ROOT / "observability/runtime/ueba-experiments" / dataset)
    identity = {"producer": PRODUCER, "dataset_id": dataset, "stage": mode, "source_binding": sources,
                "workspace_snapshot_sha256": workspace_sha, "endpoint_proof": endpoints,
                "java_class_count": len(package["classes"]), "java_jar_count": len(package["jars"]),
                "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                "split_recipe": [asdict(part) for part in parts], "batch_accounts": batch_accounts,
                "anchor_utc": generator.PROTOCOL_ANCHOR.isoformat(), "horizon_days": 110,
                "actor_namespace_recipe": "SHA256(producer,dataset,fold,actor-kind); never planned cause",
                "context_windows": {"READY": 48, "UNSEEN_READY": 48, "COLD": 3}, "cold_evaluated_windows_per_actor_maximum": 20,
                "data_provenance": "DEMO_ONLY_SIMULATION", "authentic_capture": False,
                "old_numeric_corpus_read": False, "hard_counterfactuals_in_prevalence": False,
                "fit_or_score_calls": 0, "quality_gate": "NOT_APPLICABLE" if mode == "PILOT" else "NOT_EVALUATED"}
    if resume:
        if not output.is_dir() or (output / "manifest.json").exists():
            raise ValueError("only an unpublished interrupted catalogue can resume")
    else:
        output.mkdir(mode=0o700)
        for name in ("shards", "batches", "pending", "abandoned"):
            (output / name).mkdir(mode=0o700)
    lock_descriptor = os.open(checked_path(output / "generation.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_descriptor, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("a generator currently holds the catalogue lock") from None
        # A lock file on disk alone is not a running process or a checkpoint.
        if resume:
            if parse_json(read_file(output / "generation.identity.json", MAX_RECEIPT_BYTES)) != identity:
                raise ValueError("interrupted catalogue source/recipe/frozen identity changed")
        else:
            write_new(output / "generation.identity.json", identity)
        identity_sha = digest(output / "generation.identity.json")
        completed = {}
        for directory in sorted((output / "batches").iterdir()):
            if directory.is_symlink() or not directory.is_dir() or not re.fullmatch(r"part[0-9]{2}-batch[0-9]{6}", directory.name):
                raise ValueError("invalid committed batch path")
            receipt = parse_json(read_file(directory / "receipt.json", MAX_RECEIPT_BYTES))
            if receipt.get("generation_identity_sha256") != identity_sha or receipt.get("batch_id") != directory.name:
                raise ValueError("committed batch frozen identity changed")
            completed[directory.name] = receipt
        # Only a contiguous committed prefix is a resumable stopped job.
        missing = False
        expected_ids = set(job_ids(parts, batch_accounts))
        if set(completed) - expected_ids:
            raise ValueError("committed receipt exists outside the frozen recipe")
        for batch_id in job_ids(parts, batch_accounts):
            if batch_id not in completed:
                missing = True
            elif missing:
                raise ValueError("committed receipts are not a deterministic completed prefix")
        if len(completed) > all_jobs:
            raise ValueError("committed batch count exceeds recipe")
        # Incomplete transactions are retained privately, never silently adopted.
        for directory in sorted((output / "pending").iterdir()):
            checked_path(directory)
            target = output / "abandoned" / (directory.name + "-" + str(time.time_ns()))
            directory.rename(target)
        descriptors = {part.split: [] for part in parts}
        statistics = []
        count, known = 0, set()
        for batch_id, part, batch, positive_offset in jobs(parts, batch_accounts):
            known.add(batch_id)
            assignment_sha = object_digest([asdict(part), batch, positive_offset])
            receipt = completed.get(batch_id)
            if receipt is None:
                if maximum_batches is not None and count >= maximum_batches:
                    break
                pending = output / "pending" / batch_id
                pending.mkdir(mode=0o700)
                writer = BatchShards(pending, part.split, batch_id)
                result = export_batch(generator, dataset, part, batch, positive_offset, classpath, output, writer, batch_timeout)
                if source_binding() != sources:
                    raise ValueError("bound Python producer changed during extraction")
                receipt = {"batch_id": batch_id, "split": part.split, "cohort": part.cohort,
                           "generation_identity_sha256": identity_sha, "assignment_sha256": assignment_sha,
                           "shards": writer.descriptors, "statistics": result}
                write_new(pending / "receipt.json", receipt)
                pending.rename(output / "batches" / batch_id)
                count += 1
            check_receipt(receipt, batch_id, part, batch, positive_offset, identity_sha)
            promote(output, output / "batches" / batch_id, receipt)
            descriptors[part.split].extend(receipt["shards"])
            statistics.append(receipt["statistics"])
            records = sum(item["evaluated_rows"] for item in statistics)
            elapsed = sum(item["elapsed_seconds"] for item in statistics)
            progress = {"status": "RUNNING", "dataset_id": dataset, "stage": mode, "actually_exported": records,
                        "raw_frames": sum(item["raw_frames"] for item in statistics), "completed_batches": len(statistics),
                        "active_export_elapsed_seconds": elapsed, "numeric_rows_per_second": records / max(elapsed, 0.001),
                        "quality_gate": identity["quality_gate"], "fit_or_score_calls": 0}
            replace_progress(output / "generation.progress.json", progress)
            print(canonical(progress), flush=True)
        if set(completed) - known:
            raise ValueError("receipt exists outside deterministic completed prefix")
        if source_binding() != sources or workspace_identity(Path(workspace), workspace_sha)[1] != package:
            raise ValueError("immutable source or Java dependency drift; no manifest published")
        endpoint_identity(Path(endpoint_proof), endpoint_sha, workspace_sha, package, generator)
        if len(statistics) != all_jobs:
            result = {**progress, "status": "STOPPED_AT_BATCH_BOUNDARY", "resume_required": True,
                      "published_manifest": False, "no_quality_claim": True}
            replace_progress(output / "generation.progress.json", result)
            return result
        splits = {name: split_descriptor(values) for name, values in descriptors.items()}
        for name, split in splits.items():
            normal = sum(part.normal for part in parts if part.split == name)
            positive = sum(part.positive for part in parts if part.split == name)
            if (split["normal"] != normal or split["positive"] != positive
                    or positive and any(split["families"].get(family, 0) != positive // 5 for family in FAMILIES)):
                raise ValueError("actual numeric prevalence/families differs from untouched recipe")
        expected_files = {descriptor["path"].split("/")[1] for values in descriptors.values() for descriptor in values}
        if {path.name for path in (output / "shards").iterdir()} != expected_files:
            raise ValueError("unreceipted numeric shard cannot enter published catalogue")
        manifest = {"catalog_schema_version": 2, "dataset_id": dataset, "stage": mode, "data_provenance": "DEMO_ONLY",
                    "simulation_provenance": "INDEPENDENT_VIRTUAL_CAUSAL_WORLDS_NOT_AUTHENTIC_CAPTURE_OR_RELABELLED_OLD_DATA",
                    "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                    "generation_identity_sha256": identity_sha, "workspace_snapshot_sha256": workspace_sha,
                    "endpoint_proof_sha256": endpoint_sha, "anchor_utc": identity["anchor_utc"], "split_recipe": identity["split_recipe"],
                    "raw_frames": sum(item["raw_frames"] for item in statistics), "evaluated_records": progress["actually_exported"],
                    "raw_batch_digest_chain_sha256": object_digest([item["raw_stream_sha256"] for item in statistics]),
                    "planned_batch_digest_chain_sha256": object_digest([item["planned_scenarios_sha256"] for item in statistics]),
                    "raw_digest_semantics": "ORDERED_PER_BATCH_DIGEST_CHAIN_NOT_A_CONCATENATED_RAW_STREAM_DIGEST",
                    "active_export_elapsed_seconds": progress["active_export_elapsed_seconds"],
                    "numeric_rows_per_second": progress["numeric_rows_per_second"],
                    "java_sampled_peak_rss_kib": max(item["java_sampled_peak_rss_kib"] for item in statistics),
                    "python_sampled_peak_rss_kib": max(item["python_sampled_peak_rss_kib"] for item in statistics),
                    "source_binding": sources, "quality_gate": identity["quality_gate"], "fit_or_score_calls": 0, "splits": splits}
        # A separate hard-linked view validates the catalogue before publication.
        # A failed/stopped prepublication view is retained, never adopted on resume.
        view = output / "verification"
        if view.exists():
            checked_path(view).rename(output / "abandoned" / ("verification-" + str(time.time_ns())))
        view.mkdir(mode=0o700)
        (view / "shards").mkdir(mode=0o700)
        for name in expected_files:
            os.link(output / "shards" / name, view / "shards" / name)
        write_new(view / "manifest.json", manifest)
        catalogue = ShardedDataset(view)
        for name in splits:
            for _ in catalogue.iter_shards(name):
                pass
        os.link(view / "manifest.json", output / "manifest.json")
        result = {**progress, "status": "COMPLETED", "manifest_sha256": catalogue.sha256,
                  "no_quality_claim": True, "holdout_generated": mode == "STRICT", "active_model_or_aws_changed": False}
        replace_progress(output / "generation.progress.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--mode", choices=("PILOT", "STRICT"), default="PILOT")
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--workspace-sha256", default=DEFAULT_WORKSPACE_SHA256)
    parser.add_argument("--endpoint-proof", type=Path, default=DEFAULT_ENDPOINT_PROOF)
    parser.add_argument("--endpoint-proof-sha256", default=DEFAULT_ENDPOINT_SHA256)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--pilot-fit", type=int, default=2000)
    parser.add_argument("--pilot-calibration", type=int, default=1000)
    parser.add_argument("--pilot-normal", type=int, default=1000)
    parser.add_argument("--pilot-positive", type=int, default=10)
    parser.add_argument("--batch-accounts", type=int, default=128)
    parser.add_argument("--batch-timeout", type=int, default=1800)
    parser.add_argument("--stop-after-batches", type=int)
    args = parser.parse_args()
    result = prepare(args.dataset_id, args.mode, workspace=args.workspace, workspace_sha=args.workspace_sha256,
                     endpoint_proof=args.endpoint_proof, endpoint_sha=args.endpoint_proof_sha256, output=args.output,
                     resume=args.resume, pilot_fit=args.pilot_fit, pilot_calibration=args.pilot_calibration,
                     pilot_normal=args.pilot_normal, pilot_positive=args.pilot_positive, batch_accounts=args.batch_accounts,
                     batch_timeout=args.batch_timeout, maximum_batches=args.stop_after_batches)
    print(canonical(result), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        raise SystemExit("Schema4 catalogue refused/failed: " + type(failure).__name__ + ": " + str(failure)) from None
