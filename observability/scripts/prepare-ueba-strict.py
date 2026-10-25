#!/usr/bin/env python3
"""Fresh raw-telemetry campaign, bounded Java export and numeric sharded catalogue.

PILOT cannot satisfy a quality gate. STRICT declares requested populations but
publishes a manifest only after every numeric row was actually exported. Raw
requests exist in a pipe, not a giant file; labels never enter baseline/scoring.
"""

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import resource
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_NAMES_V2
from app.policy import canonical
from app.strict_metrics import FAMILIES

AGENTS = (
    "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 Firefox/133.0",
    "Mozilla/5.0 Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
)
PATHS = ("/api/products", "/api/profile", "/api/orders/me", "/api/support/me/messages",
         "/api/reviews", "/api/promo-hunt/campaigns", "/api/sync/me/owned-lab")
BASE_COUNTS = (2, 4, 6, 9, 12, 18, 28, 42, 70, 130)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def seed(*parts): return int.from_bytes(hashlib.sha256("/".join(map(str, parts)).encode()).digest()[:8], "big")


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream: stream.write(canonical(value))
    path.chmod(0o600)


def rss_kib(pid):
    try:
        with Path(f"/proc/{pid}/statm").open() as stream: pages = int(stream.read(256).split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") // 1024
    except (OSError, ValueError, IndexError): return 0


def source_identity():
    sources = [Path(__file__), ROOT / "ueba-worker/app/catalog.py", ROOT / "backend/src/main/java/com/flarefitness/backend/ops/UebaFeatureExport.java",
               *(ROOT / "backend/src/main/java/com/flarefitness/backend/service/siem" / name
                 for name in ("SecurityEventNormalizer.java", "AccountBehaviorFeatures.java", "AccountBaselinePolicy.java", "AccountRiskEngine.java"))]
    return {"source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in sources},
            "compiled_feature_sha256": {name: digest(ROOT / "backend/target/classes/com/flarefitness/backend" / name)
                for name in ("ops/UebaFeatureExport.class", "service/siem/SecurityEventNormalizer.class",
                             "service/siem/AccountBehaviorFeatures.class", "service/siem/AccountBaselinePolicy.class",
                             "service/siem/AccountRiskEngine.class")}}


@dataclass(frozen=True)
class Part:
    split: str
    cohort: str
    day: int
    days: int
    normal: int
    positive: int = 0

    def __post_init__(self):
        if (not re.fullmatch(r"[a-z0-9_-]{4,64}", self.split) or self.cohort not in ("READY", "UNSEEN_READY", "COLD")
                or any(type(value) is not int for value in (self.day, self.days, self.normal, self.positive))
                or not 5 <= self.day <= 110 or not 1 <= self.days <= 14 or self.day + self.days - 1 > 110
                or self.normal < 0 or self.positive < 0 or self.normal + self.positive < 1):
            raise ValueError("invalid bounded campaign part")


def proportions(normal, positive):
    ready_normal, ready_positive = normal * 7 // 10, positive * 7 // 10
    unseen_normal, unseen_positive = normal * 2 // 10, positive * 2 // 10
    return [("READY", normal * 7 // 10, positive * 7 // 10),
            ("UNSEEN_READY", normal * 2 // 10, positive * 2 // 10),
            ("COLD", normal - ready_normal - unseen_normal, positive - ready_positive - unseen_positive)]


def recipe(mode, pilot_normal=100000, pilot_positive=100):
    if mode == "PILOT":
        return [Part("pilot", cohort, 15, 7, normal, positive)
                for cohort, normal, positive in proportions(pilot_normal, pilot_positive) if normal + positive]
    if mode != "STRICT": raise ValueError("unknown campaign mode")
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


def profile(account):
    rng = random.Random(seed("profile", account))
    return {"requests": rng.choice(BASE_COUNTS), "routes": rng.randint(1, 7), "first_hour": rng.randint(0, 12),
            "ip": f"198.51.100.{1 + account % 250}", "ua": AGENTS[account % len(AGENTS)]}


def make_frame(dataset, part, account, ordinal, anchor, *, context=False, positive_index=None):
    identity_kind = "cold" if part.cohort == "COLD" else "unseen" if part.cohort == "UNSEEN_READY" else "dev"
    fold = part.split[:5] if part.split.startswith("fold") else "fold3" if part.split == "holdout" else "pilot"
    identity = f"{dataset}-{fold}-{identity_kind}-{account:06d}"
    info = profile(seed(identity))
    # A mature account is observed on 12 repeated hours/day. Context is always
    # generated BEFORE evaluated activity and is identical for either label.
    if context:
        offset = -48 + ordinal if part.cohort != "COLD" else -3 + ordinal
    else: offset = ordinal
    day_offset, slot = divmod(offset, 12)
    day = part.day + day_offset
    at = anchor + timedelta(days=day - 1, hours=info["first_hour"] + slot)
    rng = random.Random(seed(dataset, part.split, part.cohort, account, ordinal, context))
    requests = max(1, min(800, round(info["requests"] * rng.lognormvariate(0, 0.28))))
    route_count = max(1, min(len(PATHS), requests, info["routes"] + rng.choice((-1, 0, 0, 1))))
    failures = client_errors = server_errors = sensitive = 0
    successful = rng.choice((0, 0, 1, 1, 2))
    ip, agent = info["ip"], info["ua"]
    family = "normal" if positive_index is None else FAMILIES[positive_index % len(FAMILIES)]
    familiar = positive_index is not None and positive_index % 10 < 6
    if not context and positive_index is None:
        variant = rng.random()
        if variant < 0.03: failures = rng.randint(1, 7)  # real retries, including near the rule boundary
        elif variant < 0.06: client_errors = min(requests, rng.randint(1, 6))
        elif variant < 0.08: server_errors = min(requests, rng.randint(1, 4))
        elif variant < 0.10: sensitive = rng.choice((1, 1, 2))
        elif variant < 0.13: requests = min(1000, requests * rng.randint(2, 5))  # legitimate heavy activity
        elif variant < 0.16:
            ip = f"203.0.113.{1 + account % 250}"
            agent = AGENTS[(account + 1) % len(AGENTS)]
    elif positive_index is not None:
        if not familiar:
            ip = f"203.0.113.{1 + (account + 17) % 250}"
            agent = AGENTS[(account + 1) % len(AGENTS)] if positive_index % 2 else "owned-lab-probe/1.0"
        if family == "request_burst":
            requests = min(1600, max(120, round(info["requests"] * rng.uniform(4.0, 10.0))))
            client_errors = rng.randint(0, min(15, requests))
            route_count = rng.randint(2, len(PATHS))
        elif family == "endpoint_scan":
            requests = rng.randint(50, 240); client_errors = round(requests * rng.uniform(0.45, 0.95))
            route_count = len(PATHS)
        elif family == "auth_failure_burst":
            requests = rng.randint(1, 12); route_count = 1
            failures = rng.randint(8, 45); successful = rng.choice((0, 0, 1))
        elif family == "sensitive_action_burst":
            requests = rng.randint(2, 18); route_count = min(2, requests)
            sensitive = rng.randint(5, 25); successful = rng.randint(0, 3)
        elif family == "http_error_burst":
            requests = rng.randint(40, 240); client_errors = rng.randint(0, 6)
            server_errors = round((requests - client_errors) * rng.uniform(0.35, 0.90))
            route_count = rng.randint(1, len(PATHS))
    events = []
    for index in range(requests):
        status = 404 if index < client_errors else 503 if index < client_errors + server_errors else 200
        path = PATHS[index % route_count]
        if family == "endpoint_scan" and status == 404:
            # Real normalization collapses these many missing paths to other_api.
            path = f"/api/owned-missing-{index}"
        events.append({"event_timestamp": (at + timedelta(seconds=1 + index % 800)).isoformat().replace("+00:00", "Z"),
                       "event_type": "HTTP_REQUEST", "action": "API_REQUEST", "outcome": "FAILURE" if status >= 400 else "SUCCESS",
                       "http_method": "GET", "http_status": status, "request_path": path, "source_ip": ip, "user_agent": agent})
    for index in range(failures + successful):
        events.append({"event_timestamp": (at + timedelta(seconds=805 + index)).isoformat().replace("+00:00", "Z"),
                       "event_type": "AUTH", "action": "LOGIN", "outcome": "FAILURE" if index < failures else "SUCCESS",
                       "source_ip": ip, "user_agent": agent})
    for index in range(sensitive):
        events.append({"event_timestamp": (at + timedelta(seconds=860 + index)).isoformat().replace("+00:00", "Z"),
                       "event_type": "DOMAIN_ACTION", "action": ("PASSWORD_CHANGE", "EMAIL_CHANGE", "PASSWORD_RESET")[index % 3],
                       "outcome": "SUCCESS"})
    value = {"frame_id": f"{dataset}-{part.split}-{identity_kind}-{account:06d}-{'ctx' if context else 'eval'}-{ordinal:03d}",
             "account_id": identity, "day": day, "cohort": "COLD" if part.cohort == "COLD" else "UNSEEN" if part.cohort == "UNSEEN_READY" else "DEVELOPMENT",
             "window_start": at.isoformat().replace("+00:00", "Z"), "telemetry_contract_version": 2,
             "demo_label": "ABNORMAL" if positive_index is not None else "NORMAL", "family": family, "events": events}
    return value, familiar


def actor_batches(part, batch_accounts=128):
    total = part.normal + part.positive
    maximum = min(20, part.days * 12) if part.cohort == "COLD" else part.days * 12
    if part.split.endswith("-fit"):
        accounts = total  # 50k seen development identities; validation/holdout remain inside this pool.
    else: accounts = math.ceil(total / maximum)
    if part.cohort == "READY" and accounts > 50000: raise ValueError("READY pool exceeds fitted development account coverage")
    # Balance window counts; no account evaluates twice in the same hour.
    per_account, extra = divmod(total, accounts)
    for begin in range(0, accounts, batch_accounts):
        batch, global_ordinal = [], begin * per_account + min(begin, extra)
        for account in range(begin, min(begin + batch_accounts, accounts)):
            count = per_account + (account < extra)
            evaluations = []
            for ordinal in range(count):
                before = global_ordinal * part.positive // total
                after = (global_ordinal + 1) * part.positive // total
                evaluations.append((ordinal, before if after > before else None))
                global_ordinal += 1
            batch.append((account, evaluations))
        yield batch


class ShardWriter:
    def __init__(self, root, name):
        self.root, self.name, self.rows, self.shards = root, name, [], []

    def append(self, row):
        self.rows.append(row)
        if len(self.rows) == 5000: self.flush()

    def flush(self):
        if not self.rows: return
        stats = validate_rows(self.rows)
        identity = f"{self.name}-{len(self.shards):06d}"
        path = self.root / "shards" / f"{identity}.json"
        write_json(path, self.rows)
        self.shards.append({"id": identity, "path": f"shards/{identity}.json", "sha256": digest(path), **stats})
        self.rows = []

    def finish(self):
        self.flush()
        counts, families, cohorts = Counter(), Counter(), Counter()
        for shard in self.shards:
            counts.update({key: shard[key] for key in ("records", "normal", "positive")})
            families.update(shard["families"]); cohorts.update(shard["cohorts"])
        value = {**dict(counts), "families": dict(sorted(families.items())), "cohorts": dict(sorted(cohorts.items())),
                 "from": min(row["from"] for row in self.shards), "to": max(row["to"] for row in self.shards), "shards": self.shards}
        return {**value, "sha256": hashlib.sha256(canonical(value).encode()).hexdigest()}


def export_batch(dataset, part, batch, anchor, writer, statistics, destination):
    classpath = ROOT / "backend/target/ueba-experiment.classpath"
    command = ["java", "-Xmx256m", "-cp", str(ROOT / "backend/target/classes") + ":" + classpath.read_text().strip(),
               "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only"]
    failures = []
    with (destination / "java-export.log").open("ab") as log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        def sample_memory():
            statistics["python_sampled_peak_rss_kib"] = max(statistics["python_sampled_peak_rss_kib"], rss_kib(os.getpid()))
            statistics["java_sampled_peak_rss_kib"] = max(statistics["java_sampled_peak_rss_kib"], rss_kib(process.pid))
        def send(value):
            data = (canonical(value) + "\n").encode()
            statistics["raw_hash"].update(data); statistics["raw_frames"] += 1
            process.stdin.write(data)
            if statistics["raw_frames"] % 256 == 0: sample_memory()
        def feed():
            try:
                for account, evaluations in batch:
                    for ordinal in range(3 if part.cohort == "COLD" else 48):
                        value, _ = make_frame(dataset, part, account, ordinal, anchor, context=True)
                        send(value)
                    for ordinal, positive_index in evaluations:
                        value, familiar = make_frame(dataset, part, account, ordinal, anchor, positive_index=positive_index)
                        statistics["abnormal_familiar"] += int(familiar)
                        statistics["abnormal"] += int(positive_index is not None)
                        send(value)
            except BaseException as failure: failures.append(type(failure).__name__)
            finally: process.stdin.close()
        thread = threading.Thread(target=feed, daemon=True); thread.start()
        expected = sum(len(evaluations) for _, evaluations in batch)
        exported = 0
        try:
            for line in process.stdout:
                if len(line) > 16384: raise ValueError("numeric exporter line exceeded bound")
                row = json.loads(line)
                if re.search(r"-ctx-[0-9]{3}$", row["frame_id"]): continue
                if row["telemetry_contract_version"] != 2 or row["data_provenance"] != "DEMO_ONLY":
                    raise ValueError("wrong live export contract")
                selected = {key: row[key] for key in ("frame_id", "account_id", "window_start", "label", "family",
                                                       "baseline_established", "trusted_window_count", "features")}
                selected["cohort"] = part.cohort
                if selected["baseline_established"] != (part.cohort != "COLD"):
                    raise ValueError("actual baseline coverage differs from requested cohort")
                writer.append(selected); exported += 1
            thread.join(timeout=30)
            if thread.is_alive() or process.wait(timeout=30) or failures or exported != expected:
                raise RuntimeError("bounded Java export did not produce its complete numeric population")
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            process.stdout.close()
            thread.join(timeout=10)
    statistics["exported"] += exported


def prepare(dataset, mode, anchor, pilot_normal=100000, pilot_positive=100):
    if not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset): raise ValueError("invalid fresh dataset ID")
    if not (ROOT / "backend/target/ueba-experiment.classpath").is_file(): raise ValueError("build the backend exporter/classpath first")
    destination = ROOT / "observability/runtime/ueba-experiments" / dataset
    destination.mkdir(mode=0o700)  # Never overwrite an opened holdout or interrupted evidence.
    (destination / "shards").mkdir(mode=0o700)
    identity = source_identity()
    write_json(destination / "generation.identity.json", identity)
    parts = recipe(mode, pilot_normal, pilot_positive)
    writers = {name: ShardWriter(destination, name) for name in dict.fromkeys(part.split for part in parts)}
    statistics = {"raw_frames": 0, "raw_hash": hashlib.sha256(), "exported": 0, "abnormal": 0, "abnormal_familiar": 0,
                  "python_sampled_peak_rss_kib": 0, "java_sampled_peak_rss_kib": 0}
    before = time.monotonic()
    for part in parts:
        for batch in actor_batches(part):
            export_batch(dataset, part, batch, anchor, writers[part.split], statistics, destination)
            elapsed = time.monotonic() - before
            progress = {"status": "RUNNING", "stage": mode, "split": part.split, "cohort": part.cohort,
                        "actually_exported": statistics["exported"], "elapsed_seconds": elapsed,
                        "numeric_rows_per_second": statistics["exported"] / max(1, elapsed)}
            temporary = destination / "generation.progress.tmp"
            temporary.write_text(canonical(progress)); temporary.chmod(0o600); temporary.replace(destination / "generation.progress.json")
            print(f"{mode} actually exported={statistics['exported']} rows/s={progress['numeric_rows_per_second']:.1f}", flush=True)
    splits = {name: writer.finish() for name, writer in writers.items()}
    for name, split in splits.items():
        expected_normal = sum(part.normal for part in parts if part.split == name)
        expected_positive = sum(part.positive for part in parts if part.split == name)
        if split["normal"] != expected_normal or split["positive"] != expected_positive:
            raise ValueError("exported population differs from recipe")
    if source_identity() != identity:
        raise ValueError("source/binary changed during export; retain evidence and create a fresh dataset")
    elapsed = time.monotonic() - before
    manifest = {"catalog_schema_version": 2, "dataset_id": dataset, "stage": mode, "data_provenance": "DEMO_ONLY",
                "feature_schema_version": 2, "telemetry_contract_version": 2, "feature_names": list(FEATURE_NAMES_V2),
                "anchor_utc": anchor.isoformat(), "split_strategy": "past_only_raw_server_normalization_account_hour_episodes",
                **identity,
                "raw_stream_sha256": statistics["raw_hash"].hexdigest(), "raw_frames": statistics["raw_frames"],
                "evaluated_records": statistics["exported"], "abnormal_familiar_identity_fraction": statistics["abnormal_familiar"] / max(1, statistics["abnormal"]),
                "elapsed_seconds": elapsed, "numeric_rows_per_second": statistics["exported"] / max(1, elapsed),
                "java_rusage_maxrss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                "python_rusage_maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "python_sampled_peak_rss_kib": statistics["python_sampled_peak_rss_kib"],
                "java_sampled_peak_rss_kib": statistics["java_sampled_peak_rss_kib"],
                "rss_sampling_method": "Linux proc statm every 256 raw frames; sampled, not an exact peak",
                "split_recipe": [part.__dict__ for part in parts], "splits": splits}
    write_json(destination / "manifest.json", manifest)
    catalogue = ShardedDataset(destination)
    for name in splits:
        for _ in catalogue.iter_shards(name): pass
    (destination / "java-export.log").chmod(0o600)
    complete = {"status": "COMPLETED", "stage": mode, "dataset_id": dataset, "actually_exported": statistics["exported"],
                "manifest_sha256": catalogue.sha256, "elapsed_seconds": elapsed}
    temporary = destination / "generation.progress.tmp"
    write_json(temporary, complete); temporary.replace(destination / "generation.progress.json")
    print(canonical(complete), flush=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--mode", choices=("PILOT", "STRICT"), default="PILOT")
    parser.add_argument("--anchor", default="2026-05-01T00:00:00Z")
    parser.add_argument("--pilot-normal", type=int, default=100000)
    parser.add_argument("--pilot-positive", type=int, default=100)
    args = parser.parse_args()
    if not 1000 <= args.pilot_normal <= 100000 or not 10 <= args.pilot_positive <= 1000:
        parser.error("pilot populations require 1000..100000 normal and 10..1000 positive")
    anchor = datetime.fromisoformat(args.anchor.replace("Z", "+00:00"))
    if anchor.utcoffset() != timedelta(0) or any((anchor.hour, anchor.minute, anchor.second, anchor.microsecond)):
        parser.error("anchor must be UTC midnight")
    prepare(args.dataset, args.mode, anchor, args.pilot_normal, args.pilot_positive)


if __name__ == "__main__": main()
